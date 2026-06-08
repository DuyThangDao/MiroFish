# Code-Normalize RAG Track (CODE Track)

## Vấn đề

OP queries hiện tại sinh NL description của operations trong code:

```
fn_body → LLM → "abi.decode int24 uint128 and bool from bytes calldata"
               → embed(NL query) → find similar NL description in RAG
```

RAG DB chứa audit findings với **NL vulnerability description + code snippet**. Khi OP query là
mechanical NL (`"abi.decode int24 uint128..."`) và RAG entry là NL vulnerability description
(`"missing bounds check causes DoS"`), embedding space không overlap → score < 0.65 → không retrieve.

Root cause: **language mismatch** — OP query mô tả "code đang làm gì", RAG description mô tả
"bug là gì và tại sao".

## Giải pháp: Normalize code → embed code

Thay vì NL query, dùng **code chunk từ fn_body** làm query, tìm **code pattern tương tự**
trong RAG. Để xử lý khác biệt variable names, normalize cả 2 phía bằng cùng 1 function trước
khi embed.

```
Actual code:  reserve0 -= uint128(amount0fees);
Normalized:   _VAR -= uint128(_VAR);

RAG entry:    reserveBalance -= uint128(feesAmount);
Normalized:   _VAR -= uint128(_VAR);
```

Hai chuỗi normalized **giống nhau** → embedding identical → perfect match, dù variable names khác nhau.

## Không cần LLM call

| Track | LLM call | Embedding call |
|-------|----------|----------------|
| OP    | ✅       | ✅             |
| ST    | ✅       | ✅             |
| CODE  | ❌       | ✅ (Vertex AI) |

CODE track chỉ dùng regex + embedding — thêm signal mà không tốn thêm LLM cost.

---

## Hàm normalize

```python
import re

# Solidity built-in types và keywords — giữ nguyên
SOLIDITY_KEYWORDS = {
    # Integer types
    "uint8", "uint16", "uint32", "uint64", "uint96", "uint128", "uint160", "uint256", "uint",
    "int8",  "int16",  "int32",  "int64",  "int96",  "int128",  "int160",  "int256",  "int",
    # Other types
    "address", "bool", "bytes", "string",
    "bytes1", "bytes2", "bytes4", "bytes8", "bytes16", "bytes20", "bytes32",
    "mapping",
    # Control flow
    "if", "else", "for", "while", "do", "return", "break", "continue",
    # State modifiers
    "unchecked", "assembly", "revert", "require", "assert",
    "try", "catch", "emit", "delete", "new",
    # Visibility / location
    "public", "private", "internal", "external",
    "view", "pure", "payable", "override", "virtual",
    "memory", "storage", "calldata", "indexed",
    # Literals / special
    "true", "false", "this", "super", "type",
    # Solidity globals
    "msg", "block", "tx", "abi",
}

def normalize_code(code: str) -> str:
    """
    Normalize Solidity code: replace all user-defined identifiers với _VAR.
    Giữ nguyên: types, keywords, operators, numbers, punctuation.

    Ví dụ:
        "reserve0 -= uint128(amount0fees);"
        → "_VAR -= uint128(_VAR);"

        "if (lowerTick <= nearestTick) {"
        → "if (_VAR <= _VAR) {"
    """
    def replace_token(m: re.Match) -> str:
        token = m.group(0)
        # PascalCase = contract/event name → replace
        # ALL_CAPS = constant → replace
        # In SOLIDITY_KEYWORDS → keep
        return token if token in SOLIDITY_KEYWORDS else "_VAR"

    # Match identifiers (letters + digits + underscore, starts with letter or _)
    return re.sub(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", replace_token, code)
```

### Ví dụ normalize

| Input | Normalized |
|-------|-----------|
| `reserve0 -= uint128(amount0fees);` | `_VAR -= uint128(_VAR);` |
| `reserveBalance -= uint128(fees);` | `_VAR -= uint128(_VAR);` |
| `if (lowerTick <= nearestTick) {` | `if (_VAR <= _VAR) {` |
| `if (tickLower <= currentTick) {` | `if (_VAR <= _VAR) {` |
| `price = sqrtPriceX96;` | `_VAR = _VAR;` |
| `price = _price;` | `_VAR = _VAR;` |
| `uint128 liquidityDelta = uint128(x);` | `uint128 _VAR = uint128(_VAR);` |
| `(uint256 a, uint256 b) = _fn(msg.sender, lower, upper, -int128(x));` | `(uint256 _VAR, uint256 _VAR) = _VAR(msg._VAR, _VAR, _VAR, -int128(_VAR));` |

---

## Kiến trúc 2 collection

```
ChromaDB
├── solodit_findings          ← collection hiện tại (NL-indexed, RETRIEVAL_DOCUMENT)
│   document: "Title: ...\nImpact: ...\n\n[full finding text with prose + code]"
│
└── solodit_code_patterns     ← collection mới (code-indexed, RETRIEVAL_DOCUMENT)
    document: normalize(vulnerable_lines)
    metadata: { parent_slug, title, impact, firm, source }
```

### Tại sao embed document bằng RETRIEVAL_DOCUMENT?

Khi query, code chunk từ fn_body cũng được embed bằng RETRIEVAL_DOCUMENT (không phải RETRIEVAL_QUERY).
Lý do: đây là **code-to-code symmetric matching** — cả 2 phía đều là "document" trong cùng code space,
không phải asymmetric question-answer.

---

## Pipeline: Indexing (build_code_pattern_db.py)

Input: `self_crafted_35.json` (và sau này: scraped entries có `@>` annotations)

```python
for finding in findings:
    content = finding["content"]

    # Extract vulnerable lines (annotated với @> hoặc # BUG)
    vuln_lines = [
        line.lstrip("0123456789 :@>").strip()
        for line in content.split("\n")
        if "@>" in line or "# BUG" in line.upper()
    ]

    if not vuln_lines:
        continue

    # Normalize và join
    code_chunk = "\n".join(vuln_lines)
    normalized = normalize_code(code_chunk)

    # Upsert vào solodit_code_patterns
    col.upsert(
        ids=[f"code_{finding['slug']}"],
        documents=[normalized],
        metadatas={
            "parent_slug": finding["slug"],
            "title":       finding["title"],
            "impact":      finding["impact"],
            "firm":        finding.get("firm", ""),
        }
    )
```

---

## Pipeline: Query time (ContractKGBuilder)

```python
CODE_CAP = 3       # max annotations từ CODE track
CODE_WINDOW = 4    # số dòng mỗi code chunk
CODE_THRESHOLD = 0.80  # threshold cao hơn vì normalized code rất specific

def _collect_code_track(fn_body: str, cap: int, retriever_code) -> list:
    """Slide window trên fn_body, normalize từng chunk, query solodit_code_patterns."""
    lines = [l for l in fn_body.split("\n") if l.strip()]
    seen_ann: set = set()
    result = []

    for i in range(len(lines) - CODE_WINDOW + 1):
        if len(result) >= cap:
            break
        chunk = "\n".join(lines[i:i + CODE_WINDOW])
        normalized = normalize_code(chunk)

        docs = retriever_code.query(normalized, n_results=2)
        for d in (docs or []):
            if d["score"] < CODE_THRESHOLD:
                continue
            ann = _make_hist_annotation(d)
            if ann not in seen_ann:
                seen_ann.add(ann)
                result.append(ann)
                break

    return result
```

Merge vào `inv_texts`:

```python
op_anns   = _collect_track(op_queries, OP_CAP)
st_anns   = _collect_track(st_queries, ST_CAP)
code_anns = _collect_code_track(fn_body, CODE_CAP, retriever_code)
inv_texts = op_anns + st_anns + code_anns
```

---

## Threshold

CODE track dùng threshold cao hơn OP/ST (0.80 thay vì 0.65) vì:
- Normalized code rất deterministic — nếu match thì score phải cao
- Score thấp (0.65–0.79) với normalized code → likely false positive (khác pattern)
- Tránh nhiễu từ các pattern quá generic (ví dụ `_VAR = _VAR;` match mọi assignment)

---

## Giới hạn

**1. Over-normalization**: `_VAR = _VAR;` (simple assignment) sẽ match tất cả assignment bugs,
gây FP. Giải pháp: dùng window >= 3 dòng để có đủ context, không query single-line chunks.

**2. Contract names / event names bị replace**: `emit Transfer(from, to, amount)` → 
`emit _VAR(_VAR, _VAR, _VAR)`. Mất tên event. Acceptable vì pattern operator/structure vẫn giữ.

**3. Chỉ work với entries có `@>` annotation**: RAG entries scrape từ Solodit hiện tại
không có annotation. Cần thêm bước LLM để extract vulnerable lines từ existing entries —
hoặc chỉ apply với self-crafted entries trước.

---

## Mở rộng tương lai

- Dùng `voyage-code-3` (code embedding model) thay Vertex AI `text-embedding-004` → 
  normalize không cần thiết vì model tự học code similarity.
- Extract `@>` lines tự động từ scraped findings bằng LLM → expand code pattern DB 
  từ 4 (self-crafted) lên hàng nghìn entries.
