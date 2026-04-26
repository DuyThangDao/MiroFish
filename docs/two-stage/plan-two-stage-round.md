# Plan: Two-Stage Round — Shared Feed Communication

**Ngày:** 2026-04-25
**Cập nhật:** 2026-04-25 (v1.4 — DRY stage1_claims trong _build_feed_context, cập nhật §3 token CLAIM block, fix Bước 6 step 3)
**Vấn đề cần giải quyết:** Agents hiện tại không đọc bài của nhau — 17 monologues song song thay vì discussion thật sự. Multi-domain architecture mất đi giá trị cốt lõi.
**Mục tiêu:** Mỗi round có 2 stage: Stage 1 agents phân tích tự do, Stage 2 agents đọc toàn bộ Stage 1 và viết FINDING/CHALLENGE/VALIDATE dựa trên collective reasoning.

> **Scope v1:** CHALLENGE/VALIDATE trong Stage 2 target Stage 1 `CLAIM:` declarations và findings từ các round trước. Không target findings cùng batch Stage 2 (ordering trap — xem Amendment 6 về cách giải quyết bằng CLAIM tag).

---

## 1. Kiến trúc mới

```
HIỆN TẠI (1 stage/round):
─────────────────────────────────────────────────────
  prior_context (titles only)
       ↓ (broadcast, tất cả nhận giống nhau)
  Agent 1 ──parallel──► FINDING  ┐
  Agent 2 ──parallel──► FINDING  ├─► parse → expert_findings
  ...                            │
  Agent 17─────────── ──► FINDING  ┘
  (không ai đọc bài của ai)

SAU THAY ĐỔI (2 stage/round):
─────────────────────────────────────────────────────
  prior_context (titles, sliding window)
       ↓ (broadcast)
  STAGE 1 — parallel, ngắn (~400 tokens output):
  Agent 1 ──► "getPriceFromAMM() dùng spot price..."
              CLAIM: getPriceFromAMM() vulnerable to flash loan manipulation
  Agent 2 ──► "holdsToken không được reset khi..."
              CLAIM: holdsToken flag causes stuck state after token transfer
  Agent 3 ──► "disburse() external call trước state update..."
              CLAIM: disburse() reentrancy possible via external callback
  ...
  Agent 17──► (free-form + optional CLAIM tags)
       ↓ (tất cả Stage 1 posts + CLAIMs được collect)

  STAGE 2 — parallel, đầy đủ (~1500 tokens output):
  [prior_context + Stage 1 posts truncated ≤300 chars/post + full CLAIM list below]
       ↓ (broadcast — agents đọc reasoning + CLAIMs của nhau)
  Agent 1 ──► VALIDATE_FINDING: holdsToken CLAIM (Agent 2's S1)
              + FINDING mới từ domain mình
  Agent 2 ──► CHALLENGE_FINDING: getPriceFromAMM CLAIM (incorrect — has TWAP)
              + SEMANTIC_FINDING: price_manipulation
  Agent 3 ──► VALIDATE_FINDING: disburse CLAIM + FINDING: reentrancy
  ...
  Agent 17──► CHALLENGE_FINDING (finding từ round cũ) + FINDING
       ↓
  parse → expert_findings, semantic_findings
        + update confident/challenged_by trên S1 CLAIMs và round-cũ findings
  ✅ Ordering trap giải quyết: CHALLENGE/VALIDATE target S1 CLAIMs (available đồng thời)
```

---

## 2. Thay đổi theo file

### 2.1 `backend/app/models/cyber_models.py`

**Thêm 1 field vào `CyberSessionState`:**

```python
# Thêm sau gap_registry (line ~211):
round_stage1_posts: Dict[int, List[Dict[str, Any]]] = field(default_factory=dict)
# Key: round_num → Value: list of Stage 1 posts {"agent_id", "domain_group", "persona", "content"}
```

**Lý do:** Cần lưu Stage 1 posts per round để:
- Build feed context cho Stage 2
- Persist qua session save/load
- Debug và analysis sau

---

### 2.2 `backend/app/services/contract_oasis_env.py`

**A. Thêm Stage 1 phase instruction vào `PHASE_CONFIG`:**

Mỗi phase cần 2 instruction variant: `stage1_instruction` và `stage2_instruction` (thay thế `instruction_addition` hiện tại).

```python
PHASE_CONFIG = {
    "A": {
        "name": "Intra-domain Analysis",
        "rounds": [1, 2, 3],
        "attacker_active": False,

        # MỚI: Stage 1 — free-form analysis + optional CLAIM tags
        "stage1_instruction": (
            "STAGE 1 — ANALYSIS\n"
            "Analyze the contract from YOUR DOMAIN perspective. Write your observations freely.\n"
            "Focus on:\n"
            "  - What specific functions or patterns concern you and why\n"
            "  - What you want other domain experts to investigate further\n"
            "  - Any state variables, mappings, or flows that look suspicious\n\n"
            "Do NOT write FINDING blocks yet. This is your reasoning phase.\n"
            "Keep it focused — reference actual function names and variables.\n\n"
            "Optionally, declare soft claims that other domains can validate or challenge:\n"
            "  CLAIM: <function_name()> may be vulnerable because <one-line reason>\n"
            "Example:\n"
            "  CLAIM: getPriceFromAMM() vulnerable to flash loan price manipulation\n"
            "  CLAIM: holdsToken flag never reset after failed transfer\n"
            "CLAIMs will be visible to ALL experts in Stage 2 — keep them specific.\n"
            + GAP_FORMAT_INSTRUCTION
        ),

        # MỚI: Stage 2 — structured findings với full feed context + CLAIM targeting
        "stage2_instruction": (
            "STAGE 2 — FINDINGS & DISCUSSION\n"
            "You have read all domain experts' Stage 1 analyses and CLAIM declarations above.\n\n"
            "Now write your structured output:\n"
            "  - FINDING / SEMANTIC_FINDING: new vulnerabilities from YOUR domain\n"
            "  - VALIDATE_FINDING: confirm a Stage 1 CLAIM or prior-round finding\n"
            "      VALIDATE_FINDING: <exact CLAIM or finding title>\n"
            "      DOMAIN_EVIDENCE: <your evidence from your domain angle>\n"
            "      FUNCTION: <function name>\n"
            "      ADDITIONAL_IMPACT: <extra impact>\n"
            "  - CHALLENGE_FINDING: dispute a Stage 1 CLAIM or prior-round finding\n"
            "      CHALLENGE_FINDING: <exact CLAIM or finding title>\n"
            "      REASON: <specific counter-evidence from code>\n"
            "      FUNCTION: <function name>\n"
            "      EVIDENCE: <code quote>\n\n"
            "Note: CHALLENGE/VALIDATE target Stage 1 CLAIMs and previous-round findings.\n"
            "New findings from THIS round's other experts will be challengeable next round.\n"
            + GAP_FORMAT_INSTRUCTION
        ),

        # Giữ instruction_addition cho backward compat (single-stage mode)
        "instruction_addition": "...(giữ nguyên như cũ)...",
    },
    # Tương tự cho Phase B và C
}
```

**B. Cập nhật `build_phase_instruction()` để nhận `stage` param:**

```python
def build_phase_instruction(
    self,
    phase: str,
    round_num: int,
    gap_context: str = "",
    phase_c_review_list: str = "",
    stage: int = 0,           # MỚI: 0 = single-stage (compat), 1 = Stage 1, 2 = Stage 2
) -> str:
    phase_cfg = PHASE_CONFIG.get(phase, {})

    if stage == 1:
        instruction_text = phase_cfg.get("stage1_instruction", phase_cfg.get("instruction_addition", ""))
    elif stage == 2:
        instruction_text = phase_cfg.get("stage2_instruction", phase_cfg.get("instruction_addition", ""))
    else:
        instruction_text = phase_cfg.get("instruction_addition", "")

    instruction = (
        f"=== Phase {phase}: {phase_cfg.get('name', '')} | Round {round_num}/{TOTAL_ROUNDS} ===\n"
        f"{instruction_text}"
    )
    if phase == "C" and phase_c_review_list:
        instruction = phase_c_review_list + "\n" + instruction
    if gap_context:
        instruction = gap_context + "\n" + instruction
    return instruction
```

**C. Thêm CLAIM/CHALLENGE/VALIDATE format strings:**

```python
# Amendment 6: CLAIM tag trong Stage 1 — soft claim cho Stage 2 agents target
CLAIM_FORMAT = "CLAIM: <function_name()> may be vulnerable because <one-line reason>"

CHALLENGE_FORMAT = """\
CHALLENGE_FINDING: <exact CLAIM title or prior-round finding title>
REASON: <specific code evidence that disproves or weakens the claim>
FUNCTION: <function name where the counter-evidence is>
EVIDENCE: <exact code snippet or behavior that contradicts the finding>
"""

VALIDATE_FORMAT = """\
VALIDATE_FINDING: <exact CLAIM title or prior-round finding title>
DOMAIN_EVIDENCE: <your domain's perspective confirming this vulnerability>
FUNCTION: <function name you verified>
ADDITIONAL_IMPACT: <any additional impact you found from your domain's angle>
"""
```

---

### 2.3 `backend/app/services/cyber_session_orchestrator.py`

**A. Thêm `_build_feed_context()` — method mới:**

```python
# Amendment 2: cap mỗi post để tránh token explosion khi STAGE1_MAX_TOKENS cao
STAGE1_FEED_CHARS_PER_POST = int(os.environ.get("STAGE1_FEED_CHARS_PER_POST", "300"))

def _build_feed_context(
    self,
    round_num: int,
    stage1_posts: List[Dict[str, Any]],
    stage1_claims: Optional[List[Dict[str, Any]]] = None,  # DRY: nhận claims đã parse sẵn
    # Khi implement: truyền [] thay None khi parse trả về list rỗng → hành vi nhất quán (if stage1_claims luôn đúng)
) -> str:
    """
    Build context từ Stage 1 posts của round hiện tại.
    Được inject vào Stage 2 prompt — đây là "shared feed" mà tất cả agents đọc.
    Mỗi post được truncate tại STAGE1_FEED_CHARS_PER_POST để giữ token budget ổn định.

    DRY: Khối CLAIM dựng từ cùng list stage1_claims đã parse bởi _parse_stage1_claims().
    Không re-parse regex ở đây — tránh hai nơi cùng regex, sửa một quên nơi kia.
    """
    if not stage1_posts:
        return ""

    cap = STAGE1_FEED_CHARS_PER_POST

    # Khối 1: summary truncated — cho reasoning context
    lines = [f"=== STAGE 1 ANALYSIS — Round {round_num} ({len(stage1_posts)} experts) ==="]
    lines.append("(Summaries — truncated for token budget)\n")
    for post in stage1_posts:
        domain = post.get("domain_group", "?")
        persona = post.get("persona", "?")
        content = post.get("content", "").strip()
        if len(content) > cap:
            content = content[:cap] + "…"
        lines.append(f"[{domain}/{persona}]: {content}")
        lines.append("")

    # Khối 2: CLAIM lines — FULL text từ stage1_claims đã parse (không truncate)
    # Dùng stage1_claims truyền vào thay vì re.finditer — một nguồn regex duy nhất
    if stage1_claims:
        lines.append(f"=== STAGE 1 CLAIMS — Round {round_num} (full, use exact title to VALIDATE/CHALLENGE) ===")
        for c in stage1_claims:
            lines.append(
                f"  [{c.get('author_domain','?')}/{c.get('author_id','?')}] "
                f"CLAIM: {c['title']}"
            )
        lines.append("")

    # Token budget:
    #   Summary block: 17 posts × 300 chars ≈ 1,275 tokens (bounded)
    #   Claims block:  17 agents × avg 2 claims × 80 chars ≈ 680 chars ≈ 170 tokens
    #   Total extra:   ~1,445 tokens max — chấp nhận được
    return "\n".join(lines)
```

**B. Thêm `_run_stage1()` — method mới:**

```python
def _run_stage1(
    self,
    round_num: int,
    phase: str,
    active_profiles: List[CyberAgentProfile],
    session_state: CyberSessionState,
    network_summary: str,
    prior_context: str,
    mode: str,
    env_builder,
    known_functions,
) -> List[Dict[str, Any]]:
    """
    Chạy Stage 1 của 1 round: tất cả agents viết analysis tự do song song.
    Không parse FINDING — chỉ collect raw posts cho Stage 2 feed.
    Returns: list of stage1 post dicts.
    """
    stage1_posts = []

    def _call_stage1(profile):
        phase_instruction = env_builder.build_phase_instruction(
            phase, round_num, stage=1,
        )
        _rate_limiter.acquire()
        import time as _t
        t0 = _t.time()
        response = self._call_agent(
            profile=profile,
            phase=phase,
            round_num=round_num,
            phase_instruction=phase_instruction,
            prior_context=prior_context,
            network_summary=network_summary,
            mode=mode,
            strip_think=True,
            max_tokens=400,       # Stage 1 ngắn hơn: 400 tokens
        )
        elapsed = _t.time() - t0
        logger.info(f"[TIMING] Phase={phase} R{round_num} S1 agent={profile.agent_id} latency={elapsed:.1f}s")
        return profile, response

    # Parallel — giống cơ chế hiện tại
    submit_delay = float(os.environ.get("LLM_SUBMIT_DELAY_S", "1.0"))
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {}
        for i, p in enumerate(active_profiles):
            if i > 0 and submit_delay > 0:
                import time as _t; _t.sleep(submit_delay)
            futures[pool.submit(_call_stage1, p)] = p
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                logger.warning(f"Stage1 agent {futures[future].agent_id} R{round_num}: {e}")

    # Collect posts — không parse finding
    for profile, response in results:
        post = {
            "round_num":    round_num,
            "phase":        phase,
            "stage":        1,
            "agent_id":     profile.agent_id,
            "domain_group": profile.domain_group,
            "persona":      profile.persona,
            "content":      response.strip(),
            "timestamp":    datetime.now().isoformat(),
        }
        stage1_posts.append(post)
        self._append_feed_post(session_state.session_id, post)

    return stage1_posts
```

**C. Thêm `_parse_stage1_claims()` — parser mới (Amendment 6):**

```python
def _parse_stage1_claims(
    self,
    stage1_posts: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Extract CLAIM: tags từ Stage 1 posts.
    CLAIMs được dùng làm target cho CHALLENGE/VALIDATE trong Stage 2.
    Không phải expert_findings — không qua consensus engine.
    """
    claims = []
    for post in stage1_posts:
        for m in re.finditer(r'(?i)^CLAIM\s*:\s*(.+)$', post["content"], re.MULTILINE):
            claims.append({
                "title":        m.group(1).strip(),
                "author_id":    post["agent_id"],
                "author_domain": post["domain_group"],
                "round_num":    post["round_num"],
                # Tracking
                "challenged_by": [],
                "validated_by":  [],
            })
    return claims
```

**D. Thêm `_parse_challenge_validate()` — parser mới:**

```python
def _parse_challenge_validate(
    self,
    text: str,
    profile: CyberAgentProfile,
    round_num: int,
    session_state: CyberSessionState,
    stage1_claims: Optional[List[Dict[str, Any]]] = None,
):
    """
    Parse CHALLENGE_FINDING và VALIDATE_FINDING từ Stage 2 response.

    Target priority:
      1. Stage 1 CLAIMs (same round — Amendment 6, giải quyết ordering trap)
      2. expert_findings từ round trước (đã commit)

    Không target expert_findings cùng batch Stage 2 (chưa commit).
    """
    _CHALLENGE_RE = re.compile(
        r'(?i)^CHALLENGE_FINDING\s*:\s*(.+?)$.*?^REASON\s*:\s*(.+?)(?=^[A-Z_]+\s*:|$)',
        re.MULTILINE | re.DOTALL
    )
    _VALIDATE_RE = re.compile(
        r'(?i)^VALIDATE_FINDING\s*:\s*(.+?)$.*?^DOMAIN_EVIDENCE\s*:\s*(.+?)(?=^[A-Z_]+\s*:|$)',
        re.MULTILINE | re.DOTALL
    )

    def _normalize(s: str) -> str:
        """Lowercase + strip trailing punctuation — giảm miss khi model rút gọn title."""
        return re.sub(r'[.,!?;:]+$', '', s.lower().strip())

    def _find_target(title_fragment: str):
        """
        Tìm target theo title — CLAIMs trước, sau đó expert_findings round cũ.
        Dùng normalize để tolerate minor abbreviation/punctuation mismatch.
        Worst case (không match): return None → no effect, không crash.
        v2: có thể thêm fuzzy matching (difflib.SequenceMatcher).
        """
        frag = _normalize(title_fragment)
        # Priority 1: Stage 1 CLAIMs (same round, available đồng thời)
        if stage1_claims:
            for c in stage1_claims:
                if frag in _normalize(c["title"]):
                    return ("claim", c)
        # Priority 2: expert_findings từ round cũ (đã commit)
        for f in session_state.expert_findings:
            if f.get("round_number", 0) < round_num and frag in _normalize(f.get("title", "")):
                return ("finding", f)
        return (None, None)

    for m in _CHALLENGE_RE.finditer(text):
        title_fragment = m.group(1).strip()
        reason = m.group(2).strip()[:300]
        kind, target = _find_target(title_fragment)
        if target is None:
            continue
        entry = {"challenger": profile.agent_id, "domain": profile.domain_group,
                 "reason": reason, "round": round_num}
        target.setdefault("challenged_by", []).append(entry)
        # Confidence penalty chỉ áp lên expert_findings (claims không có confidence)
        if kind == "finding" and profile.domain_group != target.get("author_domain"):
            target["confidence"] = max(0.1, target.get("confidence", 0.5) - 0.10)

    for m in _VALIDATE_RE.finditer(text):
        title_fragment = m.group(1).strip()
        evidence = m.group(2).strip()[:300]
        kind, target = _find_target(title_fragment)
        if target is None:
            continue
        entry = {"validator": profile.agent_id, "domain": profile.domain_group,
                 "evidence": evidence, "round": round_num}
        target.setdefault("validated_by", []).append(entry)
        if kind == "finding" and profile.domain_group != target.get("author_domain"):
            target["cross_domain_validated"] = True
            target["confidence"] = min(0.95, target.get("confidence", 0.5) + 0.08)
```

**E. Sửa `_run_round()` — canonical pipeline (Stage 1 → claims → feed → Stage 2):**

> **Source of truth:** Đây là sketch duy nhất cho `_run_round()`. Xem thêm Bước 6 (phần 4) cho chi tiết implement từng bước.

```python
def _run_round(self, round_num, phase, profiles, session_state, ...):
    active_profiles = env_builder.get_active_agents_for_phase(profiles, phase)
    prior_context = self._build_prior_context(session_state, mode=mode)
    two_stage = os.environ.get("TWO_STAGE_ROUNDS", "true").lower() == "true"

    if two_stage and mode == "contract_audit" and phase in ("A", "B"):
        # ── Stage 1: Analysis ──────────────────────────────────────────
        logger.info(f"[Round {round_num}] Stage 1 — {len(active_profiles)} agents analyzing...")
        stage1_posts = self._run_stage1(
            round_num=round_num, phase=phase,
            active_profiles=active_profiles,
            session_state=session_state,
            network_summary=network_summary,
            prior_context=prior_context,
            mode=mode, env_builder=env_builder,
            known_functions=known_functions,
        )

        # ── Extract CLAIMs từ Stage 1 — target cho Stage 2 CHALLENGE/VALIDATE
        stage1_claims = self._parse_stage1_claims(stage1_posts)
        # Lưu vào session state để persist
        session_state.round_stage1_posts[round_num] = stage1_posts

        # ── Stage 2: Findings + Discussion ────────────────────────────
        feed_context = self._build_feed_context(round_num, stage1_posts, stage1_claims=stage1_claims)
        stage2_prior = feed_context + "\n\n" + prior_context

        logger.info(f"[Round {round_num}] Stage 2 — agents writing findings from shared feed...")
        self._run_stage2(
            round_num=round_num, phase=phase,
            active_profiles=active_profiles,
            session_state=session_state,
            network_summary=network_summary,
            prior_context=stage2_prior,
            mode=mode, env_builder=env_builder,
            known_functions=known_functions,
            phase_c_review_list=phase_c_review_list,
            stage1_claims=stage1_claims,   # ← CLAIMs passed down cho CHALLENGE/VALIDATE parser
        )
    else:
        # Single-stage fallback (Phase C attackers, network_security mode, hoặc TWO_STAGE_ROUNDS=false)
        self._run_single_stage(...)  # đổi tên logic hiện tại
```

**G. Thêm `_run_stage2()` — method mới:**

Tương tự `_run_single_stage()` nhưng:
- `phase_instruction` dùng `stage=2`
- `prior_context` = `feed_context + prior_context` (đã build bên ngoài, pass vào)
- Nhận `stage1_claims: List[Dict]` param
- Sau parse expert/semantic findings, gọi `_parse_challenge_validate(text, ..., stage1_claims=stage1_claims)`
- `max_tokens=1500` (giữ nguyên)

---

### 2.4 `backend/app/services/contract_oasis_env.py` — CHALLENGE/VALIDATE trong phase_instruction

Bổ sung vào `stage2_instruction` của Phase B (cross-domain challenge là trọng tâm Phase B):

```python
"stage2_instruction": (
    "STAGE 2 — CROSS-DOMAIN FINDINGS & CHALLENGE\n"
    "You have read all domain experts' Stage 1 analyses and CLAIM declarations above.\n\n"
    "Priority actions:\n"
    "1. CHALLENGE a Stage 1 CLAIM or prior-round finding you disagree with:\n"
    "   CHALLENGE_FINDING: <exact CLAIM title or prior finding title>\n"
    "   REASON: <specific counter-evidence from code>\n"
    "   FUNCTION: <function name>\n"
    "   EVIDENCE: <code quote>\n\n"
    "2. VALIDATE a Stage 1 CLAIM or prior-round finding from YOUR domain's angle:\n"
    "   VALIDATE_FINDING: <exact CLAIM title or prior finding title>\n"
    "   DOMAIN_EVIDENCE: <your evidence>\n"
    "   FUNCTION: <function>\n"
    "   ADDITIONAL_IMPACT: <extra impact>\n\n"
    "3. Add NEW findings missed by all domains.\n"
    "4. Reclassify business-logic bugs (no SWC → use SEMANTIC_FINDING).\n\n"
    "Note: CLAIM titles come from the Stage 1 feed above — use exact wording to match.\n"
    + GAP_FORMAT_INSTRUCTION
),
```

---

## 3. Token budget impact

```
Hiện tại (1 stage):
  flat_file + prior_summary + phase_instruction → ~11K tokens (contest 19)
  flat_file + prior_summary + phase_instruction → ~35K tokens (contest 3)

Sau thay đổi (2 stage):
  Stage 1 request:
    flat_file + prior_summary + stage1_instruction → ~11K / ~35K tokens (giống cũ)
    max_tokens output = 400 (giảm từ 1500)

  Stage 2 request:
    flat_file + prior_summary
    + feed_context summary block (17 posts × 300 chars cap = 5,100 chars ≈ 1,275 tokens — bounded)
    + feed_context CLAIM block  (17 agents × avg 2 claims × 80 chars ≈ 680 chars ≈ 170 tokens)
    + stage2_instruction
    → ~12.5K / ~36.5K tokens (+1,275 + ~170 = ~1,445 tokens, +13%)
    max_tokens output = 1500 (giữ nguyên)

  ⚠ Amendment 2: con số +900 tokens ban đầu là lạc quan. Với cap 300 chars/post:
    Summary block worst case = 17 × 300 chars = 5,100 chars ≈ 1,275 tokens — bounded.
    CLAIM block: +150–400 tokens tùy số lượng CLAIM per agent; avg ~170 tokens.
    Total worst case: ~1,445 tokens extra — vẫn chấp nhận được.
    Nếu không có cap: 17 × 400 tokens output = 6,800 tokens extra — có thể gây 429.

API calls per round:
  Hiện tại: 17 calls/round × 10 rounds = 170 calls total
  Sau:      34 calls/round × 10 rounds = 340 calls total (2×)
  (Phase C giữ 1 stage → thực tế: 17×7 rounds×2 + 22×3 rounds×1 = 238+66 = 304 calls)

  Stage 1 max_tokens = 400 (vs 1500 hiện tại) → Stage 1 nhanh hơn per call
  Net thời gian tăng ~40-50% (không phải 2×)
```

---

## 4. Thứ tự triển khai

### Bước 0 — `_call_agent()` support max_tokens override (20 min) ← prerequisite
- File: `backend/app/services/cyber_session_orchestrator.py`
- Hiện tại `max_tokens` hardcode:
  ```python
  max_tok = 4096 if is_attacker_phase_c else 1500
  ```
- Thêm `max_tokens: Optional[int] = None` parameter:
  ```python
  max_tok = max_tokens if max_tokens is not None else (4096 if is_attacker_phase_c else 1500)
  ```
- **Phải làm trước Bước 4** — không có bước này, Stage 1 không enforce được 400 tokens

### Bước 1 — Data model (30 min)
- File: `backend/app/models/cyber_models.py`
- Thêm `round_stage1_posts: Dict[int, List[Dict]] = field(default_factory=dict)` vào `CyberSessionState`

### Bước 2 — Phase instructions (1 giờ)
- File: `backend/app/services/contract_oasis_env.py`
- Thêm `stage1_instruction`, `stage2_instruction` vào `PHASE_CONFIG` cho Phase A, B, C
- Cập nhật `build_phase_instruction()` nhận `stage` parameter
- Thêm format strings `CHALLENGE_FORMAT`, `VALIDATE_FORMAT`

### Bước 3 — Feed builder (30 min)
- File: `backend/app/services/cyber_session_orchestrator.py`
- Thêm `_build_feed_context()` method

### Bước 4 — Stage 1 runner (1 giờ)
- File: `backend/app/services/cyber_session_orchestrator.py`
- Thêm `_run_stage1()` method
- Đặc biệt: `max_tokens=400`, không parse FINDING, chỉ collect posts

### Bước 5 — CLAIM parser + CHALLENGE/VALIDATE parser (1.5 giờ)
- File: `backend/app/services/cyber_session_orchestrator.py`
- Thêm `_parse_stage1_claims()`: extract `CLAIM:` tags từ Stage 1 posts → list of claim dicts
- Thêm `_parse_challenge_validate()` nhận `stage1_claims` param:
  - Target priority: Stage 1 CLAIMs trước → expert_findings round cũ sau
  - Update `challenged_by` / `validated_by` trên cả claims lẫn findings
  - Confidence penalty/boost chỉ áp lên expert_findings (claims không có confidence)

### Bước 6 — Stage 2 runner và `_run_round()` refactor (1.5 giờ)
- File: `backend/app/services/cyber_session_orchestrator.py`
- Đổi tên logic hiện tại của `_run_round()` thành `_run_single_stage()`
- Thêm `_run_stage2(stage1_claims)`: giống `_run_single_stage` nhưng:
  - `phase_instruction` dùng `stage=2`
  - Gọi `_parse_challenge_validate(..., stage1_claims=stage1_claims)` sau parse findings
- Cập nhật `_run_round()`:
  1. `_run_stage1()` → collect posts
  2. `_parse_stage1_claims(posts)` → claims
  3. `_build_feed_context(round_num, posts, stage1_claims=claims)` → feed text
  4. `_run_stage2(stage1_claims=claims)` → findings + challenge/validate

### Bước 7 — Test với contest 19 (nhỏ hơn, 38K)
- Chạy 1 run với `TWO_STAGE_ROUNDS=true`
- Verify feed.jsonl có stage=1 và stage=2 posts
- Verify `round_stage1_posts` được save vào state.json
- Verify CHALLENGE/VALIDATE làm thay đổi confidence trên findings
- Kiểm tra semantic_results có tăng không

---

## 5. Expected impact

### Về S-track (vấn đề chính)

| Cơ chế | Trước | Sau |
|--------|-------|-----|
| DeFi agent thấy blockchain agent mention holdsToken | ❌ | ✅ Stage 2 có thể build on it |
| Agent dùng FINDING + DEFI-FLASH_LOAN sai format | ❌ | ✅ Blockchain agent có thể CHALLENGE và suggest SEMANTIC_FINDING |
| Cross-domain validate price manipulation | ❌ | ✅ Nhiều domain confirm → confidence tăng → semantic consensus dễ hơn |
| State machine bugs được nhắc đến trong Stage 1 | ❌ (bị chôn trong 134K) | Vẫn khó nhưng tốt hơn nếu 1 agent mention → Stage 2 agents build on |

### Về precision (vấn đề FP)

- CHALLENGE mechanism làm giảm confidence của findings sai → consensus engine loại bỏ
- Cross-domain VALIDATE tăng confidence của findings đúng → precision tăng
- Hiện tại không có bất kỳ cross-checking mechanism nào

### Về runtime

- Contest 19 (38K): ~130 min → ước tính ~160-180 min
- Contest 3 (134K): ~98 min → ước tính ~130-150 min
- Overhead chủ yếu từ 2× API calls, nhưng Stage 1 nhanh hơn (400 tokens output vs 1500)

---

## 6. Env vars

```bash
# Bật/tắt two-stage (default: true)
TWO_STAGE_ROUNDS=true

# Stage 1 max output tokens (default: 400)
STAGE1_MAX_TOKENS=400

# Cap chars per post trong feed context — kiểm soát token budget Stage 2
# 17 posts × 300 chars = 5,100 chars ≈ 1,275 tokens (bounded, không phụ thuộc STAGE1_MAX_TOKENS)
STAGE1_FEED_CHARS_PER_POST=300

# Phase C vẫn single-stage (attacker mechanics phức tạp hơn, không benefit từ S1 feed)
```

---

## 7. Risks và mitigation

| Risk | Mitigation |
|------|------------|
| Stage 1 posts quá ngắn, không đủ content cho Stage 2 | Instruction Stage 1 yêu cầu mention function names cụ thể; tăng STAGE1_MAX_TOKENS nếu cần |
| Agents Stage 2 copy lại Stage 1 thay vì build on it | Instruction nhấn mạnh "write NEW findings or CHALLENGE/VALIDATE existing ones" |
| CHALLENGE parser miss nếu agent viết format không đúng | Parser dùng fuzzy title matching; worst case: không effect nhưng không crash |
| 429 tăng do 2× API calls | Stage 1 output 400 tokens; feed capped 300 chars/post; net TPM tăng ~20% |
| Phase C agents bị confused với Stage 1 | TWO_STAGE_ROUNDS chỉ apply Phase A và B; Phase C giữ single-stage |
| **[A6] CHALLENGE/VALIDATE target finding chưa commit (ordering trap)** | **Giải quyết bằng CLAIM tag: Stage 1 agents viết `CLAIM: <title>` → Stage 2 agents target CLAIMs (available đồng thời). Instruction Stage 2 nêu rõ "target Stage 1 CLAIMs and prior-round findings"** |
| **[A2] Token vượt 900 nếu STAGE1_MAX_TOKENS cao** | **`_build_feed_context()` cap cứng 300 chars/post = max 1,275 tokens — không phụ thuộc STAGE1_MAX_TOKENS** |
| **[A4] ContractFinding vs expert_findings type mismatch** | **Confirm: contract_audit mode parse qua `cm["parse_finding"]()` → dict → append `session_state.expert_findings` — cùng list, không có bridge. `_parse_challenge_validate()` dùng cùng list này là đúng.** |

---

## 8. Definition of Done

**Tầng 1 — Cơ chế (verifiable ngay sau implement):**
- [ ] `CyberSessionState.round_stage1_posts` được lưu và load đúng qua state.json
- [ ] feed.jsonl có posts với `stage: 1` và `stage: 2` riêng biệt
- [ ] Stage 1 posts chứa `CLAIM:` tags khi agent phát hiện potential bug
- [ ] Stage 2 prompt chứa `=== STAGE 1 ANALYSIS ===`, mỗi post ≤ 300 chars, CLAIMs preserved
- [ ] `CHALLENGE_FINDING` / `VALIDATE_FINDING` được parse và:
  - Match đúng Stage 1 CLAIMs (cùng round, priority 1)
  - Match expert_findings round cũ (priority 2)
  - Update `challenged_by` / `validated_by` + confidence penalty/boost đúng
- [ ] `TWO_STAGE_ROUNDS=false` chạy giống hoàn toàn hệ thống hiện tại (không regression)
- [ ] `_call_agent()` nhận `max_tokens` override; Stage 1 output bị giới hạn tại 400 tokens

**Tầng 2 — Metric (cần thực nghiệm, có thể không đạt nếu coverage gap vẫn còn):**
- [ ] Chạy contest 19: semantic_findings ≥ 3 (baseline hiện tại = 3, không được giảm)
- [ ] Chạy contest 3: semantic_findings > 0 (baseline = 0; kỳ vọng ≥ 1 nếu bất kỳ agent nào mention H-03 oracle pattern trong Stage 1)
- [ ] F1 combined không giảm so với baseline tương ứng

> **Note [A3]:** Tầng 2 là hypothesis, không phải guarantee. Two-stage cải thiện khả năng bắt bug nếu agent đã mention ở Stage 1, nhưng không tạo ra coverage mới nếu không agent nào nhắc đến bug đó.
