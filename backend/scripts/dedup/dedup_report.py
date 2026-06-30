"""
dedup_report.py — LLM-based semantic dedup của audit_report_*_raw.json

Logic theo docs/dedup-manual-instruction.md:
  Bước 1-2: Group findings by (normalize_fn, contract)
  Bước 3:   LLM cluster mỗi group theo root cause, chọn representative
  Bước 4:   Cross-group dedup (Pattern C misattribution + Pattern D same-vuln)
  Bước 5:   Write audit_report_dedup.json

Usage:
  cd backend && source .venv/bin/activate
  python scripts/dedup_report.py \
    --input  ../benchmark/.../audit_report_71_raw.json \
    --output ../benchmark/.../audit_report_dedup.json \
    --workers 3 --batch-size 20
"""

import sys, os, re, json, time, argparse
from datetime import date
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('ATTACK_PATH_VALIDATION', 'false')

from openai import OpenAI
from app.utils.llm_client import _build_vertex_ai_http_client

# ─── LLM setup (same pattern as simulate_e2e.py) ─────────────────────────────
KEY_FILE = os.getenv('LLM_VERTEX_AI_KEY_FILE', '')
BASE_URL  = os.getenv('LLM_BASE_URL', '')
MODEL     = os.getenv('LLM_MODEL_NAME', 'google/gemini-3-flash-preview')

def _make_client(key_file: str, base_url: str) -> OpenAI:
    http_client = _build_vertex_ai_http_client(key_file)
    return OpenAI(api_key="vertex-ai", base_url=base_url,
                  http_client=http_client, max_retries=0)

_extra_clients = []
for _i in range(2, 6):
    _kf = os.getenv(f'LLM{_i}_VERTEX_AI_KEY_FILE', '')
    _bu = os.getenv(f'LLM{_i}_BASE_URL', BASE_URL)
    if _kf:
        _extra_clients.append(_make_client(_kf, _bu))

_primary_client = _make_client(KEY_FILE, BASE_URL)
_llm_pool = [_primary_client] + _extra_clients
_pool_lock = threading.Lock()
_pool_counter = [0]

def _get_client() -> OpenAI:
    with _pool_lock:
        idx = _pool_counter[0] % len(_llm_pool)
        _pool_counter[0] += 1
    return _llm_pool[idx]

def _strip(t: str) -> str:
    return re.sub(r'<think>.*?</think>', '', t or '', flags=re.DOTALL).strip()

def _llm_call(prompt: str, max_tokens: int = 2000, retries: int = 3) -> str:
    client = _get_client()
    for attempt in range(retries):
        try:
            resp = client.chat.completions.create(
                model=MODEL,
                temperature=0.3,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                extra_body={"google": {"thinking_config": {"thinking_budget": 0}}},
            )
            return _strip(resp.choices[0].message.content)
        except Exception as e:
            msg = str(e).lower()
            if attempt < retries - 1 and any(x in msg for x in ('429', 'rate', 'quota', 'overload')):
                wait = 30 * (attempt + 1)
                print(f"  [rate retry {attempt+1}/{retries}, wait {wait}s]", flush=True)
                time.sleep(wait)
            else:
                raise
    return ''

# ─── Normalize ────────────────────────────────────────────────────────────────

def _norm_fn(fn: str) -> str:
    return (fn or '').split('(')[0].strip()

def _group_key(f: dict) -> tuple:
    return (_norm_fn(f.get('function_name', '')), (f.get('contract_name') or '').lower())

# ─── Prompt A: merge-only (default = keep all) ──────────────────────────────
#
# FRAMING: không hỏi "cluster thành nhóm" mà hỏi "tìm cái nào CHẮC CHẮN giống nhau"
# Default = giữ tất cả. Chỉ merge khi 100% chắc chắn cùng bug.

_MERGE_PROMPT = """\
You are a deduplication agent for smart contract security audit findings.
FUNCTION: {fn}  CONTRACT: {contract}

The {n} findings below are about the SAME function but likely describe DIFFERENT bugs.
By default, ALL findings are kept. Your ONLY job: identify groups that describe the
EXACT SAME underlying vulnerability (same buggy line, same fix, same mechanism).

⚠️ CRITICAL: When in doubt → do NOT merge. A missed merge (keeping duplicates) is
acceptable. A wrong merge (dropping a unique TP) destroys evaluation accuracy.

MERGE ONLY IF ALL 3 are true:
1. Same buggy variable/line/state
2. Same exploit mechanism (attacker-required vs natural, external vs internal)
3. Same fix (identical code change at the same location)

DO NOT MERGE if:
- Different state variables even if same function (e.g. "balance" vs "totalDebt")
- One needs attacker action, other happens naturally without attack
- Different fix locations (e.g. add access control vs add slippage check)
- One is about CEI ordering, other is about missing validation — these are DIFFERENT bugs

FINDINGS:
{findings_block}

OUTPUT (JSON only, no markdown):
{{
  "merges": [
    {{
      "keep": <index of BEST finding (most detailed description + specific attack path)>,
      "drop": [<indices of exact duplicates to remove>],
      "reason": "<one sentence — the shared root cause>"
    }}
  ]
}}

If nothing to merge with certainty: {{"merges": []}}
"""

def _build_findings_block(findings: list, start_idx: int = 0) -> str:
    lines = []
    for i, f in enumerate(findings):
        desc = (f.get('description') or '')
        # Take first 2 sentences
        sentences = re.split(r'(?<=[.!?])\s+', desc.strip())
        short_desc = ' '.join(sentences[:2]) if sentences else desc[:200]
        lines.append(f"[{start_idx + i}] Title: {(f.get('title') or '')[:80]}")
        lines.append(f"    Description: {short_desc[:200]}")
    return '\n'.join(lines)

def _parse_merge_response(response: str, n_findings: int) -> list:
    """Parse merge-only response. Returns list of merge dicts.
    Each merge: {"keep": int, "drop": [int,...], "reason": str}
    Returns [] on failure (conservative: keep all).
    """
    text = re.sub(r'```(?:json)?\s*', '', response).strip().rstrip('`').strip()
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
        merges = data.get('merges', [])
        valid = []
        for mg in merges:
            keep = mg.get('keep')
            drop = mg.get('drop', [])
            reason = mg.get('reason', '')
            if keep is None or not isinstance(drop, list) or not drop:
                continue
            if not (0 <= keep < n_findings):
                continue
            drop = [d for d in drop if isinstance(d, int) and 0 <= d < n_findings and d != keep]
            if drop:
                valid.append({'keep': keep, 'drop': drop, 'reason': reason})
        return valid
    except Exception:
        return []

def _apply_merges(findings: list, merges: list, fn: str, contract: str) -> list:
    """Apply merge decisions: start with all findings, remove the dropped ones.
    The 'keep' finding gets a _dedup_note summarising how many were merged.
    """
    to_drop = set()
    keep_notes: dict[int, list] = {}  # keep_idx → list of reasons

    for mg in merges:
        keep_idx = mg['keep']
        for d in mg['drop']:
            if d not in to_drop:
                to_drop.add(d)
                keep_notes.setdefault(keep_idx, []).append(
                    f"merged raw[{findings[d].get('_raw_idx','?')}]: {mg['reason']}"
                )

    result = []
    for i, f in enumerate(findings):
        if i in to_drop:
            continue
        fc = dict(f)
        if i in keep_notes:
            merged_count = len(keep_notes[i]) + 1
            fc['_dedup_note'] = (
                f"Representative of {merged_count} findings in {fn}/{contract} "
                f"(merged: {'; '.join(keep_notes[i][:2])})"
            )
        else:
            fc.setdefault('_dedup_note', f"Kept (no duplicates found) in {fn}/{contract}")
        result.append(fc)
        _log_checklist_merge(i, i in keep_notes, fn, contract,
                             fc.get('_raw_idx', i), keep_notes.get(i))
    return result

def _dedup_group_small(findings: list, fn: str, contract: str) -> list:
    """Single LLM call using merge-only approach.
    Default: keep all. Only remove when LLM is certain of duplication.
    """
    n = len(findings)
    prompt = _MERGE_PROMPT.format(
        fn=fn, contract=contract, n=n,
        findings_block=_build_findings_block(findings)
    )
    response = _llm_call(prompt, max_tokens=min(2000, 150 + n * 60))
    merges = _parse_merge_response(response, n)

    if not merges:
        # No merges found (or parse fail) — keep all
        for i, f in enumerate(findings):
            f.setdefault('_dedup_note', f"No duplicates found — kept in {fn}/{contract}")
        return findings

    return _apply_merges(findings, merges, fn, contract)

def _dedup_group_large(findings: list, fn: str, contract: str, batch_size: int) -> list:
    """Multi-pass dedup for large groups.
    Pass 1: merge within batches of batch_size (parallel-safe, sequential here)
    Pass 2: merge across the survivors of pass 1
    """
    # Pass 1: process batches
    pass1 = []
    for start in range(0, len(findings), batch_size):
        batch = findings[start:start + batch_size]
        survivors = _dedup_group_small(batch, fn, contract)
        pass1.extend(survivors)

    if len(pass1) <= batch_size:
        # Pass 2: merge survivors
        return _dedup_group_small(pass1, fn, contract)
    return pass1

# ─── Checklist log ────────────────────────────────────────────────────────────

_checklist_lock = threading.Lock()
_checklist_lines: list = []

def _log_checklist_merge(idx: int, is_keep: bool, fn: str, contract: str,
                          raw_idx, notes: list | None = None) -> None:
    with _checklist_lock:
        if is_keep and notes:
            line = f"  KEEP raw[{raw_idx}] (merged {len(notes)} duplicates): {notes[0][:60]}"
        elif not is_keep:
            return  # kept but no merge — logged in group header
        else:
            line = f"  KEEP raw[{raw_idx}] (unique)"
        _checklist_lines.append(line)

def _log_group_header(fn: str, contract: str, raw_n: int, dedup_n: int) -> None:
    with _checklist_lock:
        _checklist_lines.append(f"\n[{fn}/{contract}]  raw={raw_n}  →  dedup={dedup_n}")

# ─── Bước 3: cluster all groups ───────────────────────────────────────────────

def _process_group(key: tuple, items: list, batch_size: int) -> list:
    fn, contract = key
    n = len(items)

    if n == 1:
        orig_idx, f_raw = items[0]
        f = dict(f_raw)
        f['_raw_idx'] = orig_idx
        f['_dedup_note'] = f"Singleton in {fn}/{contract}"
        _log_group_header(fn, contract, 1, 1)
        with _checklist_lock:
            _checklist_lines.append(f"  Cluster (1 finding — singleton): pass through")
        return [f]

    # Attach original indices
    indexed = []
    for orig_idx, f in items:
        fc = dict(f)
        fc['_raw_idx'] = orig_idx
        indexed.append(fc)

    if n <= batch_size:
        reps = _dedup_group_small(indexed, fn, contract)
    else:
        reps = _dedup_group_large(indexed, fn, contract, batch_size)

    _log_group_header(fn, contract, n, len(reps))
    return reps

# ─── Bước 4a: Pattern C — misattribution check ────────────────────────────────

_FN_MENTION_RE = re.compile(r'[Ii]n\s+`([a-zA-Z_][a-zA-Z0-9_]*)(?:\(\))?`|'
                             r'[Tt]he\s+`([a-zA-Z_][a-zA-Z0-9_]*)(?:\(\))?`\s+function')

def _check_misattribution(dedup_findings: list) -> list:
    """Pattern C: drop singletons where description names a different function
    that already has a representative in the dedup output."""
    # Build set of (fn, contract) already represented
    represented = set()
    for f in dedup_findings:
        represented.add((_norm_fn(f.get('function_name', '')),
                         (f.get('contract_name') or '').lower()))

    result = []
    dropped = 0
    for f in dedup_findings:
        fn_meta = _norm_fn(f.get('function_name', ''))
        contract = (f.get('contract_name') or '').lower()
        desc = (f.get('description') or '')[:300]

        # Find function names mentioned in description
        mentioned = set()
        for m in _FN_MENTION_RE.finditer(desc):
            name = m.group(1) or m.group(2)
            if name:
                mentioned.add(name)

        if mentioned and fn_meta not in mentioned:
            # Description mentions a different function — check if that fn/contract is represented
            for alt_fn in mentioned:
                if (alt_fn, contract) in represented:
                    # Misattributed singleton — drop
                    print(f"  [Pattern C drop] raw[{f.get('_raw_idx','?')}] "
                          f"meta={fn_meta} desc mentions {alt_fn}/{contract} (already represented)",
                          flush=True)
                    dropped += 1
                    break
            else:
                result.append(f)
        else:
            result.append(f)

    if dropped:
        print(f"  [Pattern C] dropped {dropped} misattributed findings", flush=True)
    return result

# ─── Bước 4b: Pattern D — same vuln across N functions (per contract) ─────────

_PATTERN_D_PROMPT = """\
You are reviewing deduplicated audit findings for contract: {contract}.

The {n} findings below come from DIFFERENT functions. Check if any pair/group describes
the EXACT SAME underlying vulnerability — same root cause, same fix location.

COLLAPSE ONLY IF: a single code change at ONE location fixes all instances.
KEEP SEPARATE IF: each function needs its own independent fix.

FINDINGS:
{findings_block}

OUTPUT (JSON only, no markdown):
{{
  "to_collapse": [
    {{"keep": <idx>, "drop": [<idxs to remove>], "reason": "<one sentence>"}}
  ]
}}
If nothing to collapse: {{"to_collapse": []}}
"""

def _pattern_d_check(dedup_findings: list) -> list:
    """Pattern D: collapse same-vuln-type findings across N functions, per contract."""
    # Group by contract
    by_contract = defaultdict(list)
    for i, f in enumerate(dedup_findings):
        contract = (f.get('contract_name') or '').lower()
        by_contract[contract].append((i, f))

    to_drop = set()
    for contract, items in by_contract.items():
        if len(items) < 5:
            continue  # Only check contracts with ≥5 dedup findings

        # Build findings block for prompt
        lines = []
        for local_i, (global_i, f) in enumerate(items):
            fn = _norm_fn(f.get('function_name', ''))
            title = (f.get('title') or '')[:60]
            note = (f.get('_dedup_note') or '')[:80]
            lines.append(f"[{local_i}] fn={fn}  Title: {title}")
            lines.append(f"    Note: {note}")
        findings_block = '\n'.join(lines)

        prompt = _PATTERN_D_PROMPT.format(
            contract=contract, n=len(items), findings_block=findings_block
        )
        try:
            response = _llm_call(prompt, max_tokens=1000)
            text = re.sub(r'```(?:json)?\s*', '', response).strip().rstrip('`').strip()
            m = re.search(r'\{.*\}', text, re.DOTALL)
            if not m:
                continue
            data = json.loads(m.group(0))
            for collapse in data.get('to_collapse', []):
                keep_local = collapse.get('keep')
                drop_locals = collapse.get('drop', [])
                reason = collapse.get('reason', '')
                if keep_local is None or not drop_locals:
                    continue
                for d_local in drop_locals:
                    if 0 <= d_local < len(items):
                        global_i = items[d_local][0]
                        to_drop.add(global_i)
                        kept_raw = items[keep_local][1].get('_raw_idx', '?') if 0 <= keep_local < len(items) else '?'
                        print(f"  [Pattern D] drop global[{global_i}] "
                              f"(keep raw[{kept_raw}]): {reason}", flush=True)
        except Exception as e:
            print(f"  [Pattern D error] contract={contract}: {e}", flush=True)

    if to_drop:
        print(f"  [Pattern D] dropped {len(to_drop)} findings", flush=True)
        return [f for i, f in enumerate(dedup_findings) if i not in to_drop]
    return dedup_findings

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='LLM-based semantic dedup of audit findings')
    parser.add_argument('--input',      required=True, help='Path to audit_report_*_raw.json')
    parser.add_argument('--output',     required=True, help='Path to output audit_report_dedup.json')
    parser.add_argument('--workers',    type=int, default=3, help='Parallel threads (default: 3)')
    parser.add_argument('--batch-size', type=int, default=20,
                        help='Max findings per LLM call within a group (default: 20)')
    parser.add_argument('--skip-cross', action='store_true',
                        help='Skip Bước 4 cross-group dedup (Pattern C/D)')
    args = parser.parse_args()

    print(f"[setup] llm_pool = {len(_llm_pool)} client(s)", flush=True)
    print(f"[setup] model = {MODEL}", flush=True)
    print(f"[setup] workers = {args.workers}  batch_size = {args.batch_size}", flush=True)

    # Bước 1: Load
    raw_report = json.load(open(args.input))
    raw_findings = raw_report.get('findings') or []
    print(f"[load] {len(raw_findings)} raw findings from {os.path.basename(args.input)}", flush=True)

    # Bước 2: Group
    groups: dict[tuple, list] = defaultdict(list)
    for i, f in enumerate(raw_findings):
        key = _group_key(f)
        groups[key].append((i, f))

    print(f"[group] {len(groups)} groups", flush=True)

    # Bước 3: Cluster each group (parallel)
    all_reps: list = []
    futures = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for key, items in sorted(groups.items(), key=lambda x: -len(x[1])):
            fut = pool.submit(_process_group, key, items, args.batch_size)
            futures[fut] = key

        for fut in as_completed(futures):
            key = futures[fut]
            try:
                reps = fut.result()
                all_reps.extend(reps)
                fn, contract = key
                print(f"  [{fn}/{contract}] {len(groups[key])} → {len(reps)}", flush=True)
            except Exception as e:
                fn, contract = key
                print(f"  [ERROR {fn}/{contract}]: {e}", flush=True)
                # Fallback: keep all originals
                for orig_idx, f in groups[key]:
                    fc = dict(f)
                    fc['_raw_idx'] = orig_idx
                    fc['_dedup_note'] = f"Error fallback: {e}"
                    all_reps.append(fc)

    print(f"\n[bước3] {len(raw_findings)} raw → {len(all_reps)} after group clustering", flush=True)

    # Bước 4: Cross-group dedup
    if not args.skip_cross:
        print("\n[bước4] Pattern C: misattribution check...", flush=True)
        all_reps = _check_misattribution(all_reps)

        print(f"[bước4] Pattern D: same-vuln-across-functions check...", flush=True)
        all_reps = _pattern_d_check(all_reps)

        print(f"[bước4] {len(all_reps)} findings after cross-group dedup", flush=True)

    # Bước 5: Write output
    output = {
        "findings": all_reps,
        "_dedup_meta": {
            "raw_count":   len(raw_findings),
            "dedup_count": len(all_reps),
            "date":        str(date.today()),
            "source_file": os.path.basename(args.input),
        }
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    json.dump(output, open(args.output, 'w'), indent=2, ensure_ascii=False)

    reduction = round((1 - len(all_reps) / max(len(raw_findings), 1)) * 100, 1)
    print(f"\n[done] {len(raw_findings)} raw → {len(all_reps)} dedup ({reduction}% reduced)", flush=True)
    print(f"[done] written to {args.output}", flush=True)

    # Print checklist log
    if _checklist_lines:
        print("\n" + "="*60, flush=True)
        print("DEDUP CHECKLIST", flush=True)
        print("="*60, flush=True)
        for line in _checklist_lines:
            print(line, flush=True)


if __name__ == '__main__':
    main()
