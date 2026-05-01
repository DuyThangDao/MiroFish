# Plan: PoC Redesign — Scenario-Driven Enrichment Layer

## Vấn đề hiện tại

| # | Vấn đề | Hệ quả |
|---|--------|--------|
| 1 | PoC là **gate** quyết định Tier-2→Tier-1 | PoC fail ≠ bug không tồn tại (môi trường Forge phức tạp, mock thiếu state) |
| 2 | Track 1/2 dùng **generic SWC template**, không dùng R3 scenarios | Test không target đúng code path, pass/fail không correlate với bug thực |
| 3 | Track 3 là **LLM re-verify lần 4** | Weaker signal hơn R1-R3, không thêm value |
| 4 | R3 `attacker_verdicts` (entry_point, attack_steps, outcome) **bị bỏ hoàn toàn** | Công sức R3 không được tận dụng |
| 5 | `v2_borderline` không đi vào PoC | Gap với architecture doc |
| 6 | Track 1+2 cover chỉ 9/34 SWCs | 74% SWC patterns không có PoC |

## Thiết kế mới

### Vai trò mới của PoC

```
Cũ:  uncertain findings → PoC → Tier-2→Tier-1 upgrade (gate)
Mới: confirmed findings → PoC → poc_verified flag (enrichment, không thay đổi tier)
```

PoC **không** quyết định finding có vào output hay không. Finding đã được quyết định bởi
R2+R3 confidence formula. PoC chỉ thêm `poc_verified=True` và `poc_results[]` làm
metadata cho auditor/risk-ranking tool.

### Luồng mới

> **Note**: Không còn tầng `v2_borderline`. Chỉ có 2 trạng thái: **confirmed** (pass threshold) và **discarded** (không pass). Chỉ confirmed findings mới đi vào PoC Enrichment Stage.

```
R3 output → confidence formula → confirmed / discarded
                                      ↓
                          confirmed findings only
                                      ↓
                          build_v2_output() → audit_report.json
                                      ↓
                              PoC Enrichment Stage
                          (chạy sau khi output đã xác định)
                                      ↓
                      Với mỗi confirmed finding:
                        Lấy CONFIRMED/PLAUSIBLE verdicts từ attacker_verdicts
                        Mỗi verdict → 1 scenario-driven Forge test
                        ≥1 pass → poc_verified=True
                                      ↓
                          audit_report.json enriched với poc_results
```

### Scenario-Driven PoC — thay thế Track 1/2/3

**Input mỗi finding:**
```python
{
  "pair_id": "p_abc",
  "kind": "swc",
  "swc_id": "SWC-101",
  "function_name": "mint()",
  "attacker_verdicts": {
    "attacker_logic_exploiter": {
      "verdict": "CONFIRMED",
      "entry_point": "mint()",
      "pre_condition": "Caller controls amount parameter",
      "attack_steps": ["Call mint() with amount = type(uint128).max + 1", "Observe overflow"],
      "expected_outcome": "liquidity overflows to 0, attacker gets free position"
    }
  }
}
```

**Process:**
```
for verdict in sorted(attacker_verdicts, key=CONFIRMED > PLAUSIBLE > INVALID):
    if verdict not in (CONFIRMED, PLAUSIBLE):
        continue

    # Build scenario context
    scenario = {
        entry_point, pre_condition, attack_steps, expected_outcome
    }

    # LLM generates targeted Forge test
    test_body = llm.generate(
        prompt=SCENARIO_POC_PROMPT,
        context={
            "function_source": extract_function_body(flat_source, entry_point),
            "scenario": scenario,
            "swc_id": finding.swc_id,
        }
    )

    # Wrap and run
    test_name = f"test_poc_{pair_id}_{attacker_id}"
    forge_pass = run_forge_test(test_body, test_name)

    poc_results.append({
        "attacker_id": attacker_id,
        "verdict": verdict,
        "forge_pass": forge_pass,
        "test_name": test_name,
    })

    if forge_pass:
        poc_verified = True
        break  # Một lần pass là đủ
```

**LLM Prompt (SCENARIO_POC_PROMPT):**
```
You are a smart contract security researcher writing a Foundry test to PROVE a vulnerability.

Target function source:
```solidity
{function_source}
```

Attack scenario:
  Entry point  : {entry_point}
  Pre-condition: {pre_condition}
  Attack steps : {attack_steps}
  Expected outcome: {expected_outcome}

Write ONLY the Solidity function body (statements inside curly braces) for a Forge test
that PASSES when this specific attack succeeds.
Rules:
- Use vm.deal, vm.prank, vm.expectRevert from forge-std when needed
- The test asserts the expected outcome (overflow, drain, revert, etc.)
- Max 30 lines. No comments. No imports. No function signature.
```

### Output schema mới

Mỗi confirmed finding trong `consensus_vulns` và `semantic_results` được thêm:

```json
{
  "vuln_id": "vuln_abc123",
  "swc_ids": ["SWC-101"],
  "affected_assets": ["mint()"],
  "confidence_score": 0.638,
  "poc_verified": true,
  "poc_results": [
    {
      "attacker_id": "attacker_logic_exploiter",
      "verdict": "CONFIRMED",
      "forge_pass": true,
      "test_name": "test_poc_pabc_logic",
      "scenario_summary": "mint() with uint128.max overflow → liquidity=0"
    },
    {
      "attacker_id": "attacker_flash_loan_attacker",
      "verdict": "PLAUSIBLE",
      "forge_pass": false,
      "test_name": "test_poc_pabc_flash",
      "scenario_summary": "flash loan + mint overflow"
    }
  ]
}
```

## Files cần thay đổi

### 1. `backend/app/services/poc_verification.py`

- **Xóa**: `_select_candidates()`, `_run_track3()`, `_run_forge_tracks()`, `_generate_poc_file()`
- **Xóa**: `POC_UNIT_SWCS`, `POC_FUZZ_SWCS`, `LLM_QUERY_CATEGORIES`, `LLM_QUERY_TEMPLATES`
- **Thêm**: `_run_scenario_driven(finding, flat_source) → list[poc_result]`
- **Thêm**: `SCENARIO_POC_PROMPT` constant
- **Sửa**: `run()` signature:
  ```python
  # Cũ:
  def run(self, consensus_vulns, gap_findings, flat_source, contest_dir, semantic_results)
  # Mới:
  def run(self, confirmed_findings: list[dict], flat_source: str) -> list[dict]
  ```

### 2. `backend/scripts/run_contract_audit.py`

```python
# Cũ:
_upd_consensus, _upd_gaps, _upd_semantic = poc_stage.run(
    consensus_vulns=_consensus_vulns,
    gap_findings=_gap_findings,
    flat_source=source_code,
    contest_dir=_contest_dir,
    semantic_results=_semantic_results,
)

# Mới (chỉ confirmed findings vào PoC, không có borderline):
all_confirmed = _consensus_vulns + _semantic_results  # chỉ confirmed, discarded đã bị loại từ R3
enriched = poc_stage.run(confirmed_findings=all_confirmed, flat_source=source_code)
# Split back
n_c = len(_consensus_vulns)
report_result["consensus_vulns"]  = enriched[:n_c]
report_result["semantic_results"] = enriched[n_c:]
```

### 3. `backend/app/services/consensus_engine.py`

`build_v2_output()` thêm default fields vào mỗi finding:
```python
entry["poc_verified"] = False
entry["poc_results"]  = []
```

### 4. `backend/app/services/contract_audit_agent.py`

Stats block cập nhật:
```python
"exploitable_count": sum(1 for v in consensus_vulns_raw if v.get("poc_verified")),
```

## Điều kiện skip PoC

PoC stage được skip (không lỗi, chỉ bỏ qua) khi:
- Forge không available (`forge --version` fail)
- Finding không có `attacker_verdicts` với verdict CONFIRMED hoặc PLAUSIBLE
- `flat_source` rỗng
- Stage timeout (`stage_timeout_s` = 300s mặc định)

## Không thay đổi

- `unvalidated_swc_gaps` vẫn tồn tại trong output JSON (traceability)
- Tiêu chí confirmed/discarded vẫn do R2+R3 confidence quyết định (xem `plan-confidence-formula.md`)
- `poc_verified` không ảnh hưởng `confidence_score` và không thay đổi confirmed/discarded status
- Risk ranking sử dụng `poc_verified` sẽ được phát triển ở phase riêng sau
