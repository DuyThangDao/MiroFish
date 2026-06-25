# LLMSmartAudit Benchmark Eval Guide

## Tool Overview

LLMSmartAudit (SmartContractTA config) runs **40 targeted detectors** — each a separate LLM call
asking a Security Analyst agent to check one specific vulnerability class:

| Detector | Vulnerability class |
|----------|-------------------|
| ArithmeticDetector | Integer overflow/underflow |
| ReentrancyDetector | Reentrancy |
| UncheckedSendDetector | Unchecked ERC20 transfer return |
| UncheckedLowLevelCallDetector | Unchecked low-level call return |
| TODDetector | Transaction order dependence |
| TimeStampManipulationDetector | block.timestamp manipulation |
| PredictableRandDetector | Predictable randomness |
| TXRelianceDetector | tx.origin misuse |
| SuicideDetector | selfdestruct misuse |
| GasLimitDetector | Gas limit DoS |
| PriceManipulationDetector | Oracle/price manipulation |
| DataCorruptionDetector | Storage corruption |
| WithdrawalFunctionDetector | Withdrawal pattern bugs |
| LackAuthorizationDetector | Missing access control |
| DataInconsistencyDetector | State inconsistency |
| HashCollisionDetector | abi.encodePacked hash collision |
| UninitializedReturnVariableDetector | Uninitialized return variable |
| MisdeclaredConstructorDetector | Wrong constructor name |
| MissingOnlyOwnerDetector | Missing ownership check |
| MisuseMsgValueDetector | msg.value in loop |
| PrecisionLossDetector | Division precision loss |
| RedundantConditionalDetector | Redundant/always-true condition |
| OracleDependencyDetector | Oracle single point of failure |
| OwnershipHijackingDetector | Ownership transfer exploit |
| CentralizationRiskDetector | Privileged admin risk |
| FundingCalculationDetector | Wrong funding math |
| FlashLoanDetector | Flash loan attack surface |
| MappingGetterDetector | Struct-in-mapping getter |
| GetterFunctionDetector | View function returning wrong value |
| UnnecessaryComparisonDetector | Tautological comparison |
| InconsistentInitializationDetector | Init order issue |
| SourceSwappingDetector | Token address swap exploit |
| SignatureVerificationDetector | Signature replay/missing check |
| OrderInitializationDetector | Constructor order issue |
| ImpracticalityMatchDetector | Protocol invariant mismatch |
| InconsistentTokensDetector | Token amount inconsistency |
| PartialWithdrawalsDetector | Partial withdrawal bug |
| FallbackFunctionDetector | Fallback/receive exploit |
| UnlimitedTokenDetector | Unlimited token approval |
| InputValidationDetector | Missing input validation |
| DoSDetector | Denial of Service |

Input: **one `.sol` file at a time** (per GT contract).  
Output: findings per detector with vulnerability name + description.

---

## Output Files

```
benchmark/web3bugs/llmsmartaudit/<contest_id>/
  findings_<ContractName>.json    ← per-contract structured findings
  findings_all.json               ← aggregated across all GT contracts
  console_<ContractName>.log      ← subprocess stdout/stderr
  warehouse_<ContractName>.log    ← full LLMSmartAudit WareHouse log
```

`findings_all.json` structure:
```json
{
  "contest_id": "104",
  "gt_contracts": ["ChestV1", "RoyaltyVault", "Splits"],
  "total_findings": 12,
  "by_phase": {"LackAuthorizationDetector": 3, "ReentrancyDetector": 1, ...},
  "findings": [
    {
      "contract_name": "ChestV1",
      "detector_phase": "LackAuthorizationDetector",
      "vulnerability_name": "LACK OF ACCESS CONTROL IN WITHDRAW",
      "function_name": "withdraw",
      "description": "The withdraw() function does not restrict..."
    }
  ]
}
```

---

## Matching Criteria

### T1 (TP) — Full match
All three must hold:
1. **Contract match**: `finding.contract_name` == GT contract (exact)
2. **Function match**: `finding.function_name` or description mentions the GT function name
3. **Root cause match**: detector type plausibly maps to GT bug root cause (see table below)

### T2 (Near-miss, NOT TP)
- Contract matches but wrong function, OR
- Correct vulnerability class but no function-level evidence

### Rule → Root cause mapping

| Detector | GT bug types it can match |
|----------|--------------------------|
| LackAuthorizationDetector | Missing access control, unprotected function |
| ReentrancyDetector | Reentrancy bugs |
| ArithmeticDetector | Integer overflow/underflow, wrong math |
| UncheckedSendDetector | Unchecked ERC20 transfer, silent failure |
| PriceManipulationDetector | Oracle manipulation, flash loan price |
| FlashLoanDetector | Flash loan attack |
| SignatureVerificationDetector | Signature replay, missing sig check |
| TXRelianceDetector | tx.origin misuse |
| PrecisionLossDetector | Rounding/precision bugs |
| InputValidationDetector | Missing validation, wrong parameter |
| DoSDetector | DoS via gas, unbounded loop |
| FundingCalculationDetector | Wrong accounting, wrong formula |
| ImpracticalityMatchDetector | Logic error, invariant violation |

---

## Eval Template (`eval_result_manual.txt`)

```
================================================================================
LLMSMARTAUDIT EVALUATION — Contest <ID> (<Name>)
================================================================================
Run tool:      LLMSmartAudit SmartContractTA (Gemini Flash via Vertex AI LLM5)
Findings file: benchmark/web3bugs/llmsmartaudit/<id>/findings_all.json
GT file:       backend/scripts/evaluate/gt/gt_<id>.json
Evaluator:     Claude manual (semantic matching per eval-llmsmartaudit-matching-guide.md)
Date:          YYYY-MM-DD

METRICS
-------
Total GT H-bugs : N
Total findings  : N (GT contracts only)
  by_detector: {...}
TP              : N
FP              : N
FN              : N
Precision       : N%
Recall          : N%
F1              : N%

================================================================================
MATCHED H-BUGS (TP = N)
================================================================================

H-XX | <Contract>.<function> | MATCH
  GT: <root cause description>
  Finding: [<DetectorPhase>] "<vulnerability_name>" — <brief match reason>
  Evidence: "<quoted snippet from finding description>"

================================================================================
MISSED H-BUGS (FN = N)
================================================================================

H-XX | <Contract>.<function> | MISS
  GT: <root cause>
  Closest: <best detector that fired, if any; or "none">
  Root cause miss: <why no detector covers this>

================================================================================
FALSE POSITIVES (FP = N)
================================================================================

FP-N | [<DetectorPhase>] <Contract>.<function>
  Finding: <description summary>
  GT connection: None / Near-miss for H-XX but wrong function
  Why flagged: <plausible reason LLM flagged this>

================================================================================
NOTES
================================================================================
- <summary observations>
```

---

## Benchmark Scale

Per contest: ~3–7 GT contracts × 40 detector calls = **120–280 LLM calls**.  
Estimated time: ~10–20 min per GT contract (depending on rate limits).

---

## Comparison with Other Tools

| Tool | Detection approach | Structured output | Function-level |
|------|--------------------|-------------------|---------------|
| Slither | Static pattern rules | Yes (detector + line) | Yes |
| GPTScan | 10 finance-specific LLM rules | Yes (line ranges) | Via line range |
| **LLMSmartAudit** | **40 LLM detectors per contract** | Prose + function name | Partial (from description) |
| simulate_e2e | Multi-agent free-form | Yes (findings[]) | Yes |
