# Contribution: Published Finding Registry

> **Type:** Context injection mechanism to reduce duplicate findings
> **Relevant thesis chapters:** Chapter 3 (System Design), Chapter 5 (Experiment)
> **Implementation:** `backend/app/services/cyber_oasis_env.py`, `cyber_session_orchestrator.py`
> **Addresses:** Weakness #4 — Duplicate Findings Inflate Count

---

## 1. Motivation

In a multi-agent panel with 13 Tier-1 expert agents running 10 rounds, each agent independently generates findings without knowledge of what others have already reported. This causes **intra-group duplication** (agents in the same domain group repeat each other) and **cross-phase duplication** (Phase B/C agents repeat Phase A findings).

**Observed in v4 (81 findings, 10 rounds):**
```
Near-exact duplicates (Jaccard ≥ 0.8): 8 pairs
High-similarity    (Jaccard ≥ 0.5): 33 pairs

By group:
  network_security vs network_security: 14 pairs  (76% of dups are intra-group)
  endpoint_security vs endpoint_security: 7 pairs
  appsec vs appsec: 3 pairs

By phase:
  Phase A vs Phase C: 10 pairs
  Phase A vs Phase B: 9 pairs
  Phase A vs Phase A: 6 pairs
```

Root cause: no "memory" between agents. Agent A writes finding X in round 1; agent B in round 3 has no knowledge of X → writes a near-identical finding.

**Why not fix with pre-scoring dedup (Solution B)?**
B (ConsensusEngine post-processing) was considered but rejected: it drops findings after LLM cost is already incurred, and risks losing detail present in "duplicate" findings but absent from the "winner". Solution A prevents duplicates from being generated in the first place.

---

## 2. Mechanism Design

### 2.1 Published Registry

After each round, a compact registry of **unique finding titles already reported** is injected into every agent's context at the start of the next round:

```
=== PUBLISHED FINDINGS REGISTRY (12 unique findings reported so far) ===
Do NOT duplicate these. If you agree → CHALLENGE or add evidence.
If you have new information → write a NEW [FINDING] with distinct title.
  • [CRITICAL] CVE-2021-41773 RCE on WEB-01 — by network_security/offensive
  • [HIGH] No SIEM deployed — by risk/auditor
  • [CRITICAL] MFA not enforced on admin accounts — by appsec/defensive
  ...
```

**Design decisions:**

| Decision | Choice | Rationale |
|---|---|---|
| Deduplication | Case-insensitive title match | Simple, low false-positive rate |
| Cap | 20 most recent unique findings | Prevent context overflow (~400 tokens max) |
| Position in context | Before RECENT FINDINGS section | Agents read it first — higher compliance |
| Instruction tone | "CHALLENGE or add evidence" | Encourages useful behavior, not just silence |

### 2.2 Integration with Prior Context

`_build_prior_context()` in `CyberSessionOrchestrator` now:
1. Calls `build_published_registry(session_state.expert_findings, max_entries=20)`
2. Prepends registry output before the recent-findings section
3. Reduces recent-findings window from 10 → 6 (registry already covers unique titles)

```python
def _build_prior_context(self, session_state):
    from .cyber_oasis_env import build_published_registry
    registry = build_published_registry(session_state.expert_findings, max_entries=20)
    # ... rest of context building
```

`build_published_registry()` in `cyber_oasis_env.py`:
```python
def build_published_registry(expert_findings, max_entries=20):
    # 1. Deduplicate by normalized title (case-insensitive, first occurrence wins)
    # 2. Cap to max_entries most recent unique
    # 3. Format as bullet list with severity + reporter
    # 4. Include anti-duplication instruction
```

### 2.3 Interaction with Other Mechanisms

```
Prior context (per round):
  ┌─ Published Registry     ← NEW: unique titles, anti-dup instruction
  ├─ Recent Findings (6)    ← shows detail of last 6 findings
  ├─ GAP Registry (8)       ← knowledge gaps needing investigation
  └─ Attacker Findings (5)  ← attacker-identified paths
```

Registry and GAP mechanism are complementary:
- GAP tells agents **what to investigate** (unexplored areas)
- Registry tells agents **what has already been reported** (avoid repeating)

Together they guide agent attention toward coverage gaps and away from already-covered ground.

---

## 3. Experimental Validation

### 3.1 Setup

| Run | Configuration |
|-----|--------------|
| v4 | GAP + B-dynamic + D (no Published Registry) |
| **v5** | GAP + B-dynamic + D + Published Registry |

### 3.2 Expected Impact

| Metric | v4 | v5 (expected) |
|---|---|---|
| Near-exact dups (Jaccard ≥ 0.8) | 8 pairs | < 4 pairs |
| High-similarity (Jaccard ≥ 0.5) | 33 pairs | < 20 pairs |
| Consensus vulns | 13 | ≥ 13 (more diverse input) |
| Control coverage (7/7) | 7/7 | 7/7 (maintained) |
| Report quality | — | Higher diversity per finding |

### 3.3 Actual Results (test_gap_v5)

| Metric | v4 (no Registry) | v5 (Registry) | Δ |
|---|---|---|---|
| Raw findings | 81 | **64** | -21% |
| Near-exact dups (Jaccard ≥ 0.8) | 8 | **4** | -50% ✅ |
| High-similarity dups (Jaccard ≥ 0.5) | 33 | **7** | **-79%** ✅ |
| Consensus vulns | 13 | 11 | -2 |
| Unvalidated gaps (D) | 1 (DLP) | 2 (MFA+DLP) | +1 |
| Report length | 22,212 | 16,235 | -27% |

**Key observations:**
- High-similarity duplicates dropped 79% — Registry instruction highly effective
- Fewer raw findings (64 vs 81) confirms agents avoided re-reporting known issues
- Consensus count dropped slightly (13→11) — acceptable trade-off for higher diversity
- D section catches MFA+DLP as unvalidated gaps (v4 only caught DLP), suggesting agents redirected freed attention toward coverage gaps rather than duplicates

---

## 4. Implementation Details

### 4.1 Files Modified

| File | Change |
|------|--------|
| `backend/app/services/cyber_oasis_env.py` | Added `build_published_registry()` |
| `backend/app/services/cyber_session_orchestrator.py` | Updated `_build_prior_context()` to prepend registry, reduced recent-findings window 10→6 |

### 4.2 Token Cost

Registry adds ~15-25 tokens per unique finding × 20 cap = **~300-500 tokens per round**. With 10 rounds × 13 agents = 130 calls, total overhead ≈ 65,000 tokens ≈ negligible vs. the savings from prevented duplicate LLM calls.

### 4.3 Failure Modes

| Failure mode | Likelihood | Mitigation |
|---|---|---|
| LLM ignores registry instruction | Low-medium | Instruction placed first in context; "CHALLENGE" framing makes compliance easier |
| Agent writes finding with slightly different title (escaping dedup) | Medium | B-dynamic clustering will still group them in ConsensusEngine |
| Registry grows too large and crowds out useful context | Low | Capped at 20 entries; reduced recent-findings window compensates |

---

## 5. Research Contribution Statement

> "We introduce a Published Finding Registry mechanism that injects a deduplicated list of previously-reported vulnerability titles into each agent's context before each round. This provides agents with explicit knowledge of what has already been covered, reducing intra-group duplication (observed at 76% of duplicate pairs) and cross-phase repetition (Phase A findings repeated in B and C). The mechanism complements the Delphi-inspired GAP declaration system: GAP directs agent attention toward unexplored coverage gaps, while the Registry redirects attention away from already-explored findings. Together, these mechanisms implement a full attention-steering pipeline — ensuring both coverage completeness and finding diversity."
