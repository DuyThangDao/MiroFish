# Contribution: Semantic Anchor Clustering + Control Coverage Enforcement

> **Type:** Enhancement to ConsensusEngine post-processing pipeline
> **Relevant thesis chapters:** Chapter 3 (System Design), Chapter 5 (Experiment & Evaluation)
> **Implementation:** `backend/app/services/consensus_engine.py`
> **Addresses:** Weakness #2 — Consensus Threshold filters out single-domain control-gap findings

---

## 1. Motivation

The 3-layer ConsensusEngine uses `cross_group_score` as its highest-weighted term (0.45):

```
confidence = intra × 0.30 + cross × 0.45 + attacker × 0.25
MIN_CONFIDENCE = 0.35
```

`cross_score = len(unique_groups) / domain_group_count` — for a finding supported by only 1 domain group: `cross_score = 1/5 = 0.20`.

A typical single-group control-gap finding (e.g., "No SIEM deployed") scores:
```
intra=0.0, cross=0.20, attacker=0.50 (neutral)
confidence = 0.0×0.30 + 0.20×0.45 + 0.50×0.25 = 0.215  →  DISCARDED
```

This is structurally correct for vulnerability findings (cross-domain agreement reduces false positives), but **incorrect for control-gap findings**: the absence of SIEM is by nature a single-domain concern (threat_intel/risk) and should not require cross-domain consensus to be reported.

Two independent problems compound this:

### Problem 1 — Clustering misses semantically equivalent titles

The original clustering uses title-token overlap ≥ 2. LLM-generated titles for the same control absence vary:
- "No centralized logging infrastructure"
- "Absence of SIEM monitoring capability"
- "Security event visibility gap"

These share 0 significant tokens → form 3 separate singleton clusters → each scores 0.215 → all discarded. Even though together they represent strong single-domain consensus (2 groups, 3 findings).

### Problem 2 — No safety net for genuinely single-domain findings

Even with better clustering, a DLP finding from 1 group with 2 agents (intra=1.0, cross=0.20) scores:
```
1.0×0.30 + 0.20×0.45 + 0.50×0.25 = 0.515  →  PASS
```
But a DLP finding from 1 group with only 1 agent (intra=0) always scores 0.215 → discarded regardless of quality.

---

## 2. Mechanism Design

### 2.1 Solution B — Semantic Anchor Clustering (dynamic)

**Principle:** Supplement title-token clustering with a second pass using semantic anchor keywords. Two findings that both mention the same control (SIEM, MFA, DLP…) or the same host (WEB-01, FW-01…) in their title or description are clustered together, regardless of title phrasing.

**Key design decision — dynamic anchors (no hardcoding):**

Anchors are derived entirely from existing data at runtime:

```python
def _build_anchors(self, findings):
    # 1. Standard controls: from SecurityControls dataclass fields
    #    → ["edr", "siem", "av", "ndr", "waf", "mfa", "dlp"]
    #    Automatically includes any new control added to SecurityControls
    control_anchors = {f.name for f in dataclass_fields(SecurityControls)}

    # 2. Host IDs: from affected_assets in findings
    #    → ["web-01", "fw-01", "mail-01", …] — scenario-specific, auto-extracted
    host_anchors = {asset.lower() for f in findings
                    for asset in f.get("affected_assets", [])}

    return control_anchors | host_anchors
```

No hardcoded scenario-specific values. Works across all scenarios automatically.

**Word-boundary matching** prevents false positives:
```python
re.search(r'\b' + re.escape(anchor) + r'\b', text)
# "av" does NOT match "traversal", "have", "average"
# "siem" matches "SIEM" (case-insensitive) but not "siemens"
```

**Clustering algorithm (two-pass):**

```
For each finding pair (i, j):
  Pass 1: share ≥2 significant title tokens   → cluster (original)
  Pass 2: share semantic anchor in title/desc  → cluster (B-dynamic)
```

**Effect on SIEM findings from v2 run (14 findings, risk + threat_intel):**

Before B: 14 singleton clusters → 14 × 0.215 → all discarded
After B:  1 cluster (14 findings, 2 groups) → cross=2/5=0.40, intra≈1.0
          confidence = 1.0×0.30 + 0.40×0.45 + 0.50×0.25 = 0.605 → PASS

### 2.2 Solution D — Post-Consensus Control Coverage Enforcement

**Principle:** After ConsensusEngine scoring, check whether each standard security control appears in the consensus output. For any control absent from consensus but present in raw findings, collect the best representative finding into a separate `unvalidated_control_gaps` section.

```python
def enforce_control_coverage(self, consensus_vulns, expert_findings_raw):
    for control in SecurityControls fields:
        if control already in consensus:
            continue
        candidates = [f for f in raw_findings if control in f title/description]
        if candidates:
            best = max(candidates, key=lambda f: f["confidence"])
            unvalidated.append({
                "control": control.upper(),
                "title": best["title"],
                "source_count": len(candidates),  # signal strength
                "note": "Single-domain — not cross-validated by consensus"
            })
```

These items appear in the report as a dedicated section "Unvalidated Control Gaps", clearly labeled with lower confidence status. VulnReportAgent's `get_coverage_gaps` tool exposes them to the ReACT reasoning loop.

**Role division between B and D:**

| Scenario | Handled by |
|---|---|
| 14 SIEM findings from 2 groups (strong signal) | B clusters → enters main consensus |
| 3 DLP findings from 1 group (medium signal) | B clusters but single-group → D catches |
| 1 NDR finding isolated (weak signal) | B no effect → D catches |

B handles the "fixable" cases — where signal exists but clustering was wrong. D is the safety net for genuinely weak single-domain signals that should still appear in the report.

---

## 3. Experimental Validation

### 3.1 Test Setup

Four runs compared on scenario `sme_no_tools`:

| Run | Configuration |
|-----|--------------|
| Baseline | Original engine, no GAP mechanism |
| v1 | GAP format added, not wired |
| v2 | GAP mechanism active, no B+D |
| **v3** | GAP mechanism + B-dynamic + D |

### 3.2 Quantitative Results

| Metric | Baseline | v1 (format) | v2 (GAP) | v3 (GAP+B+D) | Δ v2→v3 |
|---|---|---|---|---|---|
| Raw expert findings | 36 | 98 | 69 | 78 | +13% |
| CVE ratio (raw) | 11% | 14% | 4% | 9% | +5pp |
| Consensus vulns | 6 | 17 | 12 | **4** | -8 ⚠️ |
| CVE in consensus | 1/6 | 1/17 | 1/12 | **0/4** ✅ | -1 |
| Controls in raw findings | 3/7 | 4/7 | **7/7** | **7/7** | = |
| Unvalidated gaps (D) | — | — | — | **0** | — |
| GAP declarations | 0 | 0 | 127 | 125 | ≈ |
| Avg consensus confidence | ~0.52 | ~0.48 | ~0.55 | **~0.74** | +0.19 |
| Report length | 550 | 12,136 | 16,575 | 10,544 | -36% |

### 3.3 Observed Behavior

**B-dynamic successfully clustered control-gap findings into consensus:**

The mechanism correctly merged findings with different titles but shared semantic anchors:
- "No centralized logging infrastructure" + "Absence of SIEM monitoring" + "Security event visibility gap" → 1 cluster
- All 5 domain groups contributed findings about control absence → `cross_score = 1.00`
- Result: "Complete Absence of Foundational Security Controls" with `confidence = 0.863`

`enforce_control_coverage()` returned 0 unvalidated gaps — because B had already promoted all control-gap findings into the main consensus list. D's safety net was not needed.

**However: over-clustering observed**

Consensus vulns dropped from 12 → 4. Root cause: GAP mechanism induces agents to write **compound findings** listing all absent controls together ("No EDR, SIEM, WAF, AV, NDR, MFA, DLP — None deployed"). These compound findings contain all 7 control anchors, causing them to act as cluster hubs that absorb individual control findings into one mega-cluster.

Trade-off between v2 and v3:

| Aspect | v2 (GAP only) | v3 (GAP+B+D) | Better |
|---|---|---|---|
| CVE in consensus | 1/12 (8%) | **0/4 (0%)** | v3 |
| Control coverage | 7/7 | 7/7 | Equal |
| Avg confidence | ~0.55 | **~0.74** | v3 |
| Cross-group agreement (top vulns) | partial | **1.00 (all 5 groups)** | v3 |
| Finding granularity | 12 distinct | 4 broad | v2 |
| Report completeness | 16,575 chars | 10,544 chars | v2 |

v3 produces **fewer but higher-quality** consensus findings. The 4 findings represent stronger cross-domain agreement. The loss is in granularity — 7 separate control issues collapsed into 1 broad finding.

### 3.4 Over-Clustering: Root Cause and Fix

v3's over-clustering was caused by the "OR-title" rule: if anchor `a` appears in finding A's title, then finding B only needed `a` anywhere (including description) to cluster with A. GAP-induced compound findings like "Complete Absence of Foundational Security Controls" (description: "No EDR, SIEM, WAF, AV, NDR, MFA, DLP...") became hubs absorbing all control findings.

**Fix (implemented for v4): both-title rule**

```python
# OLD (v3): anchor in title of AT LEAST ONE finding
if not (in_title1 or in_title2): continue

# NEW (v4): anchor in title of BOTH findings
return any(
    self._anchor_in_text(a, t1) and self._anchor_in_text(a, t2)
    for a in anchors
)
```

Only two findings that independently chose the same control as their primary topic (visible in title) are clustered. Compound findings with abstract titles stand alone.

### 3.5 Final Results: v4 (GAP + B-dynamic both-title + D)

| Metric | Baseline | v2 (GAP) | v3 (OR-title) | **v4 (both-title)** |
|---|---|---|---|---|
| Raw findings | 36 | 69 | 78 | **81** |
| CVE ratio (raw) | 11% | 4% | 9% | 9% |
| Consensus vulns | 6 | 12 | 4 ⚠️ | **13** ✅ |
| CVE in consensus | 1/6 | 1/12 | 0/4 | **1/13** |
| Controls in raw | 3/7 | 7/7 | 7/7 | **7/7** |
| Unvalidated gaps (D) | 0 | 0 | 0 | **1** (DLP) |
| Avg consensus confidence | 0.583 | 0.552 | 0.745 | 0.562 |
| Report length | 550 | 16,575 | 10,544 | **22,212** ✅ |

**v4 findings include:** RCE + path traversal (2 CVE-related), RDP exposure, network segmentation failure, privilege escalation, endpoint hardening gap, asset management, input validation, absence of foundational controls, NDR/IDS absence, ransomware protection gap, phishing risk. DLP appears as unvalidated gap (D section) — single finding, not enough signal for consensus.

**Both-title fix resolves over-clustering** while preserving B's core benefit: findings with same control keyword in their titles (e.g., "No SIEM deployed" + "SIEM monitoring gap") still cluster correctly.

---

## 4. Implementation Details

### 4.1 Files Modified

| File | Change |
|------|--------|
| `backend/app/services/consensus_engine.py` | Added `_build_anchors()`, `_shares_anchor()`, `_anchor_in_text()`; updated `_cluster_findings()` with two-pass logic; added `enforce_control_coverage()` |
| `backend/app/services/vuln_report_agent.py` | `generate_report_sync()` calls `enforce_control_coverage()`; `_ToolContext` exposes unvalidated gaps via `get_coverage_gaps` tool; `unvalidated_control_gaps` added to return dict |
| `backend/scripts/run_security_review.py` | Logs unvalidated gaps post-consensus; appends "Unvalidated Control Gaps" section to report.md |

### 4.2 Interaction with GAP Mechanism

B+D and the GAP Declaration Mechanism are complementary layers:

```
GAP Declaration (Delphi mechanism)
  └─ generates control-gap findings that were previously absent
       └─ B-dynamic clustering
            └─ groups semantically equivalent findings across title variations
                 └─ ConsensusEngine scoring
                      └─ if passes: enters main consensus list
                      └─ if fails: D enforcement catches as unvalidated section
```

Without GAP: 0 SIEM/MFA findings → B+D have nothing to work with
Without B+D: 38 SIEM/MFA findings generated but discarded by scoring
With both: SIEM/MFA findings generated AND survive into report

### 4.3 Failure Modes

| Failure mode | Likelihood | Mitigation |
|---|---|---|
| Anchor over-clusters compound findings ("No SIEM and no MFA") | Low | Word-boundary match + title/first-150-chars-description limit |
| New control not in SecurityControls dataclass | Low | Adding control to dataclass automatically adds to anchors |
| Host anchor "db" matches "debug", "database" | Low | Word-boundary match prevents substring hits |
| D collects false positive from noisy raw finding | Medium | `source_count` shown — reader can judge signal strength |

---

## 5. Research Contribution Statement

> **Proposed contribution framing for thesis:**
>
> "We identify a structural bias in multi-expert consensus engines where the cross-domain validation weight (0.45) systematically penalizes single-domain security control findings despite their domain-specificity being correct rather than a quality defect. We address this with two complementary mechanisms: (1) a dynamic semantic anchor clustering pass that groups semantically equivalent control-gap findings across title variations using dataclass-derived anchor keywords — requiring no scenario-specific configuration; and (2) a post-consensus control coverage enforcement layer that guarantees standard security controls appear in the final report regardless of consensus scoring outcome. Together with the Delphi-inspired GAP declaration mechanism, these three components form a complete pipeline from gap elicitation to report coverage."
