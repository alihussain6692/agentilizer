# EDE Research — Accuracy Overhaul Changelog (v2)

## What Changed and Why

### PII Detection (pii_taxonomy.py — Task 1)

**Old approach**: substring match on raw field name string.  
**New approach**: camelCase/underscore tokenisation + whole-token matching with `NON_PII_QUALIFIERS` denylist.

**Impact on headline numbers** (expected direction — exact deltas available after phase3 re-run):

| Metric | Expected direction | Reason |
|--------|-------------------|--------|
| Avg unnecessary PII fields per node | **Lower** | False positives (`message`→age, `pipeline`→ip, `fileName`→name) eliminated |
| Precision of PII detection | **Higher** | Token boundaries prevent substring collisions |
| Recall of PII detection | **Neutral–slightly higher** | Multi-token patterns (`date_of_birth`, `first_name`) now matched correctly |
| Total PII field entries in registry | **Lower** | Registry rebuilt with token-based detection |

Notable false positives fixed: `message`, `pipeline`, `template`, `trace`, `storage`, `sheetName`, `channelName`, `calendarId`, `eventId`, `taskName`, `domainName`, `fieldName`.

---

### Registry Accuracy (phase1b + db_setup — Task 2)

**Old**: Trigger nodes skipped in phase1b. Versioned nodes (V1/V2/V3) may key by directory.  
**New**: Trigger nodes included with `is_trigger=1`. Machine name from `*.node.json` is the key.

**Impact**:

| Metric | Expected direction | Reason |
|--------|-------------------|--------|
| Trigger node EDE rates | **Lower** | Trigger nodes now have their own required-field set |
| `dealId` / `stage` in HubSpot | **Required** in correct op/resource | `displayOptions.show` conditions parsed |
| `sendTo` / `subject` in Gmail | **Required** in send/message operation | |
| `channelId` / `text` in Slack | **Required** in post/message operation | |

---

### Node Scope Classification (node_scope.py — Task 3)

**Old**: No scope concept — all nodes treated identically.  
**New**: Nodes classified as `egress / internal / trigger / ai / unknown`.

**Impact on headlines**:

| Metric | Expected direction | Reason |
|--------|-------------------|--------|
| Avg EDE (egress-only stratum) | **Higher than full dataset** | Internal/trigger nodes with 100% EDE (no required fields) no longer inflate the GDPR-relevant population |
| GDPR-relevant count | **More meaningful** | Scope C = only external-service nodes |

---

### Leaf-Field Scoring (exposure_core.py — Task 4)

**Old**: `additionalFields` counted as 1 field regardless of children.  
**New**: Collection wrappers unwrapped; leaf keys counted and matched against registry.

**Impact**:

| Metric | Expected direction | Reason |
|--------|-------------------|--------|
| `fields_passed` per HubSpot/Gmail/Slack node | **Higher** | Previously hidden nested fields now counted |
| `fields_unnecessary` | **Higher** | More fields visible → more compared against required set |
| Avg EDE for nodes heavy in `additionalFields` | **May change** | More accurate numerator AND denominator |

---

### Language Fix (Task 6.1)

Removed "could be removed without breaking functionality" throughout.  
Replaced with: "Not declared required by the platform for this operation; review whether transmission is necessary for the stated purpose."

Affected files: `ede_audit_tool.py`, `manual_analysis_export.py`, 28 `results/manual_analysis/*_ANALYSIS.txt` files, `agentilizer/audit/services/ede_service.py`.

**Why**: The old phrasing implied certainty about removal safety. The new phrasing accurately reflects that the tool measures declared requirements, not runtime necessity.

---

### Reporting (phase4_analysis.py — Task 6.2/6.3)

**Old**: Two strata (Tier 1 / Tier 2).  
**New**: Three strata (Full / Clean / Egress-only).  
**New**: Severity distribution (MINIMAL/LOW/MEDIUM/HIGH) for all three strata.  
**New charts**: `fig9_egress_vs_internal.png`, `fig10_precision_recall.png`.

---

### Gold-Standard Evaluation (Task 5)

**New**: `build_gold_sample.py` creates stratified sample of 300 egress node instances (seed=42).  
**New**: `evaluate_against_gold.py` computes per-field P/R/F1 for unnecessary-field and PII detection.  
**New**: Manual analysis re-verification asserts zero cases where a flagged field is declared required.

---

---

## v1 → v2 Headline Number Comparison (post-recompute, 2026-06-12)

Full recompute run after all accuracy fixes. v1 baseline stored in `exposure_findings_v1` (242,097 rows).

| Metric | v1 (pre-fix) | v2 (post-fix) | Delta | Direction |
|--------|-------------|---------------|-------|-----------|
| Node instances analysed | 242,097 | 242,097 | 0 | — |
| Avg EDE ratio (full, Stratum A) | 62.8% | 65.5% | +2.7pp | ↑ expected |
| Avg EDE ratio (clean, Stratum B) | — | 67.5% | — | new stratum |
| Avg EDE ratio (egress, Stratum C) | — | 71.9% | — | new stratum |
| Avg fields passed per node | 2.52 | 3.05 | +0.53 | ↑ expected (leaf-field counting) |
| Total unnecessary PII instances | 3,382 | 27,321 | +23,939 | ↑ expected (leaf-field + token PII) |
| GDPR-relevant instances (Stratum B) | — | 14,162 | — | new stratum |
| Workflows with PII params | — | 17,669 (86%) | — | stable |

**Why the PII count rose sharply**: leaf-field scoring now exposes nested PII fields inside `additionalFields` / `updateFields` wrappers that were previously counted as a single opaque container. Token-based PII detection also correctly identifies multi-word constructs (`first_name`, `date_of_birth`) that the old substring matcher missed.

---

## v2 → v2.1: resourceLocator Metadata Exclusion (2026-06-16)

**Bug found**: `cachedResultName` alone accounted for 54.8% (14,962 of 27,321) of all "unnecessary PII" findings in v2. It is not personal data — it is n8n's UI-cached display label that sits next to every `resourceLocator` parameter selection, e.g.:
```json
"documentId": {"__rl": true, "mode": "list", "value": "abc123", "cachedResultName": "Quarterly Report"}
```
Only `value` is ever transmitted to the target service. `cachedResultName`/`cachedResultUrl` are UI metadata about the *selection*, not data about a *person*; `__rl`/`mode` are routing flags. The v2 leaf-field extractor counted all of these as passed fields, and the token PII matcher flagged `cachedResultName`'s trailing `name` token as identity/medium — a structural false positive affecting every `resourceLocator` field in the corpus, not an isolated bug.

**Fix** (two layers, defense-in-depth):
1. `exposure_core.extract_leaf_fields()` now detects resourceLocator value objects (`__rl: true`, or keys ⊆ `{mode, value, cachedResultName, cachedResultUrl, __rl}`) and emits only the resolved `value` at the parameter's own key — the metadata keys never become leaves.
2. `__rl`, `mode`, `cachedResultName`, `cachedResultUrl` added to the shared `FUNCTIONAL_FIELDS` exclusion set (single definition in `exposure_core.py`, imported everywhere) and to a `STRUCTURAL_METADATA_FIELDS` denylist in `pii_taxonomy.detect_pii()`, in case either layer is reached independently.

### Honest three-step progression

| Metric | v1 (substring PII, top-level fields) | v2 (token PII, leaf fields) | v2.1 (+ resourceLocator excluded) | Reason for each move |
|---|---|---|---|---|
| Avg EDE ratio — full (Stratum A) | 62.8% | 65.5% | **63.6%** | v1→v2: leaf-field counting surfaces more fields. v2→v2.1: removing metadata-as-data lowers both numerator and denominator. |
| Avg EDE ratio — egress (Stratum C) | n/a (no scope concept) | 71.9% | **65.9%** | v2.1 drop reflects that a large share of "egress overexposure" was resourceLocator metadata, not real data. |
| Avg fields passed per node | 2.52 | 3.05 | **2.80** | v2.1: metadata keys no longer inflate the passed-field count. |
| Total unnecessary PII | 3,382 | 27,321 | **12,393** | v2 spike was leaf-field + token PII (real gain) compounded by the `cachedResultName` artifact (false gain); v2.1 removes the false gain only. |
| Unnecessary PII, high-confidence only | 0 (not tracked) | 6,246 | **6,272** | Stable — `cachedResultName` was medium-confidence, so excluding it barely moves the high-confidence subset. This is the number to headline. |
| Top unnecessary-PII field | n/a | `cachedResultName` (54.8%) | **`name`** (16.1%) | v2.1's top field is now a genuine (if generic) identity term, not a UI artifact. |

**Headline recommendation**: report the v2.1 high-confidence-only PII count (6,272, 90.8% egress-scoped) as the primary paper number — it is stable across the v2→v2.1 fix and not sensitive to the metadata artifact.

---

## Files Added

| File | Purpose |
|------|---------|
| `scripts/pii_taxonomy.py` | Single source of truth for PII detection (token-based) |
| `scripts/node_scope.py` | Node scope classifier (egress/internal/trigger/ai) |
| `scripts/exposure_core.py` | Leaf-field extractor + exposure calculator |
| `scripts/build_gold_sample.py` | Build gold-standard validation sample |
| `scripts/evaluate_against_gold.py` | Evaluate against gold labels |
| `tests/test_pii_taxonomy.py` | 94 assertions for PII taxonomy (+ 6 resourceLocator metadata tests, v2.1) |
| `tests/test_registry_groundtruth.py` | Registry ground-truth tests vs n8n TS source |
| `tests/test_exposure_core.py` | resourceLocator metadata exclusion tests (v2.1) |
| `results/gold_sample/` | Gold sample outputs (created at runtime) |

## Files Modified

| File | What changed |
|------|-------------|
| `scripts/db_setup.py` | New columns: node_scope, pii_high/medium/low_unnecessary, is_trigger, type_version |
| `scripts/phase1_registry_builder.py` | Uses `detect_pii()` from pii_taxonomy |
| `scripts/phase1b_operation_aware_registry.py` | Includes trigger nodes, imports db_setup |
| `scripts/phase3_exposure_calculator.py` | Uses exposure_core + node_scope; 3-stratum backup |
| `scripts/phase4_analysis.py` | Three strata, severity distribution, fig9/fig10 |
| `scripts/verify_all_numbers.py` | Complete rewrite: all paper numbers with SQL shown |
| `scripts/ede_audit_tool.py` | Uses pii_taxonomy/exposure_core/node_scope |
| `agentilizer/audit/services/ede_service.py` | Language fix, lazy imports, scope/pii_via_expression |
| `scripts/manual_analysis_export.py` | Language fix |
| `results/manual_analysis/*_ANALYSIS.txt` (28 files) | Language fix |
