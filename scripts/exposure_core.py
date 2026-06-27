"""
exposure_core.py — Shared EDE calculation logic  (Task 6.5)

Used by:
  phase3_exposure_calculator.py  (batch pipeline)
  ede_audit_tool.py              (CLI/library)
  agentilizer/audit/services/ede_service.py  (Django)

Key changes vs original phase3:
  - Counts leaf fields, not container keys (additionalFields → its children)
  - Detects PII via pii_taxonomy.detect_pii() (token-based, confidence-aware)
  - Tracks pii_via_expression (PII terms found in n8n expression references)
  - Returns per-confidence PII counts (high/medium/low)
  - Node scope is determined by node_scope.classify_scope()
"""

from __future__ import annotations
import re
import json
from pii_taxonomy import detect_pii, PiiMatch

# ── Globally functional/structural fields ─────────────────────────────────────
# Never counted as unnecessary EDE — they select the operation type and
# configure authentication, not data fields subject to data-minimisation.
#
# __rl / mode / cachedResultName / cachedResultUrl are n8n's resourceLocator UI
# metadata: every resourceLocator parameter (e.g. selecting a Sheet, Channel, or
# Deal from a dropdown) serialises as
#   {"__rl": true, "mode": "list", "value": "<id>", "cachedResultName": "<label>"}
# cachedResultName/cachedResultUrl are the human-readable label/link the n8n
# editor caches for display — metadata about a UI selection, not personal data
# about a person — and __rl/mode are pure routing flags. None of the four are
# ever transmitted to the target service as data; only "value" is. They are
# listed here as defense-in-depth (extract_leaf_fields() below already stops
# them from becoming leaves in the normal resourceLocator case).
FUNCTIONAL_FIELDS: frozenset[str] = frozenset({
    "operation",
    "resource",
    "authentication",
    "credentials",
    "options",
    "returnAll",
    "limit",
    "__rl",
    "mode",
    "cachedResultName",
    "cachedResultUrl",
})

# Known n8n collection-wrapper field names.
# These are container keys whose children should be scored, not the container itself.
# Example: additionalFields.bcc → 'bcc' is a leaf, 'additionalFields' is not scored.
COLLECTION_WRAPPERS: frozenset[str] = frozenset({
    "additionalFields",
    "updateFields",
    "otherProperties",
    "filters",
    "filterType",
    "conditions",
    "queryParameters",
    "formFields",
    "bodyParameters",
    "headerParameters",
    "sendHeaders",
    "sendBody",
    "sendQuery",
    "specifyBody",
})

# Keys that can appear inside a resourceLocator value object. "value" is the
# only one that is actually transmitted as data; the rest are UI metadata.
_RESOURCE_LOCATOR_KEYS: frozenset[str] = frozenset({
    "__rl", "mode", "value", "cachedResultName", "cachedResultUrl",
})


def _is_resource_locator(v: dict) -> bool:
    """
    True if v is an n8n resourceLocator value object, e.g.
      {"__rl": true, "mode": "list", "value": "abc123", "cachedResultName": "My Sheet"}
    Detected by either the explicit __rl marker, or — for safety against missing
    __rl in older workflow exports — by every key being a known resourceLocator key.
    """
    if not v:
        return False
    if v.get("__rl") is True:
        return True
    return set(v.keys()) <= _RESOURCE_LOCATOR_KEYS


# Expression pattern — matches n8n dynamic value references like:
#   ={{ $json.fieldName }}
#   ={{ $('NodeName').item.json.fieldName }}
#   ={{ $json["fieldName"] }}
_EXPR_FIELD_RE = re.compile(
    r'\$json(?:\.(\w+)|\["(\w+)"\])'          # $json.field or $json["field"]
    r'|\$\([\'"][\w\s]+[\'"]\)\.item\.json\.(\w+)'  # $('Node').item.json.field
)


# ── Leaf-field extractor ───────────────────────────────────────────────────────

def extract_leaf_fields(
    params: dict,
    depth: int = 0,
    max_depth: int = 3,
    prefix: str = "",
) -> dict[str, object]:
    """
    Flatten a parameters dict to its leaf values, depth-first, up to max_depth.

    Rules:
    - Functional fields (operation, resource, etc.) are excluded entirely.
    - Collection wrapper fields (additionalFields, etc.) are NOT counted as leaves;
      their children ARE descended into and counted.
    - Non-wrapper dict values whose depth > max_depth are counted as a single leaf
      (we don't know their internal structure).

    Returns {dotted_path: value}  where dotted_path ends at a leaf (non-dict) field.
    """
    if not isinstance(params, dict) or depth > max_depth:
        return {}

    leaves: dict[str, object] = {}

    for k, v in params.items():
        if k in FUNCTIONAL_FIELDS:
            continue

        full_key = f"{prefix}.{k}" if prefix else k

        if isinstance(v, dict):
            if _is_resource_locator(v):
                # resourceLocator parameter: only the resolved "value" (the actual
                # ID/selection sent to the service) is transmitted data. mode,
                # __rl, and the cached*  display labels are UI metadata — do not
                # emit them as leaves at all (see FUNCTIONAL_FIELDS comment above).
                leaves[full_key] = v.get("value", "")
                continue
            if k in COLLECTION_WRAPPERS:
                # Descend without counting the wrapper itself
                sub = extract_leaf_fields(v, depth + 1, max_depth, full_key)
                leaves.update(sub)
            elif depth < max_depth:
                # Ordinary nested dict: also descend but count nothing for this level
                # (the children are the actual fields being passed)
                sub = extract_leaf_fields(v, depth + 1, max_depth, full_key)
                if sub:
                    leaves.update(sub)
                else:
                    # Empty nested dict — count the key itself
                    leaves[full_key] = v
            else:
                # At max depth: count the key
                leaves[full_key] = v
        else:
            leaves[full_key] = v

    return leaves


def leaf_name(dotted_path: str) -> str:
    """Return the leaf field name (last segment after last dot)."""
    return dotted_path.rsplit(".", 1)[-1]


# ── Expression PII extractor ──────────────────────────────────────────────────

def extract_expression_pii_fields(value: object) -> list[str]:
    """
    If value is an n8n expression string, extract referenced upstream field names
    and return those that are PII.

    Only structural PII names in expression references are counted here —
    they are reported separately as pii_via_expression, never merged into the
    structural unnecessary-PII count.
    """
    if not isinstance(value, str):
        return []
    if not ("={{" in value or "{{ $" in value):
        return []
    pii_refs: list[str] = []
    for m in _EXPR_FIELD_RE.finditer(value):
        field_ref = m.group(1) or m.group(2) or m.group(3)
        if field_ref and detect_pii(field_ref).is_pii:
            pii_refs.append(field_ref)
    return pii_refs


# ── Core exposure calculator ───────────────────────────────────────────────────

def calc_exposure(
    params: dict,
    required_fields: set[str],
    all_pii_fields: set[str],
    pii_category_map: dict[str, str] | None = None,
    pii_confidence_map: dict[str, str] | None = None,
) -> dict:
    """
    Calculate EDE metrics for a single node instance.

    Parameters
    ----------
    params           : raw parameters dict from the workflow JSON
    required_fields  : set of field names required by this node (from registry)
    all_pii_fields   : set of field names marked PII in the registry
    pii_category_map : {field_name: category} — for PII fields
    pii_confidence_map : {field_name: confidence} — for per-confidence breakdown

    Returns a dict with keys:
      fields_passed, fields_required, fields_unnecessary, overexposure_ratio,
      pii_fields_exposed, pii_fields_required, pii_fields_unnecessary,
      pii_high_unnecessary, pii_medium_unnecessary, pii_low_unnecessary,
      pii_via_expression, leaf_fields (list of dotted paths)
    """
    # Step 1: extract leaf fields
    leaf_map = extract_leaf_fields(params)

    # Step 2: get leaf names (last segment, for registry matching)
    leaf_names = {leaf_name(path) for path in leaf_map.keys()}

    # Remove functional fields from leaf names (they can appear as leaves too)
    leaf_names -= FUNCTIONAL_FIELDS

    fields_passed = len(leaf_names)
    matched_required = leaf_names & required_fields
    fields_required = len(matched_required)
    unnecessary = leaf_names - required_fields
    fields_unnecessary = len(unnecessary)
    overexposure_ratio = fields_unnecessary / fields_passed if fields_passed > 0 else 0.0

    # Step 3: PII counts
    # Use token-based PII detection on each leaf name
    pii_exposed_names: set[str] = set()
    for name in leaf_names:
        # Check registry PII flag first (cheaper); fall back to live detection
        if name in all_pii_fields:
            pii_exposed_names.add(name)
        elif detect_pii(name).is_pii:
            pii_exposed_names.add(name)

    pii_fields_exposed = len(pii_exposed_names)
    pii_required_exposed = pii_exposed_names & required_fields
    pii_fields_required = len(pii_required_exposed)
    pii_unnecessary_names = pii_exposed_names - required_fields
    pii_fields_unnecessary = len(pii_unnecessary_names)

    # Per-confidence PII counts
    pii_high = pii_medium = pii_low = 0
    if pii_confidence_map:
        for name in pii_unnecessary_names:
            conf = pii_confidence_map.get(name) or detect_pii(name).confidence
            if conf == "high":
                pii_high += 1
            elif conf == "medium":
                pii_medium += 1
            else:
                pii_low += 1
    else:
        for name in pii_unnecessary_names:
            conf = detect_pii(name).confidence
            if conf == "high":
                pii_high += 1
            elif conf == "medium":
                pii_medium += 1
            else:
                pii_low += 1

    # Step 4: expression PII
    pii_via_expression = 0
    for path, val in leaf_map.items():
        pii_via_expression += len(extract_expression_pii_fields(val))

    return {
        "fields_passed":          fields_passed,
        "fields_required":        fields_required,
        "fields_unnecessary":     fields_unnecessary,
        "overexposure_ratio":     overexposure_ratio,
        "pii_fields_exposed":     pii_fields_exposed,
        "pii_fields_required":    pii_fields_required,
        "pii_fields_unnecessary": pii_fields_unnecessary,
        "pii_high_unnecessary":   pii_high,
        "pii_medium_unnecessary": pii_medium,
        "pii_low_unnecessary":    pii_low,
        "pii_via_expression":     pii_via_expression,
        "leaf_fields":            list(leaf_map.keys()),
        "unnecessary_field_names": sorted(unnecessary),
        "pii_unnecessary_names":   sorted(pii_unnecessary_names),
    }


def classify_populations(node_records):
    """
    Given an iterable of per-node dicts (each with keys: node_scope,
    fields_required, ede_ratio or overexposure_ratio, fields_unnecessary,
    pii_unnecessary, node_pii_confidence), compute the three paper
    populations by POOLING all nodes (matching the pipeline's AVG()).

    Returns dict with, for each population: n, avg_ede, any_ede,
    high_ede, pii_total, pii_high.
    """
    def ratio(r):
        v = r.get("ede_ratio", r.get("overexposure_ratio"))
        return float(v) if v is not None else 0.0

    def pii_counts(recs):
        total = sum(len(r.get("pii_unnecessary", []) or []) for r in recs)
        high = sum(
            len(r.get("pii_unnecessary", []) or [])
            for r in recs
            if str(r.get("node_pii_confidence", "")).upper() == "HIGH"
        )
        return total, high

    def summarize(recs):
        n = len(recs)
        if n == 0:
            return {"n": 0, "avg_ede": 0.0, "any_ede": 0, "high_ede": 0,
                    "pii_total": 0, "pii_high": 0}
        ratios = [ratio(r) for r in recs]
        pt, ph = pii_counts(recs)
        return {
            "n": n,
            "avg_ede": round(sum(ratios) / n * 100, 2),
            "any_ede": sum(1 for x in ratios if x > 0),
            "high_ede": sum(1 for x in ratios if x >= 0.5),
            "pii_total": pt,
            "pii_high": ph,
        }

    # matched = every record passed in (caller passes only registry-matched/assessed)
    matched = list(node_records)
    resolvable = [r for r in matched
                  if int(r.get("fields_required", 0)) > 0
                  and r.get("node_scope") != "unknown"]
    egress_ai = [r for r in matched
                 if int(r.get("fields_required", 0)) > 0
                 and r.get("node_scope") in ("egress", "ai")]

    return {
        "all_matched":          summarize(matched),
        "resolvable":           summarize(resolvable),
        "egress_ai_resolvable": summarize(egress_ai),
    }
