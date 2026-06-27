import sys
import json
from pathlib import Path

SCRIPTS_DIR = str(Path(__file__).resolve().parent.parent.parent.parent / "scripts")

_RISK_THRESHOLDS = [(0.70, 'HIGH'), (0.40, 'MEDIUM'), (0.20, 'LOW'), (0.00, 'MINIMAL')]

_CRED_KEY_FRAGMENTS = {
    'apikey', 'accesstoken', 'secretkey', 'password', 'passwd',
    'token', 'bearer', 'privatekey', 'clientsecret', 'authorization',
}


def _severity_from_ratio(ratio: float) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if ratio >= threshold:
            return label
    return 'MINIMAL'


def _classify_value_confidence(value) -> dict:
    """Classify a field value as HIGH/MEDIUM/LOW confidence PII/EDE finding."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith('={{') or stripped.startswith('{{'):
            return {
                'confidence': 'MEDIUM',
                'is_expression': True,
                'reason': 'n8n expression — value is computed at runtime, manual review recommended',
                'display_value': value,
            }
        elif stripped == '':
            return {
                'confidence': 'LOW',
                'is_expression': False,
                'reason': 'empty value — field is configured but has no value',
                'display_value': value,
            }
        else:
            return {
                'confidence': 'HIGH',
                'is_expression': False,
                'reason': 'literal value — hardcoded data in workflow configuration',
                'display_value': value,
            }
    elif isinstance(value, dict):
        has_expression = any(
            isinstance(v, str) and (v.strip().startswith('={{') or v.strip().startswith('{{'))
            for v in value.values()
        )
        return {
            'confidence': 'MEDIUM' if has_expression else 'HIGH',
            'is_expression': has_expression,
            'reason': 'nested object — contains expression value(s)' if has_expression
                      else 'nested object — literal values',
            'display_value': value,
        }
    elif isinstance(value, list):
        return {
            'confidence': 'MEDIUM',
            'is_expression': False,
            'reason': 'array value — review individual elements',
            'display_value': value,
        }
    else:
        return {
            'confidence': 'HIGH',
            'is_expression': False,
            'reason': 'literal value',
            'display_value': value,
        }


def _ensure_scripts_path() -> None:
    if SCRIPTS_DIR not in sys.path:
        sys.path.insert(0, SCRIPTS_DIR)


def _import_ede():
    """Lazy import — saves/restores sys.stdout to avoid the UTF-8 wrapper side effect."""
    _ensure_scripts_path()
    _orig = sys.stdout
    try:
        import ede_audit_tool as _ede
        return _ede
    finally:
        # ede_audit_tool wraps sys.stdout.buffer in a new TextIOWrapper at module
        # level. If we just restore _orig, the new wrapper becomes unreferenced and
        # its __del__ closes the underlying fd. Detach the buffer first so GC cannot
        # close it, then restore the original stream.
        if sys.stdout is not _orig and hasattr(sys.stdout, 'detach'):
            try:
                sys.stdout.detach()
            except Exception:
                pass
        sys.stdout = _orig


def _import_pii():
    _ensure_scripts_path()
    from pii_taxonomy import detect_pii, pii_confidence as get_pii_confidence
    return detect_pii, get_pii_confidence


def _import_scope():
    _ensure_scripts_path()
    from node_scope import classify_scope
    return classify_scope


def _flatten_params(params: dict, prefix: str = '') -> dict:
    """Flatten nested parameter dict into dotted-key paths → leaf values."""
    flat = {}
    for k, v in params.items():
        full_key = f'{prefix}.{k}' if prefix else k
        if isinstance(v, dict):
            flat.update(_flatten_params(v, full_key))
        else:
            flat[full_key] = v
    return flat


def _field_match(engine_name: str, flat_key: str) -> bool:
    """True if flat_key corresponds to the engine-reported field name.

    Matches the exact full dotted path (e.g. 'updateFields.phone') OR
    just the leaf segment (e.g. 'updateFields.phone' → leaf 'phone').
    """
    return flat_key == engine_name or flat_key.rsplit('.', 1)[-1] == engine_name


def _find_api_keys_in_params(params: dict) -> list:
    """Return list of {field, preview} for likely hardcoded credentials in a node's params."""
    findings = []
    flat = _flatten_params(params)
    for key, value in flat.items():
        if not isinstance(value, str) or not value:
            continue
        if value.startswith('{{') or value.startswith('='):
            continue
        key_normalised = key.lower().replace('-', '').replace('_', '').replace('.', '')
        is_cred_key = any(frag in key_normalised for frag in _CRED_KEY_FRAGMENTS)
        if is_cred_key and len(value) > 20:
            preview = value[:6] + '***' + value[-3:] if len(value) > 12 else '***'
            findings.append({'field': key, 'preview': preview, 'length': len(value)})
    return findings


def _get_required_fields_definition(
    short_type: str, operation: str, resource: str,
    global_reg: dict, op_reg: dict, functional_fields: frozenset,
) -> dict:
    """Return required fields for this node type from the Minimum Field Registry.

    Mirrors the (operation, resource) fallback chain that the real scorer
    (ede_audit_tool.get_required_fields) uses. Most action nodes — e.g.
    activeCampaign, pagerDuty — key required fields per specific operation/resource
    combo rather than a single ('*', '*') wildcard, so the node's actual
    operation/resource has to be matched, not just the wildcard.
    """
    key     = short_type.lower().strip()
    op_val  = (operation or '*').lower()
    res_val = (resource or '*').lower()
    required = {}

    op_entry = op_reg.get(key, {})
    if isinstance(op_entry, dict):
        for combo in [(op_val, res_val), (op_val, '*'), ('*', res_val), ('*', '*')]:
            if combo in op_entry:
                for field in op_entry[combo]:
                    required[field] = 'required'
                break

    if not required:
        global_entry = global_reg.get(key, {})
        if isinstance(global_entry, dict):
            for field in global_entry.get('required', set()) - functional_fields:
                required[field] = 'required'

    return required


def run_ede_audit(workflow_file_path: str) -> dict:
    try:
        raw_nodes_by_position = {}
        _raw_err_msg = ''
        for _enc in ('utf-8-sig', 'utf-8', 'latin-1'):
            try:
                with open(workflow_file_path, 'r', encoding=_enc) as f:
                    raw_workflow = json.load(f)
                for idx, raw_node in enumerate(raw_workflow.get('nodes', [])):
                    raw_nodes_by_position[idx] = {
                        'name': raw_node.get('name', ''),
                        'type': raw_node.get('type', ''),
                        'parameters': raw_node.get('parameters', {}) or {},
                    }
                break
            except UnicodeDecodeError:
                continue
            except Exception as raw_err:
                _raw_err_msg = str(raw_err)
                break

        _ede = _import_ede()
        detect_pii, get_pii_confidence = _import_pii()
        classify_scope = _import_scope()

        db_path = _ede.build_db_path()
        global_reg, op_reg, _, _ = _ede.load_registry(db_path)
        result = _ede.analyse_workflow(Path(workflow_file_path), global_reg, op_reg)

        if result is None:
            return _empty_error('File is not a valid n8n workflow.')

        node_results_list = []
        for n in result.node_results:
            ratio       = getattr(n, 'overexposure_ratio', 0.0)
            gdpr_raw    = getattr(n, 'gdpr_concern', 'NO')
            position    = getattr(n, 'position', None)
            unnecessary = getattr(n, 'unnecessary_fields', [])
            pii_unnec   = getattr(n, 'pii_unnecessary', [])
            short_type  = getattr(n, 'short_type', '')
            node_scope  = getattr(n, 'node_scope', classify_scope(getattr(n, 'node_type', '')))
            pii_via_expr= getattr(n, 'pii_via_expression', 0)

            raw_node_data = raw_nodes_by_position.get(position, {}) if position is not None else {}
            raw_params    = raw_node_data.get('parameters', {})

            unnecessary_set = set(unnecessary)
            pii_set         = set(pii_unnec)
            all_evidence    = list(unnecessary_set | pii_set)

            # Flatten all node parameters so nested fields (e.g. updateFields.phone)
            # are reachable by leaf name or full dotted path.
            flat_params = _flatten_params(raw_params)

            # Enriched EDE snippet — violations display only (unnecessary + PII fields).
            # Matches each engine-reported field name against the flattened leaf keys.
            ede_snippet = {}
            for field in all_evidence:
                for fk, fv in flat_params.items():
                    if _field_match(field, fk):
                        ci = _classify_value_confidence(fv)
                        ede_snippet[field] = {
                            'value': fv,
                            'confidence': ci['confidence'],
                            'is_expression': ci['is_expression'],
                            'reason': ci['reason'],
                            'is_pii': field in pii_set,
                        }
                        break

            # Enriched PII snippet — same flattened search.
            pii_snippet = {}
            for field in pii_unnec:
                for fk, fv in flat_params.items():
                    if _field_match(field, fk):
                        ci = _classify_value_confidence(fv)
                        pii_conf = get_pii_confidence(field) or ci['confidence']
                        pii_snippet[field] = {
                            'value': fv,
                            'confidence': pii_conf,
                            'is_expression': ci['is_expression'],
                            'reason': ci['reason'],
                        }
                        break

            node_pii_confidence = 'HIGH'
            if pii_snippet:
                confidences = [v['confidence'] for v in pii_snippet.values()]
                if all(c == 'LOW'    for c in confidences): node_pii_confidence = 'LOW'
                elif all(c == 'MEDIUM' for c in confidences): node_pii_confidence = 'MEDIUM'

            operation = str(raw_params.get('operation', '')).strip() or '*'
            resource  = str(raw_params.get('resource', '')).strip() or '*'
            required_fields_def = _get_required_fields_definition(
                short_type=short_type, operation=operation, resource=resource,
                global_reg=global_reg, op_reg=op_reg, functional_fields=_ede.FUNCTIONAL_FIELDS,
            )

            # Full comparison payload — every leaf field actually sent, with
            # is_unnecessary / is_pii flags matched by leaf name or full path.
            full_payload_snippet = {}
            for fk, fv in flat_params.items():
                leaf = fk.rsplit('.', 1)[-1]
                ci = _classify_value_confidence(fv)
                is_unnec = fk in unnecessary_set or leaf in unnecessary_set
                is_pii_f = fk in pii_set or leaf in pii_set
                full_payload_snippet[fk] = {
                    'value': fv,
                    'confidence': ci['confidence'],
                    'is_expression': ci['is_expression'],
                    'is_unnecessary': is_unnec,
                    'is_pii': is_pii_f,
                    'note': (
                        'Not declared required by the platform for this operation; '
                        'review whether transmission is necessary for the stated purpose.'
                    ) if is_unnec else '',
                }

            api_key_fields = _find_api_keys_in_params(raw_params)

            node_results_list.append({
                'node_name':           getattr(n, 'node_name', ''),
                'node_type':           getattr(n, 'node_type', ''),
                'short_name':          short_type,
                'node_scope':          node_scope,
                'status':              getattr(n, 'status', ''),
                'severity':            _severity_from_ratio(ratio),
                'ede_ratio':           ratio,
                'fields_passed':       getattr(n, 'fields_passed', 0),
                'fields_required':     getattr(n, 'fields_required', 0),
                'fields_unnecessary':  getattr(n, 'fields_unnecessary', 0),
                'unnecessary_fields':  unnecessary,
                'pii_unnecessary':     pii_unnec,
                'pii_exposed':         getattr(n, 'pii_exposed', []),
                'pii_via_expression':  pii_via_expr,
                'gdpr_concern':        gdpr_raw == 'YES',
                'position':            position,
                'raw_node_name':       raw_node_data.get('name', ''),
                'ede_snippet':         ede_snippet,
                'pii_snippet':         pii_snippet,
                'api_key_fields':      api_key_fields,
                'node_pii_confidence': node_pii_confidence,
                'required_fields_def': required_fields_def,
                'full_payload_snippet': full_payload_snippet,
            })

        # EDE is GDPR-relevant only for external-transmission nodes (egress + ai).
        # Internal/trigger/unknown nodes are excluded from the headline EDE rate
        # and from the findings list, matching the paper methodology.
        GDPR_SCOPES = ("egress", "ai")

        scoped_nodes = [
            n for n in node_results_list
            if n.get("node_scope") in GDPR_SCOPES
            and n.get("status") == "assessed"
            and int(n.get("fields_required", 0)) > 0
        ]

        if scoped_nodes:
            scoped_avg_ede = round(
                sum(float(n.get("ede_ratio", 0)) for n in scoped_nodes)
                / len(scoped_nodes) * 100, 2
            )
        else:
            scoped_avg_ede = 0.0

        scoped_nodes_with_ede = sum(
            1 for n in scoped_nodes if float(n.get("ede_ratio", 0)) > 0
        )

        # GDPR concern: only count scoped (egress+ai, assessed, req>0) nodes
        # whose own gdpr_concern flag is set. An internal/trigger node's PII
        # is not a data-minimisation transmission concern.
        scoped_gdpr_concerns = sum(
            1 for n in scoped_nodes if n.get("gdpr_concern")
        )

        # Scoped unnecessary PII (only egress+ai nodes)
        scoped_pii_total = sum(
            len(n.get("pii_unnecessary", []) or []) for n in scoped_nodes
        )

        # Risk level derived from the SCOPED average EDE (same thresholds as engine)
        def _risk_from_avg(avg_pct):
            r = avg_pct / 100.0
            if r >= 0.70: return "HIGH"
            if r >= 0.40: return "MEDIUM"
            if r >= 0.20: return "LOW"
            return "MINIMAL"
        scoped_risk_level = _risk_from_avg(scoped_avg_ede)
        # If there are GDPR concerns, risk is at least MEDIUM (data leaving externally)
        if scoped_gdpr_concerns > 0 and scoped_risk_level in ("MINIMAL", "LOW"):
            scoped_risk_level = "MEDIUM"

        return {
            'success':               True,
            'error':                 _raw_err_msg,
            'nodes_total':           result.nodes_total,
            'nodes_assessed':        len(scoped_nodes),
            'nodes_unassessed':      result.nodes_unassessed,
            'avg_ede':               scoped_avg_ede,
            'nodes_with_ede':        scoped_nodes_with_ede,
            'unnecessary_pii_total': scoped_pii_total,        # was result.unnecessary_pii_total
            'gdpr_concerns':         scoped_gdpr_concerns,     # was result.gdpr_concerns
            'gdpr_flag':             scoped_gdpr_concerns > 0, # was result.gdpr_concerns > 0
            'ede_risk_level':        scoped_risk_level,        # was result.risk_level
            'node_results':          node_results_list,
            'gdpr_scopes':           list(GDPR_SCOPES),
        }

    except Exception as e:
        return _empty_error(str(e))


def _empty_error(msg: str) -> dict:
    return {
        'success': False, 'error': msg,
        'nodes_total': 0, 'nodes_assessed': 0, 'nodes_unassessed': 0,
        'avg_ede': 0.0, 'nodes_with_ede': 0, 'unnecessary_pii_total': 0,
        'gdpr_concerns': 0, 'gdpr_flag': False, 'ede_risk_level': 'UNKNOWN',
        'node_results': [],
    }
