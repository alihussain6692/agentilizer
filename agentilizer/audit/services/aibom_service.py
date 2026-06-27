import subprocess
import json
import re
import shutil

_CRED_KEY_FRAGMENTS = {
    'apikey', 'accesstoken', 'secretkey', 'password', 'passwd',
    'token', 'bearer', 'privatekey', 'clientsecret', 'authorization',
}


def _classify_credential_confidence(value: str) -> dict:
    """
    Classify a credential finding confidence.
    Expressions are already excluded before calling this, so all inputs are literals.
    Plain strings that match API key patterns get HIGH confidence.
    """
    val = value.strip()
    looks_like_key = (
        len(val) > 20
        or val.startswith('sk-')
        or val.startswith('Bearer ')
        or val.startswith('ghp_')
        or val.startswith('xoxb-')
        or (any(c.isdigit() for c in val) and any(c.isupper() for c in val))
    )
    if looks_like_key:
        return {
            'confidence': 'HIGH',
            'reason': 'literal value matches API key pattern — likely real credential',
        }
    return {
        'confidence': 'MEDIUM',
        'reason': 'literal value in credential field — review manually to confirm',
    }


def scan_workflow_for_credentials(workflow_file_path: str) -> list:
    """Scan workflow JSON for hardcoded credentials. Always runs, no CLI dependency."""
    findings = []
    for _enc in ('utf-8-sig', 'utf-8', 'latin-1'):
        try:
            with open(workflow_file_path, 'r', encoding=_enc) as f:
                workflow = json.load(f)
            break
        except UnicodeDecodeError:
            continue
        except Exception:
            return findings
    else:
        return findings

    for node in workflow.get('nodes', []):
        node_name = node.get('name') or node.get('type', 'Unknown')
        _scan_params(node.get('parameters', {}), node_name, '', findings)

    return findings


def _scan_params(params, node_name: str, path_prefix: str, findings: list):
    """Recursively walk parameters looking for credential-like key/value pairs."""
    if not isinstance(params, dict):
        return
    for key, value in params.items():
        full_path = f'{path_prefix}.{key}' if path_prefix else key
        key_norm = key.lower().replace('-', '').replace('_', '')
        is_cred_key = any(frag in key_norm for frag in _CRED_KEY_FRAGMENTS)

        if isinstance(value, str) and value:
            # Skip n8n expressions — these are runtime values, not hardcoded secrets
            if value.startswith('{{') or value.startswith('='):
                pass
            elif re.match(r'^sk-[A-Za-z0-9]{20,}$', value):
                preview = value[:6] + '***' + value[-3:]
                ci = _classify_credential_confidence(value)
                findings.append({
                    'node': node_name, 'field': full_path,
                    'preview': preview, 'length': len(value), 'severity': 'CRITICAL',
                    'confidence': ci['confidence'],
                    'confidence_reason': ci['reason'],
                })
            elif is_cred_key and len(value) > 20:
                preview = value[:6] + '***' + value[-3:] if len(value) > 12 else '***'
                ci = _classify_credential_confidence(value)
                findings.append({
                    'node': node_name, 'field': full_path,
                    'preview': preview, 'length': len(value), 'severity': 'HIGH',
                    'confidence': ci['confidence'],
                    'confidence_reason': ci['reason'],
                })
        elif isinstance(value, dict):
            _scan_params(value, node_name, full_path, findings)


def run_aibom_audit(workflow_file_path: str) -> dict:
    # Credential scan always runs, independent of ai-bom CLI
    credential_findings = scan_workflow_for_credentials(workflow_file_path)

    if not shutil.which('ai-bom'):
        return _unavailable('ai-bom CLI not found on PATH.', credential_findings)

    try:
        result = subprocess.run(
            ['ai-bom', 'scan', workflow_file_path, '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=60,
        )

        stdout = result.stdout.strip()
        if not stdout:
            return _unavailable(
                f'ai-bom returned no output. stderr: {result.stderr[:300]}',
                credential_findings,
            )

        data = json.loads(stdout)
        components = data.get('components', [])

        findings = []
        for comp in components:
            props = {}
            for p in comp.get('properties', []):
                props[p.get('name', '')] = p.get('value', '')

            risk_score = float(props.get('trusera:ai-bom:risk-score',
                               props.get('trusera:risk_score', '0')))
            severity = props.get('trusera:ai-bom:severity',
                                 props.get('trusera:severity', 'INFO'))
            description = props.get('trusera:ai-bom:description',
                                    props.get('trusera:description', ''))

            findings.append({
                'name': comp.get('name', ''),
                'type': comp.get('type', ''),
                'severity': severity,
                'risk_score': risk_score,
                'description': description,
                'version': comp.get('version', ''),
            })

        severities = [f['severity'].upper() for f in findings]
        if 'CRITICAL' in severities:
            risk_level = 'CRITICAL'
        elif 'HIGH' in severities:
            risk_level = 'HIGH'
        elif 'MEDIUM' in severities:
            risk_level = 'MEDIUM'
        elif 'LOW' in severities or findings:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'

        return {
            'available': True,
            'success': True,
            'error': '',
            'findings': findings,
            'total_issues': len(findings),
            'risk_level': risk_level,
            'credential_findings': credential_findings,
            'total_credential_issues': len(credential_findings),
        }

    except json.JSONDecodeError as e:
        return _unavailable(f'ai-bom returned invalid JSON: {str(e)}', credential_findings)
    except subprocess.TimeoutExpired:
        return _unavailable('ai-bom timed out after 60 seconds.', credential_findings)
    except Exception as e:
        return _unavailable(str(e), credential_findings)


def _unavailable(reason: str, credential_findings: list = None) -> dict:
    creds = credential_findings or []
    return {
        'available': False,
        'success': False,
        'error': reason,
        'findings': [],
        'total_issues': 0,
        'risk_level': 'UNKNOWN',
        'credential_findings': creds,
        'total_credential_issues': len(creds),
    }
