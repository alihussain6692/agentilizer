import json
from django import template

register = template.Library()


@register.filter
def pretty_json(value):
    """Render a dict or list as indented JSON for display in a <pre> block."""
    if not value:
        return '{}'
    try:
        return json.dumps(value, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


@register.filter
def severity_colour(severity: str) -> str:
    """Return a CSS hex colour for a severity string."""
    mapping = {
        'critical': '#FF0040',
        'high':     '#FF0040',
        'medium':   '#FFD700',
        'low':      '#00FF41',
        'minimal':  '#004A10',
        'info':     '#888888',
    }
    return mapping.get(str(severity).lower(), '#888888')


@register.filter
def confidence_colour(confidence) -> str:
    """Return a CSS hex colour for a confidence level string."""
    colours = {
        'HIGH':   '#FF0040',
        'MEDIUM': '#FFD700',
        'LOW':    '#666666',
    }
    return colours.get(str(confidence).upper(), '#666666')


@register.filter
def confidence_icon(confidence) -> str:
    """Return a text icon for a confidence level string."""
    icons = {
        'HIGH':   '⚠⚠',
        'MEDIUM': '⚠',
        'LOW':    '○',
    }
    return icons.get(str(confidence).upper(), '○')


@register.filter
def pretty_json_enriched(value):
    """
    Format enriched snippet dict for display.
    Shows field name, value, confidence label, and reason as a readable block.
    """
    if not isinstance(value, dict):
        return str(value)
    lines = []
    for field_name, field_data in value.items():
        if isinstance(field_data, dict):
            confidence = field_data.get('confidence', 'UNKNOWN')
            reason = field_data.get('reason', '')
            raw_value = field_data.get('value', '')
            lines.append(f'"{field_name}": {json.dumps(raw_value, ensure_ascii=False)}')
            lines.append(f'  // confidence: {confidence} — {reason}')
        else:
            lines.append(f'"{field_name}": {json.dumps(field_data, ensure_ascii=False)}')
    return '\n'.join(lines)


@register.filter
def is_unnecessary(field_data):
    """Returns True if this field is in the unnecessary set."""
    if isinstance(field_data, dict):
        return field_data.get('is_unnecessary', False)
    return False


@register.filter
def is_pii_field(field_data):
    """Returns True if this field is in the PII unnecessary set."""
    if isinstance(field_data, dict):
        return field_data.get('is_pii', False)
    return False


@register.filter
def field_colour(field_data):
    """Returns a CSS colour based on whether the field is PII, unnecessary, or required."""
    if not isinstance(field_data, dict):
        return '#E0E0E0'
    if field_data.get('is_pii'):
        return '#FF0040'
    if field_data.get('is_unnecessary'):
        return '#FFD700'
    return '#00FF41'
