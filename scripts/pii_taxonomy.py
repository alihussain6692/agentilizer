"""
pii_taxonomy.py — Strict-absolute PII field-name detection (v3)

Single source of truth for PII classification. Used by:
  phase1_registry_builder.py, phase3_exposure_calculator.py,
  ede_audit_tool.py, exposure_core.py, Django ede_service.py

DESIGN — STRICT-ABSOLUTE (v3)
-----------------------------
A field is PII only when its name alone proves the value is personal data
about an identifiable natural person. Anything whose personal-data status
is context-dependent (technical identifiers, geo labels, pseudonymous IDs,
entity-level names, configuration enums) is deliberately EXCLUDED, so that
every reported PII finding is defensible without appeal to context.

This is a conservative, precision-first definition. Fields excluded here may
still be personal data under GDPR in context (e.g. IP address, session ID,
country); they are excluded from the headline count and discussed separately.

Detection is built around ONE coherent rule (no bolted-on filters):

  1. Tokenize the field name (camelCase / separators -> whole lowercase tokens).
  2. A leaf "structural metadata" denylist short-circuits to NOT-PII.
  3. Try multi-token PII SEQUENCES (longest first).
  4. Try the collapsed (no-separator) single form.
  5. Try each individual token against the strict-absolute KEEP set.
  At every head-token match, two uniform guards apply identically:
     (a) PRECEDING-qualifier guard: a non-personal qualifier immediately
         before the head token (fileName, sheetId) -> NOT PII.
     (b) TRAILING config-suffix guard: a config-enum token immediately
         after the head token (emailType, countryCode, sessionIdType) -> NOT PII.
  Because both guards are applied at the single point of matching, variants
  like `sessionId` and `sessionIdType` cannot contradict each other.

API
---
  detect_pii(field_name)  -> PiiMatch(is_pii, category, confidence, matched)
  is_pii(field_name)      -> bool
  pii_category(field_name)-> str
  pii_confidence(field_name)-> str
  tokenize(field_name)    -> list[str]
  PII_CATEGORIES          -> dict for legacy category listing
"""

from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class PiiMatch:
    is_pii: bool
    category: str        # '' when not PII
    confidence: str      # 'high' | 'medium' | '' when not PII
    matched: tuple       # token(s) that triggered the match


# ─────────────────────────────────────────────────────────────────────────────
# GUARD TOKEN SETS
# ─────────────────────────────────────────────────────────────────────────────

# Non-personal qualifiers: when one of these IMMEDIATELY PRECEDES an ambiguous
# head token (name / id-style), the compound is not personal data.
#   fileName, sheetId, workflowName, channelId, ...
NON_PII_QUALIFIERS: frozenset[str] = frozenset({
    # File / storage artefacts
    "file", "sheet", "table", "folder", "bucket", "blob", "document", "doc",
    # Organisational structures (non-person)
    "channel", "board", "list", "card", "group", "tag", "label", "team",
    # Workflow / automation engine concepts
    "workflow", "node", "trigger", "hook", "action", "step", "flow",
    "pipeline", "job", "queue", "event", "task", "goal", "ticket", "agent",
    # Platform / app-level concepts
    "app", "bot", "tool", "function", "plugin", "module", "service",
    "model", "schema", "template", "project", "repo", "branch", "language",
    # Infrastructure / network (non-person)
    "domain", "host", "server", "endpoint", "url", "path", "route",
    "database", "collection", "index", "cluster", "instance", "contract",
    # Data-structure concepts
    "property", "field", "column", "attribute", "variable", "key",
    "option", "setting", "config", "param", "scope", "rule", "selector",
    "class", "category", "container", "component", "widget",
    # Calendar / scheduling
    "calendar",
    # Pagination / display / media
    "page", "item", "element", "object", "resource", "icon", "image", "media",
    # Misc routing
    "output", "input", "source", "target", "filter", "sort",
    "map", "set", "binary", "operation",
    # Technical-identifier prefixes: "ip address" / "mac address" are network
    # identifiers, not a person's physical address. Suppress the address head.
    "ip", "mac",
})

# Config-enum suffixes: when one of these IMMEDIATELY FOLLOWS a head token,
# the field is a configuration selector, not personal data.
#   emailType, emailFormat, countryCode, sessionIdType, paymentMethod, ...
CONFIG_SUFFIXES: frozenset[str] = frozenset({
    "type", "format", "mode", "status", "method", "style", "kind",
    "code", "enabled", "flag", "count", "option", "setting", "config",
    "id",   # head+id => identifier-of-a-thing, not the personal value itself
})

# Structural metadata fields (n8n resourceLocator artefacts) — exact leaf match.
STRUCTURAL_METADATA_FIELDS: frozenset[str] = frozenset({
    "cachedresultname", "cachedresulturl", "__rl", "mode",
})


# ─────────────────────────────────────────────────────────────────────────────
# STRICT-ABSOLUTE KEEP SETS
# Only fields whose name alone proves personal data about a natural person.
# ─────────────────────────────────────────────────────────────────────────────

# Multi-token sequences (checked first, longest first). Each: (tokens, cat, conf)
_SEQUENCES: list[tuple[tuple[str, ...], str, str]] = [
    # Identity — names of people
    (("first", "name"),       "identity",  "high"),
    (("last", "name"),        "identity",  "high"),
    (("full", "name"),        "identity",  "high"),
    (("given", "name"),       "identity",  "high"),
    (("family", "name"),      "identity",  "high"),
    (("display", "name"),     "identity",  "high"),
    (("user", "name"),        "identity",  "high"),
    (("real", "name"),        "identity",  "high"),
    (("middle", "name"),      "identity",  "high"),
    (("maiden", "name"),      "identity",  "high"),
    # Identity — name preceded by a person-qualifier (still a person's name)
    (("recipient", "name"),   "identity",  "medium"),
    (("sender", "name"),      "identity",  "medium"),
    (("assignee", "name"),    "identity",  "high"),
    (("contact", "name"),     "identity",  "medium"),
    (("customer", "name"),    "identity",  "medium"),
    # Contact — personal contact endpoints
    (("recipient", "email"),  "contact",   "high"),
    (("sender", "email"),     "contact",   "high"),
    (("contact", "email"),    "contact",   "high"),
    (("from", "email"),       "contact",   "high"),
    (("to", "email"),         "contact",   "high"),
    (("email", "address"),    "contact",   "high"),
    (("phone", "number"),     "contact",   "high"),
    (("mobile", "number"),    "contact",   "high"),
    # Sensitive — special category (GDPR Art. 9)
    (("date", "of", "birth"), "sensitive", "high"),
    (("date", "birth"),       "sensitive", "high"),
    # Address — physical residence (a place tied to a person)
    (("street", "address"),   "location",  "high"),
    (("home", "address"),     "location",  "high"),
    (("postal", "code"),      "location",  "high"),   # in address context
    (("zip", "code"),         "location",  "high"),   # in address context
    # Government / legal — identify a specific person
    (("social", "security"),  "government","high"),
    (("national", "insurance"),"government","high"),
    (("driving", "license"),  "government","high"),
    (("driving", "licence"),  "government","high"),
    (("national", "id"),      "government","high"),
    (("tax", "id"),           "government","high"),
    (("tax", "number"),       "government","high"),
    (("passport", "number"),  "government","high"),
    # Financial — personal account / card data
    (("credit", "card"),      "financial", "high"),
    (("bank", "account"),     "financial", "high"),
    (("account", "number"),   "financial", "medium"),
    (("card", "number"),      "financial", "high"),
    (("routing", "number"),   "financial", "high"),
    # Professional — names / identifies a specific person
    (("job", "title"),        "professional","high"),
    (("employee", "id"),      "professional","high"),
]
_SEQUENCES.sort(key=lambda x: len(x[0]), reverse=True)

# Single tokens (collapsed-form and per-token). Strict-absolute KEEP only.
_SINGLE: dict[str, tuple[str, str]] = {
    # ── identity (names of people) ──────────────────────────────────────────
    "firstname":    ("identity", "high"),
    "lastname":     ("identity", "high"),
    "fullname":     ("identity", "high"),
    "displayname":  ("identity", "high"),
    "username":     ("identity", "high"),
    "givenname":    ("identity", "high"),
    "familyname":   ("identity", "high"),
    "realname":     ("identity", "high"),
    "middlename":   ("identity", "high"),
    "maidenname":   ("identity", "high"),
    "name":         ("identity", "medium"),   # qualifier-guarded

    # ── contact (personal contact values) ───────────────────────────────────
    "email":        ("contact",  "high"),
    "phone":        ("contact",  "high"),
    "mobile":       ("contact",  "high"),
    "telephone":    ("contact",  "high"),
    "fax":          ("contact",  "medium"),
    "emailaddress": ("contact",  "high"),
    "phonenumber":  ("contact",  "high"),
    "recipientemail":("contact", "high"),

    # ── sensitive (special category, GDPR Art. 9) ───────────────────────────
    "dateofbirth":  ("sensitive","high"),
    "dob":          ("sensitive","high"),
    "birthdate":    ("sensitive","high"),
    "birthday":     ("sensitive","high"),
    "age":          ("sensitive","medium"),   # qualifier-guarded
    "gender":       ("sensitive","medium"),
    "sex":          ("sensitive","medium"),
    "nationality":  ("sensitive","medium"),
    "ethnicity":    ("sensitive","high"),
    "race":         ("sensitive","high"),
    "religion":     ("sensitive","high"),

    # ── health (special category) ───────────────────────────────────────────
    "diagnosis":    ("health",   "high"),
    "prescription": ("health",   "high"),
    "patient":      ("health",   "medium"),
    "health":       ("health",   "medium"),
    "medical":      ("health",   "medium"),

    # ── government / legal IDs ──────────────────────────────────────────────
    "ssn":          ("government","high"),
    "nationalinsurance":("government","high"),
    "nin":          ("government","high"),
    "passport":     ("government","high"),
    "passportnumber":("government","high"),
    "drivinglicense":("government","high"),
    "drivinglicence":("government","high"),
    "nationalid":   ("government","high"),
    "socialsecurity":("government","high"),
    "taxid":        ("government","high"),

    # ── financial (personal account / card) ─────────────────────────────────
    "iban":         ("financial","high"),
    "creditcard":   ("financial","high"),
    "bankaccount":  ("financial","high"),
    "accountnumber":("financial","high"),
    "cardnumber":   ("financial","high"),
    "salary":       ("financial","high"),
    "income":       ("financial","high"),

    # ── precise geolocation (pinpoints a person) ────────────────────────────
    "latitude":     ("location", "high"),
    "longitude":    ("location", "high"),
    "coordinates":  ("location", "medium"),
    "lat":          ("location", "medium"),   # qualifier-guarded
    "lng":          ("location", "medium"),

    # ── address (physical residence) ────────────────────────────────────────
    "address":      ("location", "medium"),   # qualifier-guarded
    "street":       ("location", "high"),

    # ── professional (identifies a specific person) ─────────────────────────
    "assignee":     ("professional","high"),
    "employeeid":   ("professional","high"),
    "jobtitle":     ("professional","high"),
}

# Tokens whose PII status is ambiguous: only PII when NOT immediately preceded
# by a non-personal qualifier. (Applied uniformly to sequences and singles.)
_QUALIFIER_GUARDED: frozenset[str] = frozenset({
    "name", "address", "location", "age", "lat", "street",
})


# ─────────────────────────────────────────────────────────────────────────────
# TOKENIZER
# ─────────────────────────────────────────────────────────────────────────────

def tokenize(field_name: str) -> list[str]:
    """
    Split a field name (possibly dotted) into lowercase alpha tokens.
      'firstName'  -> ['first','name']
      'ip_address' -> ['ip','address']
      'emailType'  -> ['email','type']
      'sessionId'  -> ['session','id']
    """
    name = field_name.rsplit(".", 1)[-1] if "." in field_name else field_name
    s = re.sub(r"([a-z\d])([A-Z])", r"\1 \2", name)
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", s)
    return [t.lower() for t in re.split(r"[^a-zA-Z]+", s) if t]


# ─────────────────────────────────────────────────────────────────────────────
# CORE DETECTION — one coherent rule, two uniform guards
# ─────────────────────────────────────────────────────────────────────────────

def _preceded_by_qualifier(tokens: list[str], start: int) -> bool:
    """True if the token before `start` is a non-personal qualifier."""
    return start > 0 and tokens[start - 1] in NON_PII_QUALIFIERS


def _followed_by_config_suffix(tokens: list[str], end: int) -> bool:
    """True if the token after position `end` (inclusive last index) is a config suffix."""
    nxt = end + 1
    return nxt < len(tokens) and tokens[nxt] in CONFIG_SUFFIXES


def detect_pii(field_name: str) -> PiiMatch:
    """Strict-absolute PII detection. Single source of truth."""
    tokens = tokenize(field_name)
    if not tokens:
        return PiiMatch(False, "", "", ())

    leaf = field_name.rsplit(".", 1)[-1] if "." in field_name else field_name
    if leaf.lower() in STRUCTURAL_METADATA_FIELDS:
        return PiiMatch(False, "", "", ())

    n = len(tokens)

    # ── Step 0: identifier-of-a-thing rule ──────────────────────────────────
    # A field whose token stream ENDS in 'id' (phoneNumberId, sessionId,
    # userId, customerId, deviceId) is an identifier/foreign-key, not the
    # personal value itself. Under strict-absolute these are excluded as
    # pseudonymous/indirect. Single-token 'id' alone is also not PII.
    # Collapsed canonical PII forms (e.g. 'employeeid') are handled in Step 2
    # and are intentionally allowed there.
    if tokens[-1] == "id" and "".join(tokens) not in _SINGLE:
        return PiiMatch(False, "", "", ())

    # ── Step 1: multi-token sequences (longest first) ───────────────────────
    for seq, category, confidence in _SEQUENCES:
        slen = len(seq)
        for start in range(n - slen + 1):
            if tuple(tokens[start:start + slen]) == seq:
                end = start + slen - 1
                # Guard (a): preceding qualifier on an ambiguous head
                if seq[0] in _QUALIFIER_GUARDED and _preceded_by_qualifier(tokens, start):
                    continue
                # Guard (b): trailing config suffix (emailAddress+type, etc.)
                if _followed_by_config_suffix(tokens, end):
                    continue
                return PiiMatch(True, category, confidence, seq)

    # ── Step 2: collapsed single form (sessionid, dateofbirth, firstname) ────
    joined = "".join(tokens)
    if joined in _SINGLE:
        category, confidence = _SINGLE[joined]
        return PiiMatch(True, category, confidence, (joined,))

    # ── Step 3: per-token scan ──────────────────────────────────────────────
    for i, tok in enumerate(tokens):
        if tok not in _SINGLE:
            continue
        category, confidence = _SINGLE[tok]
        # Guard (a): preceding qualifier on an ambiguous head
        if tok in _QUALIFIER_GUARDED and _preceded_by_qualifier(tokens, i):
            continue
        # Guard (b): trailing config suffix (emailType, sessionId->id, etc.)
        if _followed_by_config_suffix(tokens, i):
            continue
        return PiiMatch(True, category, confidence, (tok,))

    return PiiMatch(False, "", "", ())


# ─────────────────────────────────────────────────────────────────────────────
# LEGACY COMPATIBILITY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

PII_CATEGORIES: dict[str, list[str]] = {
    "identity":     ["name", "firstname", "lastname", "fullname", "username",
                     "displayname", "givenname", "familyname"],
    "contact":      ["email", "phone", "mobile", "telephone", "fax"],
    "location":     ["address", "street", "latitude", "longitude",
                     "coordinates"],
    "sensitive":    ["dateofbirth", "dob", "age", "gender", "nationality",
                     "ethnicity", "race", "religion"],
    "financial":    ["accountnumber", "bankaccount", "creditcard", "iban",
                     "salary", "income", "cardnumber"],
    "government":   ["nationalinsurance", "nin", "ssn", "passport",
                     "drivinglicense", "nationalid", "socialsecurity", "taxid"],
    "health":       ["health", "medical", "diagnosis", "prescription", "patient"],
    "professional": ["employeeid", "jobtitle", "assignee"],
}


def is_pii(field_name: str) -> bool:
    return detect_pii(field_name).is_pii


def pii_category(field_name: str) -> str:
    return detect_pii(field_name).category


def pii_confidence(field_name: str) -> str:
    return detect_pii(field_name).confidence