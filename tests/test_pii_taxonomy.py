"""
test_pii_taxonomy_strict.py — Tests for the strict-absolute PII taxonomy (v3)

These tests encode the STRICT-ABSOLUTE methodology decision (v3.3):
only fields whose name alone proves personal data about an identifiable
natural person are PII. Context-dependent identifiers (session/IP/device),
geo labels (country/city/state), pseudonymous IDs (userId/customerId),
entity-level names (company/department), and config enums (*Type/*Format)
are deliberately EXCLUDED.

Run:  python -m pytest test_pii_taxonomy_strict.py -q
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pii_taxonomy import detect_pii, is_pii, pii_category, pii_confidence, tokenize


# ── Genuine PII — must be detected ──────────────────────────────────────────
def test_core_contact():
    assert is_pii("email")
    assert is_pii("phone")
    assert is_pii("emailAddress")
    assert is_pii("phoneNumber")
    assert pii_category("email") == "contact"

def test_names():
    for f in ("firstName", "lastName", "fullName", "givenName",
              "familyName", "displayName", "username", "middleName"):
        assert is_pii(f), f
        assert pii_category(f) == "identity"

def test_contact_sequences():
    assert is_pii("recipientEmail")
    assert is_pii("toEmail")
    assert is_pii("fromEmail")
    assert pii_category("toEmail") == "contact"

def test_sensitive_special_category():
    for f in ("dateOfBirth", "dob", "gender", "ethnicity", "race", "religion"):
        assert is_pii(f), f
        assert pii_category(f) == "sensitive"

def test_health_special_category():
    for f in ("diagnosis", "prescription", "patient", "medical"):
        assert is_pii(f), f
        assert pii_category(f) == "health"

def test_government_ids():
    for f in ("ssn", "passport", "passportNumber", "nationalId",
              "taxId", "socialSecurity", "drivingLicense"):
        assert is_pii(f), f
        assert pii_category(f) == "government"

def test_financial():
    for f in ("iban", "creditCard", "bankAccount", "accountNumber",
              "cardNumber", "salary"):
        assert is_pii(f), f
        assert pii_category(f) == "financial"

def test_precise_geolocation():
    assert is_pii("latitude")
    assert is_pii("longitude")
    assert pii_category("latitude") == "location"

def test_address_sequences():
    assert is_pii("streetAddress")
    assert is_pii("homeAddress")
    assert is_pii("zipCode")        # zip+code = address context -> KEEP
    assert is_pii("postalCode")     # postal+code = address context -> KEEP

def test_professional_person():
    assert is_pii("jobTitle")
    assert is_pii("employeeId")     # collapsed canonical form -> KEEP
    assert is_pii("assignee")
    assert pii_category("jobTitle") == "professional"


# ── Config enums — must NOT be PII (the emailType-class bug) ─────────────────
def test_config_suffix_not_pii():
    for f in ("emailType", "emailFormat", "email_status", "phoneType",
              "emailMode", "paymentMethod"):
        assert not is_pii(f), f

def test_emailType_specifically():
    # Regression: emailType was 906 false positives in v3.2
    assert not is_pii("emailType")
    assert not is_pii("emailFormat")


# ── Technical identifiers — NOT PII under strict-absolute ───────────────────
def test_technical_identifiers_excluded():
    for f in ("sessionId", "deviceId", "cookieId", "ipAddress", "ip",
              "userAgent", "macAddress", "fingerprint"):
        assert not is_pii(f), f

def test_sessionId_and_variant_consistent():
    # The v3.2 contradiction: sessionId NOT-PII but sessionIdType IS-PII.
    # Strict-absolute: BOTH are NOT-PII. No contradiction possible.
    assert not is_pii("sessionId")
    assert not is_pii("sessionIdType")

def test_phoneNumberId_is_identifier_not_pii():
    # Foreign key referencing a phone-number resource, not the number itself.
    assert not is_pii("phoneNumberId")


# ── Pseudonymous indirect identifiers — NOT PII under strict-absolute ───────
def test_pseudonymous_ids_excluded():
    assert not is_pii("userId")
    assert not is_pii("customerId")
    assert not is_pii("organizationId")


# ── Geo labels — NOT PII alone under strict-absolute ────────────────────────
def test_geo_labels_excluded():
    for f in ("country", "countryCode", "city", "state", "region",
              "regionCode", "zip", "postcode"):
        assert not is_pii(f), f


# ── Entity-level names — NOT PII (about an org, not a person) ────────────────
def test_entity_level_excluded():
    for f in ("company", "organization", "organisation", "department"):
        assert not is_pii(f), f


# ── Qualifier-guarded compounds — NOT PII ───────────────────────────────────
def test_preceding_qualifier_blocks_name():
    for f in ("fileName", "workflowName", "documentName", "ticketName",
              "taskName", "templateName", "channelName"):
        assert not is_pii(f), f

def test_qualifier_blocks_id_style():
    for f in ("sheetId", "channelId", "fileId", "folderId"):
        assert not is_pii(f), f


# ── Generic config / ambiguous — NOT PII ────────────────────────────────────
def test_generic_not_pii():
    for f in ("payment", "billing", "recipient", "location", "mode",
              "status", "type", "format"):
        assert not is_pii(f), f


# ── Tokenizer sanity ────────────────────────────────────────────────────────
def test_tokenizer():
    assert tokenize("firstName") == ["first", "name"]
    assert tokenize("ip_address") == ["ip", "address"]
    assert tokenize("emailType") == ["email", "type"]
    assert tokenize("sessionId") == ["session", "id"]
    assert tokenize("additionalFields.dateOfBirth") == ["date", "of", "birth"]


# ── Confidence levels ───────────────────────────────────────────────────────
def test_confidence_levels():
    assert pii_confidence("email") == "high"
    assert pii_confidence("firstName") == "high"
    assert pii_confidence("gender") == "medium"
    assert pii_confidence("emailType") == ""   # not PII