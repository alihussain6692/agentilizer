"""
tests/test_exposure_core.py — resourceLocator metadata exclusion (v2.1)

cachedResultName/cachedResultUrl/__rl/mode are n8n's UI-cache label/routing
flags attached to every resourceLocator parameter. They must never be counted
as passed/unnecessary fields — only the resolved "value" is transmitted data.

Run: pytest tests/test_exposure_core.py -v
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from exposure_core import extract_leaf_fields, calc_exposure, FUNCTIONAL_FIELDS


class TestResourceLocatorExtraction:
    def test_resource_locator_emits_only_value(self):
        params = {
            "documentId": {
                "__rl": True,
                "mode": "list",
                "value": "abc123",
                "cachedResultName": "Quarterly Report",
            }
        }
        leaves = extract_leaf_fields(params)
        assert "documentId" in leaves
        assert leaves["documentId"] == "abc123"

    def test_resource_locator_metadata_keys_excluded(self):
        params = {
            "documentId": {
                "__rl": True,
                "mode": "list",
                "value": "abc123",
                "cachedResultName": "Quarterly Report",
                "cachedResultUrl": "https://docs.google.com/abc123",
            }
        }
        leaves = extract_leaf_fields(params)
        for bad in ("cachedResultName", "cachedResultUrl", "mode", "__rl",
                    "documentId.cachedResultName", "documentId.cachedResultUrl",
                    "documentId.mode", "documentId.__rl"):
            assert bad not in leaves, f"{bad} should not be emitted as a leaf"

    def test_resource_locator_without_rl_flag_still_detected(self):
        # Older exports may omit __rl; detect by key-subset instead.
        params = {"channelId": {"mode": "id", "value": "C123"}}
        leaves = extract_leaf_fields(params)
        assert leaves == {"channelId": "C123"}

    def test_resource_locator_nested_in_collection_wrapper(self):
        params = {
            "additionalFields": {
                "assigneeId": {
                    "__rl": True, "mode": "list", "value": "u1",
                    "cachedResultName": "Jane Doe",
                }
            }
        }
        leaves = extract_leaf_fields(params)
        assert leaves == {"additionalFields.assigneeId": "u1"}

    def test_calc_exposure_excludes_resource_locator_metadata(self):
        params = {
            "documentId": {
                "__rl": True, "mode": "list", "value": "abc123",
                "cachedResultName": "Quarterly Report",
                "cachedResultUrl": "https://docs.google.com/abc123",
            },
            "sheetName": {"__rl": True, "mode": "id", "value": "Sheet1"},
        }
        exp = calc_exposure(params, required_fields={"documentId"}, all_pii_fields=set())
        assert exp["fields_passed"] == 2
        assert exp["unnecessary_field_names"] == ["sheetName"]
        for bad in ("cachedResultName", "cachedResultUrl", "mode", "__rl"):
            assert bad not in exp["unnecessary_field_names"]

    def test_functional_fields_contains_resource_locator_metadata(self):
        for key in ("__rl", "mode", "cachedResultName", "cachedResultUrl"):
            assert key in FUNCTIONAL_FIELDS
