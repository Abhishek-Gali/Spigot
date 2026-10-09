"""P1 Contract Tests: OpenAPI 3.0 Normalizer (T07) and Semantic Readiness Validator (T08)."""

from __future__ import annotations

import json
from pathlib import Path

from packages.core.contracts import ApiContract
from packages.core.openapi_normalizer import normalize_openapi_document
from packages.core.readiness import (
    check_contract_freeze_readiness,
    validate_contract_readiness,
)

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
OPENAPI_FIXTURE = ROOT_DIR / "fixtures" / "p1_openapi_inventory" / "inventory_openapi_3_0.yaml"
EXPECTED_JSON = ROOT_DIR / "fixtures" / "p1_openapi_inventory" / "expected_normalized.json"


def test_t07_openapi_fixture_roundtrip_auth_params_and_cycles() -> None:
    raw_yaml = OPENAPI_FIXTURE.read_text(encoding="utf-8")
    expected = json.loads(EXPECTED_JSON.read_text(encoding="utf-8"))

    contract, blocks, evidence = normalize_openapi_document(
        raw_yaml,
        project_id="proj_inv",
        source_id="src_inv_yaml",
        contract_id="cnt_inv",
    )
    validated = validate_contract_readiness(contract)

    # Round-trip JSON check preserves semantics and canonical hash
    round_tripped = ApiContract.model_validate_json(validated.model_dump_json(by_alias=True))
    assert round_tripped.canonical_hash == validated.canonical_hash
    assert validated.servers[0].base_url == expected["expected_server_url"]

    # Verify all evidence references resolve against DocumentBlock
    assert len(blocks) == 1
    for ev in evidence:
        assert ev.verify_against_block(blocks[0]) is True

    ops_by_id = {op.stable_id: op for op in validated.operations}

    # 1. Check inventory_get_item: duplicate 'id' in path and query + OR-of-ANDs auth
    get_item = ops_by_id["inventory_get_item"]
    assert get_item.support_status == "supported"
    param_summary = [
        {
            "external_name": p.external_name,
            "location": p.location,
            "safe_argument_name": p.safe_argument_name,
            "required": p.required,
        }
        for p in get_item.parameters
    ]
    expected_GetItem = expected["expected_supported_operations"][0]
    assert param_summary == expected_GetItem["parameter_locations_and_safe_names"]
    assert get_item.security_requirement.model_dump() == expected_GetItem["security_requirement"]

    # 2. Check inventory_health_check: explicit public security `[{}]`
    health_op = ops_by_id["inventory_health_check"]
    assert health_op.support_status == "supported"
    assert health_op.security_requirement.status == "public"
    assert health_op.security_requirement.alternatives == []

    # 3. Check inventory_get_category_tree: circular $ref terminates with REF_CYCLE_DETECTED
    cycle_op = ops_by_id["inventory_get_category_tree"]
    assert cycle_op.support_status == "blocked"
    cycle_codes = {
        f.code for f in validated.findings if f.operation_id == "inventory_get_category_tree"
    }
    assert "REF_CYCLE_DETECTED" in cycle_codes

    # 4. Check inventory_upload_csv: cookie auth + multipart/form-data blocked
    upload_op = ops_by_id["inventory_upload_csv"]
    assert upload_op.support_status == "blocked"
    upload_codes = {f.code for f in validated.findings if f.operation_id == "inventory_upload_csv"}
    assert "UNSUPPORTED_MEDIA_TYPE" in upload_codes
    assert "UNSUPPORTED_SECURITY_SCHEME" in upload_codes

    # 5. Readiness check: freezing all operations fails because 2 are blocked;
    # freezing only the 2 supported operations succeeds!
    all_ready, all_blockers = check_contract_freeze_readiness(validated)
    assert all_ready is False
    assert len(all_blockers) >= 3

    subset_ready, subset_blockers = check_contract_freeze_readiness(
        validated,
        selected_operation_ids=["inventory_get_item", "inventory_health_check"],
    )
    assert subset_ready is True
    assert subset_blockers == []


def test_t07_t08_unknown_auth_openapi_3_1_remote_refs_and_path_mismatches() -> None:
    # 1. OpenAPI 3.1 must be detected and blocked (not silently parsed as 3.0)
    spec_3_1 = """
openapi: 3.1.0
info:
  title: Future 3.1 Spec
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /ping:
    get:
      operationId: ping_op
      security:
        - {}
      responses:
        "200":
          description: ok
"""
    c_31, _, _ = normalize_openapi_document(spec_3_1, project_id="p_31")
    v_31 = validate_contract_readiness(c_31)
    codes_31 = {f.code for f in v_31.findings}
    assert "OPENAPI_3_1_EXTENSION_REQUIRED" in codes_31
    assert v_31.operations[0].support_status == "blocked"

    # 2. Omitted auth (unknown), unmatched path placeholder, remote $ref, and allOf composition
    spec_negatives = """
openapi: 3.0.3
info:
  title: Negative Cases API
  version: 1.0.0
servers:
  - url: https://api.example.com/v1
paths:
  /orders/{order_id}:
    get:
      operationId: get_order_missing_param_and_auth
      responses:
        "200":
          description: ok
  /remotes:
    post:
      operationId: create_remote_ref
      security:
        - {}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: "https://external.example.com/schemas/Order.json"
      responses:
        "200":
          description: ok
  /composed:
    post:
      operationId: create_composed
      security:
        - {}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              oneOf:
                - type: object
                - type: string
      responses:
        "200":
          description: ok
"""
    c_neg, _, _ = normalize_openapi_document(spec_negatives, project_id="p_neg")
    v_neg = validate_contract_readiness(c_neg)
    by_op = {op.stable_id: op for op in v_neg.operations}

    assert by_op["get_order_missing_param_and_auth"].support_status == "blocked"
    order_codes = {
        f.code for f in v_neg.findings if f.operation_id == "get_order_missing_param_and_auth"
    }
    assert "UNKNOWN_AUTH" in order_codes
    assert "UNMATCHED_PATH_PLACEHOLDER" in order_codes

    assert by_op["create_remote_ref"].support_status == "blocked"
    remote_codes = {f.code for f in v_neg.findings if f.operation_id == "create_remote_ref"}
    assert "REMOTE_REF_DISABLED" in remote_codes

    assert by_op["create_composed"].support_status == "blocked"
    comp_codes = {f.code for f in v_neg.findings if f.operation_id == "create_composed"}
    assert "UNSUPPORTED_SCHEMA_COMPOSITION" in comp_codes
