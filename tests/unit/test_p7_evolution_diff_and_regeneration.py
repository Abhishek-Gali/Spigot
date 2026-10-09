"""Phase P7 Tests — Semantic Contract Diff, Affected Tools, and Safe Regeneration (T30 & T31).

Verifies:
1. T30 — Semantic Contract Diff & Affected-Tool Mapping:
   - Formatting and description-only document edits produce `semantically_identical == True`
     and `has_breaking_changes == False` without false breakage.
   - Newly added required parameter (`required_parameter_added`) and removed path
     (`operation_removed`) flag impacted tools and emit executable regression cases.
   - Breaking changes on a prerequisite lookup operation transitively flag dependent tools
     via `ToolPlan.dependency_edges`.
   - Ambiguous endpoint renames (`GET /orders/{order_id}` -> `GET /v2/orders/{order_id}`)
     emit `operation_renamed_ambiguous` (`severity="review_required"`, `requires_review=True`).
2. T31 — Safe Regeneration, Override Carry-Forward, Stale Policy/Approval Invalidation, & Reproducibility:
   - Valid `UserOverride` records whose underlying raw field hash is unchanged in the new
     document revision are automatically carried forward (`carried_forward_overrides`).
   - Stale overrides whose target operation or raw extracted field changed in the new
     revision are rejected (`invalidated_overrides`) and emit `STALE_OVERRIDE` blockers.
   - Frozen tool names from `old_tool_plan` are preserved across regeneration even when
     display names or descriptions change.
   - Approved actions (`ApprovalAuthority` tokens) are cryptographically invalidated when
     contract or policy hashes change (`APPROVAL_CONTRACT_MISMATCH` / `APPROVAL_POLICY_MISMATCH`).
   - Frozen contract regeneration reproduces identical code artifact and ZIP SHA-256 hashes.
   - Local API `/compare` and `/regenerate` endpoints work end-to-end and preserve
     `previous_good_artifact`.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from apps.api.client import SpigotApiClient
from apps.api.server import LocalApiConfig, create_local_app
from packages.core.approval import ApprovalAuthority
from packages.core.contracts import UserOverride
from packages.core.evolution import (
    compare_contracts,
    reconcile_and_regenerate,
    verify_reproducible_regeneration,
)
from packages.core.extraction import extract_document_candidates
from packages.core.parsers import parse_document_bytes
from packages.core.pipeline import RawDocumentInput, compile_documentation_bundle
from packages.core.planning import RuntimePolicy, create_tool_plan
from packages.core.reconciliation import (
    compute_field_value_hash,
    reconcile_bundles_to_contract,
)


def _extract_bundle(source_id: str, filename: str, raw_bytes: bytes, project_id: str = "proj_p7"):
    doc, blocks, fnds = parse_document_bytes(
        source_id, filename, raw_bytes, project_id=project_id
    )
    bundle = extract_document_candidates(doc, blocks, use_local_model=False)
    if fnds:
        bundle.findings.extend(fnds)
    return bundle


def test_t30_semantic_diff_required_param_removed_path_format_only_and_ambiguous_rename() -> None:
    base_url = "http://127.0.0.1:18080"
    policy = RuntimePolicy(
        id="pol_orders_v1",
        mode="restricted_write",
        allowed_write_operations=["post_orders"],
        network_profile="STRICT_OFFLINE",
    )

    orders_v1_md = (
        f"# Commerce Orders API v1\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
        "## List Orders\n\n`GET /orders`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `customer_id` | query | string | no | Filter by customer |\n\n"
        "## Get Order\n\n`GET /orders/{order_id}`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `order_id` | path | string | yes | Order identifier |\n\n"
        "## Create Order\n\n`POST /orders`\n\n"
        "| Field | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `sku` | body | string | yes | Product SKU |\n"
    ).encode()

    comp_v1 = compile_documentation_bundle(
        [RawDocumentInput(source_id="src_v1", filename="orders_v1.md", raw_bytes=orders_v1_md)],
        contract_id="ct_orders",
        project_id="proj_orders",
        policy=policy,
        use_local_model=False,
    )
    contract_v1 = comp_v1.contract
    plan_v1 = create_tool_plan(
        contract_v1,
        policy,
        plan_id="plan_orders_v1",
        preserve_dependencies=True,
    )

    # 1. Format-only / prose-description edit -> no false breakage
    orders_v1_reformatted = (
        f"# Commerce Orders Manual (Reformatted Edition)\n\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
        "## List All Customer Orders\n\n`GET /orders`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        "| `customer_id` | query | string | no | Updated prose description for customer filter |\n\n"
        "## Retrieve Single Order Record\n\n`GET /orders/{order_id}`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        "| `order_id` | path | string | yes | Updated prose description for order ID |\n\n"
        "## Create New Order\n\n`POST /orders`\n\n"
        "| Field | Location | Type | Required | Description |\n"
        "| :--- | :--- | :--- | :--- | :--- |\n"
        "| `sku` | body | string | yes | Updated SKU field note |\n"
    ).encode()

    comp_v1_fmt = compile_documentation_bundle(
        [RawDocumentInput(source_id="src_v1_fmt", filename="orders_v1_fmt.md", raw_bytes=orders_v1_reformatted)],
        contract_id="ct_orders",
        project_id="proj_orders",
        policy=policy,
        use_local_model=False,
    )
    diff_fmt = compare_contracts(
        contract_v1,
        comp_v1_fmt.contract,
        old_tool_plan=plan_v1,
    )
    assert diff_fmt.semantically_identical is True
    assert diff_fmt.has_breaking_changes is False
    assert diff_fmt.requires_review is False
    assert diff_fmt.affected_tool_names == []
    assert all(c.severity == "cosmetic" for c in diff_fmt.changes)
    assert any(c.category == "format_or_description_only" for c in diff_fmt.changes)

    # 2. Semantic v2 change: new required `tenant_id` query param on GET /orders/{order_id}
    # and removal of POST /orders
    orders_v2_md = (
        f"# Commerce Orders API v2\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
        "## List Orders\n\n`GET /orders`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `customer_id` | query | string | no | Filter by customer |\n\n"
        "## Get Order\n\n`GET /orders/{order_id}`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `order_id` | path | string | yes | Order identifier |\n"
        "| `tenant_id` | query | string | yes | Required v2 tenant scope |\n"
    ).encode()

    comp_v2 = compile_documentation_bundle(
        [RawDocumentInput(source_id="src_v2", filename="orders_v2.md", raw_bytes=orders_v2_md)],
        contract_id="ct_orders",
        project_id="proj_orders",
        policy=policy,
        use_local_model=False,
    )
    diff_v2 = compare_contracts(
        contract_v1,
        comp_v2.contract,
        old_tool_plan=plan_v1,
    )
    assert diff_v2.semantically_identical is False
    assert diff_v2.has_breaking_changes is True
    categories_v2 = {c.category for c in diff_v2.changes}
    assert "required_parameter_added" in categories_v2
    assert "operation_removed" in categories_v2
    assert "get_orders_order_id" in diff_v2.affected_tool_names
    assert "post_orders" in diff_v2.affected_tool_names
    assert "get_orders" not in diff_v2.affected_tool_names
    reg_types = {r["type"] for r in diff_v2.regression_cases}
    assert "missing_new_required_parameter_rejected" in reg_types
    assert "operation_removed" in reg_types

    # 3. Transitive prerequisite breakage: removing `GET /orders` impacts dependent `get_orders_order_id`
    orders_no_list_md = (
        f"# Commerce Orders API (No List)\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
        "## Get Order\n\n`GET /orders/{order_id}`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `order_id` | path | string | yes | Order identifier |\n"
    ).encode()
    comp_no_list = compile_documentation_bundle(
        [RawDocumentInput(source_id="src_nolist", filename="orders_nolist.md", raw_bytes=orders_no_list_md)],
        contract_id="ct_orders",
        project_id="proj_orders",
        policy=policy,
        use_local_model=False,
    )
    diff_transitive = compare_contracts(
        contract_v1,
        comp_no_list.contract,
        old_tool_plan=plan_v1,
    )
    removed_list_change = next(
        c for c in diff_transitive.changes if c.old_operation_id == "get_orders"
    )
    # Because `get_orders_order_id` depends on `get_orders` in `plan_v1.dependency_edges`,
    # removing `get_orders` flags both `get_orders` and `get_orders_order_id`!
    assert "get_orders" in removed_list_change.affected_tools
    assert "get_orders_order_id" in removed_list_change.affected_tools

    # 4. Ambiguous endpoint rename: `GET /orders/{order_id}` -> `GET /v2/orders/{order_id}`
    orders_renamed_md = (
        f"# Commerce Orders API v2 Renamed\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
        "## List Orders\n\n`GET /orders`\n\n"
        "## Get Order v2\n\n`GET /v2/orders/{order_id}`\n\n"
        "| Parameter | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `order_id` | path | string | yes | Order identifier |\n\n"
        "## Create Order\n\n`POST /orders`\n\n"
        "| Field | Location | Type | Required | Description |\n"
        "|---|---|---|---|---|\n"
        "| `sku` | body | string | yes | Product SKU |\n"
    ).encode()
    comp_renamed = compile_documentation_bundle(
        [RawDocumentInput(source_id="src_ren", filename="orders_renamed.md", raw_bytes=orders_renamed_md)],
        contract_id="ct_orders",
        project_id="proj_orders",
        policy=policy,
        use_local_model=False,
    )
    diff_rename = compare_contracts(
        contract_v1,
        comp_renamed.contract,
        old_tool_plan=plan_v1,
    )
    assert diff_rename.requires_review is True
    rename_items = [
        c for c in diff_rename.changes if c.category == "operation_renamed_ambiguous"
    ]
    assert len(rename_items) == 1
    assert rename_items[0].old_operation_id == "get_orders_order_id"
    assert rename_items[0].new_operation_id == "get_v2_orders_order_id"
    assert "get_orders_order_id" in rename_items[0].affected_tools


def test_t31_safe_regeneration_override_carry_forward_stale_override_and_frozen_tool_names() -> None:
    base_url = "http://127.0.0.1:18080"

    # Revision 1: `/v1/inventory/snapshot` is missing HTTP method (blocked), plus `GET /items`
    inv_r1_md = (
        f"# Warehouse Inventory Guide\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Pass header `X-API-Key` on all requests.\n\n"
        "## List Items\n\n`GET /items`\n\n"
        "## Stock Snapshot\n\n"
        "Endpoint path: `/v1/inventory/snapshot`\n\n"
        "Returns warehouse stock snapshot.\n"
    ).encode()

    bundle_r1 = _extract_bundle("src_inv_r1", "inv_r1.md", inv_r1_md)
    unoverridden_r1, _ = reconcile_bundles_to_contract(
        [bundle_r1],
        contract_id="ct_inv",
        project_id="proj_inv",
        revision=1,
    )
    blocked_op = next(
        op for op in unoverridden_r1.operations if op.stable_id == "op_v1_inventory_snapshot"
    )
    assert blocked_op.support_status == "blocked"

    # Owner issues override on `method` for `op_v1_inventory_snapshot` at revision 1
    old_method_hash = compute_field_value_hash(blocked_op.method)
    ovr_r1 = UserOverride(
        id="ovr_snapshot_method",
        operation_id="op_v1_inventory_snapshot",
        target_field="method",
        old_value_hash=old_method_hash,
        new_value="GET",
        rationale="Confirmed GET method with warehouse team.",
        timestamp="2026-10-09T12:00:00Z",
        source_revision=1,
    )
    contract_r1, _ = reconcile_bundles_to_contract(
        [bundle_r1],
        contract_id="ct_inv",
        project_id="proj_inv",
        revision=1,
        overrides=[ovr_r1],
    )
    assert all(op.support_status == "supported" for op in contract_r1.operations)

    policy_r1 = RuntimePolicy(
        id="pol_inv_r1",
        revision=1,
        mode="read_only",
        network_profile="STRICT_OFFLINE",
    )
    # Create ToolPlan with custom frozen tool names
    frozen_custom_names = {
        "get_items": "custom_list_warehouse_items",
        "op_v1_inventory_snapshot": "custom_warehouse_snapshot",
    }
    plan_r1 = create_tool_plan(
        contract_r1,
        policy_r1,
        plan_id="plan_inv_r1",
        preserved_tool_names=frozen_custom_names,
    )
    assert plan_r1.tool_names == frozen_custom_names

    # Revision 2 (Compatible update): Section heading for `GET /items` changes (`## Browse All SKU Items`)
    # and a new `GET /items/{item_id}` endpoint is added, while `/v1/inventory/snapshot` is untouched.
    inv_r2_md = (
        f"# Warehouse Inventory Guide v1.1\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Pass header `X-API-Key` on all requests.\n\n"
        "## Browse All SKU Items\n\n`GET /items`\n\n"
        "## Get Item Details\n\n`GET /items/{item_id}`\n\n"
        "| Parameter | Location | Type | Required |\n|---|---|---|---|\n"
        "| `item_id` | path | string | yes |\n\n"
        "## Stock Snapshot\n\n"
        "Endpoint path: `/v1/inventory/snapshot`\n\n"
        "Returns warehouse stock snapshot.\n"
    ).encode()
    bundle_r2 = _extract_bundle("src_inv_r2", "inv_r2.md", inv_r2_md)
    regen_r2, _ = reconcile_and_regenerate(
        [bundle_r2],
        old_contract=contract_r1,
        old_tool_plan=plan_r1,
        old_policy=policy_r1,
        new_revision=2,
    )

    # Override on `op_v1_inventory_snapshot` is automatically carried forward to revision 2!
    assert len(regen_r2.carried_forward_overrides) == 1
    assert regen_r2.carried_forward_overrides[0].source_revision == 2
    assert len(regen_r2.invalidated_overrides) == 0
    assert regen_r2.policy_invalidated is False
    assert regen_r2.regenerated_tool_plan is not None
    # Existing frozen tool names are preserved even though `## List Items` became `## Browse All SKU Items`!
    assert (
        regen_r2.regenerated_tool_plan.tool_names["get_items"]
        == "custom_list_warehouse_items"
    )
    assert (
        regen_r2.regenerated_tool_plan.tool_names["op_v1_inventory_snapshot"]
        == "custom_warehouse_snapshot"
    )

    # Revision 3 (Stale override): `/v1/inventory/snapshot` is replaced by `POST /v1/inventory/snapshot`
    # in the document itself, so the previous override targeting the missing-method operation is now stale!
    inv_r3_md = (
        f"# Warehouse Inventory Guide v2.0\n\nBase URL: `{base_url}`\n\n"
        "Authentication: Pass header `X-API-Key` on all requests.\n\n"
        "## Browse All SKU Items\n\n`GET /items`\n\n"
        "## Trigger Snapshot Build\n\n`POST /v1/inventory/snapshot`\n\n"
        "Triggers an asynchronous stock snapshot build.\n"
    ).encode()
    bundle_r3 = _extract_bundle("src_inv_r3", "inv_r3.md", inv_r3_md)
    regen_r3, _ = reconcile_and_regenerate(
        [bundle_r3],
        old_contract=regen_r2.regenerated_contract,
        old_tool_plan=regen_r2.regenerated_tool_plan,
        old_policy=policy_r1,
        new_revision=3,
    )
    assert len(regen_r3.carried_forward_overrides) == 0
    assert len(regen_r3.invalidated_overrides) == 1
    assert regen_r3.policy_invalidated is True
    assert regen_r3.regenerated_tool_plan is None
    stale_codes = {f.code for f in regen_r3.regenerated_contract.findings}
    assert "STALE_OVERRIDE" in stale_codes


def test_t31_approval_invalidation_reproducibility_and_api_evolution_routes(
    tmp_path: Path,
) -> None:
    config = LocalApiConfig(workspace_dir=tmp_path / "ws")
    app = create_local_app(config)

    with TestClient(app, base_url="http://127.0.0.1:8000") as http_client:
        client = SpigotApiClient(http_client)
        client.bootstrap_session()

        proj = client.create_project("Orders Evolution Project")
        pid = proj["project_id"]

        v1_md = (
            "# Orders API v1\n\n"
            "Base URL: `http://127.0.0.1:18080`\n\n"
            "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
            "## List Orders\n\n`GET /orders`\n\n"
            "## Get Order\n\n`GET /orders/{order_id}`\n\n"
            "| Parameter | Location | Type | Required |\n|---|---|---|---|\n"
            "| `order_id` | path | string | yes |\n\n"
            "## Cancel Order\n\n`DELETE /orders/{order_id}`\n\n"
            "| Parameter | Location | Type | Required |\n|---|---|---|---|\n"
            "| `order_id` | path | string | yes |\n"
        )
        upload_v1 = client.upload_sources(
            pid,
            [("orders_v1.md", v1_md.encode("utf-8"))],
        )
        src_v1_ids = upload_v1["source_ids"]
        client.extract_project(pid, source_ids=src_v1_ids, use_local_model=False)
        frozen_v1 = client.freeze_contract(pid, expected_revision=1)
        hash_v1 = frozen_v1["canonical_hash"]
        contract_v1_dict = client.get_project(pid)["contract"]

        plan_v1_res = client.create_tool_plan(
            pid,
            contract_hash=hash_v1,
            policy_mode="approval_required",
            allowed_write_operations=["delete_orders_order_id"],
            preserve_dependencies=True,
        )
        plan_v1 = plan_v1_res["tool_plan"]
        policy_v1 = plan_v1_res["policy"]

        # Generate v1 artifact (becomes the `previous_good_artifact`)
        gen_job = client.generate_artifact(
            pid,
            plan_hash=plan_v1["plan_hash"],
            package_slug="orders_evo_server",
        )
        art_v1_id = gen_job["result"]["artifact_id"]

        # Prepare and issue an owner action approval bound to v1 contract_hash & policy_hash
        prep_v1 = client.prepare_approval(
            pid,
            operation_id="delete_orders_order_id",
            arguments={"order_id": "ord_900"},
            target_url="http://127.0.0.1:18080/orders/ord_900",
            contract_hash=hash_v1,
            policy_hash=policy_v1["policy_hash"],
        )
        issued = client.issue_approval(
            pid,
            operation_id="delete_orders_order_id",
            arguments={"order_id": "ord_900"},
            target_url="http://127.0.0.1:18080/orders/ord_900",
            contract_hash=hash_v1,
            policy_hash=policy_v1["policy_hash"],
            expected_action_digest=prep_v1["action_digest"],
            human_confirmed=True,
        )
        token_v1 = issued["approval_token"]

        # Upload v2 documentation that adds a required `reason` query parameter to DELETE /orders/{order_id}
        v2_md = (
            "# Orders API v2\n\n"
            "Base URL: `http://127.0.0.1:18080`\n\n"
            "Authentication: Send `Authorization: Bearer <token>` on all requests.\n\n"
            "## List Orders\n\n`GET /orders`\n\n"
            "## Get Order\n\n`GET /orders/{order_id}`\n\n"
            "| Parameter | Location | Type | Required |\n|---|---|---|---|\n"
            "| `order_id` | path | string | yes |\n\n"
            "## Cancel Order\n\n`DELETE /orders/{order_id}`\n\n"
            "| Parameter | Location | Type | Required |\n|---|---|---|---|\n"
            "| `order_id` | path | string | yes |\n"
            "| `reason` | query | string | yes |\n"
        )
        upload_v2 = client.upload_sources(
            pid,
            [("orders_v2.md", v2_md.encode("utf-8"))],
        )
        src_v2_ids = upload_v2["source_ids"]

        # Run safe regeneration against the v2 source document
        regen_res = client.regenerate_project(
            pid,
            source_ids=src_v2_ids,
            old_contract_hash=hash_v1,
            old_plan_hash=plan_v1["plan_hash"],
            use_local_model=False,
        )
        assert regen_res["diff_report"]["has_breaking_changes"] is True
        assert "delete_orders_order_id" in regen_res["diff_report"]["affected_tool_names"]
        # Because `delete_orders_order_id` was in `allowed_write_operations` and had a breaking change,
        # the old policy and approvals are invalidated!
        assert regen_res["policy_invalidated"] is True
        assert regen_res["approvals_invalidated"] is True
        new_contract_hash = regen_res["new_contract_hash"]
        assert new_contract_hash != hash_v1

        # Verify `/compare` endpoint directly between v1 and v2 hashes
        cmp_res = client.compare_contracts(
            pid,
            old_contract_hash=hash_v1,
            new_contract_hash=new_contract_hash,
            old_plan_hash=plan_v1["plan_hash"],
        )
        assert cmp_res["has_breaking_changes"] is True
        assert cmp_res["diff_hash"] == regen_res["diff_report"]["diff_hash"]

        # Verify that the v1 approval token is rejected when presented under the v2 contract hash!
        authority = ApprovalAuthority(
            config.approval_secret, ledger_path=tmp_path / "approvals.db"
        )
        denial_reason = authority.verify_and_consume(
            token_v1,
            operation_id="delete_orders_order_id",
            arguments={"order_id": "ord_900"},
            target_url="http://127.0.0.1:18080/orders/ord_900",
            contract_hash=new_contract_hash,
            policy_hash=policy_v1["policy_hash"],
        )
        assert denial_reason is not None
        assert "signature mismatch" in denial_reason

        # Verify `GET /api/projects/{id}` preserves `previous_good_artifact` even though current revision changed
        summary = client.get_project(pid)
        assert summary["latest_artifact"] is None
        assert summary["previous_good_artifact"] is not None
        assert summary["previous_good_artifact"]["artifact_id"] == art_v1_id

        # Verify frozen generation reproducibility (FR-13)
        from packages.core.contracts import ApiContract, ToolPlan

        repro = verify_reproducible_regeneration(
            ApiContract.model_validate(contract_v1_dict),
            ToolPlan.model_validate(plan_v1),
            RuntimePolicy.model_validate(policy_v1),
            tmp_path / "repro_check",
            package_slug="orders_evo_server",
        )
        assert repro["reproducible"] is True
        assert repro["manifest_hash_a"] == repro["manifest_hash_b"]
        assert repro["zip_sha256_a"] == repro["zip_sha256_b"]
