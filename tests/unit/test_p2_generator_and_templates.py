"""Phase P2 Unit Tests: Safe Names, Template Injection Safety, and Reproducible Manifests (T09, T11, T12)."""

from __future__ import annotations

import ast
from pathlib import Path

from packages.core.contracts import (
    ApiContract,
    OperationContract,
    ParameterContract,
    RequestBodyContract,
    ResponseContract,
    SecurityAlternative,
    SecurityRequirement,
    SecurityScheme,
    ServerContract,
    sha256_hex,
)
from packages.core.planning import (
    RuntimePolicy,
    create_tool_plan,
    normalize_safe_tool_name,
)
from packages.templates.generator import (
    export_reproducible_zip,
    generate_server_package,
)


def _build_adversarial_contract() -> ApiContract:
    hostile_desc = (
        '""" + str(__import__("os").system("echo PWNED")) + """\n'
        "@server.tool()\ndef injected_backdoor():\n    return 'pwned'\n"
        "{{7*7}} ${SECRET_TOKEN}"
    )

    return ApiContract(
        id='contract-adv-""" + __import__("os").system("calc") + """',
        project_id="proj-adv",
        revision=1,
        sources=["src-adv-1"],
        servers=[
            ServerContract(
                server_id="primary",
                base_url="http://127.0.0.1:18080",
                description=hostile_desc,
                evidence=["ev-srv"],
            )
        ],
        security_schemes=[
            SecurityScheme(
                scheme_id="bearer_auth",
                type="http",
                scheme="bearer",
                description=hostile_desc,
                evidence=["ev-auth"],
            )
        ],
        operations=[
            OperationContract(
                stable_id='server; __import__("os").system("calc")',
                display_name=hostile_desc,
                method="GET",
                relative_path="/v1/items/{item_id}",
                server_ref="primary",
                parameters=[
                    ParameterContract(
                        external_name="item_id",
                        safe_argument_name="item_id",
                        location="path",
                        required=True,
                        style="simple",
                        description=hostile_desc,
                        schema={"type": "string"},
                        evidence=["ev-get"],
                    ),
                    ParameterContract(
                        external_name="item_id",
                        safe_argument_name="query_item_id",
                        location="query",
                        required=False,
                        style="form",
                        description=hostile_desc,
                        schema={"type": "string"},
                        evidence=["ev-get"],
                    ),
                ],
                responses=[
                    ResponseContract(
                        status_code=200,
                        media_type="application/json",
                        description=hostile_desc,
                        schema={"type": "object"},
                        evidence=["ev-get"],
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
                ),
                semantic_effect="read",
                provenance={
                    "relative_path": ["ev-get"],
                    "security_requirement": ["ev-auth"],
                },
                support_status="supported",
            ),
            OperationContract(
                stable_id="server",
                display_name="Collision with reserved name",
                method="POST",
                relative_path="/v1/items",
                server_ref="primary",
                request_body=RequestBodyContract(
                    media_type="application/json",
                    required=True,
                    description=hostile_desc,
                    schema={
                        "type": "object",
                        "required": ["name"],
                        "properties": {"name": {"type": "string"}},
                    },
                    evidence=["ev-post"],
                ),
                responses=[
                    ResponseContract(
                        status_code=201,
                        media_type="application/json",
                        description="Created",
                        schema={"type": "object"},
                        evidence=["ev-post"],
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
                ),
                semantic_effect="write",
                provenance={
                    "relative_path": ["ev-post"],
                    "security_requirement": ["ev-auth"],
                },
                support_status="supported",
            ),
            OperationContract(
                stable_id="server!",
                display_name="Second collision with reserved name",
                method="GET",
                relative_path="/v1/items",
                server_ref="primary",
                parameters=[],
                responses=[
                    ResponseContract(
                        status_code=200,
                        media_type="application/json",
                        description="OK",
                        schema={"type": "object"},
                        evidence=["ev-get"],
                    )
                ],
                security_requirement=SecurityRequirement(
                    status="authenticated",
                    alternatives=[SecurityAlternative(all_of=["bearer_auth"])],
                ),
                semantic_effect="read",
                provenance={
                    "relative_path": ["ev-get"],
                    "security_requirement": ["ev-auth"],
                },
                support_status="supported",
            ),
        ],
    )


def test_safe_tool_name_normalization_and_collision_resolution() -> None:
    used: set[str] = set()
    assert normalize_safe_tool_name("server", used) == "api_server"
    assert normalize_safe_tool_name("server!", used) == "api_server_2"
    assert normalize_safe_tool_name("123-Fetch Users!", used) == "p_123_fetch_users"
    assert (
        normalize_safe_tool_name('GET /users"; import os; os.system("calc")', used)
        == "get_users_import_os_os_system_calc"
    )

    contract = _build_adversarial_contract()
    policy = RuntimePolicy(
        id="pol-adv-1",
        mode="restricted_write",
        allowed_write_operations=["server"],
    )
    plan = create_tool_plan(contract, policy)
    assert len(set(plan.tool_names.values())) == 3
    assert plan.tool_names["server"] == "api_server"
    assert plan.tool_names["server!"] == "api_server_2"


def test_injection_strings_remain_inert_data_and_ast_valid(tmp_path: Path) -> None:
    contract = _build_adversarial_contract()
    policy = RuntimePolicy(
        id="pol-adv-1",
        mode="restricted_write",
        allowed_write_operations=["server"],
    )
    plan = create_tool_plan(contract, policy)

    pkg_dir = tmp_path / "adv_pkg"
    generate_server_package(
        contract,
        plan,
        policy,
        pkg_dir,
        package_slug='123-bad;slug"test',
    )

    py_files = list(pkg_dir.rglob("*.py"))
    assert len(py_files) >= 4

    for py_file in py_files:
        source_text = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source_text, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                assert node.name != "injected_backdoor"
        assert "PWNED" not in source_text
        assert "injected_backdoor" not in source_text


def test_reproducible_generation_and_zip_hashes(tmp_path: Path) -> None:
    contract = _build_adversarial_contract()
    policy = RuntimePolicy(id="pol-det-1", mode="read_only")
    plan = create_tool_plan(contract, policy, plan_id="plan-det-1")

    dir_a = tmp_path / "run_a" / "pkg"
    dir_b = tmp_path / "run_b" / "pkg"
    zip_a = tmp_path / "run_a" / "export.zip"
    zip_b = tmp_path / "run_b" / "export.zip"

    manifest_a = generate_server_package(
        contract, plan, policy, dir_a, package_slug="det_server", manifest_id="man-1"
    )
    manifest_b = generate_server_package(
        contract, plan, policy, dir_b, package_slug="det_server", manifest_id="man-1"
    )

    assert manifest_a.manifest_hash == manifest_b.manifest_hash
    assert manifest_a.artifact_hashes == manifest_b.artifact_hashes

    bytes_a = export_reproducible_zip(dir_a, zip_a)
    bytes_b = export_reproducible_zip(dir_b, zip_b)
    assert sha256_hex(bytes_a) == sha256_hex(bytes_b)


def test_no_secrets_in_generated_artifacts_or_env_example(
    tmp_path: Path, monkeypatch
) -> None:
    canary = "SUPER_SECRET_CANARY_TOKEN_987654321"
    monkeypatch.setenv("SPIGOT_CRED_BEARER_AUTH", canary)

    contract = _build_adversarial_contract()
    policy = RuntimePolicy(id="pol-nosecret", mode="read_only")
    plan = create_tool_plan(contract, policy)

    pkg_dir = tmp_path / "no_secret_pkg"
    generate_server_package(contract, plan, policy, pkg_dir)

    env_example = (pkg_dir / ".env.example").read_text(encoding="utf-8")
    assert "SPIGOT_CRED_BEARER_AUTH=" in env_example
    assert canary not in env_example

    for file_path in pkg_dir.rglob("*"):
        if file_path.is_file():
            text = file_path.read_text(encoding="utf-8")
            assert canary not in text, f"Canary leaked into {file_path}"
