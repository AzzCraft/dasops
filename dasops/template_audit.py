from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AuditFinding:
    code: str
    path: str
    message: str
    severity: str = "error"
    expected: object | None = None
    observed: object | None = None

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "code": self.code,
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }
        if self.expected is not None:
            payload["expected"] = self.expected
        if self.observed is not None:
            payload["observed"] = self.observed
        return payload


@dataclass(frozen=True)
class TemplateAuditReport:
    factory_root: Path
    template_root: Path
    problems: list[str]
    warnings: list[str]
    problem_details: list[AuditFinding]
    warning_details: list[AuditFinding]
    required_files: dict[str, bool]
    verify_scripts: dict[str, dict[str, object]]
    structured_artifacts: dict[str, dict[str, object]]
    command_parity: dict[str, bool]
    command_parity_checks: dict[str, dict[str, object]]
    frontend_evidence_contract: dict[str, dict[str, object]]
    unsupported_hints: dict[str, dict[str, object]]

    def to_payload(self) -> dict[str, object]:
        return {
            "schemaVersion": "1.0.0",
            "factoryRoot": str(self.factory_root),
            "templateRoot": str(self.template_root),
            "ok": not self.problems,
            "problems": self.problems,
            "warnings": self.warnings,
            "problemDetails": [item.to_payload() for item in self.problem_details],
            "warningDetails": [item.to_payload() for item in self.warning_details],
            "requiredFiles": self.required_files,
            "verifyScripts": self.verify_scripts,
            "structuredArtifacts": self.structured_artifacts,
            "commandParity": self.command_parity,
            "commandParityChecks": self.command_parity_checks,
            "frontendEvidenceContract": self.frontend_evidence_contract,
            "unsupportedHints": self.unsupported_hints,
        }


REQUIRED_TEMPLATE_FILES = [
    "CHANGELOG.md",
    "VERSION",
    "LICENSE",
    "NOTICE",
    "README.md",
    "STANDARD_REF.md",
    "BUILD_REQUIREMENTS.md",
    "VERIFY_REQUIREMENTS.md",
    "tooling_lock.json",
    "local_extension_manifest.json",
    "cadence.yaml",
    "scripts/verify",
    "scripts/verify-backend",
    "scripts/verify-frontend",
    "scripts/verify_frontend_evidence.py",
    "scripts/verify-contracts",
    "scripts/run_worker_codex.sh",
    "docs/USER_MANUAL.md",
    "docs/master_doc.md",
    "docs/ui_spec.md",
    "docs/policies/AGENT_OPERATING_MODEL.md",
    "openspec/config.yaml",
    "openspec/schemas/das-standard/visual_matrix.schema.json",
    "prompts/orchestrator.md",
    "prompts/worker.md",
    "progress.txt",
]

FAIL_CLOSED_SCRIPTS = {
    "scripts/verify-backend": "fail-closed",
    "scripts/verify-frontend": "exec bash",
    "scripts/verify-contracts": "fail-closed",
}

STRUCTURED_ARTIFACT_RULES = {
    "tooling_lock.json": {
        "requiredKeys": [
            "schemaVersion",
            "standardManifestVersion",
            "sourceOfTruth",
            "verifyRuntime",
            "suiteVersionClosureRef",
            "suiteLockRef",
            "verifyRegistryRef",
            "toolchain",
        ],
        "shapeChecks": {
            "sourceOfTruth": dict,
            "verifyRuntime": dict,
            "suiteVersionClosureRef": dict,
            "suiteLockRef": dict,
            "verifyRegistryRef": dict,
            "toolchain": list,
        },
    },
    "local_extension_manifest.json": {
        "requiredKeys": ["schemaVersion", "standardManifestVersion", "extensions"],
        "shapeChecks": {
            "extensions": list,
        },
    },
}

COMMAND_PARITY_RULES = {
    "factoryReadmeCreate": ("README.md", "python3 -m dasops create"),
    "factoryReadmeVerify": ("README.md", "./scripts/verify"),
    "factoryReadmeGui": ("README.md", 'python3 -m streamlit run "$FACTORY_ROOT/gui/app.py"'),
    "factoryUserManualGui": ("docs/USER_MANUAL.md", "streamlit run gui/app.py"),
    "factoryUserManualVerify": ("docs/USER_MANUAL.md", "./scripts/verify"),
    "factoryUserManualVendorVerify": ("docs/USER_MANUAL.md", "./scripts/verify --scope full"),
    "factoryUserManualCadenceCloneFailClosed": ("docs/USER_MANUAL.md", "Clone mode is fail-closed"),
    "factoryUserManualCadenceRuntimeExec": ("docs/USER_MANUAL.md", "Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof."),
    "factoryUserManualClaimReady": ("docs/USER_MANUAL.md", "dasops claim-ready --change-id add-login"),
    "templateReadmeVerify": ("templates/das-product/README.md", "./scripts/verify"),
    "templateReadmeClaimReady": ("templates/das-product/README.md", "dasops claim-ready --change-id <change-id> --owner worker01"),
    "templateReadmeCadenceClone": ("templates/das-product/README.md", './scripts/install_cadence_vendor.sh --git-base https://github.com/<org> --commit "$CADENCE_COMMIT"'),
    "templateReadmeCadenceCloneFailClosed": ("templates/das-product/README.md", "explicit source and commit; builds and verifies before replacing"),
    "templateReadmeCadenceRuntimeExec": ("templates/das-product/README.md", "Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof."),
    "templateUserManualVerify": ("templates/das-product/docs/USER_MANUAL.md", "./scripts/verify"),
    "templateUserManualClaimReady": ("templates/das-product/docs/USER_MANUAL.md", "dasops claim-ready --change-id add-login"),
    "templateUserManualCadencew": ("templates/das-product/docs/USER_MANUAL.md", "./cadencew verify --profile dev"),
    "templateUserManualCadenceClone": ("templates/das-product/docs/USER_MANUAL.md", './scripts/install_cadence_vendor.sh --git-base https://github.com/<org> --commit "$CADENCE_COMMIT"'),
    "templateUserManualCadenceCloneFailClosed": ("templates/das-product/docs/USER_MANUAL.md", "Clone mode is fail-closed"),
    "templateUserManualCadenceRuntimeExec": ("templates/das-product/docs/USER_MANUAL.md", "Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof."),
    "templateOrchestratorStatuses": ("templates/das-product/prompts/orchestrator.md", "Status values are limited to: `TODO`, `IN_PROGRESS`, `DONE`, `BLOCKED`, `PROPOSED`."),
    "templateOrchestratorTaskStatuses": ("templates/das-product/prompts/orchestrator.md", "- Status: `TODO` or `IN_PROGRESS` or `DONE` or `BLOCKED` or `PROPOSED`"),
    "guiVerifyHint": ("gui/app.py", "./scripts/verify"),
    "guiCreateButton": ("gui/app.py", "Create product repo"),
    "factoryReadmeDoctor": ("README.md", "dasops doctor"),
    "templateReadmeDoctor": ("templates/das-product/README.md", "dasops doctor"),
    "factoryReadmeClaimReady": ("README.md", "dasops claim-ready"),
    "factoryReadmeStartTask": ("README.md", "dasops start-task"),
    "templateReadmeStartTask": ("templates/das-product/README.md", "dasops start-task"),
    "templateUserManualStartTask": ("templates/das-product/docs/USER_MANUAL.md", "dasops start-task"),
    # GUI-vs-CLI state divergence rules: ensure GUI references same commands
    "guiClaimReady": ("gui/app.py", "dasops claim-ready"),
    "guiStartTask": ("gui/app.py", "dasops start-task"),
    "guiDoctor": ("gui/app.py", "dasops doctor"),
    "guiTaskStatuses": ("gui/app.py", "TODO"),
    # Manual-page drift: user manual must reference full verify flow
    "templateUserManualVerifyBackend": ("templates/das-product/docs/USER_MANUAL.md", "scripts/verify-backend"),
    "templateUserManualVerifyFrontend": ("templates/das-product/docs/USER_MANUAL.md", "scripts/verify-frontend"),
    "factoryUserManualDoctor": ("docs/USER_MANUAL.md", "dasops doctor"),
    "factoryUserManualStartTask": ("docs/USER_MANUAL.md", "dasops start-task"),
    "factoryUserManualBaselineRatchet": ("docs/USER_MANUAL.md", "baseline ratchet"),
    "templateReadmeVisualRegression": ("templates/das-product/README.md", "visual regression"),
    "templateUserManualBaselineRatchet": ("templates/das-product/docs/USER_MANUAL.md", "baseline ratchet"),
    "templateUserManualVisualMatrix": ("templates/das-product/docs/USER_MANUAL.md", "visualMatrix"),
    "guiVisualRegressionHint": ("gui/app.py", "matrix structure"),
    "guiVisualMatrixHint": ("gui/app.py", "evidence-file presence"),
    "guiCadenceCloneWarning": ("gui/app.py", "build_install_cadence_command"),
    "guiCadenceRuntimeExecWarning": ("gui/app.py", "Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof."),
    "templateVendorReadmeCadenceClone": ("templates/das-product/vendor/README.md", './scripts/install_cadence_vendor.sh --git-base https://github.com/<org> --commit "$CADENCE_COMMIT"'),
    "templateVendorReadmeCadenceCloneFailClosed": ("templates/das-product/vendor/README.md", "Clone mode requires an explicit Git base or org and the same fixed commit."),
    "templateVendorReadmeCadenceRuntimeExec": ("templates/das-product/vendor/README.md", "Cadence host-local stays `mode=host-launcher`; non-host profiles use `mode=runtime-exec` and fail closed unless `CADENCE_SANDBOX_CONTAINER_ADAPTER` or `CADENCE_SANDBOX_MICROVM_ADAPTER` returns verified runtime proof."),
}

UNSUPPORTED_HINT_RULES = {
    "legacyScaffoldScript": (
        [
            "README.md",
            "docs/USER_MANUAL.md",
            "templates/das-product/README.md",
            "templates/das-product/docs/USER_MANUAL.md",
            "gui/app.py",
        ],
        ["python scaffold.py", "python3 scaffold.py"],
    ),
    "legacyVerifyAll": (
        [
            "README.md",
            "docs/USER_MANUAL.md",
            "templates/das-product/README.md",
            "templates/das-product/docs/USER_MANUAL.md",
            "gui/app.py",
        ],
        ["verify_all.sh", "scripts/verify_all"],
    ),
    "legacyGuiEntry": (
        ["README.md", "docs/USER_MANUAL.md", "templates/das-product/docs/USER_MANUAL.md"],
        ["streamlit run app.py"],
    ),
    "legacyVendorVerifyAll": (
        ["README.md", "docs/USER_MANUAL.md", "templates/das-product/docs/USER_MANUAL.md", "gui/app.py"],
        ["vendor/cadence/verify_all.sh"],
    ),
}

TASK_TEMPLATE_REL = "templates/das-product/openspec/schemas/das-standard/templates/tasks.md"
TASK_INDEX_HEADER = "| Task ID | Title | Owner | Status | Depends on | Verify gate |"
TASK_STATUS_LINE = "Status values: TODO | IN_PROGRESS | DONE | BLOCKED | PROPOSED"
VERIFY_SCRIPT_GUARDRAILS = {
    "taskIndexContractCheck": "check_tasks_index_contract",
    "staleLockCheck": "check_stale_lock_semantics",
    "lockSchemaCheck": "check_task_lock_schema",
}
FRONTEND_EVIDENCE_ARTIFACTS = [
    "artifacts/frontend/visualMatrix.json",
    "artifacts/frontend/baseline/",
    "artifacts/frontend/screenshots/",
]
FRONTEND_EVIDENCE_CONTRACT_RULES = {
    "templates/das-product/scripts/verify_frontend_evidence.py": FRONTEND_EVIDENCE_ARTIFACTS,
    "templates/das-product/openspec/schemas/das-standard/templates/verification_plan.md": FRONTEND_EVIDENCE_ARTIFACTS,
}
FRONTEND_EVIDENCE_RUNTIME_MARKERS = {
    "templates/das-product/scripts/verify_frontend_evidence.py": [
        "json.loads",
        "VISUAL_MATRIX_KEYS",
        "load_visual_matrix_schema",
        "visualMatrix must contain exactly these keys",
        "visualMatrix.{key} must be a non-empty array of strings",
        "require_non_empty_dir",
        "frontend baseline",
        "frontend screenshots",
    ],
}


def run_template_audit(factory_root: Path) -> TemplateAuditReport:
    if (factory_root / ".dasops-scaffold.json").is_file():
        from .scaffold_v15 import verify
        result = verify(factory_root, scope="scaffold")
        return TemplateAuditReport(factory_root, factory_root, result["problems"], result["pendingItems"],
                                   [], [], {}, {}, {}, {}, {}, {}, {})
    factory_root = factory_root.resolve()
    template_root = factory_root / "templates" / "das-product"
    problems: list[str] = []
    warnings: list[str] = []
    problem_details: list[AuditFinding] = []
    warning_details: list[AuditFinding] = []

    def add_problem(code: str, rel: str, message: str, *, expected: object | None = None, observed: object | None = None) -> None:
        problems.append(message)
        problem_details.append(
            AuditFinding(
                code=code,
                path=rel,
                message=message,
                severity="error",
                expected=expected,
                observed=observed,
            )
        )

    def add_warning(code: str, rel: str, message: str, *, expected: object | None = None, observed: object | None = None) -> None:
        warnings.append(message)
        warning_details.append(
            AuditFinding(
                code=code,
                path=rel,
                message=message,
                severity="warning",
                expected=expected,
                observed=observed,
            )
        )

    required_files = {
        rel: (template_root / rel).exists()
        for rel in REQUIRED_TEMPLATE_FILES
    }
    for rel, exists in required_files.items():
        if not exists:
            add_problem("missing_required_file", rel, f"missing template file: {rel}")

    verify_scripts: dict[str, dict[str, object]] = {}
    for rel, required_phrase in FAIL_CLOSED_SCRIPTS.items():
        path = template_root / rel
        payload: dict[str, object] = {
            "exists": path.exists(),
            "executable": False,
            "containsFailClosed": False,
            "expectedPhrase": required_phrase,
        }
        if path.exists():
            payload["executable"] = path.stat().st_mode & 0o111 != 0
            text = path.read_text(encoding="utf-8")
            payload["containsFailClosed"] = required_phrase in text
            if not payload["executable"]:
                add_problem("verify_script_not_executable", rel, f"verify gate is not executable: {rel}")
            if not payload["containsFailClosed"]:
                add_problem(
                    "verify_script_not_fail_closed",
                    rel,
                    f"verify gate does not declare fail-closed behavior: {rel}",
                    expected=required_phrase,
                )
        verify_scripts[rel] = payload

    structured_artifacts: dict[str, dict[str, object]] = {}
    for rel, rules in STRUCTURED_ARTIFACT_RULES.items():
        path = template_root / rel
        payload: dict[str, object] = {
            "exists": path.exists(),
            "jsonValid": False,
            "requiredKeys": {},
            "shapeChecks": {},
        }
        if path.exists():
            try:
                doc = json.loads(path.read_text(encoding="utf-8"))
                payload["jsonValid"] = True
                for key in rules["requiredKeys"]:
                    present = key in doc
                    payload["requiredKeys"][key] = present
                    if not present:
                        add_problem(
                            "structured_artifact_missing_key",
                            rel,
                            f"{rel} missing required key: {key}",
                            expected=key,
                        )
                for key, expected_type in rules.get("shapeChecks", {}).items():
                    present = key in doc
                    shape_ok = present and isinstance(doc.get(key), expected_type)
                    payload["shapeChecks"][key] = {
                        "ok": shape_ok,
                        "expectedType": expected_type.__name__,
                        "observedType": type(doc.get(key)).__name__ if present else None,
                    }
                    if present and not shape_ok:
                        add_problem(
                            "structured_artifact_shape_drift",
                            rel,
                            f"{rel} key {key} must be {expected_type.__name__}",
                            expected=expected_type.__name__,
                            observed=type(doc.get(key)).__name__,
                        )
                if rel == "local_extension_manifest.json":
                    if not isinstance(doc.get("extensions"), list) or not doc["extensions"]:
                        add_problem(
                            "structured_artifact_invalid_extensions",
                            rel,
                            "local_extension_manifest.json must declare at least one project-local extension",
                        )
                    else:
                        for index, item in enumerate(doc["extensions"]):
                            if not isinstance(item, dict):
                                add_problem(
                                    "structured_artifact_shape_drift",
                                    rel,
                                    f"local_extension_manifest.json extension[{index}] must be an object",
                                    expected="object",
                                    observed=type(item).__name__,
                                )
                                continue
                            for key in ("name", "compatibilityNote", "reviewDate"):
                                if not item.get(key):
                                    add_problem(
                                        "structured_artifact_missing_key",
                                        rel,
                                        f"local_extension_manifest.json extension[{index}] missing {key}",
                                        expected=key,
                                    )
                if rel == "tooling_lock.json":
                    source_of_truth = doc.get("sourceOfTruth", {})
                    if source_of_truth.get("kind") != "git":
                        add_problem(
                            "unsupported_source_of_truth",
                            rel,
                            "tooling_lock.json sourceOfTruth.kind must be git",
                            expected="git",
                            observed=source_of_truth.get("kind"),
                        )
                    # The template must not carry an executable non-release commit pin.
                    # A generated repo either receives a real HEAD pin after git
                    # init or remains explicitly pending and fail-closed.
                    sot_pin = str(source_of_truth.get("pinValue", "")).strip()
                    _tpl_unresolved_pins = ("replace-with-product-commit", "fake-sha256", "tbd", "todo", "placeholder", "")
                    if "pinValue" in source_of_truth and sot_pin.lower() in _tpl_unresolved_pins:
                        add_problem(
                            "unresolved_pin_value",
                            rel,
                            f"tooling_lock.json sourceOfTruth.pinValue is unresolved: {sot_pin!r}",
                            expected="real git commit hash",
                            observed=sot_pin,
                        )
                    verify_runtime = doc.get("verifyRuntime", {})
                    if verify_runtime.get("kind") != "package":
                        add_problem(
                            "invalid_verify_runtime_kind",
                            rel,
                            "tooling_lock.json verifyRuntime.kind must be package",
                            expected="package",
                            observed=verify_runtime.get("kind"),
                        )
                    for ref_key, expected_suffix in (
                        ("suiteVersionClosureRef", "suite_version_closure.json"),
                        ("suiteLockRef", "suite_lock.json"),
                        ("verifyRegistryRef", "registry.json"),
                    ):
                        ref_payload = doc.get(ref_key)
                        if not isinstance(ref_payload, dict):
                            add_problem(
                                "structured_artifact_shape_drift",
                                rel,
                                f"tooling_lock.json {ref_key} must be an object",
                                expected="object",
                                observed=type(ref_payload).__name__,
                            )
                            continue
                        for required_key in ("kind", "uri", "pinType", "pinValue", "floating"):
                            if required_key not in ref_payload:
                                add_problem(
                                    "structured_artifact_missing_key",
                                    rel,
                                    f"tooling_lock.json {ref_key} missing {required_key}",
                                    expected=required_key,
                                )
                        if ref_payload.get("kind") != "file":
                            add_problem(
                                "invalid_tooling_ref_kind",
                                rel,
                                f"tooling_lock.json {ref_key}.kind must be file",
                                expected="file",
                                observed=ref_payload.get("kind"),
                            )
                        uri = str(ref_payload.get("uri", ""))
                        if expected_suffix and expected_suffix not in uri:
                            add_problem(
                                "invalid_tooling_ref_uri",
                                rel,
                                f"tooling_lock.json {ref_key}.uri must include {expected_suffix}",
                                expected=expected_suffix,
                                observed=uri,
                            )
                        if ref_key == "verifyRegistryRef" and "cadence-registry/registry.json" not in uri:
                            add_problem(
                                "invalid_tooling_registry_ref",
                                rel,
                                "tooling_lock.json verifyRegistryRef.uri must target cadence-registry/registry.json",
                                expected="cadence-registry/registry.json",
                                observed=uri,
                            )
            except json.JSONDecodeError as exc:
                add_problem("invalid_json", rel, f"{rel} is not valid JSON: {exc}")
        structured_artifacts[rel] = payload

    command_parity: dict[str, bool] = {}
    command_parity_checks: dict[str, dict[str, object]] = {}
    for label, (rel, needle) in COMMAND_PARITY_RULES.items():
        path = factory_root / rel
        ok = path.exists() and needle in path.read_text(encoding="utf-8")
        command_parity[label] = ok
        command_parity_checks[label] = {
            "path": rel,
            "expected": needle,
            "ok": ok,
        }
        if not ok:
            add_problem(
                "command_parity_mismatch",
                rel,
                f"command parity mismatch: {rel} missing {needle!r}",
                expected=needle,
            )

    frontend_evidence_contract: dict[str, dict[str, object]] = {}
    for rel, artifacts in FRONTEND_EVIDENCE_CONTRACT_RULES.items():
        path = factory_root / rel
        text = path.read_text(encoding="utf-8") if path.exists() else ""
        payload = {
            "path": rel,
            "exists": path.exists(),
            "artifacts": {artifact: artifact in text for artifact in artifacts},
        }
        runtime_markers = FRONTEND_EVIDENCE_RUNTIME_MARKERS.get(rel, [])
        if runtime_markers:
            payload["runtimeMarkers"] = {marker: marker in text for marker in runtime_markers}
        frontend_evidence_contract[rel] = payload
        if not path.exists():
            continue
        for artifact in artifacts:
            if artifact not in text:
                add_problem(
                    "frontend_evidence_contract_mismatch",
                    rel,
                    f"frontend evidence contract drift: {rel} missing {artifact!r}",
                    expected=artifact,
                )
        for marker in runtime_markers:
            if marker not in text:
                add_problem(
                    "frontend_evidence_runtime_mismatch",
                    rel,
                    f"frontend verifier runtime semantics drift: {rel} missing {marker!r}",
                    expected=marker,
                )

    unsupported_hints: dict[str, dict[str, object]] = {}
    for label, (paths, needles) in UNSUPPORTED_HINT_RULES.items():
        matches: list[dict[str, str]] = []
        for rel in paths:
            path = factory_root / rel
            if not path.exists():
                continue
            text = path.read_text(encoding="utf-8")
            for needle in needles:
                if needle in text:
                    matches.append({"path": rel, "snippet": needle})
                    add_problem(
                        "unsupported_command_hint",
                        rel,
                        f"unsupported command hint in {rel}: {needle!r}",
                        observed=needle,
                    )
        unsupported_hints[label] = {"ok": not matches, "matches": matches}

    tasks_template = factory_root / TASK_TEMPLATE_REL
    if not tasks_template.exists():
        add_problem("missing_required_file", TASK_TEMPLATE_REL, f"missing template file: {TASK_TEMPLATE_REL}")
    else:
        tasks_text = tasks_template.read_text(encoding="utf-8")
        if TASK_INDEX_HEADER not in tasks_text:
            add_problem(
                "tasks_index_column_drift",
                TASK_TEMPLATE_REL,
                "tasks template is missing the canonical task index header",
                expected=TASK_INDEX_HEADER,
            )
        if TASK_STATUS_LINE not in tasks_text:
            add_problem(
                "tasks_status_rule_drift",
                TASK_TEMPLATE_REL,
                "tasks template must enumerate allowed status values including BLOCKED and PROPOSED",
                expected=TASK_STATUS_LINE,
            )

    verify_main = template_root / "scripts" / "verify"
    if verify_main.exists():
        verify_text = verify_main.read_text(encoding="utf-8")
        for label, needle in VERIFY_SCRIPT_GUARDRAILS.items():
            check_key = f"verifyScriptGuardrail:{label}"
            ok = needle in verify_text
            command_parity_checks[check_key] = {
                "path": "templates/das-product/scripts/verify",
                "expected": needle,
                "ok": ok,
            }
            if not ok:
                add_problem(
                    "verify_guardrail_missing",
                    "templates/das-product/scripts/verify",
                    f"verify script missing guardrail: {needle}",
                    expected=needle,
                )

    template_readme = template_root / "README.md"
    if template_readme.exists():
        text = template_readme.read_text(encoding="utf-8")
        if "fail-closed gates" not in text:
            add_warning(
                "missing_fail_closed_guidance",
                "templates/das-product/README.md",
                "template README no longer calls out fail-closed sub-verifiers",
            )

    return TemplateAuditReport(
        factory_root=factory_root,
        template_root=template_root,
        problems=problems,
        warnings=warnings,
        problem_details=problem_details,
        warning_details=warning_details,
        required_files=required_files,
        verify_scripts=verify_scripts,
        structured_artifacts=structured_artifacts,
        command_parity=command_parity,
        command_parity_checks=command_parity_checks,
        frontend_evidence_contract=frontend_evidence_contract,
        unsupported_hints=unsupported_hints,
    )
