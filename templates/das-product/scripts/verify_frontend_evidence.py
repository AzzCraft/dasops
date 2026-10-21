from __future__ import annotations

import json
from pathlib import Path
from jsonschema import Draft202012Validator
from referencing import Registry


REPO_ROOT = Path.cwd()
VISUAL_MATRIX_KEYS = ("viewports", "themes", "locales")


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def ok(message: str) -> None:
    print(f"[OK] {message}")


def require_non_empty_dir(path: Path, label: str) -> None:
    if not path.is_dir():
        fail(f"missing frontend evidence directory: {path.as_posix()}")
    if path.is_symlink() or not any(p.is_file() and not p.is_symlink() and not any(a.is_symlink() for a in p.parents if a != path.parent) for p in path.rglob("*")):
        fail(f"{label} dir must contain an ordinary evidence file: {path.as_posix()}")


def load_visual_matrix_schema(path: Path) -> dict:
    if not path.is_file():
        fail(f"missing visualMatrix schema: {path.as_posix()}")
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        fail(f"invalid visualMatrix schema JSON: {exc}")

    if not isinstance(schema, dict):
        fail("visualMatrix schema must be an object")
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        fail("visualMatrix schema must declare properties")
    if schema.get("additionalProperties") is not False:
        fail("visualMatrix schema must set additionalProperties to false")
    required = schema.get("required")
    if required != list(VISUAL_MATRIX_KEYS):
        fail(f"visualMatrix schema required keys must be {list(VISUAL_MATRIX_KEYS)}")
    if set(properties) != set(VISUAL_MATRIX_KEYS):
        fail(f"visualMatrix schema properties must be {list(VISUAL_MATRIX_KEYS)}")
    return schema


def validate_visual_matrix_payload(payload: object) -> None:
    if not isinstance(payload, dict):
        fail("visualMatrix payload must be an object")
    if set(payload) != set(VISUAL_MATRIX_KEYS):
        fail(f"visualMatrix must contain exactly these keys: {', '.join(VISUAL_MATRIX_KEYS)}")
    for key in VISUAL_MATRIX_KEYS:
        values = payload.get(key)
        if not isinstance(values, list) or not values or any(not isinstance(item, str) or not item.strip() for item in values):
            fail(f"visualMatrix.{key} must be a non-empty array of strings")


visual_matrix = REPO_ROOT / "artifacts/frontend/visualMatrix.json"
visual_matrix_schema = REPO_ROOT / "openspec" / "schemas" / "das-standard" / "visual_matrix.schema.json"
schema = load_visual_matrix_schema(visual_matrix_schema)
if not visual_matrix.is_file():
    fail(f"missing frontend evidence file: {visual_matrix.as_posix()}")
try:
    payload = json.loads(visual_matrix.read_text(encoding="utf-8"))
except json.JSONDecodeError as exc:
    fail(f"invalid visualMatrix.json: {exc}")

validate_visual_matrix_payload(payload)
try:
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, registry=Registry()).validate(payload)
except Exception as exc:
    fail(f"visualMatrix schema validation failed: {exc}")

baseline_dir = REPO_ROOT / "artifacts/frontend/baseline/"
screenshots_dir = REPO_ROOT / "artifacts/frontend/screenshots/"
require_non_empty_dir(baseline_dir, "frontend baseline")
require_non_empty_dir(screenshots_dir, "frontend screenshots")

ok("frontend evidence artifacts are present and non-empty; matrix structure and file presence only, no visual comparison")
