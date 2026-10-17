from __future__ import annotations

import hashlib
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from dasops.protected.schema_validation import check_schema_bytes

from dasops.protected.canonical import canonical_bytes, parse_json, verify_self_digest


class BootstrapSchemaError(ValueError):
    pass


class BootstrapSchemaRegistry:
    PACKAGE = "dasops.bootstrap.schemas"

    def __init__(self) -> None:
        self._schemas: dict[str, dict[str, Any]] = {}
        self._resources: dict[str, str] = {}
        self._raw: dict[str, bytes] = {}
        root = resources.files(self.PACKAGE)
        for resource in sorted(root.iterdir(), key=lambda item: item.name):
            if not resource.name.endswith(".schema.json"):
                continue
            try:
                raw = resource.read_bytes()
                schema = parse_json(raw)
            except Exception as exc:
                raise BootstrapSchemaError(f"invalid bootstrap schema JSON {resource.name}: {exc}") from exc
            if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
                raise BootstrapSchemaError(f"bootstrap schema has no string $id: {resource.name}")
            schema_id = schema["$id"]
            if schema_id in self._schemas:
                raise BootstrapSchemaError(f"duplicate bootstrap schema $id: {schema_id}")
            try:
                check_schema_bytes(raw)
            except SchemaError as exc:
                raise BootstrapSchemaError(f"invalid bootstrap schema {schema_id}: {exc.message}") from exc
            except ValueError as exc:
                raise BootstrapSchemaError(f"schema author exceeds the exact input bounds: {schema_id}") from exc
            self._schemas[schema_id] = schema
            self._resources[schema_id] = resource.name
            self._raw[schema_id] = raw
        if not self._schemas:
            raise BootstrapSchemaError("bootstrap schema registry is empty")

    @property
    def schema_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._schemas))

    def validate(self, value: Any, *, schema_id: str | None = None) -> None:
        if not isinstance(value, dict):
            raise BootstrapSchemaError("bootstrap contract must be an object")
        selected = schema_id or value.get("schema")
        if not isinstance(selected, str) or selected not in self._schemas:
            raise BootstrapSchemaError(f"unknown bootstrap schema: {selected}")
        try:
            Draft202012Validator(
                self._schemas[selected],
                format_checker=FormatChecker(),
            ).validate(value)
        except ValidationError as exc:
            location = ".".join(str(part) for part in exc.absolute_path) or "$"
            raise BootstrapSchemaError(f"{selected} validation failed at {location}: {exc.message}") from exc
        try:
            verify_self_digest(value)
        except Exception as exc:
            raise BootstrapSchemaError(f"{selected} self-digest failed: {exc}") from exc

    def inventory(self) -> list[dict[str, str]]:
        root = resources.files(self.PACKAGE)
        result: list[dict[str, str]] = []
        for schema_id in self.schema_ids:
            name = self._resources[schema_id]
            raw = root.joinpath(name).read_bytes()
            if raw != self._raw[schema_id]:
                raise BootstrapSchemaError("schema resource changed after registry construction")
            result.append(
                {
                    "schemaId": schema_id,
                    "resource": name,
                    "rawSha256": hashlib.sha256(raw).hexdigest(),
                    "canonicalSha256": hashlib.sha256(canonical_bytes(self._schemas[schema_id])).hexdigest(),
                }
            )
        return result
