from __future__ import annotations

import hashlib
import json
from importlib import resources
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError, ValidationError

from dasops.protected.schema_validation import check_schema_bytes

from .canonical import canonical_bytes, parse_json, verify_self_digest


class SchemaValidationError(ValueError):
    """Raised when a protected contract or schema inventory is invalid."""


class SchemaRegistry:
    PACKAGE = "dasops.protected.schemas"

    def __init__(self) -> None:
        self._schemas: dict[str, dict[str, Any]] = {}
        self._resources: dict[str, str] = {}
        self._raw: dict[str, bytes] = {}
        root = resources.files(self.PACKAGE)
        for resource in sorted(root.iterdir(), key=lambda item: item.name):
            if not resource.name.endswith(".schema.json"):
                continue
            raw = resource.read_bytes()
            try:
                schema = parse_json(raw)
            except Exception as exc:
                raise SchemaValidationError(f"invalid schema JSON {resource.name}: {exc}") from exc
            if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
                raise SchemaValidationError(f"schema has no string $id: {resource.name}")
            schema_id = schema["$id"]
            if schema_id in self._schemas:
                raise SchemaValidationError(f"duplicate schema $id: {schema_id}")
            try:
                check_schema_bytes(raw)
            except SchemaError as exc:
                raise SchemaValidationError(f"invalid Draft 2020-12 schema {schema_id}: {exc.message}") from exc
            except ValueError as exc:
                raise SchemaValidationError(f"schema author exceeds the exact input bounds: {schema_id}") from exc
            self._schemas[schema_id] = schema
            self._resources[schema_id] = resource.name
            self._raw[schema_id] = raw
        if not self._schemas:
            raise SchemaValidationError("protected schema registry is empty")

    @property
    def schema_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._schemas))

    def schema(self, schema_id: str) -> dict[str, Any]:
        try:
            return self._schemas[schema_id]
        except KeyError as exc:
            raise SchemaValidationError(f"unknown protected schema: {schema_id}") from exc

    def validate(self, value: Any, *, schema_id: str | None = None, verify_digest: bool = True) -> None:
        if not isinstance(value, dict):
            raise SchemaValidationError("protected contract must be an object")
        selected = schema_id or value.get("schema")
        if not isinstance(selected, str):
            raise SchemaValidationError("protected contract has no string schema discriminator")
        schema = self.schema(selected)
        try:
            Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)
        except ValidationError as exc:
            location = ".".join(str(part) for part in exc.absolute_path) or "$"
            raise SchemaValidationError(f"{selected} validation failed at {location}: {exc.message}") from exc
        if verify_digest and "recordDigest" in schema.get("properties", {}):
            try:
                verify_self_digest(value)
            except Exception as exc:
                raise SchemaValidationError(f"{selected} self-digest failed: {exc}") from exc

    def inventory(self) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        root = resources.files(self.PACKAGE)
        for schema_id in self.schema_ids:
            resource_name = self._resources[schema_id]
            raw = root.joinpath(resource_name).read_bytes()
            if raw != self._raw[schema_id]:
                raise SchemaValidationError("schema resource changed after registry construction")
            schema = self._schemas[schema_id]
            result.append(
                {
                    "schemaId": schema_id,
                    "resource": resource_name,
                    "rawSha256": hashlib.sha256(raw).hexdigest(),
                    "canonicalSha256": hashlib.sha256(canonical_bytes(schema)).hexdigest(),
                }
            )
        return result
