from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from copy import deepcopy
from typing import Any


MAX_CANONICAL_JSON_BYTES = 4 * 1024 * 1024
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class CanonicalJsonError(ValueError):
    """Raised when governed JSON is ambiguous or not byte-canonical."""


def _reject_constant(value: str) -> None:
    raise CanonicalJsonError(f"non-finite JSON number is forbidden: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError(f"duplicate object key: {key!r}")
        result[key] = value
    return result


def _validate_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str):
            try:
                value.encode("utf-8", "strict")
            except UnicodeEncodeError as exc:
                raise CanonicalJsonError(f"invalid Unicode scalar at {path}") from exc
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if value < -(2**63) or value > 2**63 - 1:
            raise CanonicalJsonError(f"integer outside signed 64-bit range at {path}")
        return
    if isinstance(value, float):
        raise CanonicalJsonError(f"floating-point values are forbidden at {path}")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError(f"non-string object key at {path}")
            _validate_value(child, f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _validate_value(child, f"{path}[{index}]")
        return
    raise CanonicalJsonError(f"unsupported JSON value {type(value).__name__} at {path}")


def parse_json(data: bytes, *, max_bytes: int = MAX_CANONICAL_JSON_BYTES) -> Any:
    if not isinstance(data, bytes):
        raise CanonicalJsonError("governed JSON input must be bytes")
    if len(data) > max_bytes:
        raise CanonicalJsonError(f"governed JSON exceeds {max_bytes} bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJsonError("UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise CanonicalJsonError("governed JSON is not strict UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
        )
    except CanonicalJsonError:
        raise
    except (json.JSONDecodeError, ValueError) as exc:
        raise CanonicalJsonError(f"invalid JSON: {exc}") from exc
    _validate_value(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    _validate_value(value)
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CanonicalJsonError(f"value cannot be canonicalized: {exc}") from exc
    return (text + "\n").encode("utf-8", "strict")


def load_canonical_json(data: bytes, *, max_bytes: int = MAX_CANONICAL_JSON_BYTES) -> Any:
    value = parse_json(data, max_bytes=max_bytes)
    expected = canonical_bytes(value)
    if data != expected:
        raise CanonicalJsonError("JSON bytes do not match the canonical encoding")
    return value


def semantic_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def with_self_digest(value: Mapping[str, Any], *, field: str = "recordDigest") -> dict[str, Any]:
    if field in value:
        raise CanonicalJsonError(f"self-digest field already present: {field}")
    subject = deepcopy(dict(value))
    result = deepcopy(subject)
    result[field] = semantic_digest(subject)
    return result


def verify_self_digest(value: Mapping[str, Any], *, field: str = "recordDigest") -> str:
    if field not in value or not isinstance(value[field], str) or not DIGEST_RE.fullmatch(value[field]):
        raise CanonicalJsonError(f"missing or invalid self-digest field: {field}")
    subject = deepcopy(dict(value))
    actual = str(subject.pop(field))
    expected = semantic_digest(subject)
    if actual != expected:
        raise CanonicalJsonError(f"self-digest mismatch: expected {expected}, received {actual}")
    return actual
