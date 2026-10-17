"""Protected task-state primitives for bare-canonical DAS repositories."""

from .canonical import (
    CanonicalJsonError,
    canonical_bytes,
    load_canonical_json,
    semantic_digest,
    verify_self_digest,
    with_self_digest,
)
from .schema_registry import SchemaRegistry, SchemaValidationError

__all__ = [
    "CanonicalJsonError",
    "SchemaRegistry",
    "SchemaValidationError",
    "canonical_bytes",
    "load_canonical_json",
    "semantic_digest",
    "verify_self_digest",
    "with_self_digest",
]
