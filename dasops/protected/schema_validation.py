"""Bounded metadata validation cache keyed by exact schema author bytes.

Only successful Draft 2020-12 metadata checks are cached. Registry instances
still read every resource, parse fresh dictionaries, reject duplicate IDs and
validate every message. Neither a path nor a mutable schema is a cache key.
"""
from functools import lru_cache

from jsonschema import Draft202012Validator

from .canonical import parse_json

MAX_SCHEMA_BYTES = 128 * 1024


@lru_cache(maxsize=256)
def check_schema_bytes(raw: bytes) -> None:
    # Cache keys retain at most 32 MiB; this bound also applies to source authors.
    schema = parse_json(raw, max_bytes=MAX_SCHEMA_BYTES)
    Draft202012Validator.check_schema(schema)
