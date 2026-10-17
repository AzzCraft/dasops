from __future__ import annotations

import pytest

from dasops.protected.canonical import (
    CanonicalJsonError,
    canonical_bytes,
    load_canonical_json,
    parse_json,
    semantic_digest,
    verify_self_digest,
    with_self_digest,
)


def test_canonical_round_trip_sorts_keys_and_uses_one_trailing_newline() -> None:
    value = {"z": [3, True, None], "a": "会员"}
    encoded = canonical_bytes(value)
    assert encoded == b'{"a":"\xe4\xbc\x9a\xe5\x91\x98","z":[3,true,null]}\n'
    assert load_canonical_json(encoded) == value


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1, "b":2}\n',
        b'{"b":2,"a":1}\n',
        b'{"a":1}',
        b'{"a":1}\n\n',
        b'\xef\xbb\xbf{"a":1}\n',
    ],
)
def test_noncanonical_json_bytes_fail(raw: bytes) -> None:
    with pytest.raises(CanonicalJsonError):
        load_canonical_json(raw)


def test_duplicate_keys_and_nonfinite_numbers_fail_before_validation() -> None:
    with pytest.raises(CanonicalJsonError, match="duplicate"):
        parse_json(b'{"a":1,"a":2}\n')
    with pytest.raises(CanonicalJsonError, match="non-finite"):
        parse_json(b'{"a":NaN}\n')


def test_floats_and_out_of_range_integers_are_forbidden() -> None:
    with pytest.raises(CanonicalJsonError, match="floating-point"):
        canonical_bytes({"value": 1.5})
    with pytest.raises(CanonicalJsonError, match="64-bit"):
        canonical_bytes({"value": 2**63})


def test_self_digest_is_non_circular_and_detects_mutation() -> None:
    subject = {"schema": "example/v1", "value": "stable"}
    record = with_self_digest(subject)
    assert record["recordDigest"] == semantic_digest(subject)
    assert verify_self_digest(record) == record["recordDigest"]
    record["value"] = "mutated"
    with pytest.raises(CanonicalJsonError, match="mismatch"):
        verify_self_digest(record)


def test_self_digest_cannot_be_silently_replaced() -> None:
    with pytest.raises(CanonicalJsonError, match="already present"):
        with_self_digest({"recordDigest": "sha256:" + "0" * 64})
