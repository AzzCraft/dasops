from __future__ import annotations

import base64

import pytest

from dasops.protected.encoding import strict_urlsafe_b64decode


def test_strict_urlsafe_base64_accepts_only_canonical_unpadded_exact_size() -> None:
    token = b"T" * 32
    encoded = base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")
    assert strict_urlsafe_b64decode(encoded, expected_size=32) == token
    for invalid in (encoded + "=", encoded[:-1], "A", "not+base64", "\N{SNOWMAN}"):
        with pytest.raises(ValueError):
            strict_urlsafe_b64decode(invalid, expected_size=32)
