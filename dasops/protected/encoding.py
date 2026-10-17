from __future__ import annotations

import base64
import binascii


def strict_urlsafe_b64decode(value: str, *, expected_size: int | None = None) -> bytes:
    """Decode canonical unpadded base64url and reject ambiguous representations."""

    if not isinstance(value, str) or not value or "=" in value:
        raise ValueError("base64url value must be a non-empty unpadded string")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base64url value must contain ASCII only") from exc
    padding = b"=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base64url value is malformed") from exc
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=")
    if canonical != encoded:
        raise ValueError("base64url value is not canonical")
    if expected_size is not None and len(decoded) != expected_size:
        raise ValueError(f"base64url value must decode to exactly {expected_size} bytes")
    return decoded
