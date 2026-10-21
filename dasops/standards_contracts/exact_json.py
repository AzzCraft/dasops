"""New versioned JSON/JCS boundary. Historical validators keep their identities."""
from __future__ import annotations

from decimal import Decimal, InvalidOperation
import hashlib
import json
import math

MAX_BYTES = 4 * 1024 * 1024
MAX_DEPTH = 64
MAX_NODES = 100000
MAX_CATALOG_NODES = 262144
MAX_NUMBER_BYTES = 512
MAX_SAFE_INTEGER = 9007199254740991
DIGEST_METHOD = "rfc8785-jcs-utf8-sha256"


class ExactJsonError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExactJsonError("duplicate decoded object key")
        result[key] = value
    return result


def _number(text):
    if len(text) > MAX_NUMBER_BYTES:
        raise ExactJsonError("number limit exceeded")
    try:
        exponent = text.lower().partition("e")[2]
        if exponent and not -512 <= int(exponent) <= 512:
            raise ExactJsonError("numeric exponent limit")
        return int(text) if not any(char in text for char in ".eE") else Decimal(text)
    except (ValueError, InvalidOperation) as exc:
        raise ExactJsonError("invalid number") from exc


def _constant(_):
    raise ExactJsonError("nonfinite JSON number")


def _validate(value, depth=0, count=None, node_limit=MAX_NODES):
    if count is None:
        count = [0]
    count[0] += 1
    if depth > MAX_DEPTH or count[0] > node_limit:
        raise ExactJsonError("structural limit exceeded")
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeError as exc:
            raise ExactJsonError("invalid Unicode scalar") from exc
    elif isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ExactJsonError("object key is not a string")
            _validate(key, depth, count, node_limit)
            _validate(child, depth + 1, count, node_limit)
    elif isinstance(value, list):
        for child in value:
            _validate(child, depth + 1, count, node_limit)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ExactJsonError("nonfinite number")
    elif isinstance(value, Decimal) and not value.is_finite():
        raise ExactJsonError("nonfinite number")
    elif value is not None and not isinstance(value, (bool, int, float, Decimal)):
        raise ExactJsonError("unsupported host value")


def parse(data: bytes):
    return _parse(data, MAX_NODES)


def parse_catalog(data: bytes):
    """Fixed catalog budget; callers must still check the explicit contract."""
    return _parse(data, MAX_CATALOG_NODES)


def _parse(data: bytes, node_limit):
    if not isinstance(data, bytes) or len(data) > MAX_BYTES or data.startswith(b"\xef\xbb\xbf"):
        raise ExactJsonError("invalid input encoding or size")
    try:
        value = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                           parse_int=_number, parse_float=_number, parse_constant=_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ExactJsonError("invalid exact JSON") from exc
    _validate(value, node_limit=node_limit)
    return value


def safe_integer(value):
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise ExactJsonError("expected exact number")
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise ExactJsonError("integer outside safe range")
    if isinstance(value, Decimal) and value != value.to_integral_value():
        raise ExactJsonError("number is not an exact integer")
    return int(value)


def closed_object(value, required, optional=()):
    if not isinstance(value, dict) or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ExactJsonError("missing, unknown, or incorrectly cased object field")
    return value


def _jcs_value(value):
    if type(value) is int and abs(value) > MAX_SAFE_INTEGER:
        import rfc8785
        try:
            number = float(value)
        except OverflowError as exc:
            raise ExactJsonError("number outside IEEE 754 domain") from exc
        if not math.isfinite(number) or (number != value and rfc8785.dumps(number).decode() != str(value)):
            raise ExactJsonError("integer would lose precision")
        return number
    if isinstance(value, Decimal):
        # Security fields are checked in their exact Decimal domain before this
        # explicit IEEE 754 conversion. Generic JCS numbers follow RFC 8785.
        value = float(value)
        if not math.isfinite(value):
            raise ExactJsonError("number outside IEEE 754 domain")
        return value
    if isinstance(value, dict):
        return {key: _jcs_value(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_jcs_value(child) for child in value]
    return value


def canonical(value):
    return _canonical(value, MAX_NODES)


def canonical_catalog(value):
    return _canonical(value, MAX_CATALOG_NODES)


def _canonical(value, node_limit):
    _validate(value, node_limit=node_limit)
    try:
        import rfc8785
    except ImportError as exc:
        raise ExactJsonError("locked rfc8785 implementation is required") from exc
    try:
        result = rfc8785.dumps(_jcs_value(value))
    except (ValueError, TypeError, OverflowError) as exc:
        raise ExactJsonError("value outside JCS domain") from exc
    if len(result) > MAX_BYTES:
        raise ExactJsonError("JCS output size exceeded")
    return result


def digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def digest_catalog(value):
    return "sha256:" + hashlib.sha256(canonical_catalog(value)).hexdigest()
