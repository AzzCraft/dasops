"""Shared local identifier rules; no authorization or identity service."""
import re


def validate_id(name, value):
    if (not isinstance(value, str) or not value or value in {'.', '..'}
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or '/' in value or '\\' in value):
        raise ValueError(f'Invalid {name}: {value!r}; no separators, dot components, or control characters')


def normalize_owner(value):
    value = re.sub(r'[^a-zA-Z0-9._-]+', '-', (value or '').strip())
    return re.sub(r'-+', '-', value).strip('-')
