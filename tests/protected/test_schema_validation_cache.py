from copy import deepcopy
import json

import pytest
from jsonschema.exceptions import SchemaError

from dasops.protected import SchemaRegistry, SchemaValidationError
from dasops.protected.schema_validation import check_schema_bytes,MAX_SCHEMA_BYTES


def test_meta_cache_is_bound_to_raw_bytes_and_does_not_cache_invalid_authors():
    check_schema_bytes.cache_clear()
    valid=b'{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}'
    invalid=b'{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"unrecognized"}'
    check_schema_bytes(valid);check_schema_bytes(valid)
    assert check_schema_bytes.cache_info().hits==1
    for _ in range(2):
        with pytest.raises(SchemaError):check_schema_bytes(invalid)
    assert check_schema_bytes.cache_info().hits==1
    with pytest.raises(ValueError):check_schema_bytes(b' '* (MAX_SCHEMA_BYTES+1))


def test_registry_schemas_are_not_shared_mutable_cache_objects():
    a=SchemaRegistry();b=SchemaRegistry()
    original=deepcopy(b.schema('protected-task-policy/v1'))
    a.schema('protected-task-policy/v1')['properties']['policyId']['const']='changed-only-in-a'
    assert b.schema('protected-task-policy/v1')==original
    assert a.schema('protected-task-policy/v1')!=original


def test_changed_bytes_cannot_inherit_previous_validity_from_the_same_path():
    check_schema_bytes.cache_clear()
    value={'$schema':'https://json-schema.org/draft/2020-12/schema','type':'object','properties':{'id':{'type':'string'}}}
    check_schema_bytes(json.dumps(value).encode())
    value['properties']['id']['type']='invalid-type'
    with pytest.raises(SchemaError):check_schema_bytes(json.dumps(value).encode())


def test_registry_inventory_cannot_bind_changed_raw_bytes_to_old_loaded_schema():
    registry=SchemaRegistry()
    identity=registry.schema_ids[0]
    registry._raw[identity]=b'{}'  # Simulate drift between loading and inventory.
    with pytest.raises(SchemaValidationError,match='changed after'):
        registry.inventory()
