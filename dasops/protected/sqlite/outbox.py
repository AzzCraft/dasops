"""Durable dispatch/reconciliation, consumed only by the installed control service.

Adapters, current authorization, receipt verification and termination witnesses
are trusted local dependencies, never request parameters or candidate plugins.
This kernel provides no authenticated public endpoint or deployment activation.
"""
from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import hashlib
import json
import time
from typing import Callable, Mapping, Protocol

from jsonschema import Draft202012Validator

from dasops.standards_contracts import exact_json as codec
from .store import CoordinationDatabase, CoordinationError, TaskKey, _hash

MAX_INTENT_BYTES = 65536
SCHEMA = json.loads(files('dasops.standards_contracts').joinpath('resource_action_intent.schema.json').read_text())


def encode_intent(value):
    codec.closed_object(value, SCHEMA['required'])
    normalized = dict(value)
    # Check the original exact number domain before generic JCS performs any
    # IEEE 754 conversion. A rounded fractional budget/generation is not legal.
    for field in ('taskRevision', 'taskCycle', 'targetGeneration', 'cost'):
        normalized[field] = codec.safe_integer(value[field])
    raw = codec.canonical(normalized)
    if len(raw) > MAX_INTENT_BYTES:
        raise CoordinationError('action intent exceeds the cumulative payload limit')
    result = codec.parse(raw)
    for field in ('taskRevision', 'taskCycle', 'targetGeneration', 'cost'):
        result[field] = codec.safe_integer(result.get(field))
    Draft202012Validator(SCHEMA).validate(result)
    if result['budgetIds'] != sorted(result['budgetIds']):
        raise CoordinationError('shared budget ancestry must have canonical order')
    return codec.canonical(result)


@dataclass(frozen=True)
class Observation:
    # Native bytes are retained before their digest is consumed. Neither a hash
    # nor an adapter's claimed status substitutes for independent verification.
    outcome: str
    request_digest: str
    resource_instance: str
    native_receipt: bytes


class ResourceAdapter(Protocol):
    def execute(self, intent: dict, *, deadline: float) -> Observation: ...
    def lookup(self, intent: dict, *, deadline: float) -> Observation: ...


def _load_intent(database, resource, action, business):
    stable = (database.domain, resource, action, business)
    row = database.connection.execute('SELECT b.*,p.request_digest,p.payload_json FROM business_actions b JOIN action_payloads p USING(authority_domain,resource_id,action_class,business_id) WHERE b.authority_domain=? AND b.resource_id=? AND b.action_class=? AND b.business_id=?', stable).fetchone()
    if not row:
        raise CoordinationError('no complete immutable outbox intent for this business key')
    raw = row['payload_json'].encode('utf-8')
    intent = codec.parse(raw)
    if encode_intent(intent) != raw or codec.digest(intent) != row['request_digest']:
        raise CoordinationError('outbox intent changed or is malformed')
    task = intent['taskKey']
    fingerprint = _hash({'taskKey': [task[name] for name in ('authorityDomain','projectId','changeId','taskId')],
        'cycle': intent['taskCycle'], 'originalActor': intent['originalActor'],
        'requestDigest': row['request_digest'], 'budgets': intent['budgetIds'], 'cost': intent['cost']})
    if (fingerprint != row['fingerprint'] or tuple(intent[name] for name in ('resourceId','action','businessActionId')) != stable[1:]
            or (task['authorityDomain'], task['projectId'], task['changeId'], task['taskId'], intent['taskCycle'])
            != (row['authority_domain'], row['project_id'], row['change_id'], row['task_id'], row['cycle'])):
        raise CoordinationError('outbox payload does not bind the retained business action')
    return dict(row), intent


class DurableOutbox:
    def __init__(self, database: CoordinationDatabase, *, adapters: Mapping[tuple[str, str, str], ResourceAdapter],
                 verify_observation: Callable[[dict, Observation], bool], execution_closed: Callable[[dict], bool]):
        if (not isinstance(database, CoordinationDatabase) or not adapters
                or not callable(verify_observation) or not callable(execution_closed)):
            raise CoordinationError('installed adapters, independent verification and termination witness required')
        self.database = database
        self.adapters = dict(adapters)
        for identity, adapter in self.adapters.items():
            if (not isinstance(identity, tuple) or len(identity) != 3
                    or not all(isinstance(value, str) and value for value in identity)
                    or not callable(getattr(adapter, 'execute', None)) or not callable(getattr(adapter, 'lookup', None))):
                raise CoordinationError('unsupported installed resource adapter')
        self.verify_observation = verify_observation
        self.execution_closed = execution_closed

    def submit(self, value, *, actor, now, authorize):
        raw = encode_intent(value)
        intent = codec.parse(raw)
        task = intent['taskKey']
        key = TaskKey(task['authorityDomain'], task['projectId'], task['changeId'], task['taskId'])
        if key.authority_domain != self.database.domain:
            raise CoordinationError('intent belongs to another authority domain')
        self._adapter(intent)

        def current(connection, operation, subject, epoch):
            if authorize(connection, operation, subject, epoch) is not True:
                return False
            row = connection.execute('SELECT revision,cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?', key.values()).fetchone()
            return bool(row and (row['revision'], row['cycle']) == (intent['taskRevision'], intent['taskCycle']))

        return self.database.reserve(key, resource_id=intent['resourceId'], action_class=intent['action'],
            business_id=intent['businessActionId'], original_actor=intent['originalActor'],
            request_digest=codec.digest(intent), budget_ids=intent['budgetIds'], cost=codec.safe_integer(intent['cost']),
            cycle=codec.safe_integer(intent['taskCycle']), actor=actor, now=now, authorize=current, payload=raw)

    def _load(self, resource, action, business):
        return _load_intent(self.database, resource, action, business)

    def _adapter(self, intent):
        adapter = self.adapters.get((intent['resourceId'], intent['resourceInstance'], intent['action']))
        if adapter is None:
            raise CoordinationError('resource instance/action has no installed adapter')
        return adapter

    @staticmethod
    def _deadline(timeout):
        if type(timeout) not in (int, float) or not 0 < timeout <= 30 or not hasattr(time, 'CLOCK_BOOTTIME'):
            raise CoordinationError('unsupported dispatch time budget')
        return time.clock_gettime(time.CLOCK_BOOTTIME) + timeout

    def _settle(self, row, intent, observation, *, actor, now, authorize, allow_absence):
        # Everything received from a transport starts as unknown, even exit 0.
        target, digest = 'unknown', None
        original = codec.canonical(intent)
        verifying = codec.parse(original)
        if (isinstance(observation, Observation)
                and observation.request_digest == row['request_digest']
                and observation.resource_instance == intent['resourceInstance']
                and isinstance(observation.native_receipt, bytes) and 1 <= len(observation.native_receipt) <= MAX_INTENT_BYTES
                and observation.outcome in ('confirmed', 'not_executed')
                and self.verify_observation(verifying, observation) is True
                and codec.canonical(verifying) == original):
            if observation.outcome == 'confirmed':
                target = 'confirmed'
                digest = 'sha256:' + hashlib.sha256(observation.native_receipt).hexdigest()
            elif allow_absence:
                closing = codec.parse(original)
                if self.execution_closed(closing) is True and codec.canonical(closing) == original:
                    target = 'not_executed'
        if row['state'] == 'unknown' and target == 'unknown':
            return self._load(intent['resourceId'], intent['action'], intent['businessActionId'])[0]
        self.database.transition_action(intent['resourceId'], intent['action'], intent['businessActionId'],
            expected=row['state'], target=target, receipt_digest=digest,
            receipt_bytes=observation.native_receipt if target in ('confirmed','not_executed') else None,
            actor=actor, now=now, authorize=authorize, retain_recovery=target in ('confirmed','not_executed'))
        return self._load(intent['resourceId'], intent['action'], intent['businessActionId'])[0]

    def dispatch(self, resource, action, business, *, actor, now, authorize, timeout=5.0):
        deadline = self._deadline(timeout)
        route=self.database.authority_route
        if route is not None:
            with route.locked() as record:
                if record is not None and record['phase']=='committing':
                    raise CoordinationError('pending dispatch cannot execute; reconcile original business key')
        row, intent = self._load(resource, action, business)
        if row['state'] != 'reserved':
            raise CoordinationError('dispatch requires reserved; reconcile the original business key')
        adapter = self._adapter(intent)
        # COMMIT this intent before crossing the resource boundary. A crash after
        # this point leaves dispatched, which may only be reconciled by lookup.
        self.database.transition_action(resource, action, business, expected='reserved', target='dispatched',
            actor=actor, now=now, authorize=authorize)
        row['state'] = 'dispatched'
        try:
            observation = adapter.execute(codec.parse(codec.canonical(intent)), deadline=deadline)
        except Exception:
            observation = None
        return self._settle(row, intent, observation, actor=actor, now=now, authorize=authorize, allow_absence=False)

    def reconcile(self, resource, action, business, *, actor, now, authorize, timeout=5.0):
        deadline = self._deadline(timeout)
        route = self.database.authority_route
        if route is not None:
            with route.locked() as record:
                pending = record is not None and record['phase']=='settling'
                dispatch_pending=(record is not None and record['phase']=='committing'
                    and record['migration'].get('businessIntent',{}).get('operation')=='action_dispatched')
            if pending:
                return route.recover_outbox(self, resource, action, business,
                    actor=actor, now=now, authorize=authorize, deadline=deadline)
            if dispatch_pending:
                # The finite fixed writer recovers the durable intent only.
                # This consumer then looks up the original key; never send.
                row,_=self._load(resource, action, business)
                self.database._commit_business('action_dispatched',{'key':[resource,action,business],
                    'requestDigest':row['request_digest'],'fingerprint':row['fingerprint']},actor,now,authorize,recovery_only=True)
        row, intent = self._load(resource, action, business)
        if row['state'] not in ('dispatched', 'unknown'):
            raise CoordinationError('reconciliation requires an unresolved original business key')
        adapter = self._adapter(intent)
        # Authenticated lookup must have its own current read authority; no
        # execution call or replacement business ID is issued by reconciliation.
        with self.database.transaction('action_lookup', actor, now, authorize):
            pass
        try:
            observation = adapter.lookup(codec.parse(codec.canonical(intent)), deadline=deadline)
        except Exception:
            observation = None
        return self._settle(row, intent, observation, actor=actor, now=now, authorize=authorize, allow_absence=True)
