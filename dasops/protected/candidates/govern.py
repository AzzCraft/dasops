"""Finite authenticated Unix entry to existing protected reference operations.

Installation supplies every dependency. No listener starts here; an approved
supervisor hands over one connected fd. Only existing resource-action-intent/v1
data is transported. This is not deployment activation or a signing interface.
"""
import os
import threading
import time
from jsonschema.exceptions import ValidationError

from dasops.bootstrap.ipc import authenticated_socket, deadline, read_exact, write_all, shutdown, IpcError
from dasops.protected.sqlite.store import _id, _integer, TaskKey
from dasops.protected.sqlite.outbox import encode_intent, MAX_INTENT_BYTES, DurableOutbox, Observation
from dasops.standards_contracts import exact_json as codec
from .qualification import NativeQualification
from dasops.protected.bundle import BundleError, context_pack, _validate
from .store import CandidateError, VALIDATOR as CANDIDATE_VALIDATOR
from .versions import VersionTreeManager, PLAN_VALIDATOR, RECEIPT_VALIDATOR, INTEGRATION_PLAN_VALIDATOR, INTEGRATION_RECEIPT_VALIDATOR, COMPLETION_VALIDATOR, ANALYSIS_COMPLETION_VALIDATOR, QUALIFICATION_REFS, _qualification_refs, _changes, encode_preparation_intent, submission_materials


class _Preparation:
    """Existing outbox adapter for two fixed preparation operations.

    Inline reception uses the existing bounded no-execution receiver. Lookup
    verifies the retained registration/plan; it never changes the target or
    redispatches an unknown operation.
    """
    def __init__(self, manager, actor, now, authorize):
        self.manager,self.actor,self.now,self.authorize=manager,actor,now,authorize

    def lookup(self,intent,*,deadline):
        with self.manager.database.read_snapshot() as connection:
            if intent['action']=='plan':
                digest=codec.digest(intent['parameters']['plan'])
                present=connection.execute('SELECT 1 FROM version_plans WHERE authority_domain=? AND plan_digest=?',
                    (self.manager.database.domain,digest)).fetchone()
                if not present:return Observation('unknown',codec.digest(intent),intent['resourceInstance'],b'')
                result=self.manager._plan(connection,digest)
                return Observation('confirmed',codec.digest(intent),intent['resourceInstance'],codec.canonical(result))
            registered=connection.execute('SELECT 1 FROM candidate_objects WHERE authority_domain=? AND candidate_digest=?',
                (self.manager.database.domain,intent['parameters']['candidateDigest'])).fetchone()
            if not registered:return Observation('unknown',codec.digest(intent),intent['resourceInstance'],b'')
            binding=self.manager._candidate(connection,intent['parameters']['candidateDigest'])
            if any(binding[name]!=intent[name] for name in ('taskKey','taskRevision','taskCycle','policyDigest')):
                raise CandidateError('registered candidate differs from the original submission')
            return Observation('confirmed',codec.digest(intent),intent['resourceInstance'],codec.canonical(binding))

    def execute(self,intent,*,deadline):
        if time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline:
            raise CandidateError('preparation elapsed budget exhausted')
        if intent['action']=='submit':
            materials=submission_materials(intent['parameters'],self.manager.candidates.limits)
            if materials is not None:
                binding,raw,commit,archive,external=materials
                received=self.manager.candidates.receive(raw,commit_bytes=commit,archive_bytes=archive,
                    external_materials=external,elapsed_deadline=deadline)
                if (received['candidateDigest']!=intent['parameters']['candidateDigest']
                        or time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline):
                    raise CandidateError('inline reception unconfirmed; reconcile the original key')
            self.manager.register_candidate(intent['parameters']['candidateDigest'],actor=self.actor,
                now=self.now,authorize=self.authorize,submission_intent=intent)
        else:
            plan=intent['parameters']['plan']
            reasons={item['path']:item['deletionReason'] for item in plan['changes'] if item['postimage'] is None}
            if plan['contractIdentity']=='das-version-tree-plan/v1':
                self.manager.create_plan(plan['resourceId'],plan['resourceInstance'],plan['expectedGeneration'],
                    plan['afterCandidateDigest'],qualification_refs=intent['parameters']['qualificationRefs'],rollback_of=plan['rollbackOf'],
                    deletion_reasons=reasons,actor=self.actor,now=self.now,authorize=self.authorize,preparation_intent=intent)
            else:
                self.manager.create_integration_plan(plan['resourceId'],plan['resourceInstance'],plan['expectedGeneration'],
                    plan['sourceCandidateDigest'],plan['afterCandidateDigest'],qualification_refs={name:plan[name] for name in QUALIFICATION_REFS},
                    deletion_reasons=reasons,actor=self.actor,now=self.now,authorize=self.authorize,preparation_intent=intent)
        if time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline:
            raise CandidateError('preparation confirmation delayed; reconcile original')
        return self.lookup(intent,deadline=deadline)


class _VersionSwitch:
    """Finite SQL reference adapter; lookup never performs another switch."""
    def __init__(self,manager,actor,now,authorize):
        self.manager,self.actor,self.now,self.authorize=manager,actor,now,authorize

    def lookup(self,intent,*,deadline):
        stable=(self.manager.database.domain,intent['resourceId'],intent['action'],intent['businessActionId'])
        with self.manager.database.read_snapshot() as connection:
            meta=connection.execute('SELECT authority_epoch,time_floor FROM metadata WHERE singleton=1').fetchone()
            if self.now<meta['time_floor'] or self.authorize(connection,'govern_audit',self.actor,meta['authority_epoch']) is not True:
                raise CandidateError('current original version receipt read authorization denied')
            row=connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
            if row is None:return Observation('unknown',codec.digest(intent),intent['resourceInstance'],b'')
            receipt=self.manager._read_receipt(row)
            if receipt['requestDigest']!=codec.digest(intent) or receipt['resourceInstance']!=intent['resourceInstance']:
                raise CandidateError('original version receipt belongs to another immutable request')
            return Observation('confirmed',receipt['requestDigest'],intent['resourceInstance'],row['native_bytes'])

    def execute(self,intent,*,deadline):
        if time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline:raise CandidateError('version switch deadline exhausted')
        self.manager.switch(intent,actor=self.actor,now=self.now,authorize=self.authorize)
        if time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline:raise CandidateError('version switch confirmation delayed')
        return self.lookup(intent,deadline=deadline)


class GovernDriver:
    """Installed dependencies and finite scope; actor never comes from JSON.

    The reference supports inspect, plan creation/preview, apply, submit,
    integrate, complete, rollback and original-receipt audit. Its manager
    factory opens the SAME existing database/store in the serving thread. It
    must not import candidate code or accept caller-selected roots/adapters.
    """
    def __init__(self, *, manager_context, authorize, peer_actors, task_keys,
                 resource, instance, trusted_now=None, adoption=None):
        if not callable(manager_context) or not callable(authorize):
            raise CandidateError('installed manager and current authorization required')
        actors = dict(peer_actors)
        if not actors or any(type(uid) is not int or uid < 0 for uid in actors):
            raise CandidateError('explicit kernel UID actor mapping required')
        self.peer_actors = {uid: _id(actor) for uid, actor in actors.items()}
        keys = tuple(task_keys)
        if not keys or not all(isinstance(key, TaskKey) for key in keys):
            raise CandidateError('explicit full task-key scope required')
        self.task_keys = frozenset(key.values() for key in keys)
        self.resource, self.instance = _id(resource), _id(instance)
        self.manager_context, self.authorize = manager_context, authorize
        if adoption is not None:
            from dasops.adopt import GovernedAdoption
            if not isinstance(adoption,GovernedAdoption):
                raise CandidateError('installed controlled adoption preparation required')
        self.adoption=adoption
        if trusted_now is not None and not callable(trusted_now):
            raise CandidateError('installed current clock required')
        self.trusted_now = trusted_now or (lambda: int(time.time()))
        self._clock_floor = None
        self._clock_lock = threading.Lock()

    def _now(self):
        value = _integer(self.trusted_now())
        with self._clock_lock:
            if self._clock_floor is not None and value < self._clock_floor:
                raise CandidateError('trusted service clock moved backwards')
            self._clock_floor = value
        return value

    def _consume(self, value, actor, *, release_read=None):
        # Closed intent validates exact counters before any manager is opened.
        # No separate transport approval flag or request schema is introduced.
        intent = codec.parse(encode_preparation_intent(value))
        key = TaskKey(*(intent['taskKey'][name] for name in ('authorityDomain', 'projectId', 'changeId', 'taskId')))
        if (key.values() not in self.task_keys or intent['resourceId'] != self.resource
                or intent['resourceInstance'] != self.instance
                or intent['action'] not in ('inspect', 'plan', 'apply', 'submit', 'integrate', 'complete', 'rollback', 'audit')):
            raise CandidateError('operation or full task/resource scope is unsupported')
        parameters = intent['parameters']
        if intent['action'] in ('plan', 'integrate'):
            names=['plan'] if intent['action']=='plan' and 'plan' in parameters else ['planDigest']
            codec.closed_object(parameters,names+(['qualificationRefs'] if intent['action']=='plan' and 'qualificationRefs' in parameters else []))
        elif intent['action'] in ('apply','rollback'):
            codec.closed_object(parameters,['planDigest','qualificationRefs'])
            _qualification_refs(parameters['qualificationRefs'])
        elif intent['action'] == 'inspect':
            codec.closed_object(parameters, ['candidateDigest'], ['view'])
            if 'view' in parameters and parameters['view'] != 'context-pack':
                raise CandidateError('unsupported explicit inspect view')
        elif intent['action'] == 'submit':
            submission_materials(parameters)
        elif intent['action'] == 'complete':
            codec.closed_object(parameters, ['analysisPlan','qualificationRefs'] if 'analysisPlan' in parameters else ['integrationReceiptDigest', 'qualificationRefs'])
        else:
            preparation=parameters.get('originalAction')
            codec.closed_object(parameters, ['originalRequestDigest','originalAction',
                'candidateDigest' if preparation=='submit' else 'planDigest']
                if preparation in ('submit','plan') else ['originalRequestDigest','originalAction']
                if preparation in ('apply','rollback') else ['originalRequestDigest'])
        now = self._now()
        with self.manager_context() as manager:
            if not isinstance(manager, VersionTreeManager):
                raise CandidateError('installed version manager required')
            if intent['action'] == 'audit':
                return self._lookup(manager, intent, actor, now, release_read=release_read)
            if intent['action'] == 'inspect':
                if parameters.get('view') == 'context-pack':
                    return self._read_context(manager, intent, actor, now, key, release_read=release_read)
                return self._read_current(manager, intent, actor, now, key, release_read=release_read)
            if (not isinstance(manager.check_qualification, NativeQualification)
                    or manager.check_qualification.action_authorizer is None
                    or manager.check_qualification.verification_inputs is None):
                raise CandidateError('installed native qualification and authorization required')
            if intent['action'] == 'plan':
                if 'plan' in parameters:
                    if self.adoption is not None:
                        with manager.database.read_snapshot() as connection:
                            epoch=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0]
                        self.adoption.check_plan(manager,intent,actor=actor,epoch=epoch,authorize=self.authorize)
                    return self._prepare_current(manager,intent,actor,now)
                return self._read_current(manager, intent, actor, now, key, release_read=release_read)
            if intent['action'] == 'submit':
                return self._prepare_current(manager,intent,actor,now)
            if intent['action'] in ('apply','rollback'):
                return self._switch_current(manager,intent,actor,now)
            if intent['action'] == 'integrate':
                return manager.switch(intent, actor=actor, now=now, authorize=self.authorize)
            if 'analysisPlan' in parameters:
                return manager.complete_analysis(intent,actor=actor,now=now,authorize=self.authorize)
            return codec.canonical(manager.complete_integration(key,
                cycle=intent['taskCycle'], revision=intent['taskRevision'], resource=self.resource,
                instance=self.instance, business=intent['businessActionId'],
                qualification_refs=parameters['qualificationRefs'], completion_request=intent,
                actor=actor, now=now, authorize=self.authorize))

    def _prepare_current(self,manager,intent,actor,now):
        submission=intent['action']=='submit'
        materials=submission_materials(intent['parameters'],manager.candidates.limits) if submission else None
        binding=(materials[0] if materials is not None else manager.candidates.verify(intent['parameters']['candidateDigest'])) if submission else intent['parameters']['plan']
        if (any(binding[name]!=intent[name] for name in ('taskKey','taskRevision','taskCycle','policyDigest'))
                or intent['toolDigest']!=manager.tool_digest or intent['policyDigest']!=manager.policy_digest):
            raise CandidateError('preparation differs from installed scope/tool/policy')
        if not submission and (any(binding[name]!=intent[name] for name in ('resourceId','resourceInstance','toolDigest'))
                or binding['expectedGeneration']!=intent['targetGeneration']):
            raise CandidateError('plan differs from the requested resource/generation')
        def current(connection,operation,subject,epoch):
            if subject!=actor or self.authorize(connection,operation,subject,epoch) is not True:return False
            if materials is not None:manager._current_task(connection,binding)
            target=manager._target(connection,self.resource,self.instance)
            context=dict(intent=intent,plan=dict(beforeCandidateDigest=target['candidate_digest']) if submission else binding,
                integrationReceipt=None,qualificationRefs={})
            manager.check_qualification.action_authorizer(connection,intent['action'],actor,epoch,context)
            return True
        adapter=_Preparation(manager,actor,now,current)
        box=DurableOutbox(manager.database,adapters={(self.resource,self.instance,intent['action']):adapter},
            verify_observation=lambda request,observation:observation==adapter.lookup(request,deadline=0),
            execution_closed=lambda _:False)
        row=box.submit(intent,actor=actor,now=now,authorize=current)
        if row['state']=='reserved':row=box.dispatch(self.resource,intent['action'],intent['businessActionId'],actor=actor,now=now,authorize=current)
        elif row['state'] in ('dispatched','unknown'):row=box.reconcile(self.resource,intent['action'],intent['businessActionId'],actor=actor,now=now,authorize=current)
        if row['state']!='confirmed':raise CandidateError('preparation unknown; reconcile the original business key')
        observation=adapter.lookup(intent,deadline=0)
        if observation.outcome!='confirmed' or codec.digest(codec.parse(observation.native_receipt))!=codec.digest(binding):
            raise CandidateError('preparation original unavailable')
        return observation.native_receipt

    def _switch_current(self,manager,intent,actor,now):
        # SAME native CAS, original outbox and budget. No arbitrary destination.
        adapter=_VersionSwitch(manager,actor,now,self.authorize)
        stable=(manager.database.domain,self.resource,intent['action'],intent['businessActionId'])
        with manager.database.read_snapshot() as connection:
            present=connection.execute('SELECT state FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
        if present and present['state']=='confirmed':
            return self._lookup(manager,dict(intent,action='audit',parameters=dict(originalAction=intent['action'],originalRequestDigest=codec.digest(intent))),actor,now)
        plan=manager._plan(manager.database.connection,intent['parameters']['planDigest'])
        def current(connection,operation,subject,epoch):
            if subject!=actor or self.authorize(connection,operation,subject,epoch) is not True:return False
            if operation in ('reserve','action_dispatched'):
                manager.check_qualification.action_authorizer(connection,intent['action'],actor,epoch,
                    dict(intent=intent,plan=plan,integrationReceipt=None,qualificationRefs=intent['parameters']['qualificationRefs']))
            return True
        box=DurableOutbox(manager.database,adapters={(self.resource,self.instance,intent['action']):adapter},
            verify_observation=lambda request,observation:observation==adapter.lookup(request,deadline=0),execution_closed=lambda _:False)
        if present and present['state'] in ('dispatched','unknown'):
            row,original=box._load(self.resource,intent['action'],intent['businessActionId'])
            if original!=intent:raise CandidateError('changed original version action cannot be reconciled')
        else:row=box.submit(intent,actor=actor,now=now,authorize=current)
        if row['state']=='reserved':row=box.dispatch(self.resource,intent['action'],intent['businessActionId'],actor=actor,now=now,authorize=current)
        elif row['state'] in ('dispatched','unknown'):row=box.reconcile(self.resource,intent['action'],intent['businessActionId'],actor=actor,now=now,authorize=self.authorize)
        if row['state']!='confirmed':raise CandidateError('version switch unknown; reconcile original key')
        return adapter.lookup(intent,deadline=0).native_receipt

    def _read_current(self, manager, intent, actor, now, key, *, release_read=None, qualify=True):
        # Explicit reads, not creation, adoption or business dispatch. The
        # installed predicate grants the actual actor this scoped read operation;
        # independent request/target checks below prevent scope substitution.
        with manager.database.read_snapshot() as connection:
            meta = connection.execute('SELECT authority_epoch,time_floor FROM metadata WHERE singleton=1').fetchone()
            if (now < meta['time_floor'] or intent['originalActor'] != actor
                    or self.authorize(connection, 'govern_'+intent['action'], actor, meta['authority_epoch']) is not True):
                raise CandidateError('current scoped read authorization denied')
            if intent['toolDigest'] != manager.tool_digest or intent['policyDigest'] != manager.policy_digest:
                raise CandidateError('read request differs from installed tool/policy')
            target = manager._target(connection, self.resource, self.instance)
            if target['generation'] != intent['targetGeneration']:
                raise CandidateError('current target generation changed')
            if intent['action'] == 'inspect':
                if intent['parameters']['candidateDigest'] != target['candidate_digest']:
                    raise CandidateError('inspect digest differs from the actual current target')
                result = manager._candidate(connection, target['candidate_digest'])
            else:
                result = manager._plan(connection, intent['parameters']['planDigest'])
                if (result['contractIdentity'] not in ('das-integration-plan/v1','das-version-tree-plan/v1')
                        or (result['resourceId'], result['resourceInstance'], result['expectedGeneration'],
                            result['beforeCandidateDigest'], result['toolDigest'], result['policyDigest'])
                        != (self.resource, self.instance, intent['targetGeneration'],
                            target['candidate_digest'], manager.tool_digest, manager.policy_digest)):
                    raise CandidateError('retained integration plan differs from the current target')
            if any(result[name] != intent[name] for name in ('taskKey','taskRevision','taskCycle','policyDigest')):
                raise CandidateError('read result differs from the full requested task scope')
            if intent['action'] == 'plan':
                manager.database._parent(connection, key, allowed=('active',))
                before = manager._candidate(connection, result['beforeCandidateDigest'])
                if 'sourceCandidateDigest' in result:manager._candidate(connection, result['sourceCandidateDigest'], current=True)
                after = manager._candidate(connection, result['afterCandidateDigest'], current=True)
                reasons = {item['path']:item['deletionReason'] for item in result['changes'] if item['postimage'] is None}
                if _changes(before, after, manager.ownership, reasons) != result['changes']:
                    raise CandidateError('retained plan no longer matches the complete trees and ownership')
                refs=(_qualification_refs(intent['parameters'].get('qualificationRefs')) if result['contractIdentity']=='das-version-tree-plan/v1' else {name:result[name] for name in QUALIFICATION_REFS})
                if qualify:
                    manager._qualify(connection, 'plan', actor, result, refs)
            result = codec.canonical(result)
        if release_read is not None:
            def current():
                # Recheck current read policy/target/Task and retained bytes,
                # not a new native qualification run for every partial send.
                if self._read_current(manager,intent,actor,self._now(),key,qualify=False) != result:
                    raise CandidateError('prepared read changed before disclosure')
            release_read(result,current)
        return result

    def _read_context(self, manager, intent, actor, now, key, *, release_read=None):
        """Recompute a reading view for the actual current protected reference.

        Both SQL snapshots are read only. Native work occurs between them;
        the second denies scope/target/Task/epoch/reader drift. No candidate,
        file, receipt, budget, audit or action preparation is written.
        """
        native = manager.check_qualification
        if not isinstance(native, NativeQualification) or native.bundle_resolver is None or native.adoption_bundle is None:
            raise CandidateError('installed current Bundle reader required')
        resolver, scope = native.bundle_resolver, native.adoption_bundle['scope']
        def current(connection, observed_now):
            meta = connection.execute('SELECT authority_epoch,time_floor FROM metadata WHERE singleton=1').fetchone()
            if (observed_now < meta['time_floor'] or intent['originalActor'] != actor
                    or self.authorize(connection, 'govern_inspect', actor, meta['authority_epoch']) is not True
                    or intent['toolDigest'] != manager.tool_digest or intent['policyDigest'] != manager.policy_digest):
                raise CandidateError('current Context Pack read authorization/tool/policy denied')
            target = manager._target(connection, self.resource, self.instance)
            if (target['generation'] != intent['targetGeneration']
                    or target['candidate_digest'] != intent['parameters']['candidateDigest']):
                raise CandidateError('Context Pack differs from the actual current target')
            binding = manager._candidate(connection, target['candidate_digest'])
            task = connection.execute('SELECT revision,cycle,obligation_digest FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?', key.values()).fetchone()
            if (any(binding[name] != intent[name] for name in ('taskKey','taskRevision','taskCycle','policyDigest'))
                    or not task or tuple(task) != (binding['taskRevision'], binding['taskCycle'], binding['obligationDigest'])):
                raise CandidateError('Context Pack differs from the actual current Task binding')
            baseline = target['initial_candidate_digest']
            if target['generation'] > 1:
                receipts = connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND resource_instance=? AND after_generation=?',
                    (manager.database.domain, self.resource, self.instance, target['generation'])).fetchall()
                if len(receipts) != 1:
                    raise CandidateError('current Context Pack baseline receipt unavailable/ambiguous')
                receipt = manager._read_receipt(receipts[0])
                if receipt['afterCandidateDigest'] != target['candidate_digest']:
                    raise CandidateError('current Context Pack receipt differs from the target')
                baseline = receipt['beforeCandidateDigest']
            return meta['authority_epoch'], target, binding, dict(task), baseline
        try:
            with manager.database.read_snapshot() as connection:
                original = current(connection, now)
            epoch, target, _, _, baseline = original
            bundle, requirements = resolver.resolve(manager.database, actor=actor, epoch=epoch,
                scope=scope, target=dict(candidateDigest=target['candidate_digest'], deploymentBaselineDigest=baseline),
                retain_preparation=False)
            pack = context_pack(bundle, requirements)
            with manager.database.read_snapshot() as connection:
                if current(connection, self._now()) != original:
                    raise CandidateError('current Context Pack target/Task/epoch changed during native reading')
            result = codec.canonical_catalog(pack)
            if release_read is not None:
                def before_send():
                    with manager.database.read_snapshot() as connection:
                        if current(connection,self._now()) != original:
                            raise CandidateError('prepared Context Pack changed before disclosure')
                release_read(result,before_send)
            return result
        except BundleError as exc:
            raise CandidateError('current native Context Pack reading rejected') from exc

    def _lookup(self, manager, intent, actor, now, *, release_read=None):
        # Explicit original lookup, never redispatch; no writer/audit/charge.
        preparation=intent['parameters'].get('originalAction')
        prepared=preparation in ('submit','plan')
        stable = (manager.database.domain, self.resource, preparation if prepared or preparation in ('apply','rollback') else 'integrate', intent['businessActionId'])
        with manager.database.read_snapshot() as connection:
            meta = connection.execute('SELECT authority_epoch,time_floor FROM metadata WHERE singleton=1').fetchone()
            if now < meta['time_floor'] or self.authorize(connection, 'govern_audit', actor, meta['authority_epoch']) is not True:
                raise CandidateError('current original-receipt read authorization denied')
            payload = connection.execute('SELECT request_digest,payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
            if not payload:
                raise CandidateError('original intent unavailable; outcome remains unknown')
            original = codec.parse(payload['payload_json'].encode())
            if (codec.digest(original) != payload['request_digest']
                    or encode_intent(original) != payload['payload_json'].encode()):
                raise CandidateError('original lookup subject failed exact readback')
            expected = dict(original, action='audit', parameters=dict(originalRequestDigest=payload['request_digest']))
            if preparation in ('apply','rollback'):expected['parameters']['originalAction']=preparation
            if prepared:
                expected['parameters']['originalAction']=preparation
                expected['parameters']['candidateDigest' if preparation=='submit' else 'planDigest']=original['parameters']['candidateDigest'] if preparation=='submit' else codec.digest(original['parameters']['plan'])
            if codec.canonical(intent) != codec.canonical(expected):
                raise CandidateError('audit request differs from original action scope')
            if prepared:
                row=connection.execute('SELECT o.*,b.state FROM resource_observations o JOIN business_actions b USING(authority_domain,resource_id,action_class,business_id) WHERE o.authority_domain=? AND o.resource_id=? AND o.action_class=? AND o.business_id=?',stable).fetchone()
                if not row:raise CandidateError('original submission confirmation unavailable; outcome remains unknown')
                binding=manager._candidate(connection,original['parameters']['candidateDigest']) if preparation=='submit' else manager._plan(connection,codec.digest(original['parameters']['plan']))
                if (row['state']!='confirmed' or row['outcome']!='confirmed'
                        or row['native_digest']!=codec.digest(binding) or row['native_bytes']!=codec.canonical(binding)):
                    raise CandidateError('original submission receipt differs from actual registration')
            else:
                row = connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
                if not row:
                    raise CandidateError('no recorded effect; absence is not proof of no late effect')
                manager._read_receipt(row)
            result = row['native_bytes']
        if release_read is not None:
            def current():
                if self._lookup(manager,intent,actor,self._now()) != result:
                    raise CandidateError('original receipt changed before disclosure')
            release_read(result,current)
        return result

    def dispatch(self, value):
        """Trusted local call uses actual process identity, no peer/actor option."""
        actor = self.peer_actors.get(os.getuid())
        if actor is None:
            raise CandidateError('actual local UID is outside installed scope')
        return self._consume(value, actor)

    def serve_once(self, fd):
        channel, uid = authenticated_socket(fd, self.peer_actors)
        with channel:
            try:
                limit = deadline()
                size = int.from_bytes(read_exact(channel, 8, limit), 'big')
                if not 3 <= size <= MAX_INTENT_BYTES:
                    raise CandidateError('govern intent frame exceeds the existing bound')
                value = codec.parse(read_exact(channel, size, limit))
                released = False
                def release_read(result,current):
                    nonlocal released
                    write_all(channel,len(result).to_bytes(8,'big')+result,limit,before_send=current)
                    released = True
                result = self._consume(value, self.peer_actors[uid], release_read=release_read)
                if not released:
                    write_all(channel, len(result).to_bytes(8, 'big') + result, limit)
                return result
            finally:
                shutdown(channel)


def invoke(channel, value, *, expected_server_uid):
    """Unprivileged client. Response loss means unknown; never resend here."""
    if type(expected_server_uid) is not int or expected_server_uid < 0:
        raise CandidateError('independently installed server UID required')
    raw = encode_preparation_intent(value)
    if value['action'] not in ('inspect', 'plan', 'apply', 'submit', 'integrate', 'complete', 'rollback', 'audit'):
        raise CandidateError('unsupported govern reference operation')
    checked, _ = authenticated_socket(channel.fileno(), {expected_server_uid})
    with checked:
        try:
            limit = deadline()
            write_all(checked, len(raw).to_bytes(8, 'big') + raw, limit)
            size = int.from_bytes(read_exact(checked, 8, limit), 'big')
            if not 3 <= size <= 4_194_304:
                raise IpcError('invalid native result bound')
            reading = value['action'] == 'inspect' and value['parameters'].get('view') == 'context-pack'
            result = (codec.parse_catalog if reading else codec.parse)(read_exact(checked, size, limit))
            if reading:
                _validate('context_pack_v2', result)
                subject = dict(result); received = subject.pop('contextPackDigest')
                if (received != codec.digest_catalog(subject)
                        or result['target']['candidateDigest'] != value['parameters']['candidateDigest']
                        or result['policyRef']['policyDigest'] != value['policyDigest']
                        or result['authorityVerified'] is not False or result['qualificationEligible'] is not False):
                    raise IpcError('Context Pack response differs from current reading subject or claims')
                return result
            preparation_audit=value['action']=='audit' and value['parameters'].get('originalAction') in ('submit','plan')
            if value['action'] in ('inspect', 'plan','submit') or preparation_audit:
                inspect = value['action'] in ('inspect','submit') or value['parameters'].get('originalAction')=='submit'
                validator = CANDIDATE_VALIDATOR if inspect else PLAN_VALIDATOR if result.get('contractIdentity')=='das-version-tree-plan/v1' else INTEGRATION_PLAN_VALIDATOR
                validator.validate(result)
                digest = codec.digest(value['parameters']['plan']) if 'plan' in value['parameters'] else value['parameters']['candidateDigest' if inspect else 'planDigest']
                names = ('taskKey','taskRevision','taskCycle','policyDigest')
                if (codec.digest(result) != digest or any(result[name] != value[name] for name in names)
                        or (not inspect and any(result[name] != value[name] for name in ('resourceId','resourceInstance','toolDigest')))
                        or (not inspect and result['expectedGeneration'] != value['targetGeneration'])):
                    raise IpcError('read response differs from the requested immutable subject')
                return result
            version=value['action'] in ('apply','rollback') or (value['action']=='audit' and value['parameters'].get('originalAction') in ('apply','rollback'))
            if version:
                RECEIPT_VALIDATOR.validate(result)
                operation=value['parameters']['originalAction'] if value['action']=='audit' else value['action']
                expected={name:value[name] for name in ('resourceId','resourceInstance','businessActionId')}
                expected.update(authorityDomain=value['taskKey']['authorityDomain'],action=operation,
                    requestDigest=value['parameters']['originalRequestDigest'] if value['action']=='audit' else codec.digest(value),
                    beforeGeneration=value['targetGeneration'],afterGeneration=value['targetGeneration']+1)
                if value['action']!='audit':expected['planDigest']=value['parameters']['planDigest']
                if any(result[name]!=item for name,item in expected.items()):raise IpcError('version receipt differs from original request')
                return result
            integration = value['action'] in ('integrate', 'audit')
            analysis = value['action']=='complete' and 'analysisPlan' in value['parameters']
            identity = 'das-integration-receipt/v1' if integration else 'das-analysis-completion/v1' if analysis else 'das-completion/v1'
            validator = INTEGRATION_RECEIPT_VALIDATOR if integration else ANALYSIS_COMPLETION_VALIDATOR if analysis else COMPLETION_VALIDATOR
            validator.validate(result)
            expected = {name: value[name] for name in ('taskKey', 'taskRevision', 'taskCycle',
                'resourceId', 'resourceInstance', 'businessActionId', 'policyDigest')}
            if integration:
                digest = codec.digest(value) if value['action'] == 'integrate' else value['parameters']['originalRequestDigest']
                expected.update(requestDigest=digest, beforeGeneration=value['targetGeneration'])
            else:
                expected.update(targetGeneration=value['targetGeneration'], **value['parameters']['qualificationRefs'])
                if analysis:
                    expected.update(requestDigest=codec.digest(value),taskBindingDigest=value['parameters']['analysisPlan']['bindings']['taskBindingDigest'])
                else:
                    expected['integrationReceiptDigest']=value['parameters']['integrationReceiptDigest']
            if (not isinstance(result, dict) or result.get('contractIdentity') != identity or result.get('authority') is not False
                    or result.get('qualification') is not False):
                raise IpcError('native response identity or claims are invalid')
            if any(result.get(name) != data for name, data in expected.items()):
                raise IpcError('native result does not bind the original request')
            return result
        except (OSError, ValueError, IpcError, ValidationError) as exc:
            raise CandidateError('govern outcome unknown; reconcile the original business key') from exc
        finally:
            shutdown(checked)
