"""Protected-reference staging kernel; never modifies a user's live directory.

All registrations, plans, target CAS and native receipts share the existing
coordination DB transaction domain. Complete trees are prepared/synchronized
first. A SQL reference is the only switched target: deployments must consume it
through their installed resource boundary, not copy its files into a workspace.
The integration path requires an installed current qualification predicate in
addition to authorization. Native receipts/Completions remain staging facts;
this library does not activate a service or qualify a deployment.
"""
from __future__ import annotations

from importlib.resources import files
import base64
import json
from types import MappingProxyType

from jsonschema import Draft202012Validator, validators

from dasops.standards_contracts import exact_json as codec
from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey, _id, _digest, _integer
from dasops.protected.sqlite.outbox import encode_intent
from .store import (CandidateStore, CandidateError, CandidateLimits, VALIDATOR as CANDIDATE_VALIDATOR,
                    validate_binding, _hash, _integer as exact_integer)
from .qualification import NativeQualification


def _schema(name):
    author = json.loads(files('dasops.standards_contracts').joinpath(name + '.schema.json').read_text())
    return validators.extend(Draft202012Validator, type_checker=
        Draft202012Validator.TYPE_CHECKER.redefine('integer', exact_integer))(author)


PLAN_VALIDATOR = _schema('version_tree_plan')
RECEIPT_VALIDATOR = _schema('version_switch_receipt')
INTEGRATION_PLAN_VALIDATOR = _schema('integration_plan')
INTEGRATION_RECEIPT_VALIDATOR = _schema('integration_receipt')
COMPLETION_VALIDATOR = _schema('completion')
ANALYSIS_TASK_VALIDATOR = _schema('analysis_task_binding')
ANALYSIS_PLAN_VALIDATOR = _schema('analysis_verification_plan')
ANALYSIS_COMPLETION_VALIDATOR = _schema('analysis_completion')


def analysis_scope_digest(plan):
    """Fixed check denominator, without a circular task/plan digest reference."""
    ANALYSIS_PLAN_VALIDATOR.validate(plan)
    return codec.digest({name:plan[name] for name in ('planId','actions','slots','aggregation',
                                                   'requireOverallSuccessForActions')})
QUALIFICATION_REFS = ('verificationPlanDigest', 'verificationEvidenceDigest', 'decisionDigest')


def encode_preparation_intent(value):
    # Nested plan counters must be checked before JCS can round a fractional
    # JSON number. The existing intent encoder validates its own counters.
    if isinstance(value,dict) and value.get('action')=='plan':
        parameters=value.get('parameters')
        if isinstance(parameters,dict) and 'plan' in parameters:
            version=parameters['plan'].get('contractIdentity')=='das-version-tree-plan/v1'
            codec.closed_object(parameters,['plan','qualificationRefs'] if version else ['plan'])
            (PLAN_VALIDATOR if version else INTEGRATION_PLAN_VALIDATOR).validate(parameters['plan'])
            if version:_qualification_refs(parameters['qualificationRefs'])
    if isinstance(value,dict) and value.get('action')=='submit':
        parameters=value.get('parameters')
        if isinstance(parameters,dict) and 'binding' in parameters:
            # Validate original nested counters BEFORE JCS can round them.
            CANDIDATE_VALIDATOR.validate(parameters['binding'])
    if isinstance(value,dict) and value.get('action')=='complete':
        parameters=value.get('parameters')
        if isinstance(parameters,dict) and 'analysisPlan' in parameters:
            codec.closed_object(parameters,['analysisPlan','qualificationRefs'])
            ANALYSIS_PLAN_VALIDATOR.validate(parameters['analysisPlan'])
    raw=encode_intent(value)  # The existing 64 KiB bound applies before decoding.
    if isinstance(value,dict) and value.get('action')=='submit':
        submission_materials(codec.parse(raw)['parameters'])
    return raw


def submission_materials(parameters, limits=None):
    """Two finite submit forms: received digest, or complete bounded bytes.

    No path, upload adapter, decoder or hook is selected by the request. The
    original intent/grant binds every inline byte as well as the candidate ID.
    The physical receiver still reconstructs commit/tree and verifies custody.
    """
    inline='binding' in parameters
    codec.closed_object(parameters,['candidateDigest','binding','commitBase64','archiveBase64','externalMaterials']
        if inline else ['candidateDigest'])
    _digest(parameters['candidateDigest'])
    if not inline:return None
    CANDIDATE_VALIDATOR.validate(parameters['binding'])
    binding,raw=validate_binding(codec.canonical(parameters['binding']),limits or CandidateLimits())
    if codec.digest(binding)!=parameters['candidateDigest']:
        raise CandidateError('inline candidate binding differs from the requested digest')
    materials=parameters['externalMaterials']
    if type(materials) is not dict or set(materials)!={row['materialId'] for row in binding['externalMaterials']}:
        raise CandidateError('complete declared inline external materials required')
    def decode(value):
        try:
            if type(value) is not str:raise ValueError('base64 string required')
            decoded=base64.b64decode(value.encode('ascii'),validate=True)
            if base64.b64encode(decoded).decode('ascii')!=value:raise ValueError('canonical base64 required')
            return decoded
        except (ValueError,UnicodeError) as exc:
            raise CandidateError('invalid exact inline candidate byte encoding') from exc
    return binding,raw,decode(parameters['commitBase64']),decode(parameters['archiveBase64']),{
        name:decode(value) for name,value in materials.items()}


def _qualification_refs(value):
    codec.closed_object(value, QUALIFICATION_REFS)
    return {name: _digest(value[name]) for name in QUALIFICATION_REFS}


def _images(binding):
    result = {'tree/' + item['path']: {key:item[key] for key in ('mode', 'size', 'contentSha256')}
              for item in binding['files']}
    result.update({'materials/' + item['materialId']: dict(mode='data', size=item['size'], contentSha256=item['contentSha256'])
                   for item in binding['externalMaterials']})
    return result


def _changes(before, after, owners, deletion_reasons):
    preimages, postimages = _images(before), _images(after)
    changed = sorted(path for path in preimages.keys() | postimages.keys() if preimages.get(path) != postimages.get(path))
    deleted = {path for path in changed if path not in postimages}
    if (not isinstance(deletion_reasons, dict) or set(deletion_reasons) != deleted
            or any(not isinstance(reason, str) or not reason.strip() or len(reason) > 256 or '\0' in reason for reason in deletion_reasons.values())):
        raise CandidateError('every deletion needs its exact explicit reason; unrelated reasons are rejected')
    result = []
    for path in changed:
        owner = owners.get(path)
        if owner is None:
            raise CandidateError('no installed ownership/origin for changed file: ' + path)
        result.append(dict(path=path, owner=owner[0], originDigest=owner[1], preimage=preimages.get(path),
                           postimage=postimages.get(path), deletionReason=deletion_reasons.get(path)))
    return result


class VersionTreeManager:
    def __init__(self, database, candidates, *, ownership, tool_digest, policy_digest, check_qualification=None,
                 check_reverification=None):
        if not isinstance(database, CoordinationDatabase) or not isinstance(candidates, CandidateStore):
            raise CandidateError('installed coordination DB and candidate store are required')
        if not isinstance(ownership, dict) or not ownership:
            raise CandidateError('installed per-file ownership/origin registry is required')
        registry = {}
        for path, identity in ownership.items():
            if (not isinstance(path, str) or not path.startswith(('tree/', 'materials/'))
                    or not isinstance(identity, tuple) or len(identity) != 2):
                raise CandidateError('invalid installed file ownership registry')
            registry[path] = (_id(identity[0]), _digest(identity[1]))
        self.database, self.candidates = database, candidates
        self.ownership = MappingProxyType(registry)
        self.tool_digest, self.policy_digest = _digest(tool_digest), _digest(policy_digest)
        if check_qualification is not None and not callable(check_qualification):
            raise CandidateError('installed bounded qualification predicate required')
        self.check_qualification = check_qualification
        if check_reverification is not None and not callable(check_reverification):
            raise CandidateError('installed verification-service control predicate required')
        self.check_reverification = check_reverification

    def _current_task(self, connection, binding, *, allowed=('active',)):
        task = binding['taskKey']
        key = TaskKey(*(task[name] for name in ('authorityDomain', 'projectId', 'changeId', 'taskId')))
        if key.authority_domain != self.database.domain:
            raise CandidateError('candidate belongs to another authority domain')
        self.database._parent(connection, key, allowed=allowed)
        row = connection.execute('SELECT * FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?', key.values()).fetchone()
        if (not row or (row['revision'], row['cycle'], row['obligation_digest']) !=
                (binding['taskRevision'], binding['taskCycle'], binding['obligationDigest'])
                or binding['policyDigest'] != self.policy_digest):
            raise CandidateError('candidate does not bind the current approved task/cycle/policy')
        self.database._unfinished_cycle(connection,key,binding['taskCycle'])

    def register_candidate(self, digest, *, actor, now, authorize, submission_intent=None):
        _digest(digest)
        with self.database.transaction('candidate_register', actor, now, authorize) as connection:
            binding = self.candidates.confirm_for_registration(digest)
            raw = codec.canonical(binding).decode()
            previous = connection.execute('SELECT binding_json FROM candidate_objects WHERE authority_domain=? AND candidate_digest=?', (self.database.domain, digest)).fetchone()
            if previous:
                if previous['binding_json'] != raw:
                    raise CandidateError('retained candidate has another immutable binding')
                if submission_intent is not None:self._authorize_submission(connection,binding,submission_intent,actor)
                return digest
            self._current_task(connection, binding)
            if submission_intent is not None:self._authorize_submission(connection,binding,submission_intent,actor)
            connection.execute('INSERT INTO candidate_objects VALUES (?,?,?)', (self.database.domain, digest, raw))
            self.database._audit(connection, 'candidate_registered', actor, {'candidateDigest':digest})
        return digest

    def _authorize_submission(self,connection,binding,value,actor):
        # Check again AFTER the potentially long full readback/fsync, adjacent
        # to the actual registration. Early reservation approval cannot cover
        # a grant revoked or expired during candidate preparation.
        from .qualification import NativeQualification
        intent=codec.parse(encode_preparation_intent(value))
        if (intent['action']!='submit' or intent['parameters']['candidateDigest']!=codec.digest(binding)
                or any(intent[name]!=binding[name] for name in ('taskKey','taskRevision','taskCycle','policyDigest'))
                or intent['toolDigest']!=self.tool_digest or intent['policyDigest']!=self.policy_digest
                or not isinstance(self.check_qualification,NativeQualification)
                or self.check_qualification.action_authorizer is None):
            raise CandidateError('installed action-specific submission authorization required')
        self._check_preparation_dispatch(connection,intent)
        target=self._target(connection,intent['resourceId'],intent['resourceInstance'])
        epoch=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0]
        checked=self.check_qualification.action_authorizer(connection,'submit',actor,epoch,
            dict(intent=intent,plan=dict(beforeCandidateDigest=target['candidate_digest']),
                 integrationReceipt=None,qualificationRefs={}))
        self.database._audit(connection,'candidate_submission_authorized',actor,
            dict(requestDigest=codec.digest(intent),authorization=checked))

    def _check_preparation_dispatch(self,connection,intent):
        stable=(self.database.domain,intent['resourceId'],intent['action'],intent['businessActionId'])
        original=connection.execute('SELECT b.*,p.request_digest,p.payload_json FROM business_actions b JOIN action_payloads p USING(authority_domain,resource_id,action_class,business_id) WHERE b.authority_domain=? AND b.resource_id=? AND b.action_class=? AND b.business_id=?',stable).fetchone()
        reservations=[tuple(row) for row in connection.execute('SELECT budget_id,cost FROM reservations WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=? ORDER BY budget_id',stable)]
        if (not original or original['state'] not in ('dispatched','unknown')
                or original['request_digest']!=codec.digest(intent) or original['payload_json'].encode()!=codec.canonical(intent)
                or original['original_actor']!=intent['originalActor']
                or (original['project_id'],original['change_id'],original['task_id'],original['cycle'])
                !=(*(intent['taskKey'][name] for name in ('projectId','changeId','taskId')),intent['taskCycle'])
                or reservations!=[(budget,intent['cost']) for budget in intent['budgetIds']]):
            raise CandidateError('actual immutable dispatch and original budget reservation required')

    def _candidate(self, connection, digest, *, current=False):
        _digest(digest)
        row = connection.execute('SELECT binding_json FROM candidate_objects WHERE authority_domain=? AND candidate_digest=?', (self.database.domain, digest)).fetchone()
        if not row:
            raise CandidateError('candidate was not registered after complete materialization')
        binding = self.candidates.verify(digest)
        if codec.canonical(binding).decode() != row['binding_json']:
            raise CandidateError('stored registration and actual candidate disagree')
        if current:
            self._current_task(connection, binding)
        return binding

    def install_target(self, resource, instance, initial, *, actor, now, authorize):
        resource, instance, initial = _id(resource), _id(instance), _digest(initial)
        with self.database.transaction('version_target_install', actor, now, authorize) as connection:
            self._candidate(connection, initial)
            connection.execute('INSERT INTO version_targets VALUES (?,?,?,1,?,?)', (self.database.domain, resource, instance, initial, initial))
            self.database._audit(connection, 'version_target_installed', actor,
                                 {'resourceId':resource, 'resourceInstance':instance, 'candidateDigest':initial, 'generation':1})

    def _target(self, connection, resource, instance):
        row = connection.execute('SELECT * FROM version_targets WHERE authority_domain=? AND resource_id=?', (self.database.domain, _id(resource))).fetchone()
        if not row or row['resource_instance'] != _id(instance):
            raise CandidateError('resource target instance differs from its installed identity')
        return dict(row)

    def _create_plan(self, connection, resource, instance, generation, after, deletion_reasons, actor, rollback=None, integration=None):
        target = self._target(connection, resource, instance)
        if target['generation'] != _integer(generation, 1):
            raise CandidateError('version target generation changed before planning')
        if after == target['candidate_digest']:
            raise CandidateError('version switch must change the candidate reference')
        before_binding = self._candidate(connection, target['candidate_digest'])
        after_binding = self._candidate(connection, after, current=True)
        plan = dict(contractIdentity='das-version-tree-plan/v1',
            taskKey=after_binding['taskKey'], taskRevision=after_binding['taskRevision'], taskCycle=after_binding['taskCycle'],
            resourceId=resource, resourceInstance=instance, expectedGeneration=generation,
            beforeCandidateDigest=target['candidate_digest'], afterCandidateDigest=after,
            policyDigest=self.policy_digest, toolDigest=self.tool_digest, rollbackOf=rollback,
            changes=_changes(before_binding, after_binding, self.ownership, deletion_reasons))
        if integration is not None:
            source, refs = integration
            source_binding = self._candidate(connection, source, current=True)
            if any(source_binding[name] != after_binding[name] for name in
                   ('taskKey', 'taskRevision', 'taskCycle', 'obligationDigest', 'policyDigest')):
                raise CandidateError('source C and actual I bind different current obligations')
            plan.update(contractIdentity='das-integration-plan/v1', sourceCandidateDigest=source,
                        obligationDigest=after_binding['obligationDigest'], **refs)
        validator = INTEGRATION_PLAN_VALIDATOR if integration is not None else PLAN_VALIDATOR
        validator.validate(plan)
        raw = codec.canonical(plan)
        digest = _hash(raw)
        existing = connection.execute('SELECT payload_json FROM version_plans WHERE authority_domain=? AND plan_digest=?', (self.database.domain, digest)).fetchone()
        if existing:
            if existing['payload_json'].encode() != raw:
                raise CandidateError('version plan identity conflict')
        else:
            connection.execute('INSERT INTO version_plans VALUES (?,?,?,?,?,?,?)',
                (self.database.domain, digest, resource, instance, target['candidate_digest'], after, raw.decode()))
            self.database._audit(connection, 'version_plan_created', actor, {'planDigest':digest})
        return digest, plan

    def create_plan(self, resource, instance, generation, after, *, deletion_reasons, actor, now, authorize,
                    qualification_refs=None, preparation_intent=None, rollback_of=None):
        with self.database.transaction('version_plan', actor, now, authorize) as connection:
            if rollback_of is not None:
                self._rollback_receipt(connection,resource,instance,generation,rollback_of,after)
            digest,plan=self._create_plan(connection, resource, instance, generation, after, deletion_reasons, actor,rollback=rollback_of)
            if preparation_intent is not None:
                intent=codec.parse(encode_preparation_intent(preparation_intent))
                if (intent['action']!='plan' or intent['parameters']['plan']!=plan
                        or intent['parameters']['qualificationRefs']!=_qualification_refs(qualification_refs)
                        or any(intent[name]!=plan[name] for name in ('taskKey','taskRevision','taskCycle','resourceId','resourceInstance','toolDigest','policyDigest'))
                        or intent['targetGeneration']!=plan['expectedGeneration']):
                    raise CandidateError('creation request differs from the actual version plan')
                self._check_preparation_dispatch(connection,intent)
                self._qualify(connection,'plan',actor,plan,qualification_refs,intent)
            return digest,plan

    def _rollback_receipt(self,connection,resource,instance,generation,receipt_digest,after):
        row=connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND native_digest=?',
            (self.database.domain,resource,_digest(receipt_digest))).fetchone()
        if row is None:raise CandidateError('rollback requires its retained native forward receipt')
        receipt=self._read_receipt(row)
        target=self._target(connection,resource,instance)
        if (receipt['resourceInstance']!=instance or receipt['afterGeneration']!=generation
                or receipt['afterCandidateDigest']!=target['candidate_digest'] or target['generation']!=generation):
            raise CandidateError('rollback must preserve subsequent references and exact forward postimage')
        if receipt['beforeCandidateDigest']==after:
            return  # Original identity; the caller still verifies its current task/tree.
        # A separately approved compensation task may restore the same retained
        # snapshot under a new task/obligation/current-policy binding. Compare
        # the WHOLE original source/archive/file/material identity, not just a
        # tree hash or changed paths; never rewrite the historical candidate.
        # _create_plan/switch still require the after binding's current task,
        # lease, native grant and purpose-specific verification.
        historical=self._candidate(connection,receipt['beforeCandidateDigest'])
        restored=self._candidate(connection,after,current=True)
        rebound={'taskKey','taskRevision','taskCycle','obligationDigest','policyDigest'}
        if ({name:value for name,value in historical.items() if name not in rebound}
                != {name:value for name,value in restored.items() if name not in rebound}):
            raise CandidateError('rollback compensation must restore the exact retained source/archive/material snapshot')

    def _qualify(self, connection, phase, actor, plan, refs, intent=None, receipt=None):
        if self.check_qualification is None:
            raise CandidateError('integration requires an installed current qualification predicate')
        # Only an installed, bounded local read predicate may consume the actual
        # driver/signed evidence, current plan/Decision, trust and lineage. It
        # must not execute candidate code, send network requests or write state.
        # Context is a separate exact copy, preventing mutation of the CAS plan.
        version=plan['contractIdentity']=='das-version-tree-plan/v1'
        lineage = (dict(versionPlanDigest=codec.digest(plan),beforeCandidateDigest=plan['beforeCandidateDigest'],
            afterCandidateDigest=plan['afterCandidateDigest'],rollbackOf=plan['rollbackOf']) if version else
            self.candidates.integration_lineage(plan['beforeCandidateDigest'],
            plan['sourceCandidateDigest'],plan['afterCandidateDigest'],tool_digest=self.tool_digest))
        if version:
            # The protected task row, never a loader/caller, fixes its obligation.
            key=TaskKey(*(plan['taskKey'][name] for name in ('authorityDomain','projectId','changeId','taskId')))
            row=connection.execute('SELECT obligation_digest FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
            if row is None:raise CandidateError('actual current task obligation required')
            obligation=row['obligation_digest']
        context = codec.parse(codec.canonical(dict(plan=plan, qualificationRefs=refs, intent=intent,
            integrationReceipt=receipt, lineage=lineage, **({'obligationDigest':obligation} if version else {}))))
        epoch = connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0]
        checked = self.check_qualification(connection, phase, actor, epoch, context)
        if checked is True:
            return  # compatibility with existing staging predicates, not deployment admission
        if not isinstance(checked, dict):
            raise CandidateError('current action-specific integration qualification denied')
        codec.closed_object(checked, ['authorization'])
        authorization = checked['authorization']
        codec.closed_object(authorization, ['checkedRefs', 'grantEnvelopeDigest',
            'parentEnvelopeDigests', 'controlContextDigest'])
        refs = authorization['checkedRefs']
        codec.closed_object(refs, ['authorizationId', 'principals', 'keyFingerprints',
            'authorityEpoch', 'authorizationGeneration', 'ancestorIds'])
        if phase not in ('plan', 'apply', 'rollback', 'integrate', 'complete') or refs['authorityEpoch'] != epoch:
            raise CandidateError('native grant references do not bind the current action epoch')
        # The manager, not its read predicate, appends the checked original
        # grant references in the SAME transaction as the actual effect/Completion.
        # A failed CAS or completion insert rolls this event back too.
        self.database._audit(connection, 'version_action_authorized', actor,
            dict(action=phase, taskKey=plan['taskKey'], businessActionId=intent['businessActionId'],
                planDigest=codec.digest(plan), authorization=authorization))

    def create_integration_plan(self, resource, instance, generation, source, integrated, *,
                                qualification_refs, deletion_reasons, actor, now, authorize, preparation_intent=None):
        refs = _qualification_refs(qualification_refs)
        _digest(source)
        with self.database.transaction('integration_plan', actor, now, authorize) as connection:
            digest, plan = self._create_plan(connection, resource, instance, generation, integrated,
                deletion_reasons, actor, integration=(source, refs))
            intent=None
            if preparation_intent is not None:
                intent=codec.parse(encode_preparation_intent(preparation_intent))
                codec.closed_object(intent['parameters'],['plan'])
                if (intent['action']!='plan' or intent['parameters']['plan']!=plan
                        or any(intent[name]!=plan[name] for name in ('taskKey','taskRevision','taskCycle','resourceId','resourceInstance','toolDigest','policyDigest'))
                        or intent['targetGeneration']!=plan['expectedGeneration']):
                    raise CandidateError('creation request differs from actual complete integration plan')
                self._check_preparation_dispatch(connection,intent)
            self._qualify(connection, 'plan', actor, plan, refs,intent)
            return digest, plan

    def _read_receipt(self, row):
        raw = row['native_bytes']
        receipt = codec.parse(raw)
        integration = receipt.get('contractIdentity') == 'das-integration-receipt/v1'
        (INTEGRATION_RECEIPT_VALIDATOR if integration else RECEIPT_VALIDATOR).validate(receipt)
        if (_hash(raw) != row['native_digest'] or codec.canonical(receipt) != raw
                or tuple(receipt[name] for name in ('authorityDomain', 'resourceId', 'action', 'businessActionId',
                     'resourceInstance', 'requestDigest', 'planDigest', 'beforeGeneration', 'afterGeneration',
                     'beforeCandidateDigest', 'afterCandidateDigest')) != tuple(row[name] for name in
                     ('authority_domain', 'resource_id', 'action_class', 'business_id', 'resource_instance',
                      'request_digest', 'plan_digest', 'before_generation', 'after_generation', 'before_candidate', 'after_candidate'))):
            raise CandidateError('native version switch receipt binding mismatch')
        if integration:
            plan = self._plan(self.database.connection, receipt['planDigest'])
            if plan['contractIdentity'] != 'das-integration-plan/v1' or any(
                    receipt[name] != plan[name] for name in
                    ('taskKey', 'taskRevision', 'taskCycle', 'obligationDigest', 'policyDigest', 'toolDigest', 'sourceCandidateDigest', *QUALIFICATION_REFS)):
                raise CandidateError('actual integration receipt lost its C/I/verification/Decision binding')
        return receipt

    def create_rollback_plan(self, resource, instance, forward_action, forward_business, generation, *,
                             deletion_reasons, actor, now, authorize):
        with self.database.transaction('version_rollback_plan', actor, now, authorize) as connection:
            row = connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',
                                     (self.database.domain, _id(resource), _id(forward_action), _id(forward_business))).fetchone()
            if not row:
                raise CandidateError('rollback requires a retained native forward receipt')
            receipt = self._read_receipt(row)
            target = self._target(connection, resource, instance)
            if (target['generation'] != generation or generation != receipt['afterGeneration']
                    or target['candidate_digest'] != receipt['afterCandidateDigest'] or instance != receipt['resourceInstance']):
                raise CandidateError('rollback postimage/generation conflict; preserve subsequent edits and references')
            return self._create_plan(connection, resource, instance, generation, receipt['beforeCandidateDigest'],
                                     deletion_reasons, actor, row['native_digest'])

    def _plan(self, connection, digest):
        row = connection.execute('SELECT * FROM version_plans WHERE authority_domain=? AND plan_digest=?', (self.database.domain, _digest(digest))).fetchone()
        if not row:
            raise CandidateError('no retained immutable version plan')
        raw = row['payload_json'].encode()
        plan = codec.parse(raw)
        (INTEGRATION_PLAN_VALIDATOR if plan.get('contractIdentity') == 'das-integration-plan/v1' else PLAN_VALIDATOR).validate(plan)
        if (codec.canonical(plan) != raw or _hash(raw) != digest or
                (plan['resourceId'], plan['resourceInstance'], plan['beforeCandidateDigest'], plan['afterCandidateDigest']) !=
                (row['resource_id'], row['resource_instance'], row['before_candidate'], row['after_candidate'])):
            raise CandidateError('retained version plan identity/binding mismatch')
        for name in ('taskRevision', 'taskCycle', 'expectedGeneration'):
            plan[name] = codec.safe_integer(plan[name])
        return plan

    def switch_http(self, intent, *, if_match, actor, now, authorize):
        """Exact strong tag plus native instance/generation fencing at SQL CAS.

        This profile supports one explicit tag. Authorized historical replay
        checks the original tag and returns the original receipt without effect.
        """
        if (not isinstance(if_match, str) or len(if_match) != 73
                or not if_match.startswith('"sha256:') or not if_match.endswith('"')):
            raise CandidateError('HTTP reference requires one exact strong candidate tag')
        _digest(if_match[1:-1])
        if not isinstance(intent, dict) or intent.get('action') != 'integrate':
            raise CandidateError('HTTP reference only supports qualified integration')
        return self.switch(intent, actor=actor, now=now, authorize=authorize,
                           http_condition=if_match)

    def switch(self, value, *, actor, now, authorize, http_condition=None):
        # The only executable operand is the exact retained plan digest. There
        # is no caller-controlled destination, file content, argv or extra args.
        raw_intent = encode_intent(value)
        intent = codec.parse(raw_intent)
        codec.closed_object(intent['parameters'], ('planDigest','qualificationRefs')
            if intent['action'] in ('apply','rollback') and 'qualificationRefs' in intent['parameters'] else ('planDigest',))
        digest = _digest(intent['parameters']['planDigest'])
        if intent['action'] not in ('apply', 'rollback', 'integrate'):
            raise CandidateError('unsupported version resource action')
        if intent['taskKey']['authorityDomain'] != self.database.domain:
            raise CandidateError('version action authority domain mismatch')
        stable = (self.database.domain, intent['resourceId'], intent['action'], intent['businessActionId'])
        request_digest = _hash(raw_intent)
        with self.database.transaction('version_' + intent['action'], actor, now, authorize) as connection:
            payload = connection.execute('SELECT request_digest,payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
            if not payload or payload['request_digest'] != request_digest or payload['payload_json'].encode() != raw_intent:
                raise CandidateError('version mutation requires the exact previously committed action intent')
            existing = connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
            if existing:
                retained = self._read_receipt(existing)
                if http_condition is not None and http_condition != '"'+retained['beforeCandidateDigest']+'"':
                    raise CandidateError('HTTP condition does not bind the original resource action')
                if existing['request_digest'] != request_digest:
                    raise CandidateError('original version business key already has another request')
                return existing['native_bytes']
            action = connection.execute('SELECT * FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
            if not action or action['state'] not in ('dispatched', 'unknown'):
                raise CandidateError('durable dispatch intent must precede the version resource boundary')
            plan = self._plan(connection, digest)
            integration = intent['action'] == 'integrate'
            if integration != (plan['contractIdentity'] == 'das-integration-plan/v1'):
                raise CandidateError('apply/rollback cannot substitute for qualified I integration')
            if (intent['resourceId'], intent['resourceInstance'], intent['targetGeneration'], intent['taskKey'],
                    intent['taskRevision'], intent['taskCycle'], intent['policyDigest'], intent['toolDigest']) != (
                    plan['resourceId'], plan['resourceInstance'], plan['expectedGeneration'], plan['taskKey'],
                    plan['taskRevision'], plan['taskCycle'], plan['policyDigest'], plan['toolDigest']):
                raise CandidateError('current action does not bind the exact version plan')
            if (plan['toolDigest'], plan['policyDigest']) != (self.tool_digest, self.policy_digest):
                raise CandidateError('version plan no longer matches installed tool/policy')
            if (intent['action'] == 'rollback') != (plan['rollbackOf'] is not None):
                raise CandidateError('forward and rollback plan purposes differ')
            target = self._target(connection, intent['resourceId'], intent['resourceInstance'])
            if http_condition is not None and http_condition != '"'+target['candidate_digest']+'"':
                raise CandidateError('HTTP condition failed at the actual target commit boundary')
            if (target['generation'], target['candidate_digest']) != (plan['expectedGeneration'], plan['beforeCandidateDigest']):
                raise CandidateError('conditional version switch failed; regenerate against the current target')
            before = self._candidate(connection, plan['beforeCandidateDigest'])
            after = self._candidate(connection, plan['afterCandidateDigest'], current=True)
            reasons = {item['path']:item['deletionReason'] for item in plan['changes'] if item['postimage'] is None}
            if _changes(before, after, self.ownership, reasons) != plan['changes']:
                raise CandidateError('plan preimage/postimage/ownership no longer matches the complete trees')
            if integration:
                source = self._candidate(connection, plan['sourceCandidateDigest'], current=True)
                if (any(source[name] != after[name] for name in ('taskKey', 'taskRevision', 'taskCycle', 'obligationDigest', 'policyDigest'))
                        or plan['obligationDigest'] != after['obligationDigest']):
                    raise CandidateError('source C and actual I no longer bind the same current task')
                self._qualify(connection, 'integrate', actor, plan,
                              {name:plan[name] for name in QUALIFICATION_REFS}, intent)
            elif self.check_qualification is not None:
                if not isinstance(self.check_qualification,NativeQualification):
                    raise CandidateError('installed native qualification required for governed version switches')
                if intent['action']=='rollback':
                    self._rollback_receipt(connection,intent['resourceId'],intent['resourceInstance'],
                        plan['expectedGeneration'],plan['rollbackOf'],plan['afterCandidateDigest'])
                self._qualify(connection,intent['action'],actor,plan,
                    _qualification_refs(intent['parameters'].get('qualificationRefs')),intent)
            changed = connection.execute('UPDATE version_targets SET candidate_digest=?,generation=generation+1 WHERE authority_domain=? AND resource_id=? AND resource_instance=? AND generation=? AND candidate_digest=?',
                (plan['afterCandidateDigest'], self.database.domain, intent['resourceId'], intent['resourceInstance'],
                 plan['expectedGeneration'], plan['beforeCandidateDigest']))
            if changed.rowcount != 1:
                raise CandidateError('version target CAS updated zero or multiple rows')
            receipt = dict(contractIdentity='das-version-switch-receipt/v1', authorityDomain=self.database.domain,
                resourceId=intent['resourceId'], resourceInstance=intent['resourceInstance'], action=intent['action'],
                businessActionId=intent['businessActionId'], requestDigest=request_digest, planDigest=digest,
                beforeCandidateDigest=plan['beforeCandidateDigest'], afterCandidateDigest=plan['afterCandidateDigest'],
                beforeGeneration=plan['expectedGeneration'], afterGeneration=plan['expectedGeneration'] + 1,
                rollbackOf=plan['rollbackOf'], executingActor=actor,
                authorityEpoch=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0],
                committedAt=now, committed=True, authority=False, qualification=False)
            if integration:
                receipt.update(contractIdentity='das-integration-receipt/v1',
                    **{name:plan[name] for name in ('taskKey', 'taskRevision', 'taskCycle', 'obligationDigest',
                       'policyDigest', 'toolDigest', 'sourceCandidateDigest', *QUALIFICATION_REFS)})
            (INTEGRATION_RECEIPT_VALIDATOR if integration else RECEIPT_VALIDATOR).validate(receipt)
            raw = codec.canonical(receipt)
            connection.execute('INSERT INTO version_switch_receipts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                (*stable, intent['resourceInstance'], request_digest, digest, plan['expectedGeneration'],
                 plan['expectedGeneration'] + 1, plan['beforeCandidateDigest'], plan['afterCandidateDigest'], raw, _hash(raw)))
            self.database._audit(connection, 'version_reference_switched', actor,
                                 {'key':list(stable), 'planDigest':digest, 'nativeReceiptDigest':_hash(raw)})
            return raw

    def _check_completion_request(self, connection, value, stable, receipt_digest, generation, refs):
        if value is None:
            return  # existing trusted local API; authenticated transport supplies the full intent
        requested = codec.parse(encode_intent(value))
        payload = connection.execute('SELECT request_digest,payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
        if not payload:
            raise CandidateError('completion request has no original durable integration intent')
        raw = payload['payload_json'].encode()
        original = codec.parse(raw)
        if encode_intent(original) != raw or _hash(raw) != payload['request_digest']:
            raise CandidateError('original completion request subject failed exact readback')
        expected = dict(original, action='complete', targetGeneration=generation,
            parameters=dict(integrationReceiptDigest=receipt_digest, qualificationRefs=refs))
        if codec.canonical(requested) != codec.canonical(expected):
            raise CandidateError('completion request differs from its original action/receipt/references')

    def complete_analysis(self, value, *, actor, now, authorize):
        """A01.2: one authorized SQL effect, without an integration surrogate.

        The immutable task-creation event approves analysis and its check scope.
        Budget, exact request, original evidence, native completion and the SAME
        unique task/cycle row commit atomically. No target switch or external
        dispatch occurs, so no additional outbox or fake integration is needed.
        """
        intent=codec.parse(encode_preparation_intent(value))
        codec.closed_object(intent['parameters'],['analysisPlan','qualificationRefs'])
        plan=intent['parameters']['analysisPlan']; ANALYSIS_PLAN_VALIDATOR.validate(plan)
        refs=_qualification_refs(intent['parameters']['qualificationRefs'])
        binding=plan['bindings']; key=TaskKey(*(intent['taskKey'][name] for name in
            ('authorityDomain','projectId','changeId','taskId')))
        stable=(self.database.domain,intent['resourceId'],'complete',intent['businessActionId'])
        if (intent['action']!='complete' or intent['originalActor']!=actor
                or intent['policyDigest']!=self.policy_digest or intent['toolDigest']!=self.tool_digest
                or codec.digest(plan)!=refs['verificationPlanDigest']
                or any(binding[name]!=intent[name] for name in ('taskKey','taskRevision','taskCycle',
                    'resourceId','resourceInstance','targetGeneration','toolDigest','policyDigest'))):
            raise CandidateError('analysis completion differs from its original task/plan/request')
        from .qualification import NativeQualification
        if (not isinstance(self.check_qualification,NativeQualification)
                or self.check_qualification.action_authorizer is None
                or self.check_qualification.verification_inputs is None):
            raise CandidateError('analysis requires installed native evidence and current authorization')
        with self.database.transaction('analysis_complete',actor,now,authorize) as connection:
            definition=self.database.analysis_task_binding(connection,key,cycle=intent['taskCycle'])
            ANALYSIS_TASK_VALIDATOR.validate(definition)
            if (codec.digest(definition)!=binding['taskBindingDigest']
                    or definition['verificationScopeDigest']!=analysis_scope_digest(plan)
                    or any(definition[name]!=binding[name] for name in
                        ('taskKey','taskRevision','taskCycle','obligationDigest','policyDigest','completionMode'))):
                raise CandidateError('analysis checks differ from immutable task-creation approval')
            old=connection.execute('SELECT native_bytes,native_digest FROM completion_bindings WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',
                (*key.values(),intent['taskCycle'])).fetchone()
            if old:
                completed=codec.parse(old['native_bytes']); ANALYSIS_COMPLETION_VALIDATOR.validate(completed)
                fact=connection.execute('SELECT * FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*key.values(),intent['taskCycle'])).fetchone()
                request=connection.execute('SELECT payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
                observed=connection.execute('SELECT native_bytes FROM resource_observations WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=? AND native_digest=?',(*stable,old['native_digest'])).fetchone()
                if (codec.canonical(completed)!=old['native_bytes'] or _hash(old['native_bytes'])!=old['native_digest']
                        or completed['requestDigest']!=codec.digest(intent) or not request
                        or request['payload_json'].encode()!=codec.canonical(intent) or not fact
                        or fact['evidence_digest']!=old['native_digest'] or fact['receipt_digest']!=old['native_digest']
                        or not observed or observed['native_bytes']!=old['native_bytes']):
                    raise CandidateError('task/cycle already has a different immutable completion')
                return old['native_bytes']
            source=self._candidate(connection,binding['sourceCandidateDigest'])
            self._current_task(connection,source,allowed=('active','closing'))
            if any(source[name]!=binding[name] for name in ('taskKey','taskRevision','taskCycle','obligationDigest','policyDigest')):
                raise CandidateError('analysis source does not bind the current task/cycle')
            target=self._target(connection,intent['resourceId'],intent['resourceInstance'])
            self._candidate(connection,target['candidate_digest'])
            if (target['generation'],target['candidate_digest'])!=(binding['targetGeneration'],binding['baselineCandidateDigest']):
                raise CandidateError('analysis baseline changed before completion')
            lineage=dict(sourceCandidateDigest=binding['sourceCandidateDigest'],taskBindingDigest=codec.digest(definition))
            if binding['lineageDigest']!=codec.digest(lineage):
                raise CandidateError('analysis lineage differs from the actual source and approval')
            if connection.execute("SELECT 1 FROM business_actions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=? AND action_class NOT IN ('inspect','audit') AND state IN ('reserved','dispatched','unknown') LIMIT 1",(*key.values(),intent['taskCycle'])).fetchone():
                raise CandidateError('analysis completion cannot hide an unresolved business action')
            epoch=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0]
            checked=self.check_qualification(connection,'complete',actor,epoch,
                dict(plan=plan,qualificationRefs=refs,intent=intent,integrationReceipt=None,lineage=lineage))
            codec.closed_object(checked,['authorization'])
            row=self.database._reserve(connection,key,resource_id=intent['resourceId'],action_class='complete',
                business_id=intent['businessActionId'],original_actor=actor,request_digest=codec.digest(intent),
                budget_ids=intent['budgetIds'],cost=intent['cost'],cycle=intent['taskCycle'],actor=actor,payload=codec.canonical(intent),parent_allowed=('active','closing'))
            if row['state']!='reserved': raise CandidateError('analysis action has an unresolved prior state')
            parent=self.database._parent(connection,key,allowed=('active','closing'))
            completion=dict(contractIdentity='das-analysis-completion/v1',completionMode='analysis',
                taskKey=intent['taskKey'],taskRevision=intent['taskRevision'],taskCycle=intent['taskCycle'],
                obligationDigest=source['obligationDigest'],taskBindingDigest=codec.digest(definition),
                parentChange={name:parent[column] for name,column in (('status','status'),('generation','generation'),('taskSetDigest','task_set_digest'))},
                policyDigest=self.policy_digest,sourceCandidateDigest=binding['sourceCandidateDigest'],
                resourceId=intent['resourceId'],resourceInstance=intent['resourceInstance'],targetGeneration=intent['targetGeneration'],
                businessActionId=intent['businessActionId'],requestDigest=codec.digest(intent),completedAt=now,
                authorityEpoch=epoch,authority=False,qualification=False,**refs)
            ANALYSIS_COMPLETION_VALIDATOR.validate(completion);raw=codec.canonical(completion);digest=_hash(raw)
            connection.execute("UPDATE business_actions SET state='confirmed',receipt_digest=? WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=? AND state='reserved'",(digest,*stable))
            connection.execute('INSERT INTO resource_observations VALUES (?,?,?,?,?,?,?)',(*stable,digest,'confirmed',raw))
            self.database._record_completion(connection,key,cycle=intent['taskCycle'],revision=intent['taskRevision'],
                resource_id=intent['resourceId'],action_class='complete',business_id=intent['businessActionId'],
                receipt_digest=digest,evidence_digest=digest,actor=actor)
            connection.execute('INSERT INTO completion_bindings VALUES (?,?,?,?,?,?,?)',(*key.values(),intent['taskCycle'],raw,digest))
            self.database._audit(connection,'analysis_completion_bound',actor,
                dict(taskKey=intent['taskKey'],cycle=intent['taskCycle'],nativeCompletionDigest=digest,authorization=checked['authorization']))
            return raw

    def complete_integration(self, key, *, cycle, revision, resource, instance, business,
                             qualification_refs, actor, now, authorize, completion_request=None):
        refs = _qualification_refs(qualification_refs)
        _integer(cycle, 1); _integer(revision, 1)
        stable = (self.database.domain, _id(resource), 'integrate', _id(business))
        _id(instance)
        with self.database.transaction('integration_complete', actor, now, authorize) as connection:
            old = connection.execute('SELECT native_bytes,native_digest FROM completion_bindings WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',
                                     (*key.values(), cycle)).fetchone()
            if old:
                value = codec.parse(old['native_bytes']); COMPLETION_VALIDATOR.validate(value)
                retained = connection.execute('SELECT evidence_digest,receipt_digest FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',
                                              (*key.values(), cycle)).fetchone()
                if (codec.canonical(value) != old['native_bytes'] or _hash(old['native_bytes']) != old['native_digest']
                        or value['taskKey'] != dict(zip(('authorityDomain','projectId','changeId','taskId'),key.values()))
                        or value['taskCycle'] != cycle or not retained or retained['evidence_digest'] != old['native_digest']
                        or retained['receipt_digest'] != value['integrationReceiptDigest']
                        or (value['taskRevision'], value['resourceId'], value['resourceInstance'], value['businessActionId'])
                        != (revision, resource, instance, business)
                        or any(value[name] != refs[name] for name in QUALIFICATION_REFS)):
                    raise CandidateError('completed task/cycle already has another immutable integration result')
                # Authorized historical replay returns original bytes, including
                # original time/parent. It confers no new present qualification.
                self._check_completion_request(connection, completion_request, stable,
                    value['integrationReceiptDigest'], value['targetGeneration'], refs)
                return value
            row = connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
            if not row:
                raise CandidateError('Completion requires an actual native integration receipt')
            receipt = self._read_receipt(row)
            plan = self._plan(connection, receipt['planDigest'])
            if (plan['toolDigest'], plan['policyDigest']) != (self.tool_digest, self.policy_digest):
                raise CandidateError('completion plan no longer matches the installed tool/policy')
            expected_key = dict(zip(('authorityDomain','projectId','changeId','taskId'), key.values()))
            if (receipt['contractIdentity'] != 'das-integration-receipt/v1' or receipt['taskKey'] != expected_key
                    or (receipt['taskRevision'], receipt['taskCycle'], receipt['resourceInstance']) != (revision, cycle, instance)):
                raise CandidateError('integration receipt does not bind this task/revision/cycle/instance')
            target = self._target(connection, resource, instance)
            if (target['candidate_digest'], target['generation']) != (receipt['afterCandidateDigest'], receipt['afterGeneration']):
                raise CandidateError('current target moved after integration; Completion is not established')
            integrated = self._candidate(connection, receipt['afterCandidateDigest'])
            self._current_task(connection, integrated, allowed=('active','closing'))
            self._candidate(connection, receipt['sourceCandidateDigest'])
            observation = connection.execute('SELECT outcome,native_bytes FROM resource_observations WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=? AND native_digest=?',
                                             (*stable, row['native_digest'])).fetchone()
            if not observation or observation['outcome'] != 'confirmed' or observation['native_bytes'] != row['native_bytes']:
                raise CandidateError('original resource result must be reconciled before Completion')
            payload = connection.execute('SELECT payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?', stable).fetchone()
            if not payload:
                raise CandidateError('Completion requires the original durable integration intent')
            raw_intent = payload['payload_json'].encode(); intent = codec.parse(raw_intent)
            if encode_intent(intent) != raw_intent or _hash(raw_intent) != receipt['requestDigest']:
                raise CandidateError('original integration intent no longer matches its native receipt')
            self._check_completion_request(connection, completion_request, stable,
                row['native_digest'], receipt['afterGeneration'], refs)
            self._qualify(connection, 'complete', actor, plan, refs, intent, receipt)
            parent = self.database._parent(connection, key)
            completion = dict(contractIdentity='das-completion/v1', taskKey=expected_key,
                taskRevision=revision, taskCycle=cycle, obligationDigest=integrated['obligationDigest'],
                parentChange={name:parent[column] for name,column in
                              (('status','status'),('generation','generation'),('taskSetDigest','task_set_digest'))},
                policyDigest=self.policy_digest, sourceCandidateDigest=receipt['sourceCandidateDigest'],
                integrationCandidateDigest=receipt['afterCandidateDigest'], resourceId=resource,
                resourceInstance=instance, targetGeneration=receipt['afterGeneration'], businessActionId=business,
                integrationReceiptDigest=row['native_digest'], completedAt=now,
                authorityEpoch=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0],
                authority=False, qualification=False, **refs)
            COMPLETION_VALIDATOR.validate(completion)
            raw = codec.canonical(completion); digest = _hash(raw)
            self.database._record_completion(connection, key, cycle=cycle, revision=revision,
                resource_id=resource, action_class='integrate', business_id=business,
                receipt_digest=row['native_digest'], evidence_digest=digest, actor=actor)
            connection.execute('INSERT INTO completion_bindings VALUES (?,?,?,?,?,?,?)', (*key.values(), cycle, raw, digest))
            self.database._audit(connection, 'integration_completion_bound', actor,
                {'taskKey':expected_key, 'cycle':cycle, 'nativeCompletionDigest':digest})
            return codec.parse(raw)

    def _reverification_context(self, connection, key, resource, instance, completion_digest):
        self.database._parent(connection,key,allowed=('active','closing','closed'))
        completed,revision_bindings=self.database.current_completion(connection,key,with_bindings=True)
        native=connection.execute('SELECT native_bytes,native_digest FROM completion_bindings WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',
            (*key.values(),completed['cycle'] if completed else 0)).fetchone()
        if (not completed or not native or native['native_digest']!=_digest(completion_digest)
                or completed['evidence_digest']!=completion_digest or _hash(native['native_bytes'])!=completion_digest):
            raise CandidateError('exact original native Completion required for verification')
        original=codec.parse(native['native_bytes'])
        analysis=original.get('contractIdentity')=='das-analysis-completion/v1'
        (ANALYSIS_COMPLETION_VALIDATOR if analysis else COMPLETION_VALIDATOR).validate(original)
        if (original['taskKey']!=dict(zip(('authorityDomain','projectId','changeId','taskId'),key.values()))
                or (original['taskCycle'],original['taskRevision'])!=(completed['cycle'],completed['revision'])):
            raise CandidateError('original Completion does not bind this task history')
        target=self._target(connection,resource,instance)
        retained_target=original.get('integrationCandidateDigest')
        if analysis:
            definition=self.database.analysis_task_binding(connection,key,revision=completed['revision'])
            payload=connection.execute('SELECT request_digest,payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',
                (self.database.domain,resource,'complete',original['businessActionId'])).fetchone()
            if not payload or payload['request_digest']!=original['requestDigest']:
                raise CandidateError('original analysis request and baseline required')
            retained=codec.parse(payload['payload_json'].encode()); plan=retained['parameters']['analysisPlan']
            ANALYSIS_PLAN_VALIDATOR.validate(plan)
            if (codec.digest(retained)!=original['requestDigest'] or codec.digest(plan)!=original['verificationPlanDigest']
                    or codec.digest(definition)!=original['taskBindingDigest']
                    or plan['bindings']['taskBindingDigest']!=original['taskBindingDigest']):
                raise CandidateError('analysis Completion lost its original approved baseline')
            retained_target=plan['bindings']['baselineCandidateDigest']
        if ((original['resourceId'],original['resourceInstance'])!=(resource,instance)
                or (original['targetGeneration'],retained_target)!=(target['generation'],target['candidate_digest'])
                or original['policyDigest']!=self.policy_digest):
            raise CandidateError('current target no longer satisfies the original Completion')
        self._candidate(connection,target['candidate_digest'])
        candidate=self._candidate(connection,original['sourceCandidateDigest'] if analysis else target['candidate_digest'])
        task=connection.execute('SELECT * FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
        if candidate['obligationDigest']!=task['obligation_digest'] or candidate['policyDigest']!=self.policy_digest:
            raise CandidateError('verification cannot change the original obligation or policy')
        return dict(completion=original,completionDigest=completion_digest,revisionBindings=revision_bindings,taskRevision=task['revision'],
            taskCycle=task['cycle'],obligationDigest=task['obligation_digest'],
            targetCandidateDigest=target['candidate_digest'],targetGeneration=target['generation'],
            toolDigest=self.tool_digest,policyDigest=self.policy_digest)

    def _review_reverification(self, connection, phase, actor, context):
        if self.check_reverification is None:
            raise CandidateError('independent verification service is not installed')
        epoch=connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0]
        raw=codec.canonical(context)
        with connection.approval():
            allowed=self.check_reverification(connection,phase,actor,epoch,context)
        if codec.canonical(context)!=raw:
            raise CandidateError('current verification-service authorization/plan/evidence denied')
        if allowed is True:return None  # existing finite staging control only
        if not isinstance(allowed,dict):
            raise CandidateError('current verification-service authorization/plan/evidence denied')
        codec.closed_object(allowed,['authorization'])
        authorization=allowed['authorization']
        codec.closed_object(authorization,['checkedRefs','grantEnvelopeDigest','parentEnvelopeDigests','controlContextDigest'])
        refs=authorization['checkedRefs']
        codec.closed_object(refs,['authorizationId','principals','keyFingerprints','authorityEpoch','authorizationGeneration','ancestorIds'])
        if refs['authorityEpoch']!=epoch:
            raise CandidateError('native verification grant no longer binds current authority')
        return authorization

    def start_reverification(self, key, *, resource, instance, business, completion_digest,
                           verification_plan_digest, budget_ids, cost, actor, now, authorize):
        """Reserve verification-only work BEFORE running the installed driver.

        Installed control owns the independent plan/grant/role and all test-space
        restrictions. Its readonly predicate validates this complete context.
        No Worker operation or existing integration/complete Decision maps here.
        Execution occurs outside the SQL transaction; a crash/failure retains cost
        and dispatched state. There is no automatic replay or refund.
        """
        with self.database.transaction('verification_start',actor,now,authorize) as connection:
            context=self._reverification_context(connection,key,resource,instance,completion_digest)
            _digest(verification_plan_digest)
            intent=dict(contractIdentity='das-resource-action-intent/v1',
                taskKey=dict(zip(('authorityDomain','projectId','changeId','taskId'),key.values())),
                taskRevision=context['taskRevision'],taskCycle=context['taskCycle'],resourceId=resource,
                resourceInstance=instance,targetGeneration=context['targetGeneration'],action='audit',
                businessActionId=business,originalActor=actor,toolDigest=self.tool_digest,policyDigest=self.policy_digest,
                budgetIds=budget_ids,cost=cost,parameters=dict(completionDigest=completion_digest,
                    verificationPlanDigest=verification_plan_digest,targetCandidateDigest=context['targetCandidateDigest']))
            raw=encode_intent(intent)
            authorization=self._review_reverification(connection,'plan',actor,dict(context,intent=intent))
            row=self.database._reserve(connection,key,resource_id=resource,action_class='audit',business_id=business,
                original_actor=actor,request_digest=_hash(raw),budget_ids=budget_ids,cost=cost,
                cycle=context['taskCycle'],actor=actor,payload=raw,parent_allowed=('active','closing','closed'))
            if row['state']=='reserved':
                self.database._transition_action(connection,(self.database.domain,resource,'audit',business),
                    'reserved','dispatched',None,None,None,actor,parent_allowed=('active','closing','closed'))
                if authorization is not None:
                    self.database._audit(connection,'verification_authorized',actor,
                        dict(action='audit',requestDigest=_hash(raw),completionDigest=completion_digest,authorization=authorization))
            return dict(intent=codec.parse(raw),state='dispatched' if row['state']=='reserved' else row['state'],
                newlyDispatched=row['state']=='reserved')

    def record_reverification(self, value, *, qualification_refs, actor, now, authorize):
        """Consume precollected originals; append a current result, never Completion.

        The installed service checks actual plan, action-specific Decision,
        signatures/provenance, current trust/time and original reports. A staging
        predicate is not native or deployment qualification. On refusal the
        separate start reservation remains spent; history/target stay unchanged.
        """
        raw=encode_intent(value);intent=codec.parse(raw);refs=_qualification_refs(qualification_refs)
        codec.closed_object(intent['parameters'],['completionDigest','verificationPlanDigest','targetCandidateDigest'])
        if intent['action']!='audit' or intent['originalActor']!=actor or refs['verificationPlanDigest']!=intent['parameters']['verificationPlanDigest']:
            raise CandidateError('exact verification-only action and original plan required')
        key=TaskKey(*(intent['taskKey'][n] for n in ('authorityDomain','projectId','changeId','taskId')))
        stable=(self.database.domain,intent['resourceId'],'audit',intent['businessActionId'])
        with self.database.transaction('verification_record',actor,now,authorize) as connection:
            context=self._reverification_context(connection,key,intent['resourceId'],intent['resourceInstance'],intent['parameters']['completionDigest'])
            if (any(intent[n]!=context[n] for n in ('taskRevision','taskCycle','targetGeneration','toolDigest','policyDigest'))
                    or intent['parameters']['targetCandidateDigest']!=context['targetCandidateDigest']):
                raise CandidateError('verification subject changed after reservation')
            row=connection.execute('SELECT * FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
            payload=connection.execute('SELECT payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
            if not row or not payload or payload['payload_json'].encode()!=raw or row['state'] not in ('dispatched','unknown','confirmed'):
                raise CandidateError('original dispatched verification reservation required')
            authorization=self._review_reverification(connection,'evidence',actor,dict(context,intent=intent,qualificationRefs=refs))
            result=dict(action='audit',requestDigest=_hash(raw),completionDigest=context['completionDigest'],
                taskRevision=context['taskRevision'],taskCycle=context['taskCycle'],
                targetGeneration=context['targetGeneration'],targetCandidateDigest=context['targetCandidateDigest'],
                authority=False,qualification=False,**refs)
            encoded=codec.canonical(result);digest=_hash(encoded)
            if row['state']=='confirmed':
                if row['receipt_digest']!=digest:raise CandidateError('verification already has another immutable result')
                return result
            self.database._transition_action(connection,stable,row['state'],'confirmed',digest,digest,encoded,actor)
            self.database._audit(connection,'completion_reverified',actor,
                dict(result,**({'authorization':authorization} if authorization is not None else {})))
            return result

    def lookup(self, resource, instance, action, business, *, actor, now, authorize):
        with self.database.transaction('version_lookup', actor, now, authorize) as connection:
            self._target(connection, resource, instance)
            row = connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',
                                     (self.database.domain, _id(resource), _id(action), _id(business))).fetchone()
            if row is None:
                return None  # absence alone does not prove the prior writer closed
            self._read_receipt(row)
            if row['resource_instance'] != instance:
                raise CandidateError('version receipt instance mismatch')
            return row['native_bytes']

    def read_target(self, resource, instance, *, actor, now, authorize):
        with self.database.transaction('version_read', actor, now, authorize) as connection:
            target = self._target(connection, resource, instance)
            self._candidate(connection, target['candidate_digest'])
            self.database._audit(connection, 'version_target_read', actor,
                                 {'resourceId':resource, 'resourceInstance':instance})
            return dict(resourceId=resource, resourceInstance=instance, generation=target['generation'],
                        candidateDigest=target['candidate_digest'], authority=False, qualification=False)
