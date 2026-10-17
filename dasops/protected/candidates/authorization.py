"""Installed grant consumer at the existing SQL resource boundaries.

The installer supplies original grants/trust/current revocation state. The
request, task, lease and target come from the manager's retained intent and SAME
writer transaction. No signing, network access or caller-supplied authority.
"""
from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import time

from dasops.bundle_preview import _run, pin_native, CadenceDependencyError
from dasops.standards_contracts import exact_json as codec
from dasops.protected.sqlite.store import _digest
from .store import CandidateError


def action_request_digest(context, phase):
    """Submission/integration are exact intents; Completion is a distinct subject."""
    if phase in ('plan', 'submit', 'apply', 'rollback', 'integrate', 'audit'):
        return codec.digest(context['intent'])
    if phase=='complete' and context.get('plan',{}).get('contractIdentity')=='das-analysis-verification-plan/v1':
        return codec.digest(dict(action='complete',intentDigest=codec.digest(context['intent']),
            taskBindingDigest=context['plan']['bindings']['taskBindingDigest'],
            qualificationRefs=context['qualificationRefs']))
    if phase != 'complete' or context['integrationReceipt'] is None:
        raise CandidateError('original integration receipt required for completion grant')
    return codec.digest(dict(action='complete', intentDigest=codec.digest(context['intent']),
        integrationReceiptDigest=codec.digest(context['integrationReceipt']),
        qualificationRefs=context['qualificationRefs']))


class NativeActionAuthorization:
    """Install alongside NativeQualification; never construct from RPC input.

    ``load_control(connection, phase, actor, epoch, context)`` reads only
    precollected originals and current state. This reference profile supports
    one grant budget root; SQL's shared reservation remains independently
    enforced. Unsupported multiple roots reject instead of dropping a scope.
    """
    def __init__(self, *, binary, binary_sha256, release_version, load_control,
                 audience, timeout=2):
        _digest(binary_sha256)
        if (not Path(binary).is_absolute() or not callable(load_control)
                or not isinstance(audience, str) or not 0 < len(audience) <= 128
                or not isinstance(release_version, str) or not 0 < len(release_version) <= 128
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= 2):
            raise CandidateError('installed grant consumer, audience and bounded deadline required')
        self.load_control, self.audience, self.timeout = load_control, audience, timeout
        self.binary_sha256, self.release_version = binary_sha256, release_version
        try:
            self.fd = pin_native(binary, binary_sha256, release_version, timeout)
        except CadenceDependencyError as exc:
            raise CandidateError('native grant consumer installation failed') from exc

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __call__(self, connection, phase, actor, epoch, context, *, remaining=None):
        if self.fd is None or not connection.in_transaction or phase not in ('plan', 'submit', 'apply', 'rollback', 'integrate', 'complete', 'audit'):
            raise CandidateError('current writer transaction and installed grant consumer required')
        started = time.clock_gettime(time.CLOCK_BOOTTIME)
        horizon = self.timeout if remaining is None else remaining
        bound = min(self.timeout, horizon)
        try:
            if not 0 < bound <= 2:
                raise ValueError('grant deadline exhausted')
            # A loader cannot redefine the original request it must authorize.
            approved = codec.parse(codec.canonical(self.load_control(connection, phase, actor, epoch, deepcopy(context))))
            codec.closed_object(approved, ['grantEnvelope', 'parentEnvelopes', 'trust', 'current', 'representedSubject'])
            current, intent, plan = approved['current'], context['intent'], context.get('plan', {})
            audit = phase == 'audit'
            analysis=plan.get('contractIdentity')=='das-analysis-verification-plan/v1'
            if (intent['contractIdentity'] != 'das-resource-action-intent/v1'
                    or intent['action'] != ('audit' if audit else 'complete' if analysis and phase=='complete' else phase if phase in ('plan','submit','apply','rollback') else 'integrate')):
                raise ValueError('retained action-specific intent required')
            key = intent['taskKey']
            values = tuple(key[name] for name in ('authorityDomain', 'projectId', 'changeId', 'taskId'))
            task = connection.execute('SELECT revision,cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?', values).fetchone()
            lease = connection.execute('SELECT generation,owner,expires_at FROM leases WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?', values).fetchone()
            meta = connection.execute('SELECT authority_domain,authority_epoch FROM metadata WHERE singleton=1').fetchone()
            target = connection.execute('SELECT resource_instance,generation,candidate_digest FROM version_targets WHERE authority_domain=? AND resource_id=?', (values[0], intent['resourceId'])).fetchone()
            generation = intent['targetGeneration'] + (1 if phase == 'complete' and not analysis else 0)
            expected_candidate = (context['targetCandidateDigest'] if audit else plan['bindings']['baselineCandidateDigest'] if analysis else
                                  plan['afterCandidateDigest'] if phase == 'complete' else plan['beforeCandidateDigest'])
            if (task is None or tuple(task) != (intent['taskRevision'], intent['taskCycle'])
                    or meta is None or tuple(meta) != (values[0], epoch)
                    or current['authorityEpoch'] != epoch
                    or (audit and approved['representedSubject'] != actor)
                    or (audit and lease is not None and lease[1] == actor)
                    or (not audit and (lease is None or lease[1] != approved['representedSubject']))
                    or target is None or tuple(target) != (intent['resourceInstance'], generation, expected_candidate)
                    or len(intent['budgetIds']) != 1):
                raise ValueError('actual current task/lease/target or supported budget scope changed')
            earliest = datetime.fromisoformat(current['earliest'].replace('Z', '+00:00'))
            latest = datetime.fromisoformat(current['latest'].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            if (earliest.tzinfo is None or latest.tzinfo is None or earliest > now
                    or (latest-now).total_seconds() < horizon
                    or (not audit and lease[2] <= latest.timestamp())):
                raise ValueError('trusted grant interval or actual lease cannot cover consumption')
            request = dict(actor=actor, representedSubject=approved['representedSubject'], audience=self.audience,
                taskKey=key, taskRevision=task[0], taskCycle=task[1], leaseGeneration=0 if audit else lease[0],
                resourceId=intent['resourceId'], resourceInstance=intent['resourceInstance'], action=phase,
                businessActionId=intent['businessActionId'], targetGeneration=generation,
                requestDigest=action_request_digest(context, phase), toolDigest=intent['toolDigest'],
                policyDigest=intent['policyDigest'], budgetId=intent['budgetIds'][0], cost=intent['cost'])
            probe = dict(grantEnvelope=approved['grantEnvelope'], parentEnvelopes=approved['parentEnvelopes'],
                trust=approved['trust'], current=current, request=request)
            encoded = codec.canonical(probe)
            with tempfile.TemporaryDirectory(prefix='das-native-grant-') as directory:
                deadline = bound-(time.clock_gettime(time.CLOCK_BOOTTIME)-started)
                if deadline <= 0:
                    raise ValueError('grant deadline exhausted before native consumption')
                result = codec.parse(_run(self.fd, ['contracts', 'check-authorization', '--probe'], encoded, directory, deadline))
            codec.closed_object(result, ['checkedRefs', 'authority', 'qualification'])
            checked = result['checkedRefs']
            codec.closed_object(checked, ['authorizationId', 'principals', 'keyFingerprints',
                'authorityEpoch', 'authorizationGeneration', 'ancestorIds'])
            if (result['authority'] is not False or result['qualification'] is not False
                    or checked['authorityEpoch'] != epoch or not checked['principals']
                    or actor in checked['principals']
                    or time.clock_gettime(time.CLOCK_BOOTTIME)-started >= bound
                    or not earliest <= datetime.now(timezone.utc) < latest):
                raise ValueError('native grant result or current interval changed')
            return dict(checkedRefs=checked, grantEnvelopeDigest=codec.digest(approved['grantEnvelope']),
                parentEnvelopeDigests={name: codec.digest(value) for name, value in approved['parentEnvelopes'].items()},
                controlContextDigest=codec.digest(dict(trust=approved['trust'], current=current, request=request)))
        except (OSError, ValueError, TypeError, KeyError, AttributeError, CadenceDependencyError) as exc:
            raise CandidateError('native current grant verification failed') from exc
