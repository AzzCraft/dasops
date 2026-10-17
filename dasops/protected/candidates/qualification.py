"""Installed local native consumer for the existing integration predicate.

No RPC body may supply these dependencies. The trusted loader must read current
approved context/immutable original records using this SAME SQL transaction.
This adapter performs no signing, artifact downloads or candidate execution.
It does not by itself qualify an OS deployment or C -> I materialization.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile
import sys
import time
from types import MappingProxyType
from jsonschema.exceptions import ValidationError

from dasops.bundle_preview import _run, pin_native, CadenceDependencyError
from dasops.standards_contracts import exact_json as codec
from dasops.protected.sqlite.store import _digest, _integer
from .store import CandidateError
from .authorization import NativeActionAuthorization
from dasops.protected.bundle import NativeBundleResolver, BundleError, bundle_subject, _validate


def reverification_bindings(context, verification_inputs):
    """Current completed-work subject, without a circular plan digest.

    The scope is the exact audit intent with ONLY its plan-digest reference
    omitted. Native grant consumption separately binds the full original intent.
    Both digests must be checked; neither is a replacement for the other.
    """
    intent=deepcopy(context['intent']);intent['parameters'].pop('verificationPlanDigest')
    original=context['completion'];analysis=original.get('completionMode')=='analysis'
    bindings=dict(taskKey=original['taskKey'],taskRevision=context['taskRevision'],
        taskCycle=context['taskCycle'],resourceId=intent['resourceId'],resourceInstance=intent['resourceInstance'],
        targetGeneration=context['targetGeneration'],obligationDigest=context['obligationDigest'],
        sourceCandidateDigest=original['sourceCandidateDigest'],baselineCandidateDigest=context['targetCandidateDigest'],
        policyDigest=context['policyDigest'],toolDigest=context['toolDigest'],
        lineageDigest=codec.digest(dict(completionDigest=context['completionDigest'],revisionBindings=context['revisionBindings'])),
        completionDigest=context['completionDigest'],verificationScopeDigest=codec.digest(intent),**verification_inputs)
    if analysis:bindings.update(completionMode='analysis',taskBindingDigest=original['taskBindingDigest'])
    else:bindings['integratedCandidateDigest']=context['targetCandidateDigest']
    return bindings


class NativeQualification:
    """Install once from approved service configuration, never per request.

    ``load_control(connection, phase, actor, epoch, context)`` supplies only
    precollected current control/trust/original bytes. No network or candidate
    work inside the writer transaction. The manager's canonical context is a
    separate copy; this adapter overrides/checks ALL its binding fields.
    """

    def __init__(self, *, binary, binary_sha256, release_version, load_control,
                 action_authorizer=None, verification_inputs=None, timeout=2,
                 bundle_resolver=None, adoption_bundle=None):
        path = Path(binary)
        if sys.platform != 'linux' or not path.is_absolute() or not callable(load_control):
            raise CandidateError('installed Linux native consumer and control loader required')
        _digest(binary_sha256)
        if (not isinstance(release_version,str) or not release_version or len(release_version)>128
                or isinstance(timeout,bool) or not isinstance(timeout,(int,float)) or not 0 < timeout <= 2):
            raise CandidateError('exact release identity and bounded native deadline required')
        self.load_control, self.timeout = load_control, timeout
        self.binary_sha256, self.release_version = binary_sha256, release_version
        self.verification_inputs = None
        if verification_inputs is not None:
            names = ('standardDigest','bundleDigest','factsDigest','acceptanceDigest','environmentDigest')
            codec.closed_object(verification_inputs, names)
            self.verification_inputs = MappingProxyType({name:_digest(verification_inputs[name]) for name in names})
        if action_authorizer is not None and (not isinstance(action_authorizer, NativeActionAuthorization)
                or action_authorizer.binary_sha256 != binary_sha256
                or action_authorizer.release_version != release_version):
            raise CandidateError('same installed native release required for grant and qualification')
        self.action_authorizer = action_authorizer
        self.bundle_resolver = bundle_resolver
        self.adoption_bundle = None
        if bundle_resolver is not None or adoption_bundle is not None:
            if (not isinstance(bundle_resolver, NativeBundleResolver) or self.verification_inputs is None
                    or not isinstance(adoption_bundle, dict)
                    or bundle_resolver.binary_sha256 != binary_sha256
                    or bundle_resolver.release_version != release_version):
                raise CandidateError('same installed Bundle resolver and complete prepared adoption required')
            try:
                _validate('bundle_resolution_v2', adoption_bundle)
                subject = dict(adoption_bundle); recorded = subject.pop('recordDigest')
                if (adoption_bundle['status'] != 'resolved' or recorded != codec.digest(subject)
                        or adoption_bundle['bundleDigest'] != codec.digest(bundle_subject(adoption_bundle))
                        or any(self.verification_inputs[name] != value for name, value in (
                            ('standardDigest', bundle_resolver.standard_artifact_digest),
                            ('bundleDigest', adoption_bundle['bundleDigest']),
                            ('factsDigest', adoption_bundle['factsRef']['approvedFactsDigest'])))):
                    raise BundleError('prepared adoption does not bind installed verification inputs')
            except (ValueError, KeyError, TypeError, ValidationError) as exc:
                raise CandidateError('invalid installed adoption preparation') from exc
            # Installed configuration owns this copy. RPC/candidate objects
            # cannot edit the preparation subsequently consumed at the writer.
            self.adoption_bundle = deepcopy(adoption_bundle)
        try:
            self.fd = pin_native(binary, binary_sha256, release_version, timeout)
        except CadenceDependencyError as exc:
            raise CandidateError('native qualification consumer installation failed') from exc

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None

    def reverify(self, connection, phase, actor, epoch, context):
        """Independent audit grant and native evidence at the same transaction.

        Installation supplies current audit-plan/audit-evidence originals. Audit
        uses its own signed grant (leaseGeneration=0), never the old Worker lease.
        No signing, candidate execution or network occurs in this predicate.
        """
        if (self.fd is None or not connection.in_transaction or phase not in ('plan','evidence')
                or self.action_authorizer is None or self.verification_inputs is None):
            raise CandidateError('installed verification-only native controls required')
        started=time.clock_gettime(time.CLOCK_BOOTTIME)
        try:
            self.action_authorizer(connection,'audit',actor,epoch,context,remaining=self.timeout)
            approved=codec.parse(codec.canonical(self.load_control(connection,'audit-'+phase,actor,epoch,deepcopy(context))))
            codec.closed_object(approved,['plan','evidenceEnvelope','decisionEnvelope','trust','current','originals'])
            plan=approved['plan'];expected=reverification_bindings(context,self.verification_inputs)
            identity='das-analysis-verification-plan/v1' if expected.get('completionMode')=='analysis' else 'das-verification-plan/v1'
            if (plan['contractIdentity']!=identity or plan['bindings']!=expected or plan['actions']!=['audit']
                    or codec.digest(plan)!=context['intent']['parameters']['verificationPlanDigest']):
                raise CandidateError('native audit plan differs from original Completion/current request')
            with tempfile.TemporaryDirectory(prefix='das-native-reverification-') as directory:
                remaining=self.timeout-(time.clock_gettime(time.CLOCK_BOOTTIME)-started)
                if remaining<=0:raise CandidateError('native audit deadline exhausted')
                if phase=='plan':
                    checked=codec.parse(_run(self.fd,['contracts','validate','--identity',identity],codec.canonical(plan),directory,remaining))
                    if checked!=plan:raise CandidateError('native audit plan changed')
                else:
                    control=approved['current'];refs=context['qualificationRefs']
                    if (control['bindings']!=expected or control['actor']!=actor or control['authorityEpoch']!=epoch
                            or control['action']!='audit' or control['integrationReceiptDigest'] is not None
                            or control['targetGeneration']!=context['targetGeneration']
                            or control['targetCandidateDigest']!=context['targetCandidateDigest']
                            or any(control[n]!=v for n,v in refs.items())):
                        raise CandidateError('native audit current purpose/target/references differ')
                    earliest=datetime.fromisoformat(control['earliest'].replace('Z','+00:00'))
                    latest=datetime.fromisoformat(control['latest'].replace('Z','+00:00'))
                    now=datetime.now(timezone.utc)
                    if earliest.tzinfo is None or latest.tzinfo is None or not earliest<=now or (latest-now).total_seconds()<remaining:
                        raise CandidateError('native audit current interval cannot cover consumption')
                    result=codec.parse(_run(self.fd,['contracts','check-action','--probe'],codec.canonical(approved),directory,remaining))
                    codec.closed_object(result,['checkedRefs','authority','qualification'])
                    checked=result['checkedRefs'];codec.closed_object(checked,[*refs,'observationExceptions'])
                    if (result['authority'] is not False or result['qualification'] is not False
                            or checked['observationExceptions'] or any(checked[n]!=v for n,v in refs.items())
                            or not earliest<=datetime.now(timezone.utc)<latest):
                        raise CandidateError('native audit result is not a complete current pass')
            # Evidence validation cannot hide a grant revoked meanwhile.
            remaining=self.timeout-(time.clock_gettime(time.CLOCK_BOOTTIME)-started)
            if remaining<=0:raise CandidateError('native audit deadline exhausted at final grant boundary')
            authorization=self.action_authorizer(connection,'audit',actor,epoch,context,remaining=remaining)
            if time.clock_gettime(time.CLOCK_BOOTTIME)-started>=self.timeout:
                raise CandidateError('native audit total deadline exceeded')
            if phase=='evidence' and not earliest<=datetime.now(timezone.utc)<latest:
                raise CandidateError('native audit evidence expired at final grant boundary')
            return dict(authorization=authorization)
        except (OSError,ValueError,KeyError,TypeError,AttributeError,CadenceDependencyError) as exc:
            raise CandidateError('native current verification-only grant/evidence denied') from exc

    def __call__(self,connection,phase,actor,epoch,context):
        if self.fd is None or not connection.in_transaction or phase not in ('plan','apply','rollback','integrate','complete'):
            raise CandidateError('current transaction and installed native consumer required')
        started=time.clock_gettime(time.CLOCK_BOOTTIME)
        if self.adoption_bundle is not None:
            if self.verification_inputs['standardDigest'] != self.bundle_resolver.standard_artifact_digest:
                raise CandidateError('installed Standard artifact subject changed')
            plan = context['plan']
            actual = plan['bindings'] if 'bindings' in plan else {
                'candidateDigest': plan['afterCandidateDigest'], 'baselineCandidateDigest': plan['beforeCandidateDigest']}
            if self.adoption_bundle['target'] != {
                    'candidateDigest': actual['candidateDigest'],
                    'deploymentBaselineDigest': actual['baselineCandidateDigest']}:
                raise CandidateError('prepared adoption belongs to another actual candidate/baseline')
            try:
                self.bundle_resolver.confirm_current(connection, self.adoption_bundle,
                    actor=actor, epoch=epoch, remaining=self.timeout-(time.clock_gettime(time.CLOCK_BOOTTIME)-started))
            except (ValueError, OSError, KeyError, TypeError, ValidationError) as exc:
                raise CandidateError('current adoption confirmation denied') from exc
        authorization = None
        if phase != 'plan' or context['intent'] is not None:
            if self.verification_inputs is None:
                raise CandidateError('installed standard/Bundle/facts/acceptance/environment pins required')
            if self.action_authorizer is None:
                raise CandidateError('installed current action authorization required for integration/completion')
            authorization = self.action_authorizer(connection,phase,actor,epoch,context,
                remaining=self.timeout-(time.clock_gettime(time.CLOCK_BOOTTIME)-started))
        # Preserve the manager's expected bindings independently of the loader.
        approved=codec.parse(codec.canonical(self.load_control(connection,phase,actor,epoch,deepcopy(context))))
        codec.closed_object(approved,['plan','evidenceEnvelope','decisionEnvelope','trust','current','originals'])
        control,plan=approved['current'],context['plan']
        bindings=control['bindings']
        analysis=plan.get('contractIdentity')=='das-analysis-verification-plan/v1'
        version=plan.get('contractIdentity')=='das-version-tree-plan/v1'
        if version and phase not in ('plan','apply','rollback'):
            raise CandidateError('version switch evidence cannot confer integration or completion qualification')
        if self.verification_inputs is not None and any(
                bindings.get(name) != value for name,value in self.verification_inputs.items()):
            raise CandidateError('signed verification context differs from installed input pins')
        # Current installation supplies standard/Bundle/facts/acceptance/env/
        # lineage/trust/time; the resource manager independently fixes this tuple.
        expected=(dict(plan['bindings'],lineageDigest=codec.digest(context['lineage'])) if analysis else dict(taskKey=plan['taskKey'],taskRevision=plan['taskRevision'],taskCycle=plan['taskCycle'],
            lineageDigest=codec.digest(context['lineage']),
            obligationDigest=context['obligationDigest'] if version else plan['obligationDigest'],resourceId=plan['resourceId'],resourceInstance=plan['resourceInstance'],
            targetGeneration=plan['expectedGeneration'],baselineCandidateDigest=plan['beforeCandidateDigest'],
            sourceCandidateDigest=plan.get('sourceCandidateDigest',plan['afterCandidateDigest']),
            **({} if version else dict(integratedCandidateDigest=plan['afterCandidateDigest'])),
            policyDigest=plan['policyDigest'],toolDigest=plan['toolDigest']))
        if version:
            expected['versionPlanDigest']=codec.digest(plan)
        if (any(bindings.get(name)!=value for name,value in expected.items())
                or (analysis and set(bindings)!=set(expected))):
            raise CandidateError('approved verification context does not bind the actual integration plan')
        action=('rollback' if plan['rollbackOf'] is not None else 'apply') if version else 'complete' if phase=='complete' else 'integrate'
        refs=context['qualificationRefs']
        if (control['actor']!=actor or control['authorityEpoch']!=epoch or control['action']!=action
                or any(control[name]!=value for name,value in refs.items())):
            raise CandidateError('current independent qualification identity or references changed')
        receipt=context['integrationReceipt']
        expected_receipt=codec.digest(receipt) if phase=='complete' and not analysis else None
        generation=plan['bindings']['targetGeneration'] if analysis else plan['expectedGeneration']+(1 if phase=='complete' else 0)
        target=plan['bindings']['baselineCandidateDigest'] if analysis else plan['afterCandidateDigest'] if phase=='complete' else plan['beforeCandidateDigest']
        _integer(control['targetGeneration'])
        if (control['targetGeneration']!=generation or control['targetCandidateDigest']!=target
                or control['integrationReceiptDigest']!=expected_receipt):
            raise CandidateError('qualification does not bind the actual current target/receipt')
        try:
            earliest=datetime.fromisoformat(control['earliest'].replace('Z','+00:00'))
            latest=datetime.fromisoformat(control['latest'].replace('Z','+00:00'))
            consumed_at=datetime.now(timezone.utc)
            remaining=self.timeout-(time.clock_gettime(time.CLOCK_BOOTTIME)-started)
            if (earliest.tzinfo is None or latest.tzinfo is None or earliest>consumed_at
                    or remaining<=0 or (latest-consumed_at).total_seconds()<remaining):
                raise ValueError('current interval cannot cover bounded native consumption')
        except (TypeError,ValueError,AttributeError) as exc:
            raise CandidateError('trusted current interval does not cover actual consumption') from exc
        encoded=codec.canonical(approved)
        try:
            with tempfile.TemporaryDirectory(prefix='das-native-qualification-') as directory:
                remaining=self.timeout-(time.clock_gettime(time.CLOCK_BOOTTIME)-started)
                if remaining<=0: raise CandidateError('native qualification deadline expired before consumption')
                result=codec.parse(_run(self.fd,['contracts','check-action','--probe'],encoded,directory,remaining))
            codec.closed_object(result,['checkedRefs','authority','qualification'])
            checked=result['checkedRefs']
            codec.closed_object(checked,[*refs,'observationExceptions'])
            if (result['authority'] is not False or result['qualification'] is not False
                    or any(checked[name]!=value for name,value in refs.items())
                    or not isinstance(checked['observationExceptions'],list)):
                raise CandidateError('native result changed the original context or claimed public authority')
            consumed_at=datetime.now(timezone.utc)
            if (time.clock_gettime(time.CLOCK_BOOTTIME)-started>=self.timeout
                    or not earliest<=consumed_at<latest):
                raise CandidateError('native qualification expired before the resource boundary')
            if authorization is not None:
                # Evidence consumption must not hide a grant revoked meanwhile.
                # Recheck at the effect boundary, within the SAME total budget;
                # the audit consumes these final current original references.
                authorization=self.action_authorizer(connection,phase,actor,epoch,context,
                    remaining=self.timeout-(time.clock_gettime(time.CLOCK_BOOTTIME)-started))
                if (time.clock_gettime(time.CLOCK_BOOTTIME)-started>=self.timeout
                        or not earliest<=datetime.now(timezone.utc)<latest):
                    raise CandidateError('current qualification expired at the final grant boundary')
            return True if authorization is None else dict(authorization=authorization)
        except (OSError,ValueError,CadenceDependencyError) as exc:
            raise CandidateError('native current evidence/Decision verification failed') from exc
