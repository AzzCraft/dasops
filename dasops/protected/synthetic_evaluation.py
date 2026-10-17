"""Synthetic reference scoring over the installed Cadence Linux controller.

Installed-library staging support, no RPC, approval, signer or qualification.
The installer fixes the database, candidate store, controller/snapshot function,
private scoring root, full TaskKey, protocol, controlled subjects and authority.
Nothing here is an adapter or path supplied by candidate code.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
from types import MappingProxyType
from importlib.resources import files

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from dasops.protected.candidates import CandidateStore, CandidateError
from dasops.protected.sqlite.store import CoordinationDatabase, TaskKey, _id, _integer
from dasops.protected.sqlite.outbox import DurableOutbox, Observation
from dasops.standards_contracts import exact_json as codec

INPUT_NAME='.das-evaluation-inputs.json'
MAX_PRIVATE_RECORD=4*1024*1024


def _validate_contract(name,value):
    """Existing protocol authors, installed copies, and no remote retrieval."""
    schemas={key:codec.parse(files('dasops.standards_contracts').joinpath(key+'.schema.json').read_bytes())
        for key in ('dataset_manifest','eval_report','common')}
    registry=Registry().with_resources((schema['$id'],Resource.from_contents(schema)) for schema in schemas.values())
    try:Draft202012Validator(schemas[name],registry=registry,format_checker=FormatChecker()).validate(value)
    except ValidationError as exc:raise CandidateError('existing '+name+' contract shape differs') from exc


@dataclass(frozen=True)
class SyntheticProtocol:
    protocol_id: str
    inputs: tuple = field(repr=False)
    labels: tuple = field(repr=False)
    query_cost: int = 2
    feedback_cost: int = 1

    def __post_init__(self):
        _id(self.protocol_id);_integer(self.query_cost,1);_integer(self.feedback_cost,1)
        if (type(self.inputs) is not tuple or type(self.labels) is not tuple
                or not 1<=len(self.inputs)<=32 or len(self.inputs)!=len(self.labels)
                or any(type(x) is not int or not -1000000<=x<=1000000 for x in self.inputs)
                or any(type(x) is not int or x not in (0,1) for x in self.labels)):
            raise CandidateError('bounded immutable synthetic inputs and binary labels required')

    @property
    def digest(self):
        # Public protocol identity excludes enumerable private input/label bytes.
        return codec.digest(dict(protocolId=self.protocol_id,declaredSynthetic=True,
            denominator=len(self.inputs),scoring='fixed-denominator-binary-accuracy',
            invalidResult='all-samples-failed',feedback=['LOW\n','MID\n','TOP\n'],
            queryCost=self.query_cost,feedbackCost=self.feedback_cost))

    @property
    def private_digest(self):
        return codec.digest(dict(inputs=list(self.inputs),labels=list(self.labels)))


class SyntheticEvaluation:
    """Source-only coordinator and independent scorer; not an activated gateway.

    Actor is supplied by the installed authenticated service, never candidate
    parameters. An approved source-to-subject map remains an installation input.
    Unknown controller relationships are denied rather than given new budgets.
    Controller dependencies are the fixed native reference, never plugins.
    """
    def __init__(self, *, database, candidates, controller, snapshot, private_root,
                 task_key, resource, instance, protocol, subjects, authorize,
                 dataset_manifest=None, evidence_actor=None):
        if (not isinstance(database,CoordinationDatabase) or not isinstance(candidates,CandidateStore)
                or not isinstance(task_key,TaskKey) or task_key.authority_domain!=database.domain
                or not isinstance(protocol,SyntheticProtocol) or not callable(authorize)
                or not callable(snapshot) or not callable(getattr(controller,'run',None))):
            raise CandidateError('installed evaluation dependencies required')
        root=Path(private_root);info=root.lstat()
        if (not root.is_absolute() or root.resolve()!=root or not stat.S_ISDIR(info.st_mode)
                or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700):
            raise CandidateError('fixed private scoring directory required')
        groups=dict(subjects)
        if not groups or any(not isinstance(v,tuple) or len(v)!=2 for v in groups.values()):
            raise CandidateError('explicit controlled subject and shared budget mapping required')
        self.subjects=MappingProxyType({_id(k):tuple(_id(x) for x in v) for k,v in groups.items()})
        self.dataset_manifest_bytes=None;self.evidence_actor=None
        if dataset_manifest is not None or evidence_actor is not None:
            _id(evidence_actor)
            if evidence_actor in self.subjects:
                raise CandidateError('private evidence reader must differ from development/query subjects')
            try:
                _validate_contract('dataset_manifest',dataset_manifest)
                if (dataset_manifest['provenance']['collectionMethod']!='synthetic'
                        or dataset_manifest['contentHash']!=protocol.private_digest
                        or dataset_manifest['contentHashMethod']!=codec.DIGEST_METHOD
                        or dataset_manifest['splits']!={'sealed':{'count':len(protocol.labels)}}):
                    raise CandidateError('installed synthetic dataset and full denominator differ')
            except (ValueError,KeyError,TypeError) as exc:
                raise CandidateError('installed DatasetManifest differs') from exc
            self.dataset_manifest_bytes=codec.canonical(dataset_manifest);self.evidence_actor=evidence_actor
        self.database,self.candidates,self.controller=database,candidates,controller
        self.snapshot,self.root,self.key=snapshot,root,task_key
        self.resource,self.instance,self.protocol=_id(resource),_id(instance),protocol
        self.tool_digest='sha256:'+hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        self.authorize=authorize
        self.box=DurableOutbox(database,adapters={(self.resource,self.instance,'submit'):self},
            verify_observation=self.verify,execution_closed=lambda _:False)

    def _guard(self,purpose):
        return lambda connection,operation,actor,epoch: (
            actor in self.subjects and self.authorize(connection,'sealed_'+purpose,actor,epoch) is True)

    def evaluate(self,candidate_digest,business_id,*,actor,now):
        if actor not in self.subjects:raise CandidateError('unknown controlled subject')
        binding=self.candidates.verify(candidate_digest)
        if (tuple(binding['taskKey'][name] for name in ('authorityDomain','projectId','changeId','taskId'))!=self.key.values()
                or any(x['path']==INPUT_NAME or x['path'].startswith(INPUT_NAME+'/') for x in binding['files'])):
            raise CandidateError('candidate scope or reserved input namespace differs')
        owner,budget=self.subjects[actor]
        original_actor=actor
        if self.database.connection.execute('SELECT 1 FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',
                (self.database.domain,self.resource,'submit',business_id)).fetchone():
            _,original=self.box._load(self.resource,'submit',business_id)
            original_actor=original['originalActor']
        intent=dict(contractIdentity='das-resource-action-intent/v1',taskKey=binding['taskKey'],
            taskRevision=binding['taskRevision'],taskCycle=binding['taskCycle'],resourceId=self.resource,
            resourceInstance=self.instance,targetGeneration=1,action='submit',businessActionId=_id(business_id),
            originalActor=original_actor,parameters=dict(candidateDigest=candidate_digest,protocolDigest=self.protocol.digest,controlledSubject=owner,
                privateDatasetDigest=self.protocol.private_digest),toolDigest=self.tool_digest,
            policyDigest=binding['policyDigest'],budgetIds=[budget],cost=self.protocol.query_cost)
        row=self.box.submit(intent,actor=actor,now=now,authorize=self._guard('evaluate'))
        if row['state']=='reserved':
            self.box.dispatch(self.resource,'submit',business_id,actor=actor,now=now,authorize=self._guard('evaluate'))
        elif row['state'] in ('dispatched','unknown'):
            self.box.reconcile(self.resource,'submit',business_id,actor=actor,now=now,authorize=self._guard('evaluate'))
        # This trusted service method deliberately exports no private outcome,
        # digest, prediction, log, exit code or collection status to the developer.

    def _path(self,intent):
        return self.root/(codec.digest(intent)[7:]+'.json')

    def _private(self,intent):
        # A shared resource, dataset or controlled budget does not grant access
        # to another project's original. Check the installed full scope before
        # even opening its private record, including cached feedback/recovery.
        if (tuple(intent['taskKey'][name] for name in ('authorityDomain','projectId','changeId','taskId'))!=self.key.values()
                or intent['resourceId']!=self.resource or intent['resourceInstance']!=self.instance
                or intent['toolDigest']!=self.tool_digest):
            raise CandidateError('private original installed task/resource/tool scope differs')
        path=self._path(intent)
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                    or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>MAX_PRIVATE_RECORD):
                raise CandidateError('private original custody differs')
            raw=stream.read(MAX_PRIVATE_RECORD+1)
        record=codec.parse(raw)
        if (codec.canonical(record)!=raw or record['requestDigest']!=codec.digest(intent)
                or record['protocolDigest']!=self.protocol.digest
                or record['privateDatasetDigest']!=self.protocol.private_digest
                or intent['parameters']['privateDatasetDigest']!=self.protocol.private_digest
                or record['candidateDigest']!=intent['parameters']['candidateDigest']):
            raise CandidateError('private original scope or byte identity differs')
        receipt=codec.canonical(dict(recordUse='synthetic_reference_observation_not_qualification',
            requestDigest=codec.digest(intent),privateRecordDigest='sha256:'+hashlib.sha256(raw).hexdigest(),
            candidateDigest=record['candidateDigest'],protocolDigest=self.protocol.digest,
            authority=False,qualification=False))
        return record,receipt

    def lookup(self,intent,*,deadline):
        try:record,receipt=self._private(intent)
        except FileNotFoundError:return Observation('unknown',codec.digest(intent),self.instance,b'')
        outcome='confirmed' if record['runtime']['domainTerminated'] is True else 'unknown'
        return Observation(outcome,codec.digest(intent),self.instance,receipt)

    def verify(self,intent,observation):
        return observation==self.lookup(intent,deadline=0)

    def execute(self,intent,*,deadline):
        if self._path(intent).exists():return self.lookup(intent,deadline=deadline)
        source=self.candidates.prepare_reference_view(intent['parameters']['candidateDigest'])
        directory=Path(tempfile.mkdtemp(prefix='infer-',dir=self.root));view=directory/'candidate'
        shutil.copytree(source['viewPath'],view,copy_function=shutil.copy2)
        view.chmod(0o700)
        (view/INPUT_NAME).write_bytes(codec.canonical(list(self.protocol.inputs)))
        (view/INPUT_NAME).chmod(0o444);view.chmod(0o555)
        remaining=deadline-time.clock_gettime(time.CLOCK_BOOTTIME)
        if remaining<=0:raise CandidateError('query elapsed budget exhausted before candidate execution')
        observed=self.controller.run(view,expected_snapshot=self.snapshot(view),timeout=min(5,remaining))
        correct=0;valid=False
        if (observed['domainTerminated'] is True and observed['snapshotUnchanged'] is True
                and observed['failureType'] is None and observed['exitCode']==0):
            if not isinstance(observed.get('candidateStdout'),bytes):
                raise CandidateError('installed runtime lacks the checked candidate output channel')
            try:
                predictions=codec.parse(observed['candidateStdout'])
                values=[codec.safe_integer(x) for x in predictions] if type(predictions) is list else []
                valid=len(values)==len(self.protocol.labels) and all(x in (0,1) for x in values)
                if valid:correct=sum(x==y for x,y in zip(values,self.protocol.labels))
            except (ValueError,TypeError):pass
        private_runtime=dict(observed,stdout=base64.b64encode(observed['stdout']).decode(),
            stderr=base64.b64encode(observed['stderr']).decode(),
            candidateStdout=base64.b64encode(observed['candidateStdout']).decode() if observed.get('candidateStdout') is not None else None)
        record=dict(requestDigest=codec.digest(intent),candidateDigest=intent['parameters']['candidateDigest'],
            protocolDigest=self.protocol.digest,privateDatasetDigest=self.protocol.private_digest,
            privateInputsDigest=codec.digest(list(self.protocol.inputs)),
            privateLabelsDigest=codec.digest(list(self.protocol.labels)),runtime=private_runtime,
            denominator=len(self.protocol.labels),correct=correct,validPredictions=valid,
            runAt=datetime.now(timezone.utc).isoformat().replace('+00:00','Z'),
            datasetManifestDigest=codec.digest(codec.parse(self.dataset_manifest_bytes)) if self.dataset_manifest_bytes else None)
        raw=codec.canonical(record)
        if len(raw)>MAX_PRIVATE_RECORD:raise CandidateError('private original exceeds the reference bound')
        fd=os.open(self._path(intent),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        parent=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(parent)
        finally:os.close(parent)
        # Unknown termination preserves the mounted input and cost for recovery.
        if observed['domainTerminated'] is True:
            for parent,dirs,_ in os.walk(directory):
                Path(parent).chmod(0o700)
            shutil.rmtree(directory)
        return self.lookup(intent,deadline=deadline)

    def _evidence(self,connection,business_id,actor,now):
        """Current private read, never a new query, feedback release or approval."""
        _id(actor);_integer(now)
        meta=connection.execute('SELECT authority_epoch,time_floor FROM metadata WHERE singleton=1').fetchone()
        if (self.dataset_manifest_bytes is None or actor!=self.evidence_actor or now<meta['time_floor']
                or self.authorize(connection,'sealed_evidence',actor,meta['authority_epoch']) is not True):
            raise CandidateError('current private evidence authority denied')
        self.database._parent(connection,self.key,allowed=('active',))
        row,intent=self.box._load(self.resource,'submit',business_id)
        task=connection.execute('SELECT revision,cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',self.key.values()).fetchone()
        if (not task or tuple(task)!=(intent['taskRevision'],intent['taskCycle']) or row['state']!='confirmed'
                or self.subjects.get(row['original_actor'])!=(intent['parameters']['controlledSubject'],intent['budgetIds'][0])):
            raise CandidateError('current confirmed evaluation and original subject required')
        self.database._unfinished_cycle(connection,self.key,intent['taskCycle'])
        record,receipt=self._private(intent)
        if 'sha256:'+hashlib.sha256(receipt).hexdigest()!=row['receipt_digest']:
            raise CandidateError('evaluation evidence differs from original receipt')
        manifest=codec.parse(self.dataset_manifest_bytes)
        if record.get('datasetManifestDigest')!=codec.digest(manifest):
            raise CandidateError('original dataset declaration differs')
        denominator=codec.safe_integer(record['denominator']);correct=codec.safe_integer(record['correct'])
        if denominator!=len(self.protocol.labels) or not 0<=correct<=denominator:
            raise CandidateError('original full sample denominator differs')
        runtime=record['runtime']
        valid=(record['validPredictions'] is True and runtime['domainTerminated'] is True
            and runtime['snapshotUnchanged'] is True and runtime['failureType'] is None and runtime['exitCode']==0)
        binding=dict(taskKey=intent['taskKey'],taskRevision=intent['taskRevision'],taskCycle=intent['taskCycle'],
            requestDigest=codec.digest(intent),candidateDigest=record['candidateDigest'],resourceId=self.resource,
            resourceInstance=self.instance,toolDigest=self.tool_digest,policyDigest=intent['policyDigest'],
            protocolDigest=self.protocol.digest,datasetManifestDigest=codec.digest(manifest),
            privateDatasetDigest=self.protocol.private_digest,controlledSubject=intent['parameters']['controlledSubject'],
            budgetIds=intent['budgetIds'],queryCost=intent['cost'],receiptDigest='sha256:'+hashlib.sha256(receipt).hexdigest())
        private_digest=codec.parse(receipt)['privateRecordDigest']
        report=dict(schemaVersion='1.0.0',evalId=intent['businessActionId'],runAt=record['runAt'],
            dataset={name:manifest[name] for name in ('datasetId','datasetVersion')},
            metrics=dict(correct=correct,samples=denominator,failedSamples=0 if valid else denominator),
            status='pass' if valid else 'fail',artifacts=dict(fullReportRef='urn:'+private_digest,c12=binding))
        _validate_contract('dataset_manifest',manifest);_validate_contract('eval_report',report)
        return dict(datasetManifest=manifest,evalReport=report)

    def prepare_evidence(self,business_id,*,actor,now):
        """Precollect existing wire types for the installation's trusted collector.

        Full reports/digests remain private. No public RPC exposes this method;
        current OS/transport identity and custody are installation obligations.
        """
        with self.database.read_snapshot() as connection:
            return self._evidence(connection,business_id,actor,now)

    def consume_evidence(self,business_id,evidence,*,actor,now,claim='synthetic'):
        """Verify exact originals before their existing Plan/Evidence consumption.

        A schema-valid document alone grants nothing. Synthetic data never
        supports a new independent/unseen statistical declaration.
        """
        if claim!='synthetic':raise CandidateError('synthetic reference cannot establish an unseen statistical claim')
        codec.closed_object(evidence,('datasetManifest','evalReport'))
        with self.database.read_snapshot() as connection:
            return self._consume_evidence(connection,business_id,evidence,actor,now)

    def _consume_evidence(self,connection,business_id,evidence,actor,now):
        expected=self._evidence(connection,business_id,actor,now)
        if codec.canonical(evidence)!=codec.canonical(expected):
            raise CandidateError('C12 evidence does not match retained task/candidate/data/budget originals')
        if expected['evalReport']['status']!='pass':
            raise CandidateError('failed evaluation cannot satisfy the evidence check')
        return dict(evidenceDigest=codec.digest(expected),statisticalClaim='not_assessed',
            qualificationEligible=False,authorityVerified=False)

    def confirm_evidence(self,connection,business_id,evidence,*,actor,now,context):
        """Installed load_control predicate, using its SAME owning transaction.

        Precollect/score outside the writer. Here recheck the private originals
        and the manager's actual task/candidate, under the existing SQL approval
        guard. Scoring and target operations retain distinct resource/tool/
        policy identities. This grants neither an action nor an unseen claim;
        NativeQualification still consumes current grants and signed controls.
        """
        if connection is not self.database.connection or not connection.in_transaction:
            raise CandidateError('C12 confirmation requires the owning current writer transaction')
        codec.closed_object(evidence,('datasetManifest','evalReport'))
        with connection.approval():
            checked=self._consume_evidence(connection,business_id,evidence,actor,now)
            try:
                plan=context['plan'];identity=plan['contractIdentity']
                if identity=='das-integration-plan/v1':
                    target=dict(taskKey=plan['taskKey'],taskRevision=plan['taskRevision'],
                        taskCycle=plan['taskCycle'],candidateDigest=plan['afterCandidateDigest'])
                elif identity=='das-analysis-verification-plan/v1':
                    target={name:plan['bindings'][name] for name in
                        ('taskKey','taskRevision','taskCycle','candidateDigest')}
                else:raise ValueError('unsupported C12 consuming plan')
                binding=evidence['evalReport']['artifacts']['c12']
                if codec.canonical(target)!=codec.canonical({name:binding[name] for name in target}):
                    raise ValueError('actual consuming task/candidate differs')
            except (ValueError,KeyError,TypeError) as exc:
                raise CandidateError('C12 originals do not bind the actual consuming plan') from exc
            return checked

    def feedback(self,business_id,release_id,*,actor,now):
        if actor not in self.subjects:raise CandidateError('unknown controlled subject')
        current=self._guard('feedback')
        with self.database.read_snapshot() as connection:
            meta=connection.execute('SELECT authority_epoch,time_floor FROM metadata WHERE singleton=1').fetchone()
            if now<meta['time_floor'] or current(connection,'sealed_feedback_read',actor,meta['authority_epoch']) is not True:
                raise CandidateError('current feedback authorization denied')
        row,intent=self.box._load(self.resource,'submit',business_id)
        owner,budget=self.subjects[actor]
        if row['state']!='confirmed' or intent['parameters']['controlledSubject']!=owner or intent['budgetIds']!=[budget]:
            raise CandidateError('confirmed original controlled evaluation required')
        record,receipt=self._private(intent)
        if 'sha256:'+hashlib.sha256(receipt).hexdigest()!=row['receipt_digest']:
            raise CandidateError('cached feedback differs from the retained native original')
        # Fixed four-byte policy, including every failed/invalid sample in the
        # original denominator. Raw errors, predictions and material digests stay private.
        correct,n=codec.safe_integer(record['correct']),codec.safe_integer(record['denominator'])
        result=b'TOP\n' if correct*3>=n*2 else (b'MID\n' if correct*3>=n else b'LOW\n')
        release=self._release(intent)
        release_digest=codec.digest(release)
        old_release=self.database.connection.execute('SELECT original_actor FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',
            (self.database.domain,self.resource,'inspect',release_id)).fetchone()
        released=self.database.reserve(self.key,resource_id=self.resource,action_class='inspect',
            business_id=release_id,original_actor=old_release['original_actor'] if old_release else actor,request_digest=release_digest,
            budget_ids=[budget],cost=self.protocol.feedback_cost,cycle=intent['taskCycle'],
            actor=actor,now=now,authorize=current,payload=codec.canonical(release))
        if released['state']=='reserved':
            self.database.transition_action(self.resource,'inspect',release_id,expected='reserved',target='dispatched',
                actor=actor,now=now,authorize=current)
            self.database.transition_action(self.resource,'inspect',release_id,expected='dispatched',target='confirmed',
                receipt_digest='sha256:'+hashlib.sha256(result).hexdigest(),receipt_bytes=result,
                actor=actor,now=now,authorize=current)
        elif released['state']!='confirmed':
            raise CandidateError('feedback outcome unresolved; preserve original release and budget')
        with self.database.transaction('sealed_feedback_read',actor,now,current) as connection:
            self.database._audit(connection,'sealed_feedback_released',actor,
                dict(protocolDigest=self.protocol.digest,subject=owner,businessActionId=business_id,
                    releaseId=release_id,statisticalClaim='not_assessed'))
        return result

    def _release(self,intent):
        # Existing private action_payloads retain the exact feedback preparation.
        # This is not a public C12 contract or proof of transport delivery.
        return dict(recordUse='synthetic_feedback_preparation_not_transport_delivery',
            originalBusinessId=intent['businessActionId'],originalRequestDigest=codec.digest(intent),
            protocolDigest=self.protocol.digest,toolDigest=self.tool_digest,resourceInstance=self.instance,
            controlledSubject=intent['parameters']['controlledSubject'],budgetIds=intent['budgetIds'],
            cost=self.protocol.feedback_cost)

    def select_candidate(self,candidate_digest,release_id,*,actor,now):
        if actor not in self.subjects:raise CandidateError('unknown controlled subject')
        binding=self.candidates.verify(candidate_digest)
        if tuple(binding['taskKey'][name] for name in ('authorityDomain','projectId','changeId','taskId'))!=self.key.values():
            raise CandidateError('selected candidate has another task scope')
        with self.database.transaction('sealed_selection',actor,now,self._guard('select')) as connection:
            self.database._parent(connection,self.key,allowed=('active',))
            task=connection.execute('SELECT revision,cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',self.key.values()).fetchone()
            if not task or tuple(task)!=(binding['taskRevision'],binding['taskCycle']):
                raise CandidateError('selected candidate does not bind the current task cycle')
            self.database._unfinished_cycle(connection,self.key,binding['taskCycle'])
            row=connection.execute('SELECT b.*,p.request_digest,p.payload_json FROM business_actions b LEFT JOIN action_payloads p USING(authority_domain,resource_id,action_class,business_id) WHERE b.authority_domain=? AND b.resource_id=? AND b.action_class=? AND b.business_id=?',
                (self.database.domain,self.resource,'inspect',release_id)).fetchone()
            if (not row or row['state']!='confirmed' or self.subjects.get(row['original_actor'])!=self.subjects[actor]
                    or (row['project_id'],row['change_id'],row['task_id'],row['cycle'])!=(*self.key.values()[1:],binding['taskCycle'])
                    or row['payload_json'] is None):
                raise CandidateError('actual released feedback history required')
            raw=row['payload_json'].encode('utf-8');release=codec.parse(raw)
            if (codec.canonical(release)!=raw or codec.digest(release)!=row['request_digest']
                    or release.get('recordUse')!='synthetic_feedback_preparation_not_transport_delivery'
                    or not isinstance(release.get('originalBusinessId'),str)):
                raise CandidateError('original feedback scope differs')
            query,intent=self.box._load(self.resource,'submit',release['originalBusinessId'])
            if (query['state']!='confirmed' or release!=self._release(intent)
                    or intent['parameters']['controlledSubject']!=self.subjects[actor][0]
                    or intent['budgetIds']!=[self.subjects[actor][1]]):
                raise CandidateError('original feedback scope differs')
            _,receipt=self._private(intent)
            if 'sha256:'+hashlib.sha256(receipt).hexdigest()!=query['receipt_digest']:
                raise CandidateError('original feedback receipt differs')
            self.database._audit(connection,'sealed_feedback_used_for_selection',actor,
                dict(candidateDigest=candidate_digest,protocolDigest=self.protocol.digest,releaseId=release_id,claim='adaptive'))
        return 'adaptive'
