"""Read-only current-cycle display from retained native Completion facts.

No Markdown is parsed, imported or written. A display never grants present
qualification. Installation supplies scoped current read authorization.
"""
import json

from dasops.protected.sqlite.store import CoordinationDatabase, CoordinationError, TaskKey, _id, _integer
from dasops.standards_contracts import exact_json as codec
from .store import CandidateError, _hash
from .versions import COMPLETION_VALIDATOR, INTEGRATION_RECEIPT_VALIDATOR, ANALYSIS_COMPLETION_VALIDATOR


def completion_projection(database, key, *, actor, now, authorize):
    """One short snapshot; no writer, candidate callbacks or file imports.

    authorize(connection, actor, epoch, full_task_key) is an installed scoped
    reader, separate from mutation authorization. Older cycles remain history
    and never become the new current cycle's DONE.
    """
    if (not isinstance(database, CoordinationDatabase) or not isinstance(key, TaskKey)
            or key.values()[0] != database.domain or not callable(authorize)):
        raise CandidateError('installed database and full task read scope required')
    _id(actor); _integer(now)
    with database.read_snapshot() as connection:
        meta = connection.execute('SELECT authority_epoch,time_floor FROM metadata WHERE singleton=1').fetchone()
        if now < meta['time_floor'] or authorize(connection, actor, meta['authority_epoch'], key) is not True:
            raise CandidateError('current scoped completion read denied')
        task = connection.execute('SELECT revision,cycle,obligation_digest FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?', key.values()).fetchone()
        if not task:
            raise CandidateError('registered task is absent; textual DONE is not a completion')
        stable = (*key.values(), task['cycle'])
        try:
            retained, revision_bindings = database.current_completion(connection,key,with_bindings=True)
        except CoordinationError as exc:
            raise CandidateError('current completion lacks its exact revision binding') from exc
        binding = connection.execute('SELECT * FROM completion_bindings WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?', stable).fetchone()
        subject = dict(taskKey=dict(zip(('authorityDomain','projectId','changeId','taskId'),key.values())),
            taskRevision=task['revision'],taskCycle=task['cycle'],obligationDigest=task['obligation_digest'])
        completion = None
        display_binding = {'revisionBindings':revision_bindings} if revision_bindings else {}
        if retained or binding:
            if not retained or not binding:
                raise CandidateError('native completion and retained fact do not form one binding')
            raw = binding['native_bytes']; completion = codec.parse(raw)
            if completion.get('contractIdentity')=='das-analysis-completion/v1':
                ANALYSIS_COMPLETION_VALIDATOR.validate(completion)
                definition=database.analysis_task_binding(connection,key,revision=retained['revision'])
                stable=(database.domain,retained['resource_id'],'complete',retained['business_id'])
                payload=connection.execute('SELECT request_digest,payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
                observation=connection.execute('SELECT native_bytes,outcome FROM resource_observations WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=? AND native_digest=?',(*stable,binding['native_digest'])).fetchone()
                if (codec.canonical(completion)!=raw or _hash(raw)!=binding['native_digest']
                        or retained['evidence_digest']!=binding['native_digest'] or retained['receipt_digest']!=binding['native_digest']
                        or retained['action_class']!='complete'
                        or any(completion[name]!=value for name,value in dict(subject,taskRevision=retained['revision']).items())
                        or completion['taskBindingDigest']!=codec.digest(definition)
                        or completion['resourceId']!=retained['resource_id'] or completion['businessActionId']!=retained['business_id']
                        or not payload or completion['requestDigest']!=payload['request_digest']
                        or codec.digest(codec.parse(payload['payload_json'].encode()))!=payload['request_digest']
                        or not observation or observation['outcome']!='confirmed' or observation['native_bytes']!=raw):
                    raise CandidateError('analysis completion lost its approved original and atomic effect')
                return dict(**subject,status='DONE',completionDigest=binding['native_digest'],
                    completion=completion,currentQualification='not_evaluated',authority=False,qualification=False,**display_binding)
            COMPLETION_VALIDATOR.validate(completion)
            expected = dict(subject, taskRevision=retained['revision'],resourceId=retained['resource_id'],businessActionId=retained['business_id'],
                integrationReceiptDigest=retained['receipt_digest'])
            if (codec.canonical(completion) != raw or _hash(raw) != binding['native_digest']
                    or retained['evidence_digest'] != binding['native_digest']
                    or retained['action_class'] != 'integrate'
                    or any(completion[name] != value for name,value in expected.items())):
                raise CandidateError('current completion fact changed its exact native binding')
            receipt = connection.execute('SELECT native_bytes,native_digest FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',
                (database.domain,retained['resource_id'],'integrate',retained['business_id'])).fetchone()
            if not receipt or receipt['native_digest'] != retained['receipt_digest']:
                raise CandidateError('completion lost its original integration receipt')
            value = codec.parse(receipt['native_bytes']); INTEGRATION_RECEIPT_VALIDATOR.validate(value)
            same = ('taskKey','taskRevision','taskCycle','obligationDigest','policyDigest',
                    'sourceCandidateDigest','resourceId','resourceInstance','businessActionId')
            if (codec.canonical(value) != receipt['native_bytes'] or _hash(receipt['native_bytes']) != receipt['native_digest']
                    or any(value[name] != completion[name] for name in same)
                    or value['afterGeneration'] != completion['targetGeneration']
                    or value['afterCandidateDigest'] != completion['integrationCandidateDigest']):
                raise CandidateError('completion lost its actual I/resource/generation relationship')
        return dict(**subject,status='DONE' if completion else 'TODO',
            completionDigest=binding['native_digest'] if completion else None,
            completion=completion,currentQualification='not_evaluated',authority=False,qualification=False,**display_binding)


def render_projection(value):
    """Deterministic display; edited output cannot feed back into authority."""
    codec.closed_object(value, ['taskKey','taskRevision','taskCycle','obligationDigest','status',
        'completionDigest','completion','currentQualification','authority','qualification',
        *(['revisionBindings'] if 'revisionBindings' in value else [])])
    if (value['authority'] is not False or value['qualification'] is not False
            or value['currentQualification'] != 'not_evaluated'
            or value['status'] != ('DONE' if value['completion'] is not None else 'TODO')):
        raise CandidateError('projection cannot claim current permission or change recorded status')
    if value['completion'] is not None:
        validator = ANALYSIS_COMPLETION_VALIDATOR if value['completion'].get('contractIdentity') == 'das-analysis-completion/v1' else COMPLETION_VALIDATOR
        validator.validate(value['completion'])
        revision=value['completion']['taskRevision']
        for binding in value.get('revisionBindings',[]):
            if (binding.get('taskKey')!=[value['taskKey'][n] for n in ('authorityDomain','projectId','changeId','taskId')]
                    or binding.get('cycle')!=value['taskCycle'] or binding.get('fromRevision')!=revision
                    or binding.get('toRevision')!=revision+1 or binding.get('obligationDigest')!=value['obligationDigest']
                    or binding.get('evidenceDigest')!=value['completionDigest']):
                raise CandidateError('projection changed explicit revision bindings')
            revision+=1
        if (codec.digest(value['completion']) != value['completionDigest']
                or revision!=value['taskRevision']
                or any(value['completion'][name] != value[name] for name in
                    ('taskKey','taskCycle','obligationDigest'))):
            raise CandidateError('projection changed its original completion subject')
    elif value['completionDigest'] is not None or value.get('revisionBindings'):
        raise CandidateError('unfinished projection cannot carry a completion digest')
    return ('# Task completion projection\n\n'
        'Non-authoritative display. Current qualification is not evaluated.\n\n'
        'Historical status for this current task cycle: **'+value['status']+'**.\n\n'
        'Original records and scope:\n\n```json\n'
        +json.dumps(codec.parse(codec.canonical(value)),ensure_ascii=False,sort_keys=True,separators=(',',':'))
        +'\n```\n').encode('utf-8')
