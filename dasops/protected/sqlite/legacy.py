"""Finite administrator-only import of quiescent protected-v1 task records.

Released/reclaimed, expired active and completed histories only: old approvals/
receipts never become current authorization or native Completion. Unresolved
operations must recover through their original writer before import. Installation independently stops old
binaries, direct Git writers and external dispatch before approving this import.
"""
import os
from pathlib import Path
import stat
from datetime import datetime

from dasops.protected.canonical import canonical_bytes, load_canonical_json
from dasops.protected.state_store import ProtectedStateStore, atomic_write
from dasops.standards_contracts.exact_json import MAX_BYTES, canonical, parse
from dasops.tasks import index_rows_by_id, parse_tasks_index
from .store import CoordinationError, _digest, _hash, _id, _integer


def _original(path, limit=1048576):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1
            or info.st_size > limit):
        raise CoordinationError('legacy original must be bounded, private and regular')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if (info.st_dev, info.st_ino) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
            raise CoordinationError('legacy original identity changed')
        raw = os.read(fd, limit+1)
    finally:
        os.close(fd)
    if len(raw) > limit:
        raise CoordinationError('legacy original exceeds its fixed limit')
    return raw


def _completion_history(store, objects):
    """Check closed v1 Git outcomes; they confer no v1.5 qualification."""
    results = {}
    requests = {v['operationId']: v for p,v in objects.items()
                if p.startswith('receipts/') and v['schema']=='protected-completion-request/v1'}
    for operation, request in requests.items():
        prefix = f'receipts/{operation}/'
        result = objects.get(prefix+'completion-result.json')
        if result is None:
            raise CoordinationError('unresolved legacy completion requires original recovery')
        action = 'publish' if result['outcome']=='published' else 'abort'
        decision = objects.get(prefix+f'completion-decision-{action}.json')
        claim = objects.get(f"operations/{request['claimOperationId']}/readback_complete.json")
        claimed = objects.get(f"receipts/{request['claimOperationId']}/claim-result.json")
        consumption = [v for p,v in objects.items() if p.startswith(f"receipts/{request['claimOperationId']}/")
                       and v['schema']=='protected-challenge-consumption/v1' and v['operationId']==operation]
        if (claim is None or claim['operation']!='claim' or claimed is None
                or claimed['schema']!='protected-claim-result/v1' or claimed['outcome']!='claimed_pending_activation'
                or decision is None or decision['action']!=action
                or any(result[k]!=request[k] for k in ('operationId','baseCommit','candidateCommit'))
                or result['requestDigest']!=request['recordDigest']
                or decision['requestDigest']!=request['recordDigest']
                or any(result[k]!=decision[k] for k in ('approvalDigest','verificationDigest','verifiedRoleBindingsDigest'))
                or len(consumption)!=1
                or any(consumption[0][a]!=request[b] for a,b in
                       (('challengeDigest','authorizationChallengeDigest'),('authorizationResponseDigest','authorizationResponseDigest'),('inputDigest','inputDigest')))
                or any(claim[k]!=request[k] for k in ('changeId','taskId','owner'))
                or any(claimed[k]!=request[k] for k in ('changeId','taskId','owner','claimGeneration'))
                or request['taskPath']!=f"openspec/changes/{request['changeId']}/tasks.md"):
            raise CoordinationError('legacy completion history differs from its original request/decision')
        challenge = objects.get('challenges/'+consumption[0]['challengeId']+'.json')
        if (challenge is None or challenge['recordDigest']!=request['authorizationChallengeDigest']
                or challenge['operation']!='completion_authorization'
                or any(challenge[k]!=request[k] for k in ('taskId','owner','claimGeneration','leaseGeneration'))
                or challenge['canonicalCommit']!=request['baseCommit']):
            raise CoordinationError('legacy completion lacks original consumed authorization challenge')
        if (request['taskPath'] not in request['changedPaths']
                or store.repo._run('rev-parse',request['candidateCommit']+'^',check=False).stdout.decode().strip()!=request['baseCommit']
                or sorted(store.repo._run('diff','--name-only',request['baseCommit'],request['candidateCommit']).stdout.decode().splitlines())!=request['changedPaths']):
            raise CoordinationError('legacy completion Git pre/postimage differs from original request')
        for commit, status in ((request['baseCommit'],'IN_PROGRESS'),(request['candidateCommit'],'DONE')):
            row=index_rows_by_id(parse_tasks_index(store.repo.read_path(commit,request['taskPath']).decode('utf-8'))).get(request['taskId'])
            if row is None or row.owner!=request['owner'] or row.status!=status:
                raise CoordinationError('legacy completion does not retain its original canonical Task transition')
        if store.repo._run('merge-base','--is-ancestor',result['canonicalReadback'],store.repo.head(),check=False).returncode!=0:
            raise CoordinationError('legacy completion readback is outside canonical history')
        if action=='publish':
            if (result['canonicalReadback']!=request['candidateCommit']
                    or decision['canonicalHead']!=request['baseCommit']
                    or result['verificationDigest'] is None
                    or decision['supersededDecisionDigest'] is not None):
                raise CoordinationError('legacy published completion lacks its exact canonical outcome')
        elif (result['canonicalReadback']==request['candidateCommit']
                or result['canonicalReadback']!=decision['canonicalHead']
                or result['verificationDigest'] is not None):
            raise CoordinationError('legacy aborted completion has ambiguous canonical outcome')
        prior=objects.get(prefix+'completion-decision-publish.json') if action=='abort' else None
        if (action=='abort' and decision['supersededDecisionDigest']!=(prior['recordDigest'] if prior else None)
                or action=='publish' and prefix+'completion-decision-abort.json' in objects):
            raise CoordinationError('legacy completion decisions contradict their original supersession')
        results[operation] = (request,result)
    for path, value in objects.items():
        if value['schema'] in ('protected-completion-decision-intent/v1','protected-completion-result/v1','protected-challenge-consumption/v1') and value['operationId'] not in requests:
            raise CoordinationError('legacy completion history lacks its original request')
        if value['schema']=='protected-challenge-consumption/v1' and path!=f"receipts/{requests[value['operationId']]['claimOperationId']}/challenge-{value['challengeId']}.json":
            raise CoordinationError('legacy consumed authorization belongs to another original claim')
    return results


def _snapshot(store):
    store.repo.validate()
    policy = store.policy()
    originals = {'policy.json': _original(store.root/'policy.json').decode()}
    states, objects = {}, {}
    total = len(originals['policy.json'].encode())
    for category in ('states', 'operations', 'receipts', 'challenges'):
        root = store.root/category
        if root.is_symlink() or not root.is_dir():
            raise CoordinationError('complete original legacy directories required')
        # Walk without following directory aliases; refuse unknown nested shapes.
        def failed(error):
            raise error
        for parent, directories, files in os.walk(root, followlinks=False, onerror=failed):
            directory = Path(parent)
            info = directory.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise CoordinationError('legacy original directory is not private')
            for name in directories:
                if (directory/name).is_symlink():
                    raise CoordinationError('legacy directory aliases are unsupported')
            for name in sorted(files):
                path = directory/name; relative = path.relative_to(store.root)
                parts = relative.parts
                if (path.suffix != '.json' or len(parts) != (2 if category=='challenges' else 3)
                        or len(originals) >= 1000):
                    raise CoordinationError('unsupported legacy original layout or count')
                raw = _original(path); total += len(raw)
                if total > 8388608:
                    raise CoordinationError('legacy namespace exceeds finite import limit')
                value = load_canonical_json(raw); store.registry.validate(value)
                originals[relative.as_posix()] = raw.decode(); objects[relative.as_posix()] = value
                if category == 'states':
                    if (value['schema'] != 'protected-task-state/v1'
                            or (value['changeId'], value['taskId']) != (parts[1], path.stem)
                            or value['status'] not in ('released', 'reclaimed', 'active', 'completed')
                            or any(k.startswith('pending') for k in value)):
                        raise CoordinationError('only equivalent quiescent legacy tasks can be imported')
                    states[(value['changeId'], value['taskId'])] = value
                elif category == 'operations':
                    if (value['schema'] not in ('protected-operation-wal/v1','protected-lifecycle-wal/v1')
                            or value['operationId'] != parts[1] or value['phase'] != path.stem):
                        raise CoordinationError('unsupported legacy operation original')
                elif category == 'receipts':
                    if value['schema'] not in ('protected-claim-result/v1','protected-activation-receipt/v1',
                            'protected-renewal-result/v1','protected-release-result/v1','protected-reclaim-result/v1',
                            'protected-completion-request/v1','protected-completion-decision-intent/v1',
                            'protected-completion-result/v1','protected-challenge-consumption/v1'):
                        raise CoordinationError('legacy route/completion history has no equivalent import profile')
                    if value['schema']=='protected-challenge-consumption/v1':
                        if path.stem != 'challenge-'+value['challengeId']:
                            raise CoordinationError('legacy consumption identity differs from original path')
                    elif value['operationId'] != parts[1]:
                        raise CoordinationError('legacy receipt operation identity differs from its path')
                    elif value['schema'].startswith('protected-completion-'):
                        kind = ('completion-decision-'+value['action'] if value['schema']=='protected-completion-decision-intent/v1'
                                else 'completion-request' if value['schema']=='protected-completion-request/v1' else 'completion-result')
                        if path.stem!=kind:
                            raise CoordinationError('legacy completion identity differs from original path')
                elif value['schema'] != 'protected-activation-challenge/v1' or value['challengeId'] != path.stem:
                    raise CoordinationError('unsupported legacy challenge original')
    if not states:
        raise CoordinationError('nonempty quiescent legacy task namespace required')
    for path, value in objects.items():
        if path.startswith('operations/'):
            terminal = str(Path(path).parent/'readback_complete.json')
            if terminal not in objects:
                raise CoordinationError('unresolved legacy operation requires original recovery')
        if 'changeId' in value and 'taskId' in value and (value['changeId'],value['taskId']) not in states:
            raise CoordinationError('legacy history contains an unmapped task')
    completed = _completion_history(store,objects)
    head = store.repo.head()
    for state in states.values():
        claim = objects.get(f"operations/{state['operationId']}/readback_complete.json")
        if claim is None or claim['operation'] != 'claim':
            raise CoordinationError('original completed legacy claim history required')
        if store.repo._run('merge-base','--is-ancestor',state['canonicalCommit'],head,check=False).returncode != 0:
            raise CoordinationError('legacy state is not in canonical history')
        if state['status'] in ('active','completed'):
            claimed=objects.get(f"receipts/{state['operationId']}/claim-result.json")
            if (claimed is None or claimed['schema']!='protected-claim-result/v1' or claimed['outcome']!='claimed_pending_activation'
                    or any(claimed[k]!=claim[k] for k in ('changeId','taskId','owner','tokenHash','baseCommit','candidateCommit'))
                    or any(claimed[k]!=state[k] for k in ('changeId','taskId','owner','claimGeneration'))):
                raise CoordinationError('legacy activation lacks its original claim result')
            activations = [v for v in objects.values() if v['schema']=='protected-activation-receipt/v1'
                           and v['operationId']==state['operationId'] and v['outcome']=='matched'
                           and all(v[k]==state[k] for k in ('taskId','owner','tokenHash','claimGeneration','leaseGeneration'))]
            if len(activations)!=1:
                raise CoordinationError('legacy state lacks its original matched activation')
            activation = activations[0]
            if activation['activationKind']=='claim_activation':
                origin=claimed
                bound=(origin['candidateCommit']==activation['canonicalCommit'] and
                       all(origin[k]==state[k] for k in ('tokenHash','leaseGeneration')))
            else:
                renewals=[v for v in objects.values() if v['schema']=='protected-renewal-result/v1'
                          and v['claimOperationId']==state['operationId']
                          and all(v[a]==state[b] for a,b in (('changeId','changeId'),('taskId','taskId'),('owner','owner'),('newTokenHash','tokenHash'),('newLeaseGeneration','leaseGeneration')))
                          and v['canonicalCommit']==activation['canonicalCommit']]
                bound=len(renewals)==1
            if not bound:
                raise CoordinationError('legacy activation differs from its original claim/renewal')
            challenges = [v for v in objects.values() if v['schema']=='protected-activation-challenge/v1'
                          and v['recordDigest']==activation['challengeDigest']]
            if (len(challenges)!=1 or challenges[0]['operation']!=activation['activationKind']
                    or any(challenges[0][k]!=state[k] for k in ('taskId','owner','claimGeneration','leaseGeneration'))
                    or challenges[0]['canonicalCommit']!=activation['canonicalCommit']
                    or store.repo._run('merge-base','--is-ancestor',claim['candidateCommit'],activation['canonicalCommit'],check=False).returncode!=0
                    or store.repo._run('merge-base','--is-ancestor',activation['canonicalCommit'],state['canonicalCommit'],check=False).returncode!=0):
                raise CoordinationError('legacy activation lacks its original challenge')
            row = index_rows_by_id(parse_tasks_index(store.repo.read_path(state['canonicalCommit'],
                f"openspec/changes/{state['changeId']}/tasks.md").decode('utf-8'))).get(state['taskId'])
            expected_status = 'DONE' if state['status']=='completed' else 'IN_PROGRESS'
            if row is None or row.owner!=state['owner'] or row.status!=expected_status:
                raise CoordinationError('legacy state differs from its original canonical Task')
            current=index_rows_by_id(parse_tasks_index(store.repo.read_path(head,
                f"openspec/changes/{state['changeId']}/tasks.md").decode('utf-8'))).get(state['taskId'])
            if current is None or current.owner!=row.owner or current.status!=row.status:
                raise CoordinationError('legacy state no longer matches the current canonical Task')
            if state['status']=='completed':
                matched = [(r,v) for r,v in completed.values() if r['claimOperationId']==state['operationId']
                           and v['outcome']=='published' and r['candidateCommit']==state['canonicalCommit']
                           and all(r[k]==state[k] for k in ('changeId','taskId','owner','tokenHash','claimGeneration','leaseGeneration'))]
                if len(matched)!=1:
                    raise CoordinationError('legacy completed Task lacks its original published result')
            elif any(r['claimOperationId']==state['operationId'] and v['outcome']=='published'
                     for r,v in completed.values()):
                raise CoordinationError('legacy active Task contradicts its published completion')
            continue
        kind = 'release' if state['status']=='released' else 'reclaim'
        receipts = [value for path,value in objects.items() if path.startswith('receipts/')
                    and path.endswith(f'/{kind}-result.json')
                    and value.get('claimOperationId')==state['operationId']
                    and value.get('candidateCommit')==state['canonicalCommit']]
        receipt = receipts[0] if len(receipts)==1 else None
        if (receipt is None or receipt['schema'] != f'protected-{kind}-result/v1'
                or any(receipt[field] != state[field] for field in
                       ('changeId','taskId','tokenHash','claimGeneration','leaseGeneration'))
                or receipt['owner' if kind=='release' else 'priorOwner'] != state['owner']
                or receipt['candidateCommit'] != state['canonicalCommit']
                or store.repo._run('merge-base','--is-ancestor',state['canonicalCommit'],head,check=False).returncode != 0):
            raise CoordinationError('legacy terminal state lacks its original canonical receipt')
    if policy['canonicalRepoPath'] != str(store.repo.path) or policy['canonicalRef'] != store.repo.canonical_ref:
        raise CoordinationError('legacy policy differs from canonical namespace')
    return states, {'repository':str(store.repo.path),'canonicalRef':store.repo.canonical_ref,
                    'canonicalCommit':head,'originals':dict(sorted(originals.items()))}


def _check_staged(connection, domain, project, states, mapped, now):
    expected_changes = {(domain,project,key[0],'active',1,None) for key in states}
    expected_tasks = {(*((domain,project)+key),row['obligationDigest'],row['revision'],row['cycle'])
                      for key,row in mapped.items()}
    if (set(map(tuple,connection.execute('SELECT * FROM changes'))) != expected_changes
            or set(map(tuple,connection.execute('SELECT * FROM tasks'))) != expected_tasks):
        raise CoordinationError('staged legacy namespace differs from approved original import')
    leases = list(connection.execute('SELECT * FROM leases'))
    if len(leases) != len(states):
        raise CoordinationError('staged legacy lease history differs')
    for lease in leases:
        key = (lease['change_id'],lease['task_id']); state = states.get(key)
        if (state is None or tuple(lease)[:7] != (domain,project,*key,state['leaseGeneration'],state['owner'],state['tokenHash'])
                or not datetime.fromisoformat(state['updatedAt'].replace('Z','+00:00')).timestamp() <= lease['expires_at'] <= now):
            raise CoordinationError('legacy lease must retain identity and remain expired')
    tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
    for table in tables:
        if table not in ('metadata','changes','tasks','leases','audit') and connection.execute('SELECT 1 FROM '+table+' LIMIT 1').fetchone():
            raise CoordinationError('legacy import cannot invent current authorization or business facts')
    if connection.execute('SELECT COUNT(*) FROM audit').fetchone()[0] != 1:
        raise CoordinationError('unexpected staged legacy history')


def import_legacy(store, database, *, project_id, mappings, actor, now, approve):
    """Fence the old library, atomically stage an explicitly approved namespace.

    Persist the fence BEFORE the SQL commit. Failures retain it; repeat the exact
    original import to finish, never remove it to reactivate the old authority.
    The staged database rejects ordinary reads/writes until AuthorityRoute.enroll.
    No CLI or candidate-selected filesystem path is exposed by this primitive.
    """
    if not isinstance(store, ProtectedStateStore):
        raise CoordinationError('installed legacy state store required')
    _id(project_id); _id(actor); _integer(now,1)
    if database.authority_route is not None or database.connection.in_transaction or not callable(approve):
        raise CoordinationError('fresh inactive namespace and independent import approval required')
    if database.path.is_relative_to(store.repo.path):
        raise CoordinationError('new database must be outside the legacy repository')
    mappings = parse(canonical(mappings))
    with store.writer_guard(migration=True):
        states, source = _snapshot(store)
        if not isinstance(mappings,list) or len(mappings) != len(states):
            raise CoordinationError('explicit complete task mapping required')
        mapped = {}
        for row in mappings:
            if not isinstance(row,dict) or set(row) != {'changeId','taskId','obligationDigest','revision','cycle'}:
                raise CoordinationError('explicit namespace/obligation/revision/cycle mapping required')
            key = (_id(row['changeId']), _id(row['taskId']))
            _digest(row['obligationDigest']); _integer(row['revision'],1); _integer(row['cycle'],1)
            if key not in states or key in mapped:
                raise CoordinationError('duplicate or foreign legacy task mapping')
            mapped[key] = row
        for state in states.values():
            _id(state['owner'])
            _integer(state['claimGeneration'],1); _integer(state['leaseGeneration'],1)
            if datetime.fromisoformat(state['updatedAt'].replace('Z','+00:00')).timestamp() > now:
                raise CoordinationError('trusted import time predates the original legacy state')
            if state['status']=='active' and datetime.fromisoformat(state['leaseExpiresAt'].replace('Z','+00:00')).timestamp()>now:
                raise CoordinationError('live legacy activation requires original quiescence before import')
        mappings = [mapped[key] for key in sorted(mapped)]
        subject = {'source':source,'authorityDomain':database.domain,'projectId':project_id,
                   'database':str(database.path),'instance':database.instance_id,'mappings':mappings}
        if len(canonical(subject)) > MAX_BYTES:
            raise CoordinationError('legacy import exceeds the existing audit reader byte limit')
        fence = {'identity':'das-legacy-migration/v1','importDigest':_hash(subject),
                 'database':str(database.path),'authorityDomain':database.domain,'projectId':project_id}
        marker = store.root/'migration.json'
        if os.path.lexists(marker) and _original(marker) != canonical_bytes(fence):
            raise CoordinationError('legacy authority is already fenced for a different original import')
        def authorized(connection, operation, principal, epoch):
            from .authority import _state_digest
            before = _state_digest(connection); original = canonical(subject)
            granted = approve(connection, operation, principal, epoch, subject) is True
            if before != _state_digest(connection) or original != canonical(subject):
                raise CoordinationError('import approval changed its subject or database state')
            return granted
        with database.transaction('legacy_import',actor,now,authorized) as connection:
            prior = connection.execute("SELECT body FROM audit WHERE event='legacy_import_staged'").fetchall()
            if prior:
                if len(prior)!=1 or parse(prior[0][0].encode()) != subject or not marker.exists():
                    raise CoordinationError('legacy import retry differs from original staged facts')
                if _snapshot(store) != (states,source):
                    raise CoordinationError('legacy originals changed during retry approval')
                _check_staged(connection,database.domain,project_id,states,mapped,now)
                return fence
            if any(connection.execute('SELECT 1 FROM '+table+' LIMIT 1').fetchone()
                   for table in ('changes','tasks','leases','budgets','business_actions','audit')):
                raise CoordinationError('legacy import requires an empty inactive database')
            if not marker.exists():
                atomic_write(marker,canonical_bytes(fence),create_only=True)
            # Recheck after the installation's approval; no mutable callback may
            # replace the old source while its approved digest is being consumed.
            if _snapshot(store) != (states,source):
                raise CoordinationError('legacy originals changed during approval')
            for change in sorted({key[0] for key in states}):
                connection.execute("INSERT INTO changes VALUES (?,?,?,'active',1,NULL)",
                                   (database.domain,project_id,change))
            for key in sorted(states):
                state = states[key]; row = mapped[key]
                values = (database.domain,project_id,*key)
                connection.execute('INSERT INTO tasks VALUES (?,?,?,?,?,?,?)',
                                   (*values,row['obligationDigest'],row['revision'],row['cycle']))
                connection.execute('INSERT INTO leases VALUES (?,?,?,?,?,?,?,?)',
                                   (*values,state['leaseGeneration'],state['owner'],state['tokenHash'],now))
            database._audit(connection,'legacy_import_staged',actor,subject)
        database.check_integrity()
        return fence
