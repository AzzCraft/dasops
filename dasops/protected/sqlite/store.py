"""Single-database coordination kernel with explicit SQL transaction ownership.

This is not an activated protected service. Installation, authenticated IPC,
current authorization/evidence services, independent checkpoints and migration
routing must close before a deployment can accept these records as authority.
The development DELETE mode exercises real transactions; WAL admission requires
an exact independently approved runtime including the WAL-reset fix.
"""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import json
from urllib.parse import quote
import sqlite3
import stat
from typing import Callable

from dasops.standards_contracts.exact_json import canonical, parse

MAX = 9007199254740991
DIGEST = re.compile(r'^sha256:[0-9a-f]{64}$')
SCHEMA = Path(__file__).with_name('schema_v1.sql')


class CoordinationError(RuntimeError):
    pass


def _id(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or '\x00' in value:
        raise CoordinationError('invalid identity')
    value.encode('utf-8', 'strict')
    return value


def _integer(value, minimum=0):
    if type(value) is not int or not minimum <= value <= MAX:
        raise CoordinationError('invalid exact safe integer')
    return value


def _digest(value):
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise CoordinationError('invalid digest')
    return value


def _hash(value):
    return 'sha256:' + hashlib.sha256(canonical(value)).hexdigest()


def _sync_backup(path):
    """Confirm retained bytes and their name before acknowledging a snapshot."""
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class TaskKey:
    authority_domain: str
    project_id: str
    change_id: str
    task_id: str

    def values(self):
        return tuple(_id(value) for value in (self.authority_domain, self.project_id, self.change_id, self.task_id))


@dataclass(frozen=True)
class RuntimeApproval:
    """Only the installed control plane supplies this approved artifact binding.

    A verified backport maps to an exact source ID, not a claimed version range.
    It is not sufficient for activation or a substitute for signature validation.
    """
    version: str
    source_id: str
    driver_sha256: str
    compile_options_digest: str
    loaded_library_sha256: tuple[str, ...]
    approval_digest: str
    wal_reset_fix_proof: str


def runtime_identity(connection):
    import _sqlite3
    version, source = connection.execute('SELECT sqlite_version(),sqlite_source_id()').fetchone()
    driver = Path(_sqlite3.__file__).resolve()
    options = sorted(row[0] for row in connection.execute('PRAGMA compile_options'))
    libraries = []
    for line in Path('/proc/self/maps').read_text().splitlines():
        parts = line.split(None, 5)
        if len(parts) != 6 or 'libsqlite3.so' not in parts[5]:
            continue
        library = Path(parts[5])
        if not library.is_absolute() or not library.is_file():
            raise CoordinationError('loaded SQLite library cannot be bound to original bytes')
        descriptor = os.open(library, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            device = ':'.join(format(value, '02x') for value in (os.major(info.st_dev), os.minor(info.st_dev)))
            if int(parts[4]) != info.st_ino or device != parts[3]:
                raise CoordinationError('SQLite library pathname no longer identifies loaded object')
            digest = hashlib.sha256()
            with os.fdopen(os.dup(descriptor), 'rb') as loaded:
                for chunk in iter(lambda: loaded.read(65536), b''):
                    digest.update(chunk)
            libraries.append(digest.hexdigest())
        finally:
            os.close(descriptor)
    return {'sqliteVersion': version, 'sqliteSourceId': source,
            'loadedLibrarySha256': sorted(set(libraries)),
            'driverPath': str(driver), 'driverSha256': hashlib.sha256(driver.read_bytes()).hexdigest(),
            'compileOptionsDigest': _hash(options), 'pythonDriverVersion': sqlite3.version,
            'walResetFix': 'unapproved'}


def admit_wal(identity, approval):
    if not isinstance(approval, RuntimeApproval):
        raise CoordinationError('WAL requires an independently approved exact runtime')
    if (identity['sqliteVersion'] != approval.version or identity['sqliteSourceId'] != approval.source_id
            or identity['driverSha256'] != approval.driver_sha256
            or identity['compileOptionsDigest'] != approval.compile_options_digest
            or tuple(identity['loadedLibrarySha256']) != approval.loaded_library_sha256):
        raise CoordinationError('loaded SQLite runtime differs from approved artifact')
    _digest(approval.approval_digest)
    _digest(approval.wal_reset_fix_proof)
    # Fix provenance is always required, including for a legitimate distributor
    # backport. No host CLI version, FULL setting or stress-test shortcut.


def _schema_statements():
    statements=[];pending=''
    for line in SCHEMA.read_text().splitlines(keepends=True):
        pending+=line
        if sqlite3.complete_statement(pending):
            statements.append(pending);pending=''
    if pending.strip(): raise CoordinationError('incomplete schema author')
    return statements


def _schema_shape(connection):
    return [tuple(row) for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]


class _CoordinationConnection(sqlite3.Connection):
    """Owner-managed SQL policy; trusted approval code gets a read-only interval."""
    _authorizer = None
    _approval_guard = None

    def set_authorizer(self, callback):
        if self._approval_guard is not None:
            self._approval_guard[0] = True
            raise CoordinationError('approval modified its SQL policy')
        # Python 3.10 does not support disabling this callback with None.
        # An explicit allow predicate preserves the owner's no-policy semantics.
        super().set_authorizer(callback if callback is not None else lambda *args: sqlite3.SQLITE_OK)
        self._authorizer = callback

    @contextmanager
    def approval(self):
        if self._approval_guard is not None:
            yield  # The enclosing store approval owns the same guard.
            return
        if not self.in_transaction:
            raise CoordinationError('approval requires the owning transaction')
        prior = self._authorizer
        violated = self._approval_guard = [False]
        def readonly(action, first, second, database, trigger):
            allowed = action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ,
                                 sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE)
            if action == sqlite3.SQLITE_PRAGMA:
                allowed = second is None and first in (
                    'foreign_keys', 'ignore_check_constraints', 'synchronous',
                    'trusted_schema', 'recursive_triggers', 'journal_mode', 'busy_timeout', 'database_list')
            if not allowed:
                violated[0] = True
                return sqlite3.SQLITE_DENY
            return prior(action, first, second, database, trigger) if prior is not None else sqlite3.SQLITE_OK
        super().set_authorizer(readonly)
        try:
            try:
                yield
            except sqlite3.DatabaseError as exc:
                if violated[0]:
                    raise CoordinationError('approval modified or attempted to modify SQL/transaction policy') from exc
                raise
            if violated[0] or not self.in_transaction:
                raise CoordinationError('approval modified or attempted to modify SQL/transaction policy')
        finally:
            self._approval_guard = None
            super().set_authorizer(prior if prior is not None else lambda *args: sqlite3.SQLITE_OK)


class CoordinationDatabase:
    def __init__(self, path, *, authority_domain, journal='DELETE', runtime_approval=None, busy_ms=250, authority_route=None):
        self.path = Path(path)
        if (not self.path.is_absolute() or self.path.is_symlink() or self.path.resolve() != self.path
                or not self.path.is_file() or self.path.parent.is_symlink()):
            raise CoordinationError('database must be a normalized regular file in the control directory')
        for member in (self.path, self.path.parent):
            info = os.stat(member)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise CoordinationError('database and control directory must be private and owner controlled')
        if journal not in ('DELETE', 'WAL') or not 0 <= _integer(busy_ms) <= 2000:
            raise CoordinationError('unsupported connection policy')
        self.journal = journal
        self.domain = _id(authority_domain)
        self.authority_route = authority_route
        if authority_route is not None:
            from .authority import AuthorityRoute
            if not isinstance(authority_route, AuthorityRoute) or authority_route.domain != self.domain:
                raise CoordinationError('installed authority route has the wrong domain')
        self.connection = sqlite3.connect(f'file:{quote(self.path.as_posix(), safe="/")}?mode=rw', uri=True,
                                         isolation_level=None, timeout=busy_ms/1000, factory=_CoordinationConnection)
        self.connection.row_factory = sqlite3.Row
        try:
            self.runtime = runtime_identity(self.connection)
            if journal == 'WAL':
                admit_wal(self.runtime, runtime_approval)
            self.connection.execute('PRAGMA foreign_keys=ON')
            self.connection.execute('PRAGMA ignore_check_constraints=OFF')
            self.connection.execute('PRAGMA synchronous=FULL')
            self.connection.execute('PRAGMA trusted_schema=OFF')
            self.connection.execute('PRAGMA recursive_triggers=ON')
            self.connection.execute(f'PRAGMA busy_timeout={busy_ms}')
            if self.connection.execute('PRAGMA journal_mode').fetchone()[0].upper() != journal:
                raise CoordinationError('journal differs; connection cannot silently convert an active database')
            for name, expected in [('foreign_keys',1), ('ignore_check_constraints',0), ('synchronous',2), ('trusted_schema',0), ('recursive_triggers',1)]:
                if self.connection.execute('PRAGMA '+name).fetchone()[0] != expected:
                    raise CoordinationError('connection constraint/durability policy not enforced')
            meta = self.connection.execute('SELECT * FROM metadata WHERE singleton=1').fetchone()
            if (not meta or meta['identity'] != 'das-coordination-state/v1' or meta['authority_domain'] != self.domain
                    or meta['schema_digest'] != hashlib.sha256(SCHEMA.read_bytes()).hexdigest()):
                raise CoordinationError('unsupported or mismatched state identity')
            self.instance_id = meta['instance_id']
            self.check_integrity()
        except BaseException:
            self.connection.close()
            raise

    @classmethod
    def create(cls, path, *, authority_domain, instance_id):
        """Create a new staging database; never replace or auto-migrate a writer."""
        path = Path(path)
        _id(authority_domain); _id(instance_id)
        if not path.is_absolute() or path.resolve() != path or not path.parent.is_dir():
            raise CoordinationError('control directory must already exist at a normalized absolute path')
        parent = os.stat(path.parent)
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise CoordinationError('private control directory required')
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        connection = sqlite3.connect(path, isolation_level=None)
        try:
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute('PRAGMA synchronous=FULL')
            connection.execute('BEGIN IMMEDIATE')
            # executescript may implicitly COMMIT. Execute fixed author statements
            # individually, including full trigger definitions, inside our BEGIN.
            for statement in _schema_statements():
                connection.execute(statement)
            connection.execute('INSERT INTO metadata VALUES (1,?,?,?,?,?,0)',
                               ('das-coordination-state/v1', hashlib.sha256(SCHEMA.read_bytes()).hexdigest(), authority_domain, instance_id, 1))
            connection.execute('COMMIT')
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            if connection.in_transaction:
                connection.execute('ROLLBACK')
            raise
        finally:
            connection.close()
        return cls(path, authority_domain=authority_domain)

    def close(self):
        self.connection.close()

    @contextmanager
    def read_snapshot(self):
        """Short read of this same database; never retain a writer for native work."""
        if self.connection.in_transaction:
            raise CoordinationError('read preparation must precede the writer transaction')
        guard = self.authority_route.locked() if self.authority_route is not None else nullcontext(None)
        with guard as route:
            with self._read_snapshot(route) as connection:
                yield connection

    @contextmanager
    def _read_snapshot(self, route):
        connection = sqlite3.connect(f'file:{quote(self.path.as_posix(), safe="/")}?mode=ro',
            uri=True, isolation_level=None, timeout=0.250, factory=_CoordinationConnection)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA trusted_schema=OFF')
            connection.execute('BEGIN')
            meta = connection.execute('SELECT * FROM metadata WHERE singleton=1').fetchone()
            if (not meta or meta['identity'] != 'das-coordination-state/v1'
                    or meta['authority_domain'] != self.domain or meta['instance_id'] != self.instance_id
                    or meta['schema_digest'] != hashlib.sha256(SCHEMA.read_bytes()).hexdigest()):
                raise CoordinationError('read snapshot state identity changed')
            self._check_authority_enrollment(connection)
            if self.authority_route is not None:
                self.authority_route.check_current(connection, self, route)
            with connection.approval():
                yield connection
        finally:
            if connection.in_transaction:
                connection.execute('ROLLBACK')
            connection.close()

    @contextmanager
    def transaction(self, operation, actor, now, authorize: Callable):
        _id(operation); _id(actor); _integer(now)
        if not callable(authorize) or self.connection.in_transaction:
            raise CoordinationError('bounded local authorization and nonnested transaction required')
        guard = self.authority_route.locked() if self.authority_route is not None else nullcontext(None)
        with guard as route:
            with self._transaction(operation, actor, now, authorize, route) as connection:
                yield connection

    @contextmanager
    def _transaction(self, operation, actor, now, authorize, route, *, settlement=None, business=None):
        try:
            for name, expected in [('foreign_keys',1), ('ignore_check_constraints',0), ('synchronous',2), ('trusted_schema',0), ('recursive_triggers',1)]:
                if self.connection.execute('PRAGMA '+name).fetchone()[0]!=expected:
                    raise CoordinationError('writer connection policy changed')
            self._check_database_domain()
            self.connection.execute('BEGIN IMMEDIATE')
            self._check_authority_enrollment(self.connection, operation=operation)
            if self.authority_route is not None:
                self.authority_route.check_current(self.connection, self, route)
            meta = self.connection.execute('SELECT * FROM metadata WHERE singleton=1').fetchone()
            if meta['instance_id'] != self.instance_id:
                raise CoordinationError('writer state instance changed')
            if now < meta['time_floor']:
                raise CoordinationError('trusted clock moved backwards')
            # The callback is the installed service's local current-state predicate;
            # it must not send network requests or produce resource side effects.
            with self.connection.approval():
                allowed = authorize(self.connection, operation, actor, meta['authority_epoch'])
            if allowed is not True:
                raise CoordinationError('current authorization denied')
            if business is not None:
                from .authority import _state_digest
                business.update(actor=actor, time=now, sourceCheckpoint=self.checkpoint(),
                    sourceStateDigest=_state_digest(self.connection))
            if settlement is not None:
                from .authority import _state_digest
                from .outbox import _load_intent
                row, _ = _load_intent(self, *settlement['key'])
                if row['state']!=settlement['expected']:
                    raise CoordinationError('action CAS conflict; reconcile original key')
                settlement.update(actor=actor, time=now, requestDigest=row['request_digest'],
                    fingerprint=row['fingerprint'], sourceCheckpoint=self.checkpoint(),
                    sourceStateDigest=_state_digest(self.connection))
            self.connection.execute('UPDATE metadata SET time_floor=? WHERE singleton=1', (now,))
            yield self.connection
            if business is not None:
                self._audit(self.connection, 'business_committed', actor,
                    {'operation':operation, 'intentDigest':_hash(business)})
            if self.authority_route is not None:
                pending = self.authority_route.before_commit(self, route, settlement=settlement, business=business)
            self.connection.execute('COMMIT')
            if settlement is not None or business is not None:
                self.authority_route._publish(dict(pending, phase='active', migration=None))
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute('ROLLBACK')
            raise

    def _check_authority_enrollment(self, connection, *, operation=None):
        if self.authority_route is None and connection.execute(
                "SELECT 1 FROM audit WHERE event='authority_enrolled' LIMIT 1").fetchone():
            raise CoordinationError('enrolled state requires its independently installed authority route')
        if (self.authority_route is None and operation not in ('legacy_import','authority_enroll')
                and connection.execute("SELECT 1 FROM audit WHERE event='legacy_import_staged' LIMIT 1").fetchone()):
            raise CoordinationError('legacy import is inactive until independently approved route enrollment')

    def _audit(self, connection, event, actor, value):
        prior = connection.execute('SELECT sequence,digest FROM audit ORDER BY sequence DESC LIMIT 1').fetchone()
        sequence, previous = (prior['sequence']+1, prior['digest']) if prior else (1, 'sha256:'+'0'*64)
        body = canonical(value).decode('utf-8')
        digest = _hash({'sequence':sequence, 'event':event, 'actor':actor, 'body':value, 'previousDigest':previous})
        connection.execute('INSERT INTO audit VALUES (?,?,?,?,?,?)', (sequence,event,actor,body,previous,digest))

    def create_change(self, project, change, *, actor, now, authorize, predecessor=None):
        project, change = _id(project), _id(change)
        if predecessor is not None: _id(predecessor)
        with self.transaction('create_change',actor,now,authorize) as connection:
            prior = None
            if predecessor is not None:
                prior = self._parent(connection,TaskKey(self.domain,project,predecessor,'lineage'),
                    allowed=('closed','cancelled','superseded'))
            connection.execute('INSERT INTO changes VALUES (?,?,?,\'active\',1,NULL)', (self.domain,project,change))
            body = {'project':project,'change':change}
            if prior is not None:
                body.update(predecessor=predecessor,predecessorGeneration=prior['generation'],
                    predecessorStatus=prior['status'])
            self._audit(connection,'change_created',actor,body)

    def terminate_change(self, project, change, generation, *, status, actor, now, authorize, successor=None):
        """Installed control operation; never a Worker status/DONE projection.

        Authorization must approve this exact parent, terminal outcome and any
        successor. Reserved sends and terminal state share the dispatch writer's
        transaction; in-flight facts remain available to separately authorized
        lookup. No budget is refunded and no successful Completion is created.
        """
        key=TaskKey(self.domain,_id(project),_id(change),'termination');_integer(generation,1)
        if status not in ('cancelled','superseded') or (successor is not None) != (status=='superseded'):
            raise CoordinationError('cancellation or supersession with an explicit successor required')
        if successor is not None:
            _id(successor)
            if successor==change: raise CoordinationError('successor must have a new protected identity')
        with self.transaction('terminate_change',actor,now,authorize) as connection:
            parent=self._parent(connection,key,allowed=('active','closing'))
            if parent['generation']!=generation: raise CoordinationError('change generation moved')
            if successor is not None:
                connection.execute("INSERT INTO changes VALUES (?,?,?,'active',1,NULL)",
                    (self.domain,project,successor))
            stopped=connection.execute("SELECT resource_id,action_class,business_id FROM business_actions WHERE authority_domain=? AND project_id=? AND change_id=? AND state='reserved' ORDER BY resource_id,action_class,business_id",key.values()[:3]).fetchall()
            connection.execute("UPDATE business_actions SET state='not_executed' WHERE authority_domain=? AND project_id=? AND change_id=? AND state='reserved'",key.values()[:3])
            connection.execute("UPDATE changes SET status=?,generation=generation+1 WHERE authority_domain=? AND project_id=? AND change_id=?",(status,*key.values()[:3]))
            self._audit(connection,'change_'+status,actor,{'project':project,'change':change,
                'beforeGeneration':generation,'generation':generation+1,'successor':successor,
                'stoppedBeforeDispatch':[dict(row) for row in stopped]})
            if successor is not None:
                self._audit(connection,'change_created',actor,{'project':project,'change':successor,
                    'predecessor':change,'predecessorGeneration':generation+1,'predecessorStatus':status})
            return generation+1

    def add_task(self, key, obligation, *, actor, now, authorize, analysis_binding=None, predecessor=None):
        values=key.values(); _digest(obligation)
        if values[0]!=self.domain: raise CoordinationError('wrong authority domain')
        if analysis_binding is not None:
            from dasops.protected.candidates.versions import ANALYSIS_TASK_VALIDATOR
            ANALYSIS_TASK_VALIDATOR.validate(analysis_binding)
            analysis_binding = parse(canonical(analysis_binding))
            if (analysis_binding['taskKey'] != dict(zip(('authorityDomain','projectId','changeId','taskId'),values))
                    or (analysis_binding['taskRevision'],analysis_binding['taskCycle'],analysis_binding['obligationDigest']) != (1,1,obligation)):
                raise CoordinationError('analysis approval must bind the newly created task')
        with self.transaction('add_task',actor,now,authorize) as connection:
            self._parent(connection,key,allowed=('active',))
            prior = None
            if predecessor is not None:
                if (not isinstance(predecessor, TaskKey) or predecessor.authority_domain != self.domain
                        or predecessor == key):
                    raise CoordinationError('distinct same-domain predecessor task required')
                prior = connection.execute('SELECT * FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?', predecessor.values()).fetchone()
                if prior is None: raise CoordinationError('predecessor task absent')
            connection.execute('INSERT INTO tasks VALUES (?,?,?,?,?,1,1)', (*values,obligation))
            connection.execute('UPDATE changes SET generation=generation+1 WHERE authority_domain=? AND project_id=? AND change_id=?',values[:3])
            body={'taskKey':list(values),'obligationDigest':obligation}
            if prior is not None: body['predecessor'] = dict(prior)
            if analysis_binding is not None: body['analysisBinding']=analysis_binding
            self._audit(connection,'task_added',actor,body)

    def clarify_task(self, key, *, revision, cycle, obligation, clarification_digest,
                     review_digest, review, actor, now, authorize, analysis_binding=None):
        """Installed nonmaterial-revision control; never changes the obligation.

        The bounded readonly reviewer independently resolves the two retained
        document/review digests and approves this exact context. It is installed
        control code, not a Worker-supplied predicate or an evidence waiver.
        Old candidate/plan bytes remain old; current qualification must explicitly
        consume the rebinding event. Completion history is never rewritten.
        """
        _integer(revision,1); _integer(cycle,1); _digest(obligation)
        _digest(clarification_digest); _digest(review_digest)
        if not callable(review): raise CoordinationError('independent clarification review required')
        with self.transaction('clarify_task',actor,now,authorize) as connection:
            self._parent(connection,key,allowed=('active',))
            task=connection.execute('SELECT * FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
            if (key.authority_domain!=self.domain or not task
                    or (task['revision'],task['cycle'],task['obligation_digest'])!=(revision,cycle,obligation)):
                raise CoordinationError('current definition changed; material obligations require a new Task')
            lease=connection.execute('SELECT owner,expires_at FROM leases WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
            if lease and (lease['owner']==actor or lease['expires_at']>now):
                raise CoordinationError('independent review and quiescent task required')
            pending=connection.execute("SELECT 1 FROM business_actions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND state IN ('reserved','dispatched','unknown') LIMIT 1",key.values()).fetchone()
            if pending: raise CoordinationError('unresolved task actions prevent revision rebinding')
            completed=self.current_completion(connection,key)
            context=dict(taskKey=list(key.values()),cycle=cycle,fromRevision=revision,toRevision=revision+1,
                obligationDigest=obligation,clarificationDigest=clarification_digest,reviewDigest=review_digest,
                completionDigest=_hash(completed) if completed else None,
                evidenceDigest=completed['evidence_digest'] if completed else None)
            analysis=any('analysisBinding' in parse(row['body'].encode()) and
                parse(row['body'].encode()).get('taskKey')==list(key.values())
                for row in connection.execute("SELECT body FROM audit WHERE event='task_added'"))
            if analysis:
                from dasops.protected.candidates.versions import ANALYSIS_TASK_VALIDATOR
                if analysis_binding is None:raise CoordinationError('fresh explicit analysis revision binding required')
                ANALYSIS_TASK_VALIDATOR.validate(analysis_binding)
                old_binding=self.analysis_task_binding(connection,key)
                if (analysis_binding['taskRevision']!=revision+1 or any(analysis_binding[n]!=old_binding[n]
                        for n in ('taskKey','taskCycle','obligationDigest','policyDigest','completionMode'))):
                    raise CoordinationError('analysis clarification cannot change completion mode or obligation')
                context['analysisBinding']=parse(canonical(analysis_binding))
            elif analysis_binding is not None:raise CoordinationError('cannot add a retroactive analysis exemption')
            raw=canonical(context)
            with connection.approval(): approved=review(connection,context)
            if approved is not True or canonical(context)!=raw:
                raise CoordinationError('nonmaterial equivalence and exact evidence rebinding denied')
            connection.execute('UPDATE tasks SET revision=revision+1 WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values())
            connection.execute('UPDATE changes SET generation=generation+1 WHERE authority_domain=? AND project_id=? AND change_id=?',key.values()[:3])
            self._audit(connection,'task_revision_rebound',actor,context)
            return revision+1

    def current_completion(self, connection, key, *, with_bindings=False):
        """Original completion plus explicit contiguous same-obligation mappings.

        This resolves historical completion identity, not present qualification.
        Callers still check current targets, authorization and evidence lifetime.
        """
        if (not connection.in_transaction or key.authority_domain!=self.domain
                or [(r[1],r[2]) for r in connection.execute('PRAGMA database_list') if r[1]!='temp']!=[('main',str(self.path))]):
            raise CoordinationError('current authority transaction required')
        task=connection.execute('SELECT * FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
        if task is None: raise CoordinationError('task absent')
        row=connection.execute('SELECT * FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*key.values(),task['cycle'])).fetchone()
        if row is None:return (None,[]) if with_bindings else None
        completion=dict(row);revision=completion['revision'];bindings=[]
        for event in connection.execute("SELECT body FROM audit WHERE event='task_revision_rebound' ORDER BY sequence"):
            mapping=parse(event['body'].encode())
            if mapping['taskKey']!=list(key.values()) or mapping['cycle']!=task['cycle'] or mapping['fromRevision']<revision:continue
            if (mapping['fromRevision']!=revision or mapping['toRevision']!=revision+1
                    or mapping['obligationDigest']!=task['obligation_digest']
                    or mapping['completionDigest']!=_hash(completion)
                    or mapping['evidenceDigest']!=completion['evidence_digest']):
                raise CoordinationError('explicit completion revision mapping differs')
            revision+=1
            bindings.append(mapping)
        if revision!=task['revision']:raise CoordinationError('current completion requires explicit revision rebinding')
        return (completion,bindings) if with_bindings else completion

    def analysis_task_binding(self, connection, key, *, cycle=None, revision=None):
        """Original approval and explicit revision/cycle bindings; no new waiver.

        The existing control-plane add_task transaction establishes this record
        before a worker can claim the task. Legacy tasks keep their integration
        requirement. The audit author remains append-only and backup-checked.
        """
        if (not connection.in_transaction or
                [(row[1],row[2]) for row in connection.execute('PRAGMA database_list') if row[1]!='temp'] != [('main',str(self.path))]):
            raise CoordinationError('current task snapshot required')
        creations=[];matches=[]
        current=connection.execute('SELECT revision,cycle,obligation_digest FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
        if not current: raise CoordinationError('current analysis task absent')
        selected=current['cycle'] if cycle is None else _integer(cycle,1)
        selected_revision=current['revision'] if revision is None else _integer(revision,1)
        if selected>current['cycle'] or selected_revision>current['revision']:raise CoordinationError('analysis cycle/revision is not established')
        for row in connection.execute("SELECT event,body FROM audit WHERE event IN ('task_added','task_rework','task_revision_rebound')"):
            body=parse(row['body'].encode())
            if body.get('taskKey')!=list(key.values()):continue
            if row['event']=='task_added':creations.append(body)
            bound=body.get('analysisBinding')
            if bound and (bound['taskRevision'],bound['taskCycle'],bound['obligationDigest'])==(selected_revision,selected,current['obligation_digest']):matches.append(bound)
        if len(creations)!=1 or 'analysisBinding' not in creations[0] or len(matches)!=1:
            raise CoordinationError('analysis completion was not approved at task creation')
        return matches[0]

    def _parent(self, connection, key, allowed=('active','closing')):
        row=connection.execute('SELECT * FROM changes WHERE authority_domain=? AND project_id=? AND change_id=?',key.values()[:3]).fetchone()
        if not row or row['status'] not in allowed: raise CoordinationError('parent does not permit this operation')
        return row

    def _unfinished_cycle(self, connection, key, cycle):
        if connection.execute('SELECT 1 FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*key.values(),cycle)).fetchone():
            raise CoordinationError('current task cycle is completed; explicit rework required')

    def claim(self, key, token_hash, *, actor, expires_at, now, authorize):
        _digest(token_hash);_integer(expires_at,1)
        if expires_at<=now: raise CoordinationError('lease must expire in the future')
        with self.transaction('claim',actor,now,authorize) as connection:
            for row in connection.execute("SELECT actor,body FROM audit WHERE event IN ('task_added','task_rework','task_revision_rebound')"):
                creation=parse(row['body'].encode())
                if (creation.get('taskKey')==list(key.values()) and 'analysisBinding' in creation
                        and row['actor']==actor):
                    raise CoordinationError('analysis approver cannot claim its own task')
            self._parent(connection,key,allowed=('active',))
            task=connection.execute('SELECT * FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
            if not task: raise CoordinationError('task absent')
            self._unfinished_cycle(connection,key,task['cycle'])
            old=connection.execute('SELECT * FROM leases WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
            if old and old['expires_at']>now: raise CoordinationError('lease already held')
            generation=old['generation']+1 if old else 1
            if old:
                connection.execute('UPDATE leases SET generation=?,owner=?,token_hash=?,expires_at=? WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',(generation,actor,token_hash,expires_at,*key.values()))
            else:
                connection.execute('INSERT INTO leases VALUES (?,?,?,?,?,?,?,?)',(*key.values(),generation,actor,token_hash,expires_at))
            self._audit(connection,'lease_claimed',actor,{'taskKey':list(key.values()),'generation':generation})
            return generation

    def renew(self, key, token_hash, generation, *, actor, expires_at, now, authorize):
        _digest(token_hash);_integer(generation,1);_integer(expires_at,1)
        if expires_at<=now: raise CoordinationError('lease expiry invalid')
        with self.transaction('renew',actor,now,authorize) as connection:
            self._parent(connection,key,allowed=('active',))
            task=connection.execute('SELECT cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
            if not task: raise CoordinationError('task absent')
            self._unfinished_cycle(connection,key,task['cycle'])
            result=connection.execute('UPDATE leases SET expires_at=? WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND generation=? AND owner=? AND token_hash=? AND expires_at>? AND expires_at<=?',(expires_at,*key.values(),generation,actor,token_hash,now,expires_at))
            if result.rowcount!=1: raise CoordinationError('expired, superseded or mismatched lease')
            self._audit(connection,'lease_renewed',actor,{'taskKey':list(key.values()),'generation':generation,'expiresAt':expires_at})

    def create_budget(self, budget_id, ceiling, *, actor, now, authorize):
        _id(budget_id);_integer(ceiling,1)
        with self.transaction('create_budget',actor,now,authorize) as connection:
            connection.execute('INSERT INTO budgets VALUES (?,?,?,0)',(self.domain,budget_id,ceiling))
            self._audit(connection,'budget_created',actor,{'budgetId':budget_id,'ceiling':ceiling})

    def reserve(self, key, *, resource_id, action_class, business_id, original_actor, request_digest,
                budget_ids, cost, cycle, actor, now, authorize, payload=None):
        if payload is not None and self.authority_route is not None:
            arguments={'taskKey':list(key.values()), 'resource':resource_id, 'action':action_class,
                'business':business_id, 'originalActor':original_actor, 'requestDigest':request_digest,
                'budgets':list(budget_ids), 'cost':cost, 'cycle':cycle}
            return self._commit_business('reserve', arguments, actor, now, authorize, payload=payload)
        with self.transaction('reserve',actor,now,authorize) as connection:
            return self._reserve(connection,key,resource_id=resource_id, action_class=action_class, business_id=business_id,
                original_actor=original_actor, request_digest=request_digest, budget_ids=budget_ids,
                cost=cost, cycle=cycle, actor=actor, payload=payload)

    def _commit_business(self, operation, arguments, actor, now, authorize, *, payload=None, recovery_only=False):
        """Only three fixed installed writers; not arbitrary SQL or adapter replay."""
        _id(actor); _integer(now)
        if (operation not in ('reserve','action_dispatched','complete') or not callable(authorize)
                or self.connection.in_transaction or self.authority_route is None):
            raise CoordinationError('fixed routed business writer required')
        with self.authority_route.locked() as route:
            if route is not None and route['phase']=='committing':
                return self.authority_route.recover_business(self, route, operation, arguments,
                    actor=actor, now=now, authorize=authorize, payload=payload)
            if recovery_only:
                # Another connection may already have recovered while this
                # lookup waited. Never turn that race into a new dispatch.
                with self._read_snapshot(route):
                    return self._business_result(operation,arguments)
            intent={'operation':operation, 'arguments':parse(canonical(arguments)),
                'auditBinding':'intent-sha256-v1'}
            with self._transaction(operation,actor,now,authorize,route,business=intent) as connection:
                result=self._apply_business(connection,operation,arguments,actor,payload=payload)
            return result

    def _apply_business(self, connection, operation, arguments, actor, *, payload=None):
        # Each branch invokes its existing fixed invariant checks. The route
        # retains only exact arguments/digests, never a replay function or SQL.
        a=arguments
        if operation=='reserve':
            if set(a)!={'taskKey','resource','action','business','originalActor','requestDigest','budgets','cost','cycle'}:
                raise CoordinationError('exact original reservation arguments required')
            return self._reserve(connection,TaskKey(*a['taskKey']),resource_id=a['resource'],
                action_class=a['action'],business_id=a['business'],original_actor=a['originalActor'],
                request_digest=a['requestDigest'],budget_ids=a['budgets'],cost=a['cost'],cycle=a['cycle'],
                actor=actor,payload=payload)
        if operation=='action_dispatched':
            from .outbox import _load_intent
            if set(a)!={'key','requestDigest','fingerprint'}:
                raise CoordinationError('exact original dispatch arguments required')
            row,_=_load_intent(self,*a['key'])
            if (row['request_digest'],row['fingerprint'])!=(a['requestDigest'],a['fingerprint']):
                raise CoordinationError('dispatch intent differs from the original request')
            self._transition_action(connection,(self.domain,*a['key']),'reserved','dispatched',None,None,None,actor)
            return self._business_result(operation,a)
        if operation=='complete':
            if set(a)!={'taskKey','cycle','revision','resource','action','business','receiptDigest','evidenceDigest'}:
                raise CoordinationError('exact original Completion arguments required')
            return self._record_completion(connection,TaskKey(*a['taskKey']),cycle=a['cycle'],revision=a['revision'],
                resource_id=a['resource'],action_class=a['action'],business_id=a['business'],
                receipt_digest=a['receiptDigest'],evidence_digest=a['evidenceDigest'],actor=actor)
        raise CoordinationError('unsupported retained business operation')

    def _business_result(self, operation, arguments):
        a=arguments
        if operation=='complete':
            row=self.connection.execute('SELECT * FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*a['taskKey'],a['cycle'])).fetchone()
        else:
            key=a['key'] if operation=='action_dispatched' else [a['resource'],a['action'],a['business']]
            row=self.connection.execute('SELECT * FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',(self.domain,*key)).fetchone()
        if row is None:raise CoordinationError('original committed business result missing')
        return dict(row)

    def _reserve(self, connection, key, *, resource_id, action_class, business_id, original_actor,
                 request_digest, budget_ids, cost, cycle, actor, payload=None, parent_allowed=('active',)):
        if connection is not self.connection or not connection.in_transaction or key.authority_domain!=self.domain:
            raise CoordinationError('current authority-domain writer required')
        stable=(self.domain,_id(resource_id),_id(action_class),_id(business_id))
        _id(original_actor);_digest(request_digest);_integer(cost,1);_integer(cycle,1)
        if (not isinstance(budget_ids,(tuple,list)) or not 1<=len(budget_ids)<=9
                or len(budget_ids)!=len(set(budget_ids))): raise CoordinationError('shared budget ancestry required')
        budgets=sorted(_id(value) for value in budget_ids)
        if payload is not None:
            if (not isinstance(payload, bytes) or not 2 <= len(payload) <= 65536
                    or canonical(parse(payload)) != payload
                    or 'sha256:' + hashlib.sha256(payload).hexdigest() != request_digest):
                raise CoordinationError('immutable action payload must bind exact bounded JCS bytes')
        fingerprint=_hash({'taskKey':list(key.values()),'cycle':cycle,'originalActor':original_actor,
                           'requestDigest':request_digest,'budgets':budgets,'cost':cost})
        existing=connection.execute('SELECT * FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
        if existing:
            if existing['fingerprint']!=fingerprint: raise CoordinationError('same business key has different immutable request')
            if payload is not None:
                stored=connection.execute('SELECT request_digest,payload_json FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
                if not stored or stored['request_digest']!=request_digest or stored['payload_json'].encode()!=payload:
                    raise CoordinationError('cannot attach or change an intent after reservation')
            return dict(existing)
        if original_actor!=actor: raise CoordinationError('new action original actor must be authenticated actor')
        self._parent(connection,key,allowed=parent_allowed)
        task=connection.execute('SELECT cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
        if not task or task['cycle']!=cycle: raise CoordinationError('current task cycle mismatch')
        if action_class not in ('inspect','audit'): self._unfinished_cycle(connection,key,cycle)
        connection.execute('INSERT INTO business_actions VALUES (?,?,?,?,?,?,?,?,?,?,\'reserved\',NULL)',(*stable,*key.values()[1:],cycle,fingerprint,original_actor))
        if payload is not None:
            connection.execute('INSERT INTO action_payloads VALUES (?,?,?,?,?,?)',(*stable,request_digest,payload.decode('utf-8')))
        for budget in budgets:
            changed=connection.execute('UPDATE budgets SET reserved=reserved+? WHERE authority_domain=? AND budget_id=? AND reserved<=ceiling-?',(cost,self.domain,budget,cost))
            if changed.rowcount!=1: raise CoordinationError('shared budget absent or exceeded')
            connection.execute('INSERT INTO reservations VALUES (?,?,?,?,?,?)',(*stable,budget,cost))
        self._audit(connection,'action_reserved',actor,{'key':list(stable),'fingerprint':fingerprint})
        return dict(connection.execute('SELECT * FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone())

    def transition_action(self, resource, action, business, *, expected, target, receipt_digest=None, receipt_bytes=None, actor, now, authorize, retain_recovery=False):
        # A crash after the durable dispatch intent can leave dispatched without
        # any send. The installed consumer may settle verified absence only with
        # an independent execution-closure witness, just as for unknown. Neither
        # unresolved state can go directly back to reserved or be redispatched.
        allowed={('reserved','dispatched'),('dispatched','unknown'),('dispatched','confirmed'),('dispatched','not_executed'),('unknown','confirmed'),('unknown','not_executed'),('not_executed','reserved')}
        if (expected,target) not in allowed: raise CoordinationError('unsupported action transition; unknown cannot be redispatched')
        if target=='confirmed': _digest(receipt_digest)
        elif receipt_digest is not None: raise CoordinationError('receipt requires confirmed resource outcome')
        native_digest=None
        if receipt_bytes is not None:
            if (target not in ('confirmed','not_executed') or not isinstance(receipt_bytes,bytes)
                    or not 1<=len(receipt_bytes)<=65536):
                raise CoordinationError('unsupported original resource observation')
            native_digest='sha256:'+hashlib.sha256(receipt_bytes).hexdigest()
            if target=='confirmed' and receipt_digest!=native_digest:
                raise CoordinationError('receipt digest differs from retained original bytes')
        stable=(self.domain,_id(resource),_id(action),_id(business))
        if ((expected,target)==('reserved','dispatched') and self.authority_route is not None
                and self.connection.execute('SELECT 1 FROM action_payloads WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()):
            from .outbox import _load_intent
            row,_=_load_intent(self,*stable[1:])
            self._commit_business('action_dispatched',{'key':list(stable[1:]),
                'requestDigest':row['request_digest'],'fingerprint':row['fingerprint']},actor,now,authorize)
            return
        if retain_recovery and self.authority_route is not None:
            if target not in ('confirmed','not_executed') or receipt_bytes is None:
                raise CoordinationError('only verified original outbox settlement can retain recovery')
            _id(actor);_integer(now)
            if not callable(authorize) or self.connection.in_transaction:
                raise CoordinationError('bounded local authorization and nonnested transaction required')
            with self.authority_route.locked() as route:
                settlement={'key':list(stable[1:]),'expected':expected,'nativeDigest':native_digest,
                    'auditBinding':'intent-sha256-v1'}
                # Confirmation remains the default target; old intent shapes
                # retain their reader. Absence is never inferred from a receipt.
                if target=='not_executed':settlement['target']=target
                with self._transaction('action_'+target,actor,now,authorize,route,settlement=settlement) as connection:
                    self._transition_action(connection,stable,expected,target,receipt_digest,native_digest,receipt_bytes,actor,
                        settlement_digest=_hash(settlement))
            return
        with self.transaction('action_'+target,actor,now,authorize) as connection:
            self._transition_action(connection,stable,expected,target,receipt_digest,native_digest,receipt_bytes,actor)

    def _transition_action(self, connection, stable, expected, target, receipt_digest, native_digest, receipt_bytes, actor, *, settlement_digest=None, parent_allowed=('active',)):
        action=stable[2]
        row=connection.execute('SELECT * FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
        if not row: raise CoordinationError('unknown business action')
        # The resource gateway's predicate must verify current authorization,
        # fencing and receipt provenance, not merely a client-supplied hash.
        key=TaskKey(self.domain,row['project_id'],row['change_id'],row['task_id'])
        if target in ('dispatched','reserved'):
            self._parent(connection,key,allowed=parent_allowed)
            if action not in ('inspect','audit'): self._unfinished_cycle(connection,key,row['cycle'])
        changed=connection.execute('UPDATE business_actions SET state=?,receipt_digest=? WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=? AND state=?',(target,receipt_digest,*stable,expected))
        if changed.rowcount!=1: raise CoordinationError('action CAS conflict; reconcile original key')
        if receipt_bytes is not None:
            old=connection.execute('SELECT outcome,native_bytes FROM resource_observations WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=? AND native_digest=?',(*stable,native_digest)).fetchone()
            if old:
                if old['outcome']!=target or old['native_bytes']!=receipt_bytes:
                    raise CoordinationError('resource observation already has another immutable meaning')
            else:
                connection.execute('INSERT INTO resource_observations VALUES (?,?,?,?,?,?,?)',(*stable,native_digest,target,receipt_bytes))
        body={'key':list(stable),'receiptDigest':receipt_digest}
        if settlement_digest is not None:body['settlementDigest']=settlement_digest
        self._audit(connection,'action_'+target,actor,body)

    def _check_database_domain(self):
        if self.connection.execute('PRAGMA journal_mode').fetchone()[0].upper() != self.journal:
            raise CoordinationError('writer journal policy changed; exact runtime admission required')
        names={row[1] for row in self.connection.execute('PRAGMA database_list')}
        if names - {'main','temp'} or self.connection.execute('SELECT COUNT(*) FROM sqlite_temp_master').fetchone()[0]:
            raise CoordinationError('attached databases or shadowing TEMP objects are outside the authority transaction domain')

    def check_integrity(self):
        reference=sqlite3.connect(':memory:',isolation_level=None)
        try:
            for statement in _schema_statements(): reference.execute(statement)
            if _schema_shape(self.connection)!=_schema_shape(reference):
                raise CoordinationError('physical schema/constraint author mismatch')
        finally:
            reference.close()
        if self.connection.execute('PRAGMA integrity_check').fetchall()[0][0]!='ok' or self.connection.execute('PRAGMA foreign_key_check').fetchall():
            raise CoordinationError('database integrity or foreign-key failure')
        self._check_database_domain()
        previous='sha256:'+'0'*64
        expected_sequence=1
        for row in self.connection.execute('SELECT * FROM audit ORDER BY sequence'):
            digest=_hash({'sequence':row['sequence'],'event':row['event'],'actor':row['actor'],
                          'body':json.loads(row['body']),'previousDigest':previous})
            if row['sequence']!=expected_sequence or row['previous_digest']!=previous or row['digest']!=digest:
                raise CoordinationError('audit chain or sequence mismatch')
            expected_sequence+=1; previous=digest
        # Budget totals are derivable from retained reservation history.
        wrong=self.connection.execute('SELECT b.budget_id FROM budgets b WHERE b.reserved != COALESCE((SELECT SUM(r.cost) FROM reservations r WHERE r.authority_domain=b.authority_domain AND r.budget_id=b.budget_id),0)').fetchall()
        if wrong: raise CoordinationError('budget/reservation invariant violated')
        for row in self.connection.execute('SELECT request_digest,payload_json FROM action_payloads'):
            raw=row['payload_json'].encode('utf-8')
            if canonical(parse(raw))!=raw or 'sha256:'+hashlib.sha256(raw).hexdigest()!=row['request_digest']:
                raise CoordinationError('retained action payload integrity violated')
        for row in self.connection.execute('SELECT native_digest,native_bytes FROM resource_observations'):
            if 'sha256:'+hashlib.sha256(row['native_bytes']).hexdigest()!=row['native_digest']:
                raise CoordinationError('retained native resource observation integrity violated')
        for table, payload, identity in [('candidate_objects','binding_json','candidate_digest'),
                                         ('version_plans','payload_json','plan_digest')]:
            for row in self.connection.execute('SELECT * FROM '+table):
                raw=row[payload].encode('utf-8')
                if canonical(parse(raw))!=raw or 'sha256:'+hashlib.sha256(raw).hexdigest()!=row[identity]:
                    raise CoordinationError('retained candidate/plan byte identity violated')
        for target in self.connection.execute('SELECT * FROM version_targets'):
            generation,candidate=1,target['initial_candidate_digest']
            for receipt in self.connection.execute('SELECT * FROM version_switch_receipts WHERE authority_domain=? AND resource_id=? ORDER BY after_generation',
                    (target['authority_domain'],target['resource_id'])):
                raw=receipt['native_bytes'];value=parse(raw)
                expected=(receipt['authority_domain'],receipt['resource_id'],receipt['resource_instance'],
                    receipt['action_class'],receipt['business_id'],receipt['request_digest'],receipt['plan_digest'],
                    receipt['before_generation'],receipt['after_generation'],receipt['before_candidate'],receipt['after_candidate'])
                observed=tuple(value.get(name) for name in ('authorityDomain','resourceId','resourceInstance',
                    'action','businessActionId','requestDigest','planDigest','beforeGeneration','afterGeneration',
                    'beforeCandidateDigest','afterCandidateDigest')) if isinstance(value,dict) else ()
                if (canonical(value)!=raw or 'sha256:'+hashlib.sha256(raw).hexdigest()!=receipt['native_digest']
                        or observed!=expected or receipt['before_generation']!=generation
                        or receipt['before_candidate']!=candidate):
                    raise CoordinationError('native version receipt or generation lineage violated')
                generation,candidate=receipt['after_generation'],receipt['after_candidate']
            if (target['generation'],target['candidate_digest'])!=(generation,candidate):
                raise CoordinationError('version target differs from retained native switch lineage')

    def begin_closing(self, project, change, generation, *, actor, now, authorize):
        key=TaskKey(self.domain,_id(project),_id(change),'closing')
        _integer(generation,1)
        with self.transaction('begin_closing',actor,now,authorize) as connection:
            parent=self._parent(connection,key,allowed=('active',))
            if parent['generation']!=generation: raise CoordinationError('change generation moved')
            rows=connection.execute('SELECT task_id,obligation_digest,revision,cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? ORDER BY task_id',key.values()[:3]).fetchall()
            if not rows: raise CoordinationError('empty task set cannot close')
            task_set=_hash([dict(row) for row in rows])
            connection.execute("UPDATE changes SET status='closing',generation=generation+1,task_set_digest=? WHERE authority_domain=? AND project_id=? AND change_id=?",(task_set,*key.values()[:3]))
            self._audit(connection,'change_closing',actor,{'project':project,'change':change,'taskSetDigest':task_set})
            return generation+1,task_set

    def withdraw_closing(self, project, change, generation, *, actor, now, authorize):
        """Withdraw only a current closing plan, never a terminal result."""
        key=TaskKey(self.domain,_id(project),_id(change),'closing');_integer(generation,1)
        with self.transaction('withdraw_closing',actor,now,authorize) as connection:
            parent=self._parent(connection,key,allowed=('closing',))
            if parent['generation']!=generation: raise CoordinationError('change generation moved')
            connection.execute("UPDATE changes SET status='active',generation=generation+1,task_set_digest=NULL WHERE authority_domain=? AND project_id=? AND change_id=?",key.values()[:3])
            self._audit(connection,'closing_withdrawn',actor,{'project':project,'change':change,
                'beforeGeneration':generation,'generation':generation+1,'taskSetDigest':parent['task_set_digest']})
            return generation+1

    def record_completion(self, key, *, cycle, revision, resource_id, action_class, business_id,
                          receipt_digest, evidence_digest, actor, now, authorize):
        """Trusted evidence consumer only; no CLI or unauthenticated RPC maps here.

        authorize must independently validate required slots, actual I, Decision
        purpose and current resource result. This kernel alone is not execution.
        """
        if self.authority_route is not None:
            return self._commit_business('complete',{'taskKey':list(key.values()),'cycle':cycle,'revision':revision,
                'resource':resource_id,'action':action_class,'business':business_id,
                'receiptDigest':receipt_digest,'evidenceDigest':evidence_digest},actor,now,authorize)
        with self.transaction('complete',actor,now,authorize) as connection:
            return self._record_completion(connection,key,cycle=cycle,revision=revision,
                resource_id=resource_id,action_class=action_class,business_id=business_id,
                receipt_digest=receipt_digest,evidence_digest=evidence_digest,actor=actor)

    def _record_completion(self, connection, key, *, cycle, revision, resource_id, action_class,
                           business_id, receipt_digest, evidence_digest, actor):
        """Share the existing uniqueness invariant inside an authorized transaction."""
        if connection is not self.connection or not connection.in_transaction or key.authority_domain!=self.domain:
            raise CoordinationError('current authority-domain transaction required')
        _integer(cycle,1);_integer(revision,1);_digest(receipt_digest);_digest(evidence_digest)
        stable=(self.domain,_id(resource_id),_id(action_class),_id(business_id))
        old=connection.execute('SELECT * FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*key.values(),cycle)).fetchone()
        if old:
            expected={'revision':revision,'resource_id':resource_id,'action_class':action_class,'business_id':business_id,'receipt_digest':receipt_digest,'evidence_digest':evidence_digest}
            if any(old[name]!=value for name,value in expected.items()): raise CoordinationError('completion cycle already has different immutable result')
            return dict(old)
        self._parent(connection,key)
        task=connection.execute('SELECT revision,cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',key.values()).fetchone()
        if not task or (task['revision'],task['cycle'])!=(revision,cycle): raise CoordinationError('current task definition/cycle mismatch')
        action=connection.execute('SELECT * FROM business_actions WHERE authority_domain=? AND resource_id=? AND action_class=? AND business_id=?',stable).fetchone()
        if (not action or action['state']!='confirmed' or action['receipt_digest']!=receipt_digest
                or (action['project_id'],action['change_id'],action['task_id'],action['cycle'])!=(*key.values()[1:],cycle)):
            raise CoordinationError('confirmed integration receipt does not bind this task/cycle')
        connection.execute('INSERT INTO completions VALUES (?,?,?,?,?,?,?,?,?,?,?)',(*key.values(),cycle,revision,evidence_digest,resource_id,action_class,business_id,receipt_digest))
        self._audit(connection,'completion_recorded',actor,{'taskKey':list(key.values()),'cycle':cycle,'revision':revision,'evidenceDigest':evidence_digest,'receiptDigest':receipt_digest})
        return dict(connection.execute('SELECT * FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*key.values(),cycle)).fetchone())

    def close_change(self, project, change, generation, task_set_digest, *, actor, now, authorize):
        key=TaskKey(self.domain,_id(project),_id(change),'closing');_integer(generation,1);_digest(task_set_digest)
        with self.transaction('close_change',actor,now,authorize) as connection:
            parent=self._parent(connection,key,allowed=('closing',))
            rows=connection.execute('SELECT task_id,obligation_digest,revision,cycle FROM tasks WHERE authority_domain=? AND project_id=? AND change_id=? ORDER BY task_id',key.values()[:3]).fetchall()
            if (parent['generation']!=generation or parent['task_set_digest']!=task_set_digest
                    or _hash([dict(row) for row in rows])!=task_set_digest): raise CoordinationError('closing task set/generation changed')
            missing=[row['task_id'] for row in rows if self.current_completion(connection,
                TaskKey(self.domain,project,change,row['task_id'])) is None]
            pending=connection.execute("SELECT business_id FROM business_actions WHERE authority_domain=? AND project_id=? AND change_id=? AND state IN ('reserved','dispatched','unknown')",key.values()[:3]).fetchall()
            if not rows or missing or pending: raise CoordinationError('incomplete task set or unresolved resource side effects')
            connection.execute("UPDATE changes SET status='closed',generation=generation+1 WHERE authority_domain=? AND project_id=? AND change_id=?",key.values()[:3])
            self._audit(connection,'change_closed',actor,{'project':project,'change':change,
                'beforeGeneration':generation,'generation':generation+1,'taskSetDigest':task_set_digest})

    def rescind_closure(self, project, change, generation, *, actor, now, authorize, impact_evidence_digest, verify_no_impact):
        """Narrow administrative exception, using installed independent facts.

        verify_no_impact is a bounded, read-only local control predicate, not a
        Worker flag. It must verify independent evidence of no deployment,
        migration, external dependency impact or downstream consumption of this
        exact closure and the retained impact_evidence_digest. Unknown is refusal.
        Historical closures without a bound
        generation require successor work, not an inferred administrative waiver.
        """
        key=TaskKey(self.domain,_id(project),_id(change),'closure');_integer(generation,1)
        _digest(impact_evidence_digest)
        if not callable(verify_no_impact): raise CoordinationError('independent closure impact verification required')
        with self.transaction('rescind_closure',actor,now,authorize) as connection:
            parent=self._parent(connection,key,allowed=('closed',))
            if parent['generation']!=generation: raise CoordinationError('change generation moved')
            matching=[]
            for row in connection.execute("SELECT sequence,digest,actor,body FROM audit WHERE event='change_closed'"):
                body=parse(row['body'].encode())
                if (body.get('project'),body.get('change'),body.get('generation'))==(project,change,generation):
                    matching.append(dict(row,body=body))
            if len(matching)!=1 or matching[0]['actor']==actor:
                raise CoordinationError('exact closure and independent approving actor required')
            closure=matching[0];original=canonical(closure)
            with connection.approval():
                no_impact=verify_no_impact(connection,closure,impact_evidence_digest)
            if no_impact is not True or canonical(closure)!=original:
                raise CoordinationError('closure impact or downstream consumption is unknown or present')
            connection.execute("UPDATE changes SET status='active',generation=generation+1,task_set_digest=NULL WHERE authority_domain=? AND project_id=? AND change_id=?",key.values()[:3])
            self._audit(connection,'closureRescinded',actor,{'project':project,'change':change,
                'beforeGeneration':generation,'generation':generation+1,'closureDigest':closure['digest'],
                'impactEvidenceDigest':impact_evidence_digest})
            return generation+1

    def rework(self, key, *, expected_cycle, actor, now, authorize, analysis_binding=None):
        _integer(expected_cycle,1)
        with self.transaction('rework',actor,now,authorize) as connection:
            self._parent(connection,key,allowed=('active',))
            completed=connection.execute('SELECT 1 FROM completions WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*key.values(),expected_cycle)).fetchone()
            if not completed: raise CoordinationError('rework requires a completed current obligation')
            if analysis_binding is not None:
                from dasops.protected.candidates.versions import ANALYSIS_TASK_VALIDATOR
                ANALYSIS_TASK_VALIDATOR.validate(analysis_binding)
                analysis_binding=parse(canonical(analysis_binding))
                original=self.analysis_task_binding(connection,key)
                with connection.approval():
                    reviewed=authorize(connection,'approve_analysis_rework',actor,
                        connection.execute('SELECT authority_epoch FROM metadata WHERE singleton=1').fetchone()[0])
                if (analysis_binding['taskCycle']!=expected_cycle+1
                        or any(analysis_binding[name]!=original[name] for name in
                            ('taskKey','taskRevision','obligationDigest','policyDigest','completionMode'))
                        or reviewed is not True):
                    raise CoordinationError('fresh independent analysis-cycle approval required')
            changed=connection.execute('UPDATE tasks SET cycle=cycle+1 WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=? AND cycle=?',(*key.values(),expected_cycle))
            if changed.rowcount!=1: raise CoordinationError('task cycle CAS conflict')
            connection.execute('UPDATE leases SET expires_at=? WHERE authority_domain=? AND project_id=? AND change_id=? AND task_id=?',(now,*key.values()))
            connection.execute('UPDATE changes SET generation=generation+1 WHERE authority_domain=? AND project_id=? AND change_id=?',key.values()[:3])
            body={'taskKey':list(key.values()),'cycle':expected_cycle+1}
            if analysis_binding is not None:body['analysisBinding']=analysis_binding
            self._audit(connection,'task_rework',actor,body)
            return expected_cycle+1

    def checkpoint(self):
        row=self.connection.execute('SELECT sequence,digest FROM audit ORDER BY sequence DESC LIMIT 1').fetchone()
        return dict(row) if row else {'sequence':0,'digest':'sha256:'+'0'*64}

    def verify_checkpoint(self, minimum):
        """minimum comes from an independent protected witness, not this DB."""
        if set(minimum)!= {'sequence','digest'}: raise CoordinationError('invalid independent checkpoint')
        sequence=_integer(minimum['sequence']);_digest(minimum['digest'])
        if sequence==0:
            if minimum['digest']!='sha256:'+'0'*64: raise CoordinationError('invalid initial checkpoint')
            return
        row=self.connection.execute('SELECT digest FROM audit WHERE sequence=?',(sequence,)).fetchone()
        if not row or row[0]!=minimum['digest']: raise CoordinationError('state is older than or differs from independent history')

    def backup(self, output, *, minimum_checkpoint):
        # sqlite3_backup copies main only. Never call it from this connection's
        # unfinished transaction (which can block indefinitely), or silently
        # certify a source that depends on attached/TEMP state not in the copy.
        if self.connection.in_transaction:
            raise CoordinationError('backup requires a connection outside a transaction')
        self._check_database_domain()
        self.verify_checkpoint(minimum_checkpoint)
        output=Path(output)
        if not output.is_absolute() or output.resolve()!=output or output.parent!=self.path.parent:
            raise CoordinationError('backup must be a fresh object in the same protected artifact directory')
        descriptor=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(descriptor)
        destination=sqlite3.connect(output,isolation_level=None)
        try:
            self.connection.backup(destination)
        finally:
            destination.close()
        restored=CoordinationDatabase(output,authority_domain=self.domain)
        try:
            restored.verify_checkpoint(minimum_checkpoint)
            checkpoint=restored.checkpoint()
        finally:
            restored.close()
        _sync_backup(output)
        return {'checkpoint':checkpoint,'sha256':hashlib.sha256(output.read_bytes()).hexdigest()}
