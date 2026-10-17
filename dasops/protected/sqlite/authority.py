"""Finite installed SQLite writer routing and forward migration.

The small route/watermark lives outside the database backup domain. The installed
administrator owns its directory, lock and approval predicate. This is not a
candidate endpoint, signature verifier, old protected-v1 importer or new service.
Durability/OS separation of that installation still needs deployment acceptance.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import time

from dasops.protected.state_store import atomic_write
from dasops.standards_contracts.exact_json import canonical, parse
from .store import CoordinationDatabase, CoordinationError, _hash, _id, _integer, _sync_backup


def _private(path, *, directory=False):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or path.is_symlink():
        raise CoordinationError('authority path must be normalized without aliases')
    info = path.stat()
    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink != 1)):
        raise CoordinationError('authority material must be private and owner controlled')
    return info


def _state_digest(connection, *, time_floor=None):
    """Exact rows/columns of every table, including metadata and audit history."""
    tables = [r[0] for r in connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    state = {}
    for table in tables:
        # Names come only from the already checked fixed schema author.
        rows = []
        for row in connection.execute('SELECT * FROM '+table):
            values = [{'blob':v.hex()} if isinstance(v,bytes) else v for v in row]
            if table=='metadata' and time_floor is not None:
                # Only administrative recovery uses this normalization. All
                # other columns/rows stay exact; the real floor is separately
                # bounded by the original intent and independent route below.
                values[row.keys().index('time_floor')] = time_floor
            rows.append(values)
        state[table] = sorted(rows, key=canonical)
    return _hash(state)


def _approve(connection, operation, actor, epoch, subject, approve):
    """An installed approval may inspect, but cannot rewrite, its subject/SQL."""
    raw=canonical(subject); copy=parse(raw); before=_state_digest(connection)
    with connection.approval():
        allowed=approve(connection,operation,actor,epoch,copy)
    if canonical(copy)!=raw or _state_digest(connection)!=before:
        raise CoordinationError('administrative approval modified its subject or authority state')
    if allowed is not True:
        raise CoordinationError('current independent administrative approval denied')
    return True


def _check_recovery_audit(database, record, intent, committed, event, *, route_path=None):
    """Bind retained first recovery identity to its existing immutable audit."""
    migration=record['migration']
    fields_present=set(migration)&{'recoveryIntent','priorCheckpoint','priorResultDigest'}
    if fields_present and len(fields_present)!=3:
        raise CoordinationError('complete retained first recovery binding required')
    if not fields_present:return
    recovery=migration['recoveryIntent']
    fields={'actor','time'}|({'phase','checkpoint'} if event=='authority_reconciled' else set())
    if not isinstance(recovery,dict) or set(recovery)!=fields:
        raise CoordinationError('exact original recovery identity required')
    _id(recovery['actor']);_integer(recovery['time'])
    if not intent['time']<=recovery['time']<=record['timeFloor']:
        raise CoordinationError('first recovery time differs from retained interval')
    if event=='authority_reconciled':
        from .store import _digest
        checkpoint=recovery['checkpoint']
        if not isinstance(checkpoint,dict) or set(checkpoint)!={'sequence','digest'}:
            raise CoordinationError('exact first administrative checkpoint required')
        _integer(checkpoint['sequence']);_digest(checkpoint['digest'])
        if recovery['phase']!=record['phase'] or canonical(checkpoint)!=canonical(migration['priorCheckpoint']):
            raise CoordinationError('first administrative recovery binding changed')
    if committed:
        body=({'route':str(route_path),'originalIntent':intent,'recovery':recovery}
            if event=='authority_reconciled' else {'original':intent,'recovery':recovery})
        row=database.connection.execute('SELECT * FROM audit WHERE sequence=?',(record['checkpoint']['sequence'],)).fetchone()
        if (not row or row['event']!=event or row['actor']!=recovery['actor']
                or row['digest']!=record['checkpoint']['digest'] or canonical(parse(row['body'].encode()))!=canonical(body)):
            raise CoordinationError('first recovery audit differs from retained identity')


def _recovery_result(connection, migration, intent):
    result=_state_digest(connection,time_floor=intent['time'])
    if 'recoveryIntent' in migration and result!=migration['resultDigest']:
        raise CoordinationError('recreated recovery differs from its retained exact result')
    return result


class AuthorityRoute:
    """One protected routing record; all participating writer transactions lock it.

    A checkpoint is published and fsynced BEFORE COMMIT/return. If publication or
    SQL commit is uncertain, a record ahead of the DB stops writes; it is never
    silently lowered to make an old backup usable. Enrollment, freeze and
    activation retain exact administrative intents for forward recovery.
    """
    def __init__(self, path, *, authority_domain):
        self.path = Path(path)
        self.domain = _id(authority_domain)
        _private(self.path.parent, directory=True)
        if self.path.resolve() != self.path or not self.path.is_absolute():
            raise CoordinationError('normalized installed route path required')
        self.lock_path = self.path.with_name(self.path.name+'.lock')

    @contextmanager
    def locked(self):
        _private(self.path.parent, directory=True)
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = _private(self.lock_path)
            if (info.st_dev,info.st_ino) != (os.fstat(fd).st_dev,os.fstat(fd).st_ino):
                raise CoordinationError('authority lock identity changed')
            deadline=time.monotonic()+0.250
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic()>=deadline:
                        raise CoordinationError('authority route busy; retry the complete operation')
                    time.sleep(0.005)
            current = _private(self.lock_path)
            if (current.st_dev,current.st_ino) != (info.st_dev,info.st_ino):
                raise CoordinationError('authority lock was replaced')
            yield self._read() if self.path.exists() else None
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _read(self):
        identity = _private(self.path)
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            opened=os.fstat(fd)
            if (opened.st_dev,opened.st_ino)!=(identity.st_dev,identity.st_ino):
                raise CoordinationError('authority record identity changed')
            raw = os.read(fd, 65537)
        finally:
            os.close(fd)
        if len(raw)>65536:
            raise CoordinationError('authority route exceeds its fixed limit')
        value = parse(raw)
        fields = {'identity','authorityDomain','database','instance','epoch','phase',
                  'generation','checkpoint','timeFloor','migration'}
        if (not isinstance(value,dict) or set(value)!=fields or canonical(value)!=raw
                or value['identity']!='das-sqlite-authority-route/v1'
                or value['authorityDomain']!=self.domain
                or value['phase'] not in ('active','enrolling','freezing','frozen','activating','settling','committing')):
            raise CoordinationError('invalid installed authority route')
        _integer(value['epoch'],1); _integer(value['generation'],1); _integer(value['timeFloor'])
        _id(value['instance'])
        if (not isinstance(value['checkpoint'],dict) or set(value['checkpoint'])!={'sequence','digest'}
                or not isinstance(value['database'],str)
                or Path(value['database']).resolve()!=Path(value['database'])
                or not Path(value['database']).is_absolute()
                or (value['phase']=='active' and value['migration'] is not None)
                or (value['phase']!='active' and not isinstance(value['migration'],dict))):
            raise CoordinationError('invalid installed route binding')
        _integer(value['checkpoint']['sequence'])
        from .store import _digest, _hash
        _digest(value['checkpoint']['digest'])
        return value

    def _publish(self, record, *, create=False):
        raw = canonical(record)
        if len(raw)>65536:
            raise CoordinationError('authority route exceeds its fixed limit')
        atomic_write(self.path, raw, mode=0o600, create_only=create)

    def check_current(self, connection, database, record):
        if record is None or record['phase']!='active':
            raise CoordinationError('authority is frozen or requires forward recovery')
        enrolled=connection.execute("SELECT body FROM audit WHERE event='authority_enrolled'").fetchall()
        if len(enrolled)!=1 or parse(enrolled[0][0].encode())!={'route':str(self.path)}:
            raise CoordinationError('authority route differs from its original installation')
        meta = connection.execute('SELECT * FROM metadata WHERE singleton=1').fetchone()
        if (record['database']!=str(database.path) or record['instance']!=meta['instance_id']
                or record['epoch']!=meta['authority_epoch'] or meta['time_floor']<record['timeFloor']):
            raise CoordinationError('writer differs from the current authority route')
        # Read using this transaction, not a second connection with an older view.
        checkpoint = record['checkpoint']
        sequence = _integer(checkpoint['sequence'])
        row = connection.execute('SELECT digest FROM audit WHERE sequence=?',(sequence,)).fetchone()
        if (sequence and (not row or row[0]!=checkpoint['digest'])) or (
                not sequence and checkpoint!={'sequence':0,'digest':'sha256:'+'0'*64}):
            raise CoordinationError('writer is older than the independent authority watermark')

    def before_commit(self, database, record, *, settlement=None, business=None):
        next_record = dict(record, checkpoint=database.checkpoint(),
            timeFloor=database.connection.execute('SELECT time_floor FROM metadata').fetchone()[0])
        row = database.connection.execute("SELECT body FROM audit WHERE event='authority_frozen' ORDER BY sequence DESC LIMIT 1").fetchone()
        if row:
            freeze = parse(row[0].encode())
            if freeze['epoch']==record['epoch']:
                next_record.update(phase='frozen', migration=freeze)
                if 'freezeIntent' in freeze:
                    next_record.update(phase='freezing',migration=dict(freeze,
                        resultDigest=_state_digest(database.connection)))
        if settlement is not None:
            next_record.update(phase='settling',migration={'settlementIntent':settlement,
                'resultDigest':_state_digest(database.connection)})
        if business is not None:
            next_record.update(phase='committing',migration={'businessIntent':business,
                'resultDigest':_state_digest(database.connection)})
        self._publish(next_record)
        return next_record

    def recover_business(self, database, record, operation, arguments, *, actor, now, authorize, payload=None):
        """Recover only an exact resubmission of three fixed local writers.

        Caller owns the route lock. No resource execution, new qualification,
        arbitrary callback/SQL replay, or reconstruction from guessed inputs.
        """
        from .store import _digest
        import hashlib
        _id(actor);_integer(now)
        c=database.connection
        if database.authority_route is not self or not callable(authorize) or c.in_transaction:
            raise CoordinationError('installed nonnested business recovery required')
        for name, expected in [('foreign_keys',1),('ignore_check_constraints',0),('synchronous',2),('trusted_schema',0),('recursive_triggers',1)]:
            if c.execute('PRAGMA '+name).fetchone()[0]!=expected:
                raise CoordinationError('business recovery writer policy changed')
        database._check_database_domain()
        try:
            c.execute('BEGIN IMMEDIATE')
            # Row digests do not bind sqlite_master constraints/triggers. An
            # already-open handle must recheck the actual fixed schema while
            # holding this recovery snapshot, before publishing authority.
            database.check_integrity()
            meta=c.execute('SELECT * FROM metadata').fetchone()
            if (record['phase']!='committing' or record['database']!=str(database.path)
                    or record['instance']!=meta['instance_id'] or record['epoch']!=meta['authority_epoch']):
                raise CoordinationError('retained business intent belongs to another writer')
            migration=record['migration'];intent=migration.get('businessIntent')
            fields={'operation','arguments','auditBinding','actor','time','sourceCheckpoint','sourceStateDigest'}
            required={'businessIntent','resultDigest'}
            if 'recoveryIntent' in migration:required.update(('recoveryIntent','priorCheckpoint','priorResultDigest'))
            if (not isinstance(intent,dict) or set(intent)!=fields or set(migration)!=required
                    or intent['auditBinding']!='intent-sha256-v1'
                    or operation not in ('reserve','action_dispatched','complete')
                    or intent['operation']!=operation or canonical(intent['arguments'])!=canonical(arguments)):
                raise CoordinationError('complete exact original business input required')
            _id(intent['actor']);_integer(intent['time']);_digest(intent['sourceStateDigest']);_digest(migration['resultDigest'])
            if now<record['timeFloor'] or now<meta['time_floor']:
                raise CoordinationError('business recovery clock moved backwards')
            if operation=='reserve':
                # A rolled-back reservation has no SQL payload. Its original
                # canonical request must be provided, not synthesized from DB.
                from .outbox import encode_intent
                if (not isinstance(payload,bytes) or encode_intent(parse(payload))!=payload
                        or 'sha256:'+hashlib.sha256(payload).hexdigest()!=arguments.get('requestDigest')):
                    raise CoordinationError('exact original canonical reservation payload required')
            enrolled=c.execute("SELECT body FROM audit WHERE event='authority_enrolled'").fetchall()
            if len(enrolled)!=1 or parse(enrolled[0][0].encode())!={'route':str(self.path)}:
                raise CoordinationError('business recovery route differs from original installation')
            checkpoint=database.checkpoint();actual=_state_digest(c)
            original=(actual==intent['sourceStateDigest'] and checkpoint==intent['sourceCheckpoint'])
            committed=(checkpoint==record['checkpoint'] and
                _state_digest(c,time_floor=intent['time'])==migration['resultDigest'])
            prior=('recoveryIntent' in migration and checkpoint==migration['priorCheckpoint'] and
                _state_digest(c,time_floor=intent['time'])==migration['priorResultDigest'])
            if not (original or committed or prior) or (not original and not intent['time']<=meta['time_floor']<=record['timeFloor']):
                raise CoordinationError('business state differs from retained exact pre/postimage')
            _check_recovery_audit(database,record,intent,committed,'business_reconciled')
            if not original:
                original_checkpoint=migration.get('priorCheckpoint',record['checkpoint'])
                marker=c.execute('SELECT * FROM audit WHERE sequence=?',(original_checkpoint['sequence'],)).fetchone()
                if (not marker or marker['event']!='business_committed' or marker['actor']!=intent['actor']
                        or marker['digest']!=original_checkpoint['digest']
                        or parse(marker['body'].encode())!={'operation':operation,'intentDigest':_hash(intent)}):
                    raise CoordinationError('original business audit does not bind retained intent')
            _approve(c,operation,actor,record['epoch'],record,lambda c,o,a,e,s:authorize(c,o,a,e))
            if original:
                c.execute('UPDATE metadata SET time_floor=?',(intent['time'],))
                database._apply_business(c,operation,arguments,intent['actor'],payload=payload)
                database._audit(c,'business_committed',intent['actor'],{'operation':operation,'intentDigest':_hash(intent)})
                if _state_digest(c,time_floor=intent['time'])!=migration.get('priorResultDigest',migration['resultDigest']):
                    raise CoordinationError('recreated business operation differs from exact retained result')
            if not committed or 'recoveryIntent' not in migration:
                recovery=migration.get('recoveryIntent',{'actor':actor,'time':now})
                if set(recovery)!={'actor','time'}:raise CoordinationError('exact original recovery identity required')
                _id(recovery['actor']);_integer(recovery['time'])
                database._audit(c,'business_reconciled',recovery['actor'],{'original':intent,'recovery':recovery})
                migration=dict(migration,recoveryIntent=recovery,
                    priorCheckpoint=migration.get('priorCheckpoint',record['checkpoint']),
                    priorResultDigest=migration.get('priorResultDigest',migration['resultDigest']),
                    resultDigest=_recovery_result(c,migration,intent))
            c.execute('UPDATE metadata SET time_floor=?',(now,))
            pending=dict(record,timeFloor=now,checkpoint=database.checkpoint(),migration=migration)
            self._publish(pending)
            c.execute('COMMIT')
            self._publish(dict(pending,phase='active',migration=None))
            return database._business_result(operation,arguments)
        except BaseException:
            if c.in_transaction:c.execute('ROLLBACK')
            raise

    def recover_outbox(self, outbox, resource, action, business, *, actor, now, authorize, deadline):
        """Finish a retained verified settlement; lookup never executes.

        External lookup/verification runs outside SQL/route locks. Both current
        permission and the exact captured route/state are checked again before
        writing. Other ordinary commit uncertainties remain unsupported/fenced.
        """
        from .outbox import Observation, _load_intent
        from .store import _digest
        import hashlib
        _id(actor);_integer(now)
        key=[_id(resource),_id(action),_id(business)]
        if not callable(authorize) or outbox.database.authority_route is not self:
            raise CoordinationError('installed current outbox recovery authority required')

        def inspect(database, record):
            c=database.connection;meta=c.execute('SELECT * FROM metadata').fetchone()
            if (record is None or record['phase']!='settling' or record['database']!=str(outbox.database.path)
                    or record['instance']!=meta['instance_id'] or record['epoch']!=meta['authority_epoch']):
                raise CoordinationError('retained settlement belongs to another installed writer')
            migration=record['migration'];intent=migration.get('settlementIntent')
            fields={'key','expected','nativeDigest','actor','time','requestDigest','fingerprint','sourceCheckpoint','sourceStateDigest'}
            required={'settlementIntent','resultDigest'}
            if 'recoveryIntent' in migration:required.update(('recoveryIntent','priorCheckpoint','priorResultDigest'))
            if (not isinstance(intent,dict) or set(intent) not in (fields,fields|{'target'},fields|{'auditBinding'},fields|{'auditBinding','target'})
                    or ('target' in intent and intent['target']!='not_executed')
                    or ('auditBinding' in intent and intent['auditBinding']!='intent-sha256-v1') or set(migration)!=required):
                raise CoordinationError('complete original settlement evidence required')
            _id(intent['actor']);_integer(intent['time'])
            for name in ('nativeDigest','requestDigest','fingerprint','sourceStateDigest'):_digest(intent[name])
            if (intent['key']!=key or intent['expected'] not in ('dispatched','unknown')
                    or now<max(meta['time_floor'],record['timeFloor'])):
                raise CoordinationError('original settlement key or current clock differs')
            _digest(intent['nativeDigest']);_digest(migration['resultDigest'])
            row,payload=_load_intent(database,*key)
            if row['request_digest']!=intent['requestDigest'] or row['fingerprint']!=intent['fingerprint']:
                raise CoordinationError('original settlement request differs')
            original=(_state_digest(c)==intent['sourceStateDigest']
                and database.checkpoint()==intent['sourceCheckpoint'] and row['state']==intent['expected'])
            normalized=_state_digest(c,time_floor=intent['time'])
            committed=(intent['time']<=meta['time_floor']<=record['timeFloor']
                and normalized==migration['resultDigest'] and database.checkpoint()==record['checkpoint'])
            prior=('recoveryIntent' in migration and intent['time']<=meta['time_floor']<=record['timeFloor']
                and normalized==migration['priorResultDigest'] and database.checkpoint()==migration['priorCheckpoint'])
            if not (original or committed or prior):
                raise CoordinationError('settlement state differs from retained original')
            _check_recovery_audit(database,record,intent,committed,'outbox_reconciled')
            if not original:
                # A matching SQL result does not itself bind mutable recovery
                # metadata. New events bind the whole intent; old events still
                # bind original actor, native result and exact checkpoint.
                source=intent['sourceCheckpoint'];sequence=_integer(source['sequence'])+1
                event=c.execute('SELECT * FROM audit WHERE sequence=?',(sequence,)).fetchone()
                target=intent.get('target','confirmed')
                body={'key':[self.domain,*key],'receiptDigest':intent['nativeDigest'] if target=='confirmed' else None}
                if 'auditBinding' in intent:body['settlementDigest']=_hash(intent)
                checkpoint=migration.get('priorCheckpoint',record['checkpoint'])
                if (not event or event['event']!='action_'+target or event['actor']!=intent['actor']
                        or event['previous_digest']!=source['digest'] or parse(event['body'].encode())!=body
                        or checkpoint!={'sequence':sequence,'digest':event['digest']}):
                    raise CoordinationError('original settlement audit differs from retained intent')
            enrolled=c.execute("SELECT body FROM audit WHERE event='authority_enrolled'").fetchall()
            if len(enrolled)!=1 or parse(enrolled[0][0].encode())!={'route':str(self.path)}:
                raise CoordinationError('original settlement route enrollment differs')
            return intent,migration,payload,original,committed

        # Capture and authorize the actual SQL snapshot, then release all locks.
        with self.locked() as record:
            if record is None or record['phase']!='settling':
                raise CoordinationError('retained verified settlement required')
            database=CoordinationDatabase(record['database'],authority_domain=self.domain)
            try:
                c=database.connection;c.execute('BEGIN IMMEDIATE')
                intent,migration,payload,_,_=inspect(database,record)
                _approve(c,'action_lookup',actor,record['epoch'],record,
                    lambda c,o,a,e,s:authorize(c,o,a,e))
                captured_state=_state_digest(c);captured_route=canonical(record)
            finally:
                if database.connection.in_transaction:database.connection.execute('ROLLBACK')
                database.close()
        if time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline:
            raise CoordinationError('settlement lookup deadline expired')
        observation=outbox._adapter(payload).lookup(parse(canonical(payload)),deadline=deadline)
        target=intent.get('target','confirmed')
        verifying=parse(canonical(payload));raw=canonical(verifying)
        if (time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline or not isinstance(observation,Observation)
                or observation.outcome!=target or observation.request_digest!=intent['requestDigest']
                or observation.resource_instance!=payload['resourceInstance']
                or not isinstance(observation.native_receipt,bytes) or not 1<=len(observation.native_receipt)<=65536
                or 'sha256:'+hashlib.sha256(observation.native_receipt).hexdigest()!=intent['nativeDigest']
                or outbox.verify_observation(verifying,observation) is not True or canonical(verifying)!=raw):
            raise CoordinationError('independent original settlement observation unavailable or changed')
        if target=='not_executed':
            # A fresh monotone closure witness for this original execution is
            # required even if SQL already committed the absence. Empty lookup
            # or a retained earlier True cannot establish execution closure.
            closing=parse(canonical(payload));original_payload=canonical(closing)
            if outbox.execution_closed(closing) is not True or canonical(closing)!=original_payload:
                raise CoordinationError('independent original execution closure unavailable or changed')
        with self.locked() as record:
            if canonical(record)!=captured_route:
                raise CoordinationError('settlement route changed during lookup; retry original key')
            database=CoordinationDatabase(record['database'],authority_domain=self.domain)
            try:
                c=database.connection;c.execute('BEGIN IMMEDIATE')
                intent,migration,_,original,committed=inspect(database,record)
                if _state_digest(c)!=captured_state:
                    raise CoordinationError('settlement state changed during lookup')
                _approve(c,'action_'+target,actor,record['epoch'],record,
                    lambda c,o,a,e,s:authorize(c,o,a,e))
                if time.clock_gettime(time.CLOCK_BOOTTIME)>=deadline:
                    raise CoordinationError('settlement recovery deadline expired')
                if original:
                    c.execute('UPDATE metadata SET time_floor=?',(intent['time'],))
                    database._transition_action(c,(self.domain,*key),intent['expected'],target,
                        intent['nativeDigest'] if target=='confirmed' else None,
                        intent['nativeDigest'],observation.native_receipt,intent['actor'],
                        settlement_digest=_hash(intent) if 'auditBinding' in intent else None)
                    expected=migration.get('priorResultDigest',migration['resultDigest'])
                    if _state_digest(c,time_floor=intent['time'])!=expected:
                        raise CoordinationError('recreated settlement differs from retained exact result')
                if not committed or 'recoveryIntent' not in migration:
                    recovery=migration.get('recoveryIntent',{'actor':actor,'time':now})
                    database._audit(c,'outbox_reconciled',recovery['actor'],
                        {'original':intent,'recovery':recovery})
                    migration=dict(migration,recoveryIntent=recovery,
                        priorCheckpoint=migration.get('priorCheckpoint',record['checkpoint']),
                        priorResultDigest=migration.get('priorResultDigest',migration['resultDigest']),
                        resultDigest=_recovery_result(c,migration,intent))
                c.execute('UPDATE metadata SET time_floor=?',(now,))
                pending=dict(record,timeFloor=now,checkpoint=database.checkpoint(),migration=migration)
                self._publish(pending)
                c.execute('COMMIT')
                self._publish(dict(pending,phase='active',migration=None))
                return _load_intent(database,*key)[0]
            finally:
                if database.connection.in_transaction:database.connection.execute('ROLLBACK')
                database.close()

    def enroll(self, database, *, actor, now, approve):
        """Administrative installation; never silently enroll a restored copy."""
        _id(actor); _integer(now)
        if database.authority_route is not None or database.connection.in_transaction:
            raise CoordinationError('fresh unbound database connection required for enrollment')
        if database.path.parent==self.path.parent or database.domain!=self.domain:
            raise CoordinationError('route must be in a separate protected backup domain')
        _private(database.path)
        with self.locked() as prior:
            if prior is not None:
                raise CoordinationError('authority already enrolled; do not replace its history')
            intent={}
            def authorize(c,o,a,e):
                intent.update(database=str(database.path),instance=database.instance_id,epoch=e,
                    actor=actor,time=now,sourceCheckpoint=database.checkpoint(),stateDigest=_state_digest(c))
                return _approve(c,o,a,e,intent,approve)
            with database.transaction('authority_enroll',actor,now,authorize):
                database._audit(database.connection,'authority_enrolled',actor,{'route':str(self.path)})
                meta=database.connection.execute('SELECT * FROM metadata').fetchone()
                record={'identity':'das-sqlite-authority-route/v1','authorityDomain':self.domain,
                    'database':str(database.path),'instance':database.instance_id,'epoch':meta['authority_epoch'],
                    'phase':'enrolling','generation':1,'checkpoint':database.checkpoint(),
                    'timeFloor':now,'migration':{'enrollmentIntent':intent,
                        'resultDigest':_state_digest(database.connection)}}
                self._publish(record,create=True)
            self._publish(dict(record,phase='active',migration=None))
        database.authority_route=self

    def open_current(self):
        with self.locked() as record:
            if record is None or record['phase']!='active':
                raise CoordinationError('authority requires controlled forward recovery')
            database=CoordinationDatabase(record['database'],authority_domain=self.domain,authority_route=self)
            try:
                self.check_current(database.connection,database,record)
            except BaseException:
                database.close();raise
            return database

    def freeze(self, database, *, destination, new_instance, migration_id, actor, now, approve):
        """The installed approver must fence external dispatch domains as well."""
        destination=Path(destination);_id(new_instance);_id(migration_id)
        if (database.authority_route is not self or destination.parent!=database.path.parent
                or destination.resolve()!=destination or destination.exists() or destination.is_symlink()
                or new_instance==database.instance_id):
            raise CoordinationError('fresh same-domain migration destination and instance required')
        _private(database.path)
        intent={}
        def authorize(c,o,a,e):
            intent.update(database=str(database.path),instance=database.instance_id,epoch=e,
                actor=actor,time=now,sourceCheckpoint=database.checkpoint(),stateDigest=_state_digest(c))
            return _approve(c,o,a,e,dict(intent,destination=str(destination),newInstance=new_instance,
                migrationId=migration_id,nextEpoch=_integer(e+1,1)),approve)
        with database.transaction('authority_freeze',actor,now,authorize) as connection:
            epoch=connection.execute('SELECT authority_epoch FROM metadata').fetchone()[0]
            database._audit(connection,'authority_frozen',actor,{'destination':str(destination),
                'newInstance':new_instance,'migrationId':migration_id,'epoch':epoch,
                'nextEpoch':_integer(epoch+1,1),'freezeIntent':intent})
        with self.locked() as record:
            self._check_admin_result(database,record)
            self._publish(dict(record,phase='frozen'))

    def _check_admin_result(self, database, record, *, prior=False):
        if record is None or record['phase'] not in ('enrolling','freezing'):
            raise CoordinationError('retained administrative enrollment/freeze intent required')
        migration=record['migration']
        intent=migration.get('enrollmentIntent') if record['phase']=='enrolling' else migration.get('freezeIntent')
        if not intent:
            raise CoordinationError('original administrative recovery intent is unavailable')
        _id(intent['actor']);_integer(intent['time']);_integer(intent['epoch'],1)
        checkpoint=migration['priorCheckpoint'] if prior else record['checkpoint']
        digest=migration['priorResultDigest'] if prior else migration['resultDigest']
        meta=database.connection.execute('SELECT * FROM metadata').fetchone()
        if (database.path.as_posix()!=record['database'] or meta['instance_id']!=record['instance']
                or meta['authority_epoch']!=record['epoch'] or intent['database']!=record['database']
                or intent['instance']!=record['instance'] or intent['epoch']!=record['epoch']
                or not intent['time']<=meta['time_floor']<=record['timeFloor']
                or database.checkpoint()!=checkpoint
                or _state_digest(database.connection,time_floor=intent['time'])!=digest):
            raise CoordinationError('administrative result differs from retained original')
        database.verify_checkpoint(checkpoint)
        source=intent['sourceCheckpoint'];sequence=_integer(source['sequence'])+1
        event=database.connection.execute('SELECT * FROM audit WHERE sequence=?',(sequence,)).fetchone()
        original_checkpoint=migration.get('priorCheckpoint',record['checkpoint'])
        expected_event='authority_enrolled' if record['phase']=='enrolling' else 'authority_frozen'
        body=({'route':str(self.path)} if record['phase']=='enrolling' else
            {k:v for k,v in migration.items() if k not in ('resultDigest','recoveryIntent','priorCheckpoint','priorResultDigest')})
        if (not event or event['event']!=expected_event or event['actor']!=intent['actor']
                or event['previous_digest']!=source['digest'] or canonical(parse(event['body'].encode()))!=canonical(body)
                or original_checkpoint!={'sequence':sequence,'digest':event['digest']}):
            raise CoordinationError('original administrative audit differs from retained intent')
        return intent

    def reconcile(self, *, actor, now, approve):
        """Finish one retained enrollment/freeze; never replay business SQL.

        The installed administrator has already stopped unbound enrollment
        entrances. All route-bound readers/writers remain fenced until the
        original SQL fact is verified/recreated and COMMIT is confirmed.
        """
        _id(actor);_integer(now)
        with self.locked() as record:
            if record is None or record['phase'] not in ('enrolling','freezing'):
                raise CoordinationError('retained administrative enrollment/freeze intent required')
            _private(record['database'])
            database=CoordinationDatabase(record['database'],authority_domain=self.domain)
            try:
                c=database.connection;c.execute('BEGIN IMMEDIATE')
                migration=record['migration']
                intent=migration.get('enrollmentIntent') if record['phase']=='enrolling' else migration.get('freezeIntent')
                if not intent:
                    raise CoordinationError('original administrative recovery intent is unavailable')
                _id(intent['actor']);_integer(intent['time']);_integer(intent['epoch'],1)
                # Validate retained fields before choosing current/prior SQL;
                # otherwise a missing prior checkpoint escapes as KeyError.
                _check_recovery_audit(database,record,intent,False,'authority_reconciled',route_path=self.path)
                meta=c.execute('SELECT * FROM metadata').fetchone()
                if now<max(meta['time_floor'],record['timeFloor']):
                    raise CoordinationError('trusted clock moved backwards')
                original=(_state_digest(c)==intent['stateDigest'] and
                    database.checkpoint()==intent['sourceCheckpoint'] and
                    intent['database']==record['database'] and intent['instance']==meta['instance_id']==record['instance']
                    and intent['epoch']==meta['authority_epoch']==record['epoch'])
                reconciled=False
                if not original:
                    try:
                        self._check_admin_result(database,record)
                        reconciled='recoveryIntent' in migration
                    except CoordinationError:
                        if 'recoveryIntent' not in migration:raise
                        self._check_admin_result(database,record,prior=True)
                _approve(c,'authority_reconcile',actor,record['epoch'],
                    {'route':str(self.path),'original':record},approve)
                _check_recovery_audit(database,record,intent,reconciled,'authority_reconciled',route_path=self.path)
                if original:
                    c.execute('UPDATE metadata SET time_floor=?',(intent['time'],))
                    if record['phase']=='enrolling':
                        database._audit(c,'authority_enrolled',intent['actor'],{'route':str(self.path)})
                    else:
                        body={k:v for k,v in migration.items() if k not in (
                            'resultDigest','recoveryIntent','priorCheckpoint','priorResultDigest')}
                        database._audit(c,'authority_frozen',intent['actor'],body)
                    self._check_admin_result(database,record,prior='recoveryIntent' in migration)
                if not reconciled:
                    prior_checkpoint=migration.get('priorCheckpoint',record['checkpoint'])
                    prior_digest=migration.get('priorResultDigest',migration['resultDigest'])
                    recovery=migration.get('recoveryIntent',{'actor':actor,'time':now,
                        'phase':record['phase'],'checkpoint':prior_checkpoint})
                    database._audit(c,'authority_reconciled',recovery['actor'],
                        {'route':str(self.path),'originalIntent':intent,'recovery':recovery})
                    migration=dict(migration,recoveryIntent=recovery,priorCheckpoint=prior_checkpoint,
                        priorResultDigest=prior_digest,resultDigest=_recovery_result(c,migration,intent))
                c.execute('UPDATE metadata SET time_floor=?',(now,))
                pending=dict(record,timeFloor=now,migration=migration,checkpoint=database.checkpoint())
                self._publish(pending)
                c.execute('COMMIT')
                final=dict(pending,phase='active' if record['phase']=='enrolling' else 'frozen')
                if final['phase']=='active':final['migration']=None
                self._publish(final)
                return {'database':record['database'],'phase':final['phase'],
                    'checkpoint':pending['checkpoint'],'epoch':record['epoch']}
            finally:
                if database.connection.in_transaction:database.connection.execute('ROLLBACK')
                database.close()

    def stage(self, database):
        """Copy only a frozen current DB; retries inspect exact existing bytes."""
        with self.locked() as record:
            if (record is None or record['phase']!='frozen' or record['database']!=str(database.path)
                    or database.authority_route is not self):
                raise CoordinationError('current frozen source required')
            database.check_integrity();database.verify_checkpoint(record['checkpoint'])
            if database.checkpoint()!=record['checkpoint']:
                raise CoordinationError('frozen source changed')
            destination=Path(record['migration']['destination'])
            retained=destination.exists()
            if not retained:
                database.backup(destination,minimum_checkpoint=record['checkpoint'])
            _private(destination)
            staged=CoordinationDatabase(destination,authority_domain=self.domain)
            try:
                if _state_digest(staged.connection)!=_state_digest(database.connection):
                    raise CoordinationError('staged namespace or retained history differs from frozen source')
                # An interrupted backup may have all bytes but no confirmed
                # sync. Existence/integrity alone cannot acknowledge durability.
                if retained:_sync_backup(destination)
                return {'database':str(destination),'checkpoint':staged.checkpoint(),
                        'stateDigest':_state_digest(staged.connection)}
            finally:
                staged.close()

    def activate(self, *, actor, now, approve):
        """Publish exact intent before COMMIT, then recover that same intent.

        Failure at either publication/COMMIT leaves all ordinary writes fenced.
        Re-entry inspects actual SQL state: finish the original import or confirm
        its original committed activation, never restore the old route.
        """
        _id(actor);_integer(now)
        with self.locked() as record:
            if record is None or record['phase'] not in ('frozen','activating'):
                raise CoordinationError('frozen or interrupted activation required')
            migration=record['migration']; destination=Path(migration['destination'])
            _private(destination)
            database=CoordinationDatabase(destination,authority_domain=self.domain)
            try:
                database.connection.execute('BEGIN IMMEDIATE')
                meta=database.connection.execute('SELECT * FROM metadata').fetchone()
                if now<max(meta['time_floor'],record['timeFloor']):
                    raise CoordinationError('trusted clock moved backwards')
                if record['phase']=='frozen':
                    source=CoordinationDatabase(record['database'],authority_domain=self.domain)
                    try:
                        source.verify_checkpoint(record['checkpoint'])
                        if (source.checkpoint()!=record['checkpoint'] or
                                _state_digest(source.connection)!=_state_digest(database.connection)):
                            raise CoordinationError('migration source or exact namespace changed')
                    finally:source.close()
                    intent={'migration':migration,'source':record['database'],'sourceInstance':record['instance'],
                        'sourceCheckpoint':record['checkpoint'],'stateDigest':_state_digest(database.connection),
                        'actor':actor,'time':now}
                else:
                    intent=migration['activationIntent']; migration=intent['migration']
                    from .store import _digest
                    _digest(record['migration'].get('activationResultDigest'))
                before=_state_digest(database.connection)
                _approve(database.connection,'authority_activate',actor,migration['epoch'],intent,approve)
                committed=(meta['instance_id']==migration['newInstance'] and meta['authority_epoch']==migration['nextEpoch'])
                if committed:
                    if (record['phase']!='activating' or database.checkpoint()!=record['checkpoint']
                            or not intent['time']<=meta['time_floor']<=record['timeFloor']
                            or _state_digest(database.connection,time_floor=intent['time'])
                                !=record['migration']['activationResultDigest']):
                        raise CoordinationError('activation result differs from retained original')
                    database.verify_checkpoint(record['checkpoint'])
                else:
                    if (meta['instance_id']!=intent['sourceInstance'] or meta['authority_epoch']!=migration['epoch']
                            or before!=intent['stateDigest']):
                        raise CoordinationError('staged activation state differs from retained original')
                    # Also cover callers resuming directly from a retained
                    # snapshot after stage/backup failed before confirmation.
                    _sync_backup(destination)
                    database.connection.execute('UPDATE metadata SET instance_id=?,authority_epoch=?,time_floor=?',
                        (migration['newInstance'],migration['nextEpoch'],intent['time']))
                    database.connection.execute('UPDATE leases SET expires_at=?',(intent['time'],))
                    database._audit(database.connection,'authority_activated',intent['actor'],intent)
                result_digest=_state_digest(database.connection,time_floor=intent['time'])
                if record['phase']=='activating' and result_digest!=record['migration']['activationResultDigest']:
                    raise CoordinationError('activation result differs from retained original')
                pending=dict(record,database=str(destination),instance=migration['newInstance'],
                    epoch=migration['nextEpoch'],phase='activating',checkpoint=database.checkpoint(),
                    generation=record['generation']+(record['phase']=='frozen'),
                    timeFloor=max(now,meta['time_floor']), migration=dict(migration,activationIntent=intent,
                        activationResultDigest=result_digest))
                database.connection.execute('UPDATE metadata SET time_floor=?',(pending['timeFloor'],))
                self._publish(pending)
                database.connection.execute('COMMIT')
                self._publish(dict(pending,phase='active',migration=None))
                return {'database':str(destination),'instance':pending['instance'],
                        'epoch':pending['epoch'],'checkpoint':pending['checkpoint']}
            finally:
                if database.connection.in_transaction:database.connection.execute('ROLLBACK')
                database.close()
