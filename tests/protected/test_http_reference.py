"""Real loopback HTTP to the existing SQL resource boundary; TEST identities."""
from contextlib import contextmanager
from copy import deepcopy
import errno
import http.client
import hashlib
import json
import os
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
import socket
import sqlite3
import subprocess
import threading
import time

import pytest

from dasops.protected.candidates.http_reference import handler_for, ReferenceHTTPAdapter
from dasops.protected.candidates import CandidateError
from dasops.protected.candidates.versions import VersionTreeManager
from dasops.protected.sqlite.store import CoordinationDatabase
from dasops.protected.sqlite.outbox import DurableOutbox
from dasops.standards_contracts import exact_json as codec
from tests.protected.test_integration_chain import chain, integration_plan, COMPLETE_REFS
from tests.protected.test_version_trees import setup, authorized, intent, durable_dispatch, target, DELETIONS, KEY


@pytest.fixture
def service(chain, request):
    prepare_dispatch = getattr(request, 'param', True)
    db, store, kernel, before, integrated, _, _, state = chain
    digest, plan = integration_plan(chain)
    request = intent(digest, plan, action='integrate')
    if prepare_dispatch: durable_dispatch(db, request)
    # Each request opens its own real writer connection on the server thread.
    @contextmanager
    def installed_manager():
        connection = CoordinationDatabase(db.path, authority_domain=db.domain)
        try:
            if state.get('rejectCas'):
                connection.connection.set_authorizer(lambda operation, table, *_:
                    sqlite3.SQLITE_DENY if operation == sqlite3.SQLITE_UPDATE and table == 'version_targets'
                    else sqlite3.SQLITE_OK)
            manager = VersionTreeManager(connection, store, ownership=dict(kernel.ownership),
                tool_digest=kernel.tool_digest, policy_digest=kernel.policy_digest,
                check_qualification=kernel.check_qualification)
            yield manager
        finally:
            connection.close()
    def current_permission(connection, operation, actor, epoch):
        if state.get('denyCurrentActor') and actor=='worker':return False
        if actor in state.get('readActors', ()):
            state.setdefault('readActorOperations', []).append((actor, operation))
            return connection.in_transaction and epoch == 1 and operation in ('version_lookup', 'version_read')
        return authorized(connection, operation, actor, epoch)
    base = handler_for(installed_manager,
        authenticate=lambda token: 'worker' if token == 'TEST-only-worker' else state.get('testPrincipals', {}).get(token),
        authorize=current_permission, now=lambda: 101, resource='target', instance='instance')
    state['received'] = []
    class ObservedHandler(base):
        def do_PUT(self):
            state['received'].append('PUT')
            state.setdefault('receivedHeaders',[]).append(dict(
                earlyData=self.headers.get_all('Early-Data',[]),
                businessKey=self.headers.get_all('Idempotency-Key',[])))
            if state.get('redirect'):
                self.send_response(307); self.send_header('Location', state['redirect'])
                self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'{}')
                return
            if state.get('fake202'):
                return self._reply(202, {'accepted':True}, close=True)
            return super().do_PUT()
        def do_GET(self):
            state['received'].append('GET')
            return super().do_GET()
        def _reply(self, status, value, **kwargs):
            if (state.get('dropReceipt') and status == 200 and isinstance(value, dict)
                    and value.get('contractIdentity') == 'das-integration-receipt/v1'):
                state['dropReceipt'] = False
                self.close_connection = True
                self.connection.shutdown(socket.SHUT_RDWR)
                return
            return super()._reply(status, value, **kwargs)
    server = HTTPServer(('127.0.0.1', 0), ObservedHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, db, before, integrated, request, state
    server.shutdown(); server.server_close(); thread.join(3)
    assert not thread.is_alive()


def request_http(service, *, headers=None, method='PUT', body=None, path='/integrations'):
    server, _, before, _, request, _ = service
    connection = http.client.HTTPConnection(*server.server_address, timeout=3)
    base = {'Authorization': 'Bearer TEST-only-worker', 'If-Match': '"'+before+'"',
            'Idempotency-Key': request['businessActionId'], 'Content-Type': 'application/json'}
    base.update(headers or {})
    base = {key: value for key, value in base.items() if value is not None}
    connection.request(method, path, body=codec.canonical(request) if body is None else body, headers=base)
    response = connection.getresponse()
    status, payload = response.status, response.read()
    connection.close()
    return status, payload


def test_actual_http_condition_and_stable_replay_use_native_sql_target(service):
    status, raw = request_http(service)
    assert status == 200
    receipt = codec.parse(raw)
    assert receipt['committed'] and receipt['afterCandidateDigest'] == service[3]
    assert target(service[1]) == (2, service[3])
    assert request_http(service) == (200, raw)
    assert service[1].connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 1
    assert service[1].connection.execute('SELECT reserved FROM budgets').fetchone()[0] == 1


def test_registered_http_surface_feeds_independent_native_coverage(service):
    """Actual dispatcher + requests; fixed TEST policy is not candidate approval."""
    if all(os.environ.get(key) is None for key in ('CADENCE_DAS_V15_INSTALLED_NATIVE',
            'CADENCE_DAS_V15_INSTALLED_NATIVE_SHA256', 'DAS_HTTP_COVERAGE_EVIDENCE')):
        pytest.skip('explicit pinned native and retained coverage evidence required')
    native = Path(os.environ['CADENCE_DAS_V15_INSTALLED_NATIVE'])
    assert native.is_absolute() and hashlib.sha256(native.read_bytes()).hexdigest() == os.environ['CADENCE_DAS_V15_INSTALLED_NATIVE_SHA256']
    evidence = Path(os.environ['DAS_HTTP_COVERAGE_EVIDENCE'])
    assert evidence.is_absolute() and evidence.is_dir()
    projection = (evidence/'runtime-attempt-inventory.json').read_bytes()
    inventory = codec.parse(projection)
    # Fixed test-control identities, authored independently of this projection
    # and of the handler's current route table. This is not an approved baseline.
    baseline = [dict(operationId='das.reference.version.read', method='GET', path='/target'),
                dict(operationId='das.reference.version.integrate', method='PUT', path='/integrations')]
    handler = service[0].RequestHandlerClass
    methods = sorted(name[3:] for name in dir(handler) if name.startswith('do_') and callable(getattr(handler, name)))
    observed = [dict(method=method, path=path) for method, path, _ in handler.routes]
    assert methods == sorted(row['method'] for row in observed) == ['GET', 'PUT']
    assert request_http(service, method='GET', path='/target', body=b'')[0] == 200
    status, receipt = request_http(service)
    assert status == 200 and codec.parse(receipt)['afterCandidateDigest'] == service[3]
    assert request_http(service, method='GET', path='/target?businessActionId=forward', body=b'') == (200, receipt)
    assert request_http(service, method='GET', path='/unregistered', body=b'')[0] == 404
    assert request_http(service, method='POST', body=b'')[0] == 501
    assert target(service[1]) == (2, service[3])
    assert service[1].connection.execute('SELECT reserved FROM budgets').fetchone()[0] == 1
    assert service[1].connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 1
    assert service[1].connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0] == 0
    import inspect
    source = Path(inspect.getfile(handler_for))
    (evidence/'runtime-attempt-collector.json').write_bytes(codec.canonical(dict(
        use='TEST-reference-not-approved-baseline', sourceSha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        nativeSha256=hashlib.sha256(native.read_bytes()).hexdigest(),
        candidateDigest=service[3], resourceId='target', resourceInstance='instance',
        observed=observed, handlers=methods, observationComplete=True,
        completenessBasis='Closed fixed dispatcher; all implemented do_* methods covered. Requests alone do not prove completeness.',
        baseline=baseline, baselineApproved=False, requestStatuses=[200, 200, 200, 404, 501])))
    for variant in ('matched', 'incomplete', 'deleted'):
        value = dict(inventory=deepcopy(inventory), baseline=baseline, observed=observed,
                     observationComplete=variant != 'incomplete')
        if variant == 'deleted': value['inventory']['operations'].pop()
        raw = codec.canonical(value)
        (evidence/('runtime-attempt-'+variant+'-input.json')).write_bytes(raw)
        result = subprocess.run([str(native), 'contracts', 'check-http-coverage', '--probe'],
                                input=raw, capture_output=True, timeout=10)
        (evidence/('runtime-attempt-'+variant+'-stdout.json')).write_bytes(result.stdout)
        (evidence/(variant+'-stderr.log')).write_bytes(result.stderr)
        (evidence/(variant+'-exit.log')).write_text(str(result.returncode)+'\n')
        if variant == 'deleted':
            assert result.returncode != 0 and result.stdout == b''
        else:
            assert result.returncode == 0, result.stderr
            checked = codec.parse(result.stdout)
            assert checked['coverage'] == ('matched' if variant == 'matched' else 'unknown')
            assert checked['inputDigest'] == codec.digest(value)
            assert not checked['authority'] and not checked['qualification']


@pytest.mark.parametrize('field,value', [
    ('resourceId', 'other-tenant'), ('resourceId', '../target'),
    ('resourceId', 'target%2Fother'), ('resourceInstance', 'other-instance'),
])
def test_final_http_resource_binding_rejects_foreign_or_alias_operands(service, field, value):
    changed = deepcopy(service[4]); changed[field] = value
    assert request_http(service, body=codec.canonical(changed))[0] == 400
    assert target(service[1]) == (1, service[2])
    assert service[1].connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 0
    assert request_http(service)[0] == 200  # legitimate exact resource still works
    assert target(service[1]) == (2, service[3]) and service[5]['received'] == ['PUT', 'PUT']
    assert service[1].connection.execute('SELECT reserved FROM budgets').fetchone()[0] == 1


@pytest.mark.parametrize('path', ['/integrations/../other', '/%69ntegrations',
                                  '/integrations%2Fother', '/integrations?tenant=other'])
def test_encoded_http_alias_cannot_choose_another_semantic_resource(service, path):
    assert request_http(service, path=path)[0] == 404
    assert target(service[1]) == (1, service[2])
    assert request_http(service)[0] == 200
    assert service[1].connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 1


@pytest.mark.parametrize('redirect', [False, True], ids=['exact-destination', 'foreign-redirect'])
def test_fixed_http_adapter_never_follows_redirect_or_transfers_credentials(service, redirect):
    received = []
    class ForeignHandler(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_PUT(self):
            received.append(self.headers.get('Authorization'))
            self.send_response(500); self.send_header('Content-Length', '0'); self.end_headers()
    foreign = HTTPServer(('127.0.0.1', 0), ForeignHandler)
    thread = threading.Thread(target=foreign.serve_forever, daemon=True); thread.start()
    try:
        if redirect: service[5]['redirect'] = 'http://127.0.0.1:%d/other-tenant' % foreign.server_address[1]
        adapter = ReferenceHTTPAdapter(port=service[0].server_address[1], before_candidate=service[2],
            resource='target', instance='instance', read_token=lambda: 'TEST-only-worker')
        observed = adapter.execute(service[4], deadline=time.clock_gettime(time.CLOCK_BOOTTIME)+5)
        assert observed.outcome == ('unknown' if redirect else 'confirmed')
        assert received == [] and service[5]['received'] == ['PUT']
        assert target(service[1]) == (1 if redirect else 2, service[2] if redirect else service[3])
        assert service[1].connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == int(not redirect)
    finally:
        foreign.shutdown(); foreign.server_close(); thread.join(3)
        assert not thread.is_alive()


@pytest.mark.parametrize('principal', ['TEST-verifier', 'TEST-cleanup'])
def test_authenticated_test_principal_can_read_but_not_mutate_business_target(service, principal):
    service[5].update(testPrincipals={'TEST-read-token': principal}, readActors={principal})
    headers={'Authorization': 'Bearer TEST-read-token', 'X-DAS-Purpose': 'test', 'X-DAS-Admin': 'false'}
    status, raw = request_http(service, method='GET', path='/target', body=b'', headers=headers)
    assert status == 200 and codec.parse(raw)['candidateDigest'] == service[2]
    assert request_http(service, headers=headers)[0] == 412
    assert service[5]['readActorOperations'][-1][0] == principal
    assert target(service[1]) == (1, service[2])
    assert service[1].connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 0
    assert service[1].connection.execute('SELECT reserved FROM budgets').fetchone()[0] == 1
    assert request_http(service)[0] == 200  # granted business identity remains usable


@pytest.mark.parametrize('condition', [None, '*', 'W/"sha256:'+'0'*64+'"', '"sha256:'+'0'*64+'"'])
def test_stripped_weak_wildcard_or_wrong_condition_cannot_commit(service, condition):
    assert request_http(service, headers={'If-Match': condition})[0] in (400, 412, 428)
    assert target(service[1]) == (1, service[2])
    assert service[1].connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 0


@pytest.mark.parametrize('fault', ['aba', 'revoked'])
def test_http_a_b_a_generation_and_revoked_current_authority_still_reject(service, chain, fault):
    db = service[1]
    if fault == 'aba':
        # Construct real legacy staging ABA history; the installed HTTP
        # integration predicate still owns the actual rejection assertion.
        installed = chain[2]
        kernel = VersionTreeManager(db, chain[1], ownership=dict(installed.ownership),
            tool_digest=installed.tool_digest, policy_digest=installed.policy_digest)
        digest, plan = kernel.create_plan('target', 'instance', 1, chain[4],
            deletion_reasons=DELETIONS, actor='worker', now=101, authorize=authorized)
        forward = intent(digest, plan, business='aba-forward')
        durable_dispatch(db, forward)
        kernel.switch(forward, actor='worker', now=101, authorize=authorized)
        digest, plan = kernel.create_rollback_plan('target', 'instance', 'apply', 'aba-forward', 2,
            deletion_reasons={'tree/config.json':'approved TEST restoration'},
            actor='worker', now=101, authorize=authorized)
        rollback = intent(digest, plan, business='aba-return', action='rollback')
        durable_dispatch(db, rollback)
        kernel.switch(rollback, actor='worker', now=101, authorize=authorized)
        db.check_integrity()  # A -> B -> A is real retained switch history.
    else:
        service[5]['allow'] = False
    assert request_http(service)[0] == 412
    assert target(db) == (3 if fault == 'aba' else 1, service[2])
    assert db.connection.execute("SELECT COUNT(*) FROM version_switch_receipts WHERE action_class='integrate'").fetchone()[0] == 0


@pytest.mark.parametrize('headers', [
    {'Authorization': None}, {'Authorization': 'Bearer candidate-claimed-identity'},
    {'Idempotency-Key': 'replacement-key'}, {'Early-Data': '1'},
])
def test_http_identity_action_key_and_early_data_fail_before_effect(service, headers):
    assert request_http(service, headers=headers)[0] in (400, 401, 425)
    assert target(service[1]) == (1, service[2])


@pytest.mark.parametrize('variant',['retry','revoked','changed-body'])
def test_early_data_refusal_then_explicit_current_same_key_retry(service,variant):
    server,db,before,integrated,request,state=service
    first,raw=request_http(service,headers={'Early-Data':'1'})
    assert first==425 and codec.parse(raw)=={'error':'early_data_not_supported'}
    assert target(db)==(1,before)
    assert db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0]==0
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==1
    if variant=='revoked':state['denyCurrentActor']=True
    body=deepcopy(request)
    if variant=='changed-body':body['parameters']['planDigest']='sha256:'+'0'*64
    second,receipt=request_http(service,body=codec.canonical(body))
    expected=200 if variant=='retry' else 412
    assert second==expected
    if variant=='retry':
        assert codec.parse(receipt)['afterCandidateDigest']==integrated
        assert target(db)==(2,integrated)
        replay,retained=request_http(service)
        assert replay==200 and retained==receipt
    else:assert target(db)==(1,before)
    count=db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0]
    assert count==(1 if variant=='retry' else 0)
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0]==1
    assert not db.connection.execute('SELECT * FROM completions').fetchall()
    assert state['received']==['PUT']*(3 if variant=='retry' else 2)
    assert state['receivedHeaders']==[
        dict(earlyData=['1'],businessKey=[request['businessActionId']]),
        *[dict(earlyData=[],businessKey=[request['businessActionId']])
          for _ in range(2 if variant=='retry' else 1)]]
    db.check_integrity()
    destination=os.environ.get('DAS_V15_HTTP_EVIDENCE_DIR')
    if destination:
        import dasops.protected.candidates.http_reference as implementation
        proof=dict(variant=variant,actualStatuses=[first,second]+([replay] if variant=='retry' else []),
            request=codec.digest(request),receiptSha256=hashlib.sha256(receipt).hexdigest(),
            actualReceivedHeaders=state['receivedHeaders'],actualTarget=list(target(db)),
            actualReceipts=count,actualReserved=1,completions=0,serverAddress=list(server.server_address),
            actualServerSocketType=type(server.socket).__name__,
            implementationPath=implementation.__file__,
            implementationSha256=hashlib.sha256(Path(implementation.__file__).read_bytes()).hexdigest(),
            tlsTerminator=False,proxy=False,automaticRetry=False,productAcceptance='not_run')
        path=Path(destination)/('http-early-'+variant+'.json')
        with path.open('x') as stream:stream.write(json.dumps(proof,indent=2)+'\n')


def raw_http(service, data):
    with socket.create_connection(service[0].server_address, timeout=3) as connection:
        connection.sendall(data)
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError as error:
            # A rejected request can close before the client's half-close.
            # Still read the response; absence of the required 400 must fail.
            if error.errno != errno.ENOTCONN:
                raise
        output = b''
        while True:
            try:part = connection.recv(65536)
            except ConnectionResetError:
                # Rejection may close with unread request bytes and reset after
                # sending 4xx. Preserve actual response; empty/missing headers
                # still fail the caller's status/close/resource assertions.
                break
            if not part: break
            output += part
    return output


@pytest.mark.parametrize('framing', [
    b'Transfer-Encoding: chunked\r\nContent-Length: 1\r\n',
    b'Content-Length: 1\r\nContent-Length: 2\r\n',
    b'Content-Length: 99\r\n', b'Transfer-Encoding: chunked\r\n',
    b'Authorization: Bearer other\r\nContent-Length: 1\r\n',
    b'Content-Length : 1\r\n', b'Content-Length: 1\n',
    b'Content-Length: 1\r\n ignored: folded\r\n',
])
def test_actual_raw_framing_rejection_leaves_final_resource_unchanged(service, framing):
    host = '%s:%d' % service[0].server_address
    data = ('PUT /integrations HTTP/1.1\r\nHost: '+host+'\r\nAuthorization: Bearer TEST-only-worker\r\n').encode()
    output = raw_http(service, data+framing+b'\r\nx')
    assert output.startswith(b'HTTP/1.1 4')
    assert b'Connection: close' in output
    assert target(service[1]) == (1, service[2])

@pytest.mark.parametrize('prefix', [b'\x00', b'\x01', b'\x7f'])
def test_raw_request_target_control_bytes_cannot_be_normalized_into_a_resource_write(service, prefix):
    server,db,before,_,request,_=service
    host='%s:%d' % server.server_address
    body=codec.canonical(request);checkpoint=db.checkpoint()
    headers=(' HTTP/1.1\r\nHost: '+host+'\r\nAuthorization: Bearer TEST-only-worker\r\n'
        'If-Match: "'+before+'"\r\nIdempotency-Key: '+request['businessActionId']+'\r\n'
        'Content-Type: application/json\r\nContent-Length: '+str(len(body))+'\r\n\r\n').encode()
    output=raw_http(service,b'PUT '+prefix+b'/integrations'+headers+body)
    observed=(int(output.split(b' ',2)[1]),target(db)[0],db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0])
    assert observed==(400,1,0),observed
    assert b'Connection: close' in output
    assert target(db)==(1,before) and db.checkpoint()==checkpoint


def test_legal_chunked_and_connection_reuse_reach_one_resource_commit(service):
    server, db, before, integrated, request, _ = service
    host = '%s:%d' % server.server_address
    body = codec.canonical(request)
    wire = ('PUT /integrations HTTP/1.1\r\nHost: '+host+'\r\nAuthorization: Bearer TEST-only-worker\r\n'
        'Content-Type: application/json\r\nIf-Match: "'+before+'"\r\nIdempotency-Key: '+request['businessActionId']+
        '\r\nTransfer-Encoding: chunked\r\n\r\n').encode()
    wire += ('%x\r\n' % len(body)).encode()+body+b'\r\n0\r\n\r\n'
    wire += ('GET /target HTTP/1.1\r\nHost: '+host+'\r\nAuthorization: Bearer TEST-only-worker\r\nConnection: close\r\n\r\n').encode()
    output = raw_http(service, wire)
    assert output.count(b'HTTP/1.1 200 OK') == 2
    assert target(db) == (2, integrated)
    assert db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 1


def test_get_queries_actual_target_with_current_read_identity(service):
    status, raw = request_http(service, method='GET', path='/target', body=b'',
        headers={'Content-Type': None, 'If-Match': None, 'Idempotency-Key': None})
    assert status == 200
    value = codec.parse(raw)
    assert (value['generation'], value['candidateDigest']) == target(service[1])
    assert value['resourceInstance'] == 'instance' and not value['qualification']


def test_raw_lf_request_line_is_rejected_before_any_resource_effect(service):
    output = raw_http(service, b'GET /target HTTP/1.1\nHost: invalid\n\n')
    assert output.startswith(b'HTTP/1.1 400') and target(service[1]) == (1, service[2])


def test_actual_target_storage_failure_is_not_202_or_a_completion(service):
    db = service[1]
    service[5]['rejectCas'] = True
    assert request_http(service)[0] == 503
    assert target(db) == (1, service[2])
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0] == 0
    assert db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 0
    service[5]['rejectCas'] = False
    assert request_http(service)[0] == 200 and target(db) == (2, service[3])


@pytest.mark.parametrize('fault', ['none', '202', 'lost-response'])
@pytest.mark.parametrize('service', [False], indirect=True)
def test_real_http_outbox_preserves_unknown_and_recovers_without_another_send(service, chain, fault):
    db, _, kernel, _, integrated, _, _, _ = chain
    state = service[5]
    state['fake202'], state['dropReceipt'] = fault == '202', fault == 'lost-response'
    adapter = ReferenceHTTPAdapter(port=service[0].server_port, before_candidate=service[2],
        resource='target', instance='instance', read_token=lambda: 'TEST-only-worker')
    request = dict(service[4])
    def verify(value, observation):
        # Independent protected storage read, not HTTP status/self-reported PASS.
        retained = kernel.lookup('target', 'instance', 'integrate', value['businessActionId'],
                                 actor='worker', now=101, authorize=authorized)
        return retained is not None and retained == observation.native_receipt
    outbox = DurableOutbox(db, adapters={('target','instance','integrate'):adapter},
        verify_observation=verify, execution_closed=lambda _: False)
    outbox.submit(request, actor='worker', now=101, authorize=authorized)
    result = outbox.dispatch('target', 'integrate', 'forward', actor='worker', now=101, authorize=authorized)
    assert state['received'] == ['PUT']
    if fault == '202':
        assert result['state'] == 'unknown' and target(db) == (1, service[2])
        with pytest.raises(CandidateError):
            kernel.complete_integration(KEY, cycle=1, revision=1, resource='target', instance='instance',
                business='forward', qualification_refs=COMPLETE_REFS, actor='worker', now=101, authorize=authorized)
        assert not db.connection.execute('SELECT * FROM completions').fetchall()
        result = outbox.reconcile('target','integrate','forward',actor='worker',now=101,authorize=authorized)
        assert result['state'] == 'unknown' and state['received'] == ['PUT','GET']
        assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0] == 1
        return
    if fault == 'lost-response':
        assert result['state'] == 'unknown' and target(db) == (2, integrated)
        result = outbox.reconcile('target','integrate','forward',actor='worker',now=101,authorize=authorized)
        assert state['received'] == ['PUT','GET']
    assert result['state'] == 'confirmed' and target(db) == (2, integrated)
    completion = kernel.complete_integration(KEY, cycle=1, revision=1, resource='target', instance='instance',
        business='forward', qualification_refs=COMPLETE_REFS, actor='worker', now=101, authorize=authorized)
    assert completion['integrationCandidateDigest'] == integrated
    assert db.connection.execute('SELECT COUNT(*) FROM completions').fetchone()[0] == 1
    assert db.connection.execute('SELECT COUNT(*) FROM version_switch_receipts').fetchone()[0] == 1
    assert db.connection.execute('SELECT reserved FROM budgets').fetchone()[0] == 1


def test_slow_drip_request_has_a_cumulative_input_deadline_and_no_effect(service):
    server = service[0]
    connection = socket.create_connection(server.server_address, timeout=3)
    host = '%s:%d' % server.server_address
    header = ('PUT /integrations HTTP/1.1\r\nHost: '+host+'\r\nAuthorization: Bearer TEST-only-worker\r\n'
        'Content-Type: application/json\r\nIf-Match: "'+service[2]+'"\r\nIdempotency-Key: forward\r\nContent-Length: 999\r\n\r\n').encode()
    started = time.monotonic()
    connection.sendall(header)
    for _ in range(25):
        try: connection.sendall(b'x')
        except OSError: break
        time.sleep(0.1)
    output = connection.recv(65536)
    connection.close()
    assert time.monotonic()-started < 3.2
    assert not output or output.startswith(b'HTTP/1.1 400')
    assert target(service[1]) == (1, service[2])
