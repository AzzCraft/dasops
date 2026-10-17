"""Small loopback HTTP/1.1 reference adapter to the existing version resource.

No listener starts on import and there is no public activation CLI. Installation
supplies the manager, authenticated token mapping, current local authorization
and trusted time. This adapter does not qualify those dependencies. It never
reserves new action keys, signs, completes tasks or executes candidate code.
"""
from http.server import BaseHTTPRequestHandler
import re
import time
import http.client
from urllib.parse import parse_qs, urlsplit, urlencode

from dasops.standards_contracts import exact_json as codec
from dasops.protected.sqlite.store import CoordinationError, _id, _digest
from dasops.protected.sqlite.outbox import Observation, encode_intent, MAX_INTENT_BYTES
from .store import CandidateError, DIGEST, _check_time, _deadline, _decode, validate_binding

MAX_BODY = 4 * 1024 * 1024


class HTTPInputError(ValueError):
    pass


class _DeadlineReader:
    """Bound every underlying read, including stdlib header/chunk parsing."""
    def __init__(self, original, check): self.original, self.check = original, check
    def __getattr__(self, name): return getattr(self.original, name)
    def read(self, count):
        if count < 0: raise HTTPInputError('unbounded transport read')
        output = bytearray()
        while len(output) < count:
            self.check()
            part = self.original.read1(min(65536, count-len(output)))
            if not part: break
            output.extend(part)
        return bytes(output)
    def readline(self, limit=-1):
        output = bytearray()
        while len(output) < (65537 if limit < 0 else limit):
            self.check()
            part = self.original.read1(1)
            if not part: break
            output.extend(part)
            if part == b'\n': break
        return bytes(output)


def receive_candidate_http(store, connection, target, binding_bytes, *, commit_bytes,
                           content_sha256, content_encoding='identity', prefix=b'',
                           strong_etag=None, external_materials=None):
    """Receive one pinned HTTP/1 response into the existing candidate store.

    Trusted installation supplies an already-connected HTTP(S) origin, request
    target, approved full HTTP representation digest/encoding and optional
    bounded resume prefix/strong validator. These are not response self-claims
    or Worker-selected URLs. The connection is consumed/closed, never redirected
    or cached. TLS, origin authentication and permission remain installation
    responsibilities; the resulting stored object confers no authority.

    Only explicit Content-Length framing is supported. 206 requires the exact
    requested range and strong validator; 200 replaces the whole prefix. Cache
    revalidation, chunked/trailer and other encodings are not supported, and
    cannot manufacture a complete object. Prefix plus newly received bytes,
    decoding and publication share existing installed byte/time limits.
    """
    original_response = connection.response_class
    deadline = _deadline(store.limits)
    try:
        binding, _ = validate_binding(binding_bytes, store.limits)
        if (not isinstance(content_sha256, str) or not DIGEST.fullmatch(content_sha256)
                or content_encoding not in ('identity', 'gzip')
                or not isinstance(prefix, bytes) or len(prefix) >= store.limits.max_archive_bytes
                or not isinstance(target, str) or not target.startswith('/')
                or target.startswith('//') or any(ord(c) <= 32 or ord(c) >= 127 for c in target)
                or '#' in target or connection.sock is None):
            raise CandidateError('installed HTTP origin, target and byte-domain pins required')
        if prefix and (not isinstance(strong_etag, str)
                       or not re.fullmatch(r'"[!#-~]{1,240}"', strong_etag)):
            raise CandidateError('resume requires an exact strong validator')
        transport = connection.sock

        def remaining():
            seconds = deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
            if seconds <= 0:
                raise CandidateError('cumulative candidate reception deadline')
            transport.settimeout(seconds)

        class Response(http.client.HTTPResponse):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.fp = _DeadlineReader(self.fp, remaining)

        connection.response_class = Response
        headers = {'Accept-Encoding': content_encoding, 'Connection': 'close'}
        if prefix:
            headers.update({'Range': 'bytes=%d-' % len(prefix), 'If-Range': strong_etag})
        remaining()
        connection.request('GET', target, headers=headers)
        with connection.getresponse() as response:
            def single(name):
                values = response.headers.get_all(name, [])
                if len(values) > 1 or any(ord(c) < 32 or ord(c) == 127 for v in values for c in v):
                    raise CandidateError('ambiguous HTTP response header')
                return values[0] if values else None

            length, transfer, trailer = (single(name) for name in
                ('Content-Length', 'Transfer-Encoding', 'Trailer'))
            encoding = (single('Content-Encoding') or 'identity').strip().lower()
            range_value, etag = single('Content-Range'), single('ETag')
            if (transfer is not None or trailer is not None or encoding != content_encoding
                    or length is None or not re.fullmatch(r'[0-9]{1,9}', length)):
                raise CandidateError('unsupported or unpinned HTTP response representation')
            count = int(length)
            if response.status == 200 and range_value is None:
                assembled = bytearray()  # Range ignored: start a new full object.
            elif response.status == 206 and prefix and etag == strong_etag:
                match = re.fullmatch(r'bytes ([0-9]{1,9})-([0-9]{1,9})/([0-9]{1,9})', range_value or '', re.I)
                if (match is None or tuple(map(int, match.groups())) !=
                        (len(prefix), len(prefix) + count - 1, len(prefix) + count)):
                    raise CandidateError('HTTP range does not finish the same exact object')
                assembled = bytearray(prefix)
            else:
                raise CandidateError('complete 200 or approved exact 206 required; no cache synthesis')
            if not 0 < count <= store.limits.max_archive_bytes - len(assembled):
                raise CandidateError('cumulative HTTP reception byte limit')
            received = 0
            while received < count:
                remaining()
                part = response.read(min(65536, count - received))
                if not part:
                    raise CandidateError('incomplete HTTP representation')
                assembled.extend(part)
                received += len(part)
            # Raw HTTP content and decoded archive are distinct pinned domains.
            archive = _decode(bytes(assembled), dict(encoding='tar-ustar' if encoding == 'identity'
                else 'gzip-tar-ustar', rawSha256=content_sha256,
                decodedSha256=binding['archive']['rawSha256']), store.limits, deadline)
        return store.receive(binding_bytes, commit_bytes=commit_bytes, archive_bytes=archive,
            external_materials=external_materials, elapsed_deadline=deadline)
    except (OSError, http.client.HTTPException, HTTPInputError) as exc:
        raise CandidateError('HTTP acquisition did not complete within its approved framing/budget') from exc
    finally:
        connection.response_class = original_response
        connection.close()


def handler_for(manager_context, *, authenticate, authorize, now, resource, instance):
    if not all(callable(value) for value in (manager_context, authenticate, authorize, now)):
        raise ValueError('installed dependencies are required')

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        server_version = 'DAS-reference'
        sys_version = ''
        # This is the actual dispatcher, not a second description of routes.
        # Installation collectors may inspect it without inferring completeness
        # from successful requests or granting authority to an Inventory.
        routes = (('GET', '/target', False), ('PUT', '/integrations', True))

        def setup(self):
            super().setup()
            self.connection.settimeout(2)
            self.rfile = _DeadlineReader(self.rfile, self._remaining)

        def handle_one_request(self):
            self.input_deadline = time.clock_gettime(time.CLOCK_BOOTTIME) + 2
            self.request_version, self.requestline, self.command = 'HTTP/1.1', '', None
            try:
                super().handle_one_request()
            except HTTPInputError:
                self._reply(400, {'error':'request_input_deadline_exceeded'}, close=True)

        def log_message(self, *_):
            # Authorization, request bodies and raw hostile headers stay out of logs.
            pass

        def _remaining(self):
            remaining = self.input_deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
            if remaining <= 0: raise HTTPInputError('request input deadline exceeded')
            self.connection.settimeout(remaining)

        def parse_request(self):
            if (not self.raw_requestline.endswith(b'\r\n')
                    or any(byte<32 or byte==127 for byte in self.raw_requestline[:-2])):
                self.request_version = 'HTTP/1.1'
                self.requestline = ''
                self.command = None
                self._reply(400, {'error':'invalid_request_line'}, close=True)
                return False
            handler, original = self, self.rfile
            class HeaderReader:
                invalid = False
                def readline(self, limit=-1):
                    handler._remaining()
                    line = original.readline(limit)
                    if (not line.endswith(b'\r\n') or (line != b'\r\n' and
                            not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[^\r\n]*\r\n", line))):
                        self.invalid = True
                    return line
            reader = HeaderReader()
            self.rfile = reader
            try:
                parsed = super().parse_request()
            except (OSError, HTTPInputError):
                parsed = False
                reader.invalid = True
            finally:
                self.rfile = original
            if reader.invalid:
                self._reply(400, {'error':'invalid_header_framing'}, close=True)
                return False
            return parsed

        def _reply(self, status, value, *, close=False, etag=None):
            body = codec.canonical(value)
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            if status == 401: self.send_header('WWW-Authenticate', 'Bearer realm="DAS-reference"')
            if etag is not None: self.send_header('ETag', etag)
            if close:
                self.close_connection = True
                self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def _single(self, name, *, required=False):
            values = self.headers.get_all(name, [])
            if len(values) > 1 or (required and not values):
                raise HTTPInputError('ambiguous or missing header')
            if values and any(ord(char) < 32 or ord(char) == 127 for char in values[0]):
                raise HTTPInputError('control byte in header')
            return values[0] if values else None

        def _framing(self):
            host = self._single('Host', required=True)
            expected = '%s:%d' % self.server.server_address
            if (self.server.server_address[0] != '127.0.0.1' or host != expected
                    or self.request_version != 'HTTP/1.1'):
                raise HTTPInputError('unsupported authority or protocol')
            length, transfer = self._single('Content-Length'), self._single('Transfer-Encoding')
            if length is not None and transfer is not None:
                raise HTTPInputError('ambiguous framing')
            if transfer is not None and transfer.lower() != 'chunked':
                raise HTTPInputError('unsupported transfer coding')
            if length is not None and (not re.fullmatch(r'[0-9]{1,8}', length) or int(length) > MAX_BODY):
                raise HTTPInputError('invalid or excessive body length')
            if self._single('Expect') is not None:
                raise HTTPInputError('Expect is outside this reference profile')
            return int(length or 0), transfer

        def handle_expect_100(self):
            self._reply(417, {'error':'expect_not_supported'}, close=True)
            return False

        def _exact(self, count):
            self._remaining()
            data = self.rfile.read(count)
            if len(data) != count: raise HTTPInputError('truncated body')
            return data

        def _body(self, length, transfer):
            if transfer is None: return self._exact(length)
            output = bytearray()
            for _ in range(1024):
                self._remaining()
                line = self.rfile.readline(128)
                # Chunk extensions/trailers are explicitly unsupported here.
                if not re.fullmatch(rb'[0-9a-fA-F]{1,8}\r\n', line):
                    raise HTTPInputError('invalid or unsupported chunk boundary')
                count = int(line[:-2], 16)
                if count > MAX_BODY - len(output): raise HTTPInputError('body too large')
                if count == 0:
                    if self._exact(2) != b'\r\n': raise HTTPInputError('trailers not supported')
                    return bytes(output)
                output.extend(self._exact(count))
                if self._exact(2) != b'\r\n': raise HTTPInputError('invalid chunk ending')
            raise HTTPInputError('too many chunks')

        def _serve(self):
            try:
                length, transfer = self._framing()
                token = self._single('Authorization')
                if token is None:
                    return self._reply(401, {'error':'authentication_required'}, close=True)
                if not token.startswith('Bearer ') or not re.fullmatch(r'[A-Za-z0-9._~-]{1,512}', token[7:]):
                    raise HTTPInputError('unsupported authentication syntax')
                actor = authenticate(token[7:])
                if actor is None:
                    return self._reply(401, {'error':'authentication_required'}, close=True)
                if self._single('Early-Data') is not None:
                    return self._reply(425, {'error':'early_data_not_supported'}, close=True)
                location = urlsplit(self.path)
                route = next((row for row in self.routes
                              if row[:2] == (self.command, location.path)), None)
                if (location.scheme or location.netloc or location.fragment or route is None
                        or (route[2] and location.query)):
                    return self._reply(404, {'error':'unknown_route'}, close=True)
                mutation = route[2]
                if mutation:
                    tag = self._single('If-Match')
                    if tag is None:
                        return self._reply(428, {'error':'exact_condition_required'}, close=True)
                    key = self._single('Idempotency-Key', required=True)
                    if self._single('Content-Type', required=True) != 'application/json':
                        raise HTTPInputError('unsupported request representation')
                    value = codec.parse(self._body(length, transfer))
                    if (not isinstance(value, dict) or value.get('businessActionId') != key
                            or value.get('resourceId') != resource or value.get('resourceInstance') != instance):
                        raise HTTPInputError('request does not bind installed action/resource')
                    with manager_context() as manager:
                        raw = manager.switch_http(value, if_match=tag, actor=actor, now=now(), authorize=authorize)
                    return self._reply(200, codec.parse(raw))
                if length or transfer is not None:
                    raise HTTPInputError('GET body outside profile')
                if location.query:
                    query = parse_qs(location.query, strict_parsing=True, keep_blank_values=True)
                    if (set(query) != {'businessActionId'} or len(query['businessActionId']) != 1
                            or not query['businessActionId'][0]):
                        raise HTTPInputError('unsupported query')
                    with manager_context() as manager:
                        raw = manager.lookup(resource, instance, 'integrate', query['businessActionId'][0],
                                             actor=actor, now=now(), authorize=authorize)
                    return self._reply(200, None if raw is None else codec.parse(raw))
                with manager_context() as manager:
                    value = manager.read_target(resource, instance, actor=actor, now=now(), authorize=authorize)
                return self._reply(200, value, etag='"'+value['candidateDigest']+'"')
            except (HTTPInputError, ValueError, OSError):
                return self._reply(400, {'error':'invalid_http_input'}, close=True)
            except (CandidateError, CoordinationError):
                return self._reply(412, {'error':'current_resource_precondition_failed'}, close=True)
            except Exception:
                # An unknown internal outcome is never a success or permission
                # to resend another action. Query/reconcile the original key.
                return self._reply(503, {'error':'resource_outcome_requires_reconciliation'}, close=True)

        def do_GET(self): self._serve()
        def do_PUT(self): self._serve()

    return Handler


class ReferenceHTTPAdapter:
    """One fixed loopback destination; no redirects or automatic retries.

    DurableOutbox owns action state and budget. Native observations must still
    pass its installed independent verifier; HTTP 200 itself proves nothing.
    Bearer mapping is a TEST/reference installation input, not production TLS.
    """
    def __init__(self, *, port, before_candidate, resource, instance, read_token):
        if type(port) is not int or not 0 < port < 65536 or not callable(read_token):
            raise ValueError('fixed installed loopback destination and token reader required')
        self.port, self.before_candidate = port, before_candidate
        _digest(before_candidate); _id(resource); _id(instance)
        self.resource, self.instance, self.read_token = resource, instance, read_token

    def _send(self, intent, deadline, mutation):
        raw = encode_intent(intent)
        if (intent['resourceId'], intent['resourceInstance'], intent['action']) != (self.resource, self.instance, 'integrate'):
            raise ValueError('intent does not bind the installed HTTP resource')
        def remaining():
            value = deadline - time.clock_gettime(time.CLOCK_BOOTTIME)
            if value <= 0: raise TimeoutError('HTTP operation deadline exceeded')
            return value
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=remaining())
        class BoundedResponse(http.client.HTTPResponse):
            def __init__(self, sock, *args, **kwargs):
                super().__init__(sock, *args, **kwargs)
                def check(): sock.settimeout(remaining())
                self.fp = _DeadlineReader(self.fp, check)
        connection.response_class = BoundedResponse
        try:
            token = self.read_token()
            if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~-]{1,512}', token):
                raise ValueError('invalid installed bearer token')
            headers = {'Authorization':'Bearer '+token}
            if mutation:
                headers.update({'If-Match':'"'+self.before_candidate+'"',
                    'Idempotency-Key':intent['businessActionId'], 'Content-Type':'application/json'})
                connection.request('PUT', '/integrations', body=raw, headers=headers)
            else:
                connection.request('GET', '/target?'+urlencode({'businessActionId':intent['businessActionId']}), headers=headers)
            connection.sock.settimeout(remaining())
            response = connection.getresponse()
            output = bytearray()
            while True:
                remaining()
                if connection.sock is not None: connection.sock.settimeout(remaining())
                part = response.read1(min(65536, MAX_INTENT_BYTES+1-len(output)))
                if not part: break
                output.extend(part)
                if len(output)>MAX_INTENT_BYTES: raise ValueError('HTTP receipt exceeds original-byte limit')
            remaining()
            original = bytes(output)
            # 202, redirection, timeout and absent receipt are all unresolved.
            outcome = 'confirmed' if response.status == 200 and original != b'null' else 'unknown'
            return Observation(outcome, codec.digest(intent), intent['resourceInstance'], original)
        finally:
            connection.close()

    def execute(self, intent, *, deadline): return self._send(intent, deadline, True)
    def lookup(self, intent, *, deadline): return self._send(intent, deadline, False)
