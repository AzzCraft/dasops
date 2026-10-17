"""Unprivileged finite client; no authority configuration or local fallback."""
import sys

from dasops.bootstrap.ipc import authenticated_socket
from dasops.protected.sqlite.outbox import MAX_INTENT_BYTES
from dasops.standards_contracts import exact_json as codec
from dasops.protected.candidates.govern import invoke
from dasops.protected.candidates.projection import render_projection


def add_govern_parsers(sub):
    parser = sub.add_parser('govern', help='Call the installed protected reference over authenticated Unix IPC')
    parser.add_argument('operation', choices=('inspect', 'plan', 'apply', 'submit', 'integrate', 'complete', 'rollback', 'audit'))
    parser.add_argument('--driver-fd', required=True, type=int, help='Connected Unix stream supplied by the approved supervisor')
    parser.add_argument('--server-uid', required=True, type=int, help='Independently installed expected server UID')
    parser.add_argument('--projection', choices=('json', 'markdown'), default='json',
                        help='Complete only: deterministic local display, with no authority or file writes')


def handle_govern(args):
    if args.cmd != 'govern':
        return None
    try:
        if args.projection != 'json' and args.operation != 'complete':
            raise ValueError('completion projection requires the complete operation')
        raw = sys.stdin.buffer.read(MAX_INTENT_BYTES+1)
        if len(raw) > MAX_INTENT_BYTES:
            raise ValueError('request exceeds the immutable intent bound')
        value = codec.parse(raw)
        if not isinstance(value, dict) or value.get('action') != args.operation:
            raise ValueError('request action differs from fixed CLI operation')
        # Authentication uses the kernel's actual connected peer; no socket
        # pathname or arbitrary adapter/program is opened by this client.
        channel, _ = authenticated_socket(args.driver_fd, {args.server_uid})
        with channel:
            result = invoke(channel, value, expected_server_uid=args.server_uid)
        if args.projection == 'markdown':
            subject = {name: result[name] for name in ('taskKey','taskRevision','taskCycle','obligationDigest')}
            sys.stdout.buffer.write(render_projection(dict(**subject,status='DONE',
                completionDigest=codec.digest(result),completion=result,currentQualification='not_evaluated',
                authority=False,qualification=False)))
        else:
            reading = args.operation == 'inspect' and value['parameters'].get('view') == 'context-pack'
            sys.stdout.buffer.write((codec.canonical_catalog if reading else codec.canonical)(result)+b'\n')
        return 0
    except Exception:
        # Input/transport errors are not success or proof of no effect. Never
        # echo hostile data, secrets or arbitrary exceptions into the terminal.
        print('govern result unavailable; reconcile the original business key before retrying', file=sys.stderr)
        return 2
