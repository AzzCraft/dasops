"""Bounded Unix stream framing; one deadline covers all partial transfers."""
import math
import os
import select
import socket
import struct
import time


class IpcError(RuntimeError):
    pass


def authenticated_socket(fd, allowed_peer_uids):
    """Duplicate a connected Linux Unix stream and read actual kernel identity."""
    if type(fd) is not int or fd < 3:
        raise IpcError('authority driver FD is invalid')
    duplicate = os.dup(fd)
    try:
        channel = socket.socket(fileno=duplicate)
    except OSError as exc:
        os.close(duplicate)
        raise IpcError('authority driver FD is not a socket') from exc
    try:
        if channel.family != socket.AF_UNIX or channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
            raise IpcError('authority driver requires a Unix stream socket')
        if not hasattr(socket, 'SO_PEERCRED'):
            raise IpcError('authority driver peer credentials are unavailable')
        channel.getpeername()
        credentials = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
        _pid, uid, _gid = struct.unpack('3i', credentials)
        if uid not in allowed_peer_uids:
            raise IpcError('authority driver peer UID is not allowed')
        return channel, uid
    except Exception:
        shutdown(channel)
        channel.close()
        raise


def deadline(timeout=30.0):
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise IpcError('invalid IPC time budget')
    return now()+timeout


def now():
    if not hasattr(time,'CLOCK_BOOTTIME'):
        raise IpcError('IPC reference requires Linux CLOCK_BOOTTIME')
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def _ready(channel, limit, *, write=False):
    remaining=limit-now()
    if remaining<=0:
        raise IpcError('IPC deadline exceeded; operation outcome is unknown until reconciled')
    readable,writable,_=select.select([] if write else [channel],[channel] if write else [],[],remaining)
    if not (writable if write else readable):
        raise IpcError('IPC deadline exceeded; operation outcome is unknown until reconciled')


def read_exact(channel,size,limit):
    if type(size) is not int or not 0<=size<=4_194_304:
        raise IpcError('invalid IPC read bound')
    result=bytearray()
    while len(result)<size:
        _ready(channel,limit)
        try:
            value=channel.recv(size-len(result),socket.MSG_DONTWAIT)
        except BlockingIOError:
            continue
        if not value:
            raise IpcError('IPC peer closed before returning a complete frame; reconcile original operation')
        result.extend(value)
    return bytes(result)


def write_all(channel,value,limit,*,before_send=None):
    if len(value)>4_194_312:
        raise IpcError('IPC frame exceeds bound')
    view=memoryview(value)
    while view:
        _ready(channel,limit,write=True)
        # A prepared response is not permission to disclose it later. The
        # installed sender checks AFTER backpressure and before each new send;
        # already sent bytes remain in flight and cannot be recalled here.
        if before_send is not None:
            before_send()
            # Authorization may itself take time; retain the SAME deadline.
            if limit-now() <= 0:
                raise IpcError('IPC deadline exceeded; operation outcome is unknown until reconciled')
        try:
            sent=channel.send(view,socket.MSG_DONTWAIT|socket.MSG_NOSIGNAL)
        except BlockingIOError:
            continue
        if sent<=0:
            raise IpcError('IPC peer write failed; reconcile original operation')
        view=view[sent:]


def shutdown(channel):
    # Shutdown the connection, not just one duplicated descriptor. The caller
    # may retain an alias; a denied peer must still observe EOF immediately.
    try:
        channel.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
