import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from dasops.bootstrap.ipc import deadline,read_exact,write_all,IpcError,shutdown
from dasops.bootstrap import ipc


def test_partial_frames_use_one_cumulative_deadline():
    a,b=socket.socketpair()
    try:
        a.sendall(b'x')
        limit=deadline(.05)
        assert read_exact(b,1,limit)==b'x'
        time.sleep(.06)
        a.sendall(b'y')
        with pytest.raises(IpcError,match='deadline'):
            read_exact(b,1,limit)
    finally:a.close();b.close()


def test_shutdown_closes_all_aliases_for_denied_peer():
    a,b=socket.socketpair();alias=b.dup()
    try:
        shutdown(alias)
        with pytest.raises(IpcError,match='closed'):
            read_exact(a,1,deadline(.1))
    finally:a.close();b.close();alias.close()


def test_silent_peer_and_blocked_writer_are_bounded():
    a,b=socket.socketpair()
    try:
        with pytest.raises(IpcError,match='deadline'):
            read_exact(a,8,deadline(.02))
        a.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
        with pytest.raises(IpcError,match='deadline'):
            write_all(a,b'x'*1048576,deadline(.02))
    finally:a.close();b.close()


@pytest.mark.parametrize('value',[True,0,-1,31,float('nan'),float('inf')])
def test_invalid_time_budget_rejects(value):
    with pytest.raises(IpcError):deadline(value)


@pytest.mark.parametrize('revoke',[False,True])
def test_partial_sends_check_permission_and_keep_irrevocable_prefix(revoke,monkeypatch):
    sender,reader=socket.socketpair();checks=[];value=b'TEST bounded release\n'*8192
    sender.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
    # A concurrent reader can let even MSG_DONTWAIT send the entire frame in
    # one syscall. Hold that reader until the real first send has returned.
    partial_sent=threading.Event();ready=ipc._ready;attempts=[]
    def observed_ready(channel,limit,*,write=False):
        if write:
            attempts.append(1)
            if len(attempts)>1:partial_sent.set()
        return ready(channel,limit,write=write)
    monkeypatch.setattr(ipc,'_ready',observed_ready)
    def current():
        checks.append(len(checks)+1)
        if revoke and len(checks)>1:raise IpcError('TEST current release revoked')
    def send():
        try:write_all(sender,value,deadline(5),before_send=current)
        finally:shutdown(sender)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(send);received=bytearray()
            assert partial_sent.wait(5),'sender did not reach a real partial-send boundary'
            reader.settimeout(5)
            while chunk:=reader.recv(4096):received.extend(chunk)
            if revoke:
                with pytest.raises(IpcError,match='revoked'):future.result(timeout=5)
                assert 0<len(received)<len(value) and bytes(received)==value[:len(received)]
                assert len(checks)==2
            else:
                future.result(timeout=5)
                assert bytes(received)==value and len(checks)>1
    finally:sender.close();reader.close()


def test_release_check_cannot_reset_or_overrun_original_deadline(monkeypatch):
    sender,reader=socket.socketpair();limit=deadline(5)
    def current():monkeypatch.setattr(ipc,'now',lambda:limit+1)
    try:
        with pytest.raises(IpcError,match='deadline'):
            write_all(sender,b'TEST never disclosed',limit,before_send=current)
        shutdown(sender)
        assert reader.recv(4096)==b''
    finally:sender.close();reader.close()
