import errno
from http.client import HTTPResponse
import json
import socket
import threading

import pytest

from hookreplay import cli, store

BASE = {
    "Content-Type": "application/json", "Content-Length": "2",
    "X-GitHub-Delivery": "test-delivery-001", "X-GitHub-Event": "ping",
}


def request_bytes(method="POST", headers=None):
    headers = BASE if headers is None else headers
    return (f"{method} /webhook HTTP/1.1\r\nHost: localhost\r\n" + "".join(
        f"{name}: {value}\r\n" for name, value in headers.items()
    ) + "\r\n").encode("latin-1")


def response(connection):
    reply = HTTPResponse(connection)
    reply.begin()
    body = reply.read()
    return reply.status, json.loads(body) if body else None


def exchange(server, request, body=b"", shutdown=False):
    with socket.create_connection(server.server_address, timeout=2) as connection:
        connection.sendall(request + body)
        if shutdown:
            connection.shutdown(socket.SHUT_WR)
        return response(connection)


@pytest.mark.parametrize(("method", "changes", "removed", "status", "reason"), [
    ("GET", {}, [], 405, "method_not_allowed"),
    ("POST", {"Content-Type": "text/plain"}, [], 415, "unsupported_media_type"),
    ("POST", {}, ["Content-Length"], 411, "length_required"),
    ("POST", {"Transfer-Encoding": "Chunked"}, [], 411, "length_required"),
    ("POST", {"Content-Length": "-1"}, [], 400, "bad_content_length"),
    ("POST", {"Content-Length": "bad"}, [], 400, "bad_content_length"),
    ("POST", {"Content-Length": "10"}, [], 413, "body_too_large"),
    ("POST", {}, ["X-GitHub-Delivery"], 400, "bad_delivery_id"),
    ("POST", {"X-GitHub-Delivery": "../outside"}, [], 400, "bad_delivery_id"),
    ("POST", {}, ["X-GitHub-Event"], 400, "bad_event"),
    ("POST", {"X-GitHub-Event": "Ping"}, [], 400, "bad_event"),
    ("POST", {"User-Agent": "bad\x01agent"}, [], 400, "bad_header"),
    ("POST", {"User-Agent": "é"}, [], 400, "bad_header"),
])
def test_request_reason_codes_before_reading_body(recorder, tmp_path, method, changes, removed, status, reason):
    server = recorder(max_body_bytes=8)
    headers = {**BASE, **changes}
    for name in removed:
        del headers[name]
    # No body sent: an immediate response proves rejection before body reading.
    assert exchange(server, request_bytes(method, headers)) == (status, {"reason": reason})
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("reason", ["storage_collision", "storage_error"])
def test_storage_failure_response(recorder, tmp_path, monkeypatch, reason):
    def fail(*args, **kwargs):
        raise store.StorageError(reason, "PermissionError" if reason == "storage_error" else "")
    monkeypatch.setattr(store, "write_record", fail)
    expected = {"reason": reason}
    if reason == "storage_error":
        expected["error_class"] = "PermissionError"
    assert exchange(recorder(), request_bytes(), b"{}") == (500, expected)
    assert list(tmp_path.iterdir()) == []


def test_content_type_case_and_opaque_bytes(recorder, tmp_path):
    headers = {**BASE, "Content-Type": "Application/JSON ; Charset=UTF-8", "Content-Length": "4"}
    status, result = exchange(recorder(), request_bytes(headers=headers), b"\xffx\n\x00")
    assert status == 202
    assert result["verified"] is None
    data, body = store.read_record(tmp_path / result["file"])
    assert body == b"\xffx\n\x00"
    assert data["headers"]["Content-Type"] == "Application/JSON ; Charset=UTF-8"


def test_truncated_body_half_close(recorder, tmp_path):
    assert exchange(recorder(), request_bytes(), b"{", shutdown=True) == (400, {"reason": "truncated_body"})
    assert list(tmp_path.iterdir()) == []


def test_body_deadline(recorder, tmp_path):
    assert exchange(recorder(read_timeout=0.15), request_bytes(), b"{") == (408, {"reason": "read_timeout"})
    assert list(tmp_path.iterdir()) == []


def test_idle_header_connection_closes(recorder, tmp_path):
    server = recorder(read_timeout=0.15)
    with socket.create_connection(server.server_address, timeout=2) as connection:
        assert connection.recv(1) == b""
    assert list(tmp_path.iterdir()) == []


def test_full_disconnect_before_complete_body_leaves_no_record(recorder, tmp_path, monkeypatch):
    server = recorder()
    finished = threading.Event()
    original = server.finish_request

    def finish(*args):
        try:
            return original(*args)
        finally:
            finished.set()

    monkeypatch.setattr(server, "finish_request", finish)
    with socket.create_connection(server.server_address, timeout=2) as connection:
        connection.sendall(request_bytes() + b"{")
    assert finished.wait(2)
    assert list(tmp_path.iterdir()) == []


def test_very_large_content_length_rejected_before_integer_conversion(recorder, tmp_path):
    headers = {**BASE, "Content-Length": "9" * 5000}
    assert exchange(recorder(), request_bytes(headers=headers)) == (413, {"reason": "body_too_large"})
    assert list(tmp_path.iterdir()) == []


def test_large_finite_read_timeout_is_accepted(recorder, tmp_path):
    status, result = exchange(recorder(read_timeout=1e308), request_bytes(), b"{}")
    assert status == 202
    assert store.read_record(tmp_path / result["file"])[1] == b"{}"


def test_malicious_id_cannot_escape_or_enter_log(recorder, tmp_path, capsys):
    server = recorder()
    before = set(tmp_path.parent.iterdir())
    headers = {**BASE, "X-GitHub-Delivery": "../escaped-record"}
    assert exchange(server, request_bytes(headers=headers)) == (400, {"reason": "bad_delivery_id"})
    assert list(tmp_path.iterdir()) == []
    assert set(tmp_path.parent.iterdir()) == before
    assert capsys.readouterr().err == "POST 400 - ping - -\n"


def test_log_and_header_allowlist(recorder, tmp_path, capsys):
    headers = {
        **BASE, "X-Hub-Signature-256": "sha256=not-to-persist", "X-Hub-Signature": "sha1=private",
        "Authorization": "not-to-persist", "X-GitHub-Hook-ID": "12",
    }
    status, result = exchange(recorder(), request_bytes(headers=headers), b"{}")
    assert status == 202
    path = tmp_path / result["file"]
    assert store.read_record(path)[0]["headers"] == {**{k: v for k, v in BASE.items() if k != "Content-Length"}, "X-GitHub-Hook-ID": "12"}
    assert "not-to-persist" not in path.read_text()
    assert capsys.readouterr().err == "POST 202 test-delivery-001 ping 2 null\n"


@pytest.mark.parametrize("kind", ["missing", "file", "symlink"])
def test_record_directory_errors_precede_socket(tmp_path, monkeypatch, capsys, kind):
    target = tmp_path / "target"
    if kind == "file":
        target.write_text("not a directory")
    elif kind == "symlink":
        target.symlink_to(tmp_path, target_is_directory=True)
    def forbidden(*args, **kwargs):
        pytest.fail("socket opened for invalid directory")
    monkeypatch.setattr(socket, "socket", forbidden)
    assert cli.main(["record", "--dir", str(target)]) == 2
    assert "dir:" in capsys.readouterr().err


def raw_exchange(server, payload):
    with socket.create_connection(server.server_address, timeout=2) as connection:
        connection.sendall(payload)
        reply = HTTPResponse(connection)
        reply.begin()
        return reply.status, dict(reply.getheaders()), reply.read()


@pytest.mark.parametrize(("request_line", "status", "method"), [
    pytest.param(b"GARBAGE\r\n\r\n", 400, "-", id="garbage-request-line"),
    pytest.param(b"POST / HTTP/9.9\r\n\r\n", 505, "-", id="unsupported-version"),
    pytest.param(b"POST / HTTP/1.1\r\nX: " + b"a" * 70000 + b"\r\n\r\n", 431, "POST", id="oversized-header"),
])
def test_unparseable_request_keeps_json_contract_and_log(recorder, tmp_path, capsys, request_line, status, method):
    code, headers, body = raw_exchange(recorder(), request_line)
    assert code == status
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == {"reason": "bad_request"}
    assert b"GARBAGE" not in body and b"<" not in body
    assert list(tmp_path.iterdir()) == []
    # The method is logged once the request line parsed; everything else is "-".
    assert capsys.readouterr().err == f"{method} {status} - - - -\n"


def test_server_header_discloses_no_version(recorder):
    _, headers, _ = raw_exchange(recorder(), request_bytes() + b"{}")
    assert headers["Server"] == "hookreplay"
    assert "Python" not in headers["Server"]


def test_reset_during_headers_leaves_no_traceback(recorder, tmp_path, monkeypatch, capsys):
    import struct

    server = recorder()
    finished = threading.Event()
    original = server.finish_request

    def finish(*args):
        try:
            return original(*args)
        finally:
            finished.set()

    monkeypatch.setattr(server, "finish_request", finish)
    with socket.create_connection(server.server_address, timeout=2) as connection:
        connection.sendall(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n")
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    assert finished.wait(2)
    assert list(tmp_path.iterdir()) == []
    assert capsys.readouterr().err == ""


def test_log_line_is_written_atomically(recorder, monkeypatch):
    import sys

    writes = []

    class Stream:
        def write(self, text):
            writes.append(text)

        def flush(self):
            pass

    monkeypatch.setattr(sys, "stderr", Stream())
    assert exchange(recorder(), request_bytes(), b"{}")[0] == 202
    assert writes == ["POST 202 test-delivery-001 ping 2 null\n"]


def test_storage_error_response_names_only_the_exception_class(recorder, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError(errno.EPERM, "sensitive path /private/tmp")

    monkeypatch.setattr(store.os, "link", fail)
    status, result = exchange(recorder(), request_bytes(), b"{}")
    assert (status, result) == (500, {"reason": "storage_error", "error_class": "PermissionError"})
    assert list(tmp_path.iterdir()) == []


def test_storage_collision_response_has_no_error_class(recorder, tmp_path, monkeypatch):
    from conftest import NOW

    monkeypatch.setattr(store, "clock", lambda: NOW)
    monkeypatch.setattr(store, "new_id", lambda: "c" * 12)
    assert exchange(recorder(), request_bytes(), b"{}")[0] == 202
    status, result = exchange(recorder(), request_bytes(), b"{}")
    assert (status, result) == (500, {"reason": "storage_collision"})
    assert len(list(tmp_path.iterdir())) == 1
