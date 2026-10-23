from http.client import HTTPResponse
import json
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import sysconfig

import pytest

from hookreplay import __version__, cli, store
from conftest import FIXTURES, HEADERS
from test_record_limits import exchange, request_bytes


def test_record_to_replay_byte_exact(recorder, receiver, tmp_path, capsys):
    # Independent literal, not a serialization produced by hookreplay.
    expected = b'{ "z": 2, "message": "caf\xc3\xa9 \xe2\x98\x95", "a": [1, true] }\n'
    assert (FIXTURES / "weird-bytes.json").read_bytes() == expected
    headers = {
        **HEADERS, "Content-Length": str(len(expected)), "User-Agent": "original-client",
        "X-GitHub-Hook-ID": "42", "X-GitHub-Hook-Installation-Target-ID": "123",
        "X-GitHub-Hook-Installation-Target-Type": "organization",
    }
    status, result = exchange(recorder(), request_bytes(headers=headers), expected)
    assert status == 202
    target = receiver()
    assert cli.main(["replay", str(tmp_path / result["file"]), "--url", target.url, "--format", "json"]) == 0
    assert len(target.requests) == 1
    received = target.requests[0]
    assert received["body"] == expected
    assert received["valid_signature"] is False
    sent_headers = {name.lower(): value for name, value in received["headers"].items()}
    assert sent_headers == {
        "host": f"127.0.0.1:{target.server_port}", "content-type": "application/json",
        "x-github-event": "ping", "x-github-delivery": "test-delivery-001",
        "user-agent": f"hookreplay/{__version__}", "content-length": str(len(expected)),
        "x-github-hook-id": "42", "x-github-hook-installation-target-id": "123",
        "x-github-hook-installation-target-type": "organization",
    }
    output = capsys.readouterr()
    report = json.loads(output.out)
    assert report["status"] == 202
    assert report["delivery_id"] == "test-delivery-001"
    assert report["body_sha256"] == store.read_record(tmp_path / result["file"])[0]["body_sha256"]
    assert report["duration_ms"] >= 0


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_is_not_followed(record_factory, receiver, capsys, status):
    destination = receiver()
    redirector = receiver(status=status, location=destination.url)
    path = record_factory()
    assert cli.main(["replay", str(path), "--url", redirector.url, "--format", "json"]) == 1
    assert len(redirector.requests) == 1
    assert destination.requests == []
    output = capsys.readouterr()
    assert f"HTTP {status}" in output.err
    assert json.loads(output.out)["redirect_host"] == "127.0.0.1"


@pytest.mark.parametrize(("command", "flag", "value"), [
    ("record", "--port", "-1"), ("record", "--port", "65536"), ("record", "--port", "1.5"),
    ("record", "--max-body-bytes", "0"), ("record", "--max-body-bytes", "-1"),
    ("record", "--max-body-bytes", "1.5"), ("record", "--max-body-bytes", "true"),
    *[("record", "--read-timeout", value) for value in ("0", "-1", "nan", "inf", "-inf", "1e999")],
    *[("replay", "--timeout", value) for value in ("0", "-1", "nan", "inf", "-inf", "1e999")],
])
def test_invalid_numeric_arguments_have_no_side_effects(tmp_path, monkeypatch, capsys, command, flag, value):
    def forbidden(*args, **kwargs):
        pytest.fail("side effect before numeric validation")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(store, "write_record", forbidden)
    monkeypatch.setattr(store, "read_record", forbidden)
    if command == "record":
        argv = ["record", "--dir", str(tmp_path)]
    else:
        argv = ["replay", "missing.json", "--url", "http://127.0.0.1:1"]
    with pytest.raises(SystemExit) as exit:
        cli.main([*argv, f"{flag}={value}"])
    assert exit.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert len(output.err.splitlines()) == 1
    assert "Traceback" not in output.err
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("defect", ["digest", "base64", "filename", "header", "missing"])
def test_invalid_record_sends_nothing(record_factory, receiver, capsys, defect):
    target = receiver()
    path = record_factory()
    data = json.loads(path.read_text())
    if defect == "digest":
        data["body_sha256"] = "0" * 64
    elif defect == "base64":
        data["body_base64"] = "not base64"
    elif defect == "header":
        data["headers"]["User-Agent"] = "bad\r\ninjection"
    elif defect == "filename":
        path = path.rename(path.parent / "wrong.json")
    else:
        path.unlink()
    if defect != "missing":
        path.write_text(json.dumps(data))
    assert cli.main(["replay", str(path), "--url", target.url]) == 2
    assert target.requests == []
    output = capsys.readouterr()
    assert output.out == ""
    assert "Traceback" not in output.err


@pytest.mark.parametrize("url", ["ftp://127.0.0.1/x", "http:///x", "http://user:private@127.0.0.1/x", "http://127.0.0.1:99999/x"])
def test_invalid_url_opens_no_socket(record_factory, monkeypatch, capsys, url):
    path = record_factory()
    def forbidden(*args, **kwargs):
        pytest.fail("invalid URL opened a socket")
    monkeypatch.setattr(socket, "socket", forbidden)
    assert cli.main(["replay", str(path), "--url", url]) == 2
    assert "private" not in capsys.readouterr().err


def test_proxy_environment_is_not_used(record_factory, receiver, monkeypatch):
    target = receiver()
    # A loopback-only unused proxy would break replay if consulted.
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    assert cli.main(["replay", str(record_factory()), "--url", target.url]) == 0
    assert len(target.requests) == 1


def test_cli_help_version_and_installed_entrypoint():
    for args in (["--version"], ["--help"], ["record", "--help"], ["replay", "--help"]):
        result = subprocess.run([sys.executable, "-m", "hookreplay", *args], capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, result.stderr
        assert result.stdout
        assert result.stderr == ""
    executable = Path(sysconfig.get_path("scripts")) / "hookreplay"
    result = subprocess.run([str(executable), "--version"], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0
    assert result.stdout == f"hookreplay {__version__}\n"


def test_large_finite_timeout_is_accepted(record_factory, receiver):
    target = receiver()
    assert cli.main(["replay", str(record_factory()), "--url", target.url, "--timeout", "1e308"]) == 0
    assert len(target.requests) == 1


def test_record_cli_prints_only_port_before_accepting(tmp_path):
    process = subprocess.Popen(
        [sys.executable, "-m", "hookreplay", "record", "--dir", str(tmp_path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(timeout=5), "recorder did not print its port"
        line = process.stdout.readline()
        assert line.strip().isdecimal()
        with socket.create_connection(("127.0.0.1", int(line)), timeout=2) as connection:
            connection.sendall(request_bytes() + b"{}")
            response = HTTPResponse(connection)
            response.begin()
            assert response.status == 202
            result = json.loads(response.read())
        assert store.read_record(tmp_path / result["file"])[1] == b"{}"
    finally:
        import signal
        process.send_signal(signal.SIGINT)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            raise
    assert process.returncode == 0
    assert stdout == ""
    assert stderr == "POST 202 test-delivery-001 ping 2 null\n"
