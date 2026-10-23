from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

import pytest

from hookreplay import record, store

FIXTURES = Path(__file__).parent / "fixtures"
HEADERS = {
    "Content-Type": "application/json",
    "X-GitHub-Event": "ping",
    "X-GitHub-Delivery": "test-delivery-001",
}
NOW = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)


@contextmanager
def running(server, ready):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        assert ready.wait(2), "server did not activate"
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive(), "server thread did not stop"


class Receiver(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, ready, status, location, secret):
        self.ready = ready
        self.status = status
        self.location = location
        self.secret = secret
        self.requests = []
        self.lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), ReceiverHandler)
        self.url = f"http://127.0.0.1:{self.server_port}/webhook"

    def server_activate(self):
        super().server_activate()
        self.ready.set()


class ReceiverHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.connection.settimeout(2)
        body = self.rfile.read(int(self.headers["Content-Length"]))
        # Independent of all product code: future signing tests use this too.
        expected = b"sha256=" + hmac.new(self.server.secret, body, hashlib.sha256).hexdigest().encode("ascii")
        received = self.headers.get("X-Hub-Signature-256", "").encode("ascii", errors="replace")
        with self.server.lock:
            self.server.requests.append({
                "body": body, "headers": dict(self.headers), "path": self.path,
                "valid_signature": hmac.compare_digest(expected, received),
            })
        self.send_response(self.server.status)
        if self.server.location:
            self.send_header("Location", self.server.location)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture
def receiver():
    with ExitStack() as stack:
        def create(status=202, location=None, secret=b"synthetic-receiver-secret"):
            ready = threading.Event()
            server = Receiver(ready, status, location, secret)
            return stack.enter_context(running(server, ready))
        yield create


@pytest.fixture
def recorder(tmp_path):
    with ExitStack() as stack:
        def create(**options):
            ready = threading.Event()
            target = options.pop("path", tmp_path)
            server = record.make_server(target, ready=ready, **options)
            return stack.enter_context(running(server, ready))
        yield create


@pytest.fixture
def record_factory(tmp_path):
    counter = 0

    def create(body=None, headers=None, path=None):
        nonlocal counter
        def deterministic_id():
            nonlocal counter
            counter += 1
            return f"{counter:012x}"
        if body is None:
            body = (FIXTURES / "ping.json").read_bytes()
        return store.write_record(
            path or tmp_path, body, headers or HEADERS,
            clock=lambda: NOW, new_id=deterministic_id,
        )
    return create
