"""Bounded local HTTP recording. This is not a production ingress."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
from pathlib import Path
import re
import sys
from threading import TIMEOUT_MAX
import time

from . import store


def is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Recorder(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, directory: Path, max_body_bytes: int, read_timeout: float, ready=None):
        self.directory = directory
        self.max_body_bytes = max_body_bytes
        self.read_timeout = read_timeout
        self.ready = ready
        super().__init__(address, Handler)

    def server_activate(self):
        super().server_activate()
        if self.ready is not None:
            self.ready.set()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(min(self.read_timeout, TIMEOUT_MAX))
        return connection, address

    def handle_error(self, request, client_address):
        # A reset or broken pipe during the header phase is the client's
        # business: no traceback on stderr. Anything else is a defect and
        # keeps the default report.
        if not isinstance(sys.exc_info()[1], OSError):
            super().handle_error(request, client_address)


class Handler(BaseHTTPRequestHandler):
    def __getattr__(self, name):
        # BaseHTTPRequestHandler dispatches by method name. All methods reach
        # the same ordered checks instead of its default 501 response.
        if name.startswith("do_"):
            return self._record
        raise AttributeError(name)

    def log_message(self, format, *args):
        pass

    def version_string(self):
        # No interpreter or library version in the Server header.
        return "hookreplay"

    def send_error(self, code, message=None, explain=None):
        # The stdlib parser calls this for a malformed request line, an
        # unsupported HTTP version or oversized headers. Keep the JSON
        # contract and the one-line log; never echo the request back.
        self._respond(int(code), {"reason": "bad_request"})

    def _log(self, status: int, *, complete=False):
        command = getattr(self, "command", None) or ""
        headers = getattr(self, "headers", None)
        delivery = headers.get("X-GitHub-Delivery", "") if headers is not None else ""
        event = headers.get("X-GitHub-Event", "") if headers is not None else ""
        method = command if re.fullmatch(r"[A-Z]{1,16}", command) else "-"
        delivery = delivery if store.DELIVERY_RE.fullmatch(delivery) else "-"
        event = event if store.EVENT_RE.fullmatch(event) else "-"
        size = str(self.body_size) if complete else "-"
        verified = "null" if status == 202 else "-"
        # One write call per line: handler threads never interleave fields.
        sys.stderr.write(f"{method} {status} {delivery} {event} {size} {verified}\n")
        sys.stderr.flush()

    def _respond(self, status: int, payload: dict, *, complete=False):
        self._log(status, complete=complete)
        encoded = json.dumps(payload, separators=(",", ":")).encode("ascii")
        self.close_connection = True
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(encoded)
        except OSError:
            # A disconnect after a full request must not roll back publication.
            pass

    def _reject(self, status: int, reason: str, *, complete=False):
        self._respond(status, {"reason": reason}, complete=complete)

    def _record(self):
        if self.command != "POST":
            return self._reject(405, "method_not_allowed")
        content_types = self.headers.get_all("Content-Type", [])
        if len(content_types) != 1 or not store.is_json_content_type(content_types[0]):
            return self._reject(415, "unsupported_media_type")
        encodings = ",".join(self.headers.get_all("Transfer-Encoding", []))
        lengths = self.headers.get_all("Content-Length", [])
        if "chunked" in (value.strip().lower() for value in encodings.split(",")) or not lengths:
            return self._reject(411, "length_required")
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0], re.ASCII):
            return self._reject(400, "bad_content_length")
        # Compare decimal strings before int(): very large valid lengths must
        # still be rejected as too large, not hit Python's integer digit limit.
        digits = lengths[0].lstrip("0") or "0"
        limit = str(self.server.max_body_bytes)
        if len(digits) > len(limit) or (len(digits) == len(limit) and digits > limit):
            return self._reject(413, "body_too_large")
        self.body_size = int(digits)
        for header, pattern, reason in (
            ("X-GitHub-Delivery", store.DELIVERY_RE, "bad_delivery_id"),
            ("X-GitHub-Event", store.EVENT_RE, "bad_event"),
        ):
            values = self.headers.get_all(header, [])
            if len(values) != 1 or not pattern.fullmatch(values[0]):
                return self._reject(400, reason)
        headers = {}
        for name in store.HEADER_NAMES:
            values = self.headers.get_all(name, [])
            if len(values) > 1 or (values and not store.valid_header(values[0])):
                return self._reject(400, "bad_header")
            if values:
                headers[name] = values[0]
        body = bytearray()
        deadline = time.monotonic() + self.server.read_timeout
        try:
            while len(body) < self.body_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return self._reject(408, "read_timeout")
                self.connection.settimeout(min(remaining, TIMEOUT_MAX))
                chunk = self.rfile.read1(min(65536, self.body_size - len(body)))
                if not chunk:
                    return self._reject(400, "truncated_body")
                body.extend(chunk)
            if time.monotonic() > deadline:
                return self._reject(408, "read_timeout")
        except TimeoutError:
            return self._reject(408, "read_timeout")
        except OSError:
            return  # Client disconnected before a complete body; no file.
        try:
            record = store.write_record(self.server.directory, bytes(body), headers)
        except store.StorageError as exc:
            payload = {"reason": exc.reason}
            if exc.error_class:
                payload["error_class"] = exc.error_class
            return self._respond(500, payload, complete=True)
        except (OSError, store.RecordError) as exc:
            # The exception class only: never a path, errno text or payload.
            return self._respond(500, {"reason": "storage_error", "error_class": type(exc).__name__}, complete=True)
        self._respond(202, {"file": record.name, "verified": None}, complete=True)


def make_server(path: str | Path, host="127.0.0.1", port=0, max_body_bytes=2097152, read_timeout=10, ready=None):
    target = store.directory(path)
    if not is_loopback(host):
        print("warning: http.server is not intended for public ingress", file=sys.stderr, flush=True)
    # HTTPServer defaults to IPv4; support explicit IPv6 loopback as well.
    if ":" in host:
        import socket

        class IPv6Recorder(Recorder):
            address_family = socket.AF_INET6

        server_class = IPv6Recorder
    else:
        server_class = Recorder
    return server_class((host, port), target, max_body_bytes, read_timeout, ready)


def run(**options) -> int:
    server = make_server(**options)
    try:
        print(server.server_port, flush=True)
        server.serve_forever(poll_interval=0.05)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
