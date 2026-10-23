"""Explicit, proxy-independent, non-redirecting HTTP transport."""

from __future__ import annotations

import hashlib
import http.client
import json
import sys
from threading import TIMEOUT_MAX
import time
from urllib.parse import urlsplit

from . import __version__, store


def target_url(url: str):
    if any(ord(char) <= 32 or ord(char) > 126 for char in url):
        raise store.RecordError("url: expected an ASCII HTTP(S) URL without whitespace")
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError
        if parts.username is not None or parts.password is not None or parts.fragment:
            raise ValueError
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        # Validate host encoding before any connection is attempted.
        parts.hostname.encode("ascii")
    except (ValueError, UnicodeError):
        raise store.RecordError("url: expected HTTP(S) URL without userinfo or fragment") from None
    return parts


def run(file: str, url: str, timeout=10, format="text") -> int:
    parts = target_url(url)
    record, body = store.read_record(file)
    headers = dict(record["headers"])
    headers["User-Agent"] = f"hookreplay/{__version__}"
    headers["Content-Length"] = str(len(body))
    connection_class = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    connection = connection_class(parts.hostname, parts.port, timeout=min(timeout, TIMEOUT_MAX))
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    report = {
        "delivery_id": record["delivery_id"], "event": record["event"],
        "url": url, "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    started = time.monotonic()
    exit_code = 1
    try:
        # The protocol-required Host is the only implicit header. In particular,
        # do not add Accept-Encoding or consult proxy environment variables.
        connection.putrequest("POST", path, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        report["status"] = response.status
        if 200 <= response.status < 300:
            exit_code = 0
        else:
            if 300 <= response.status < 400:
                try:
                    host = urlsplit(response.getheader("Location", "")).hostname or "-"
                    host = host if store.valid_header(host) else "-"
                except ValueError:
                    host = "-"
                report["redirect_host"] = host
            print(f"delivery failed: HTTP {response.status}", file=sys.stderr)
        response.close()
    except (OSError, http.client.HTTPException, ValueError) as exc:
        report["error"] = type(exc).__name__
        print(f"delivery failed: {type(exc).__name__}", file=sys.stderr)
    finally:
        connection.close()
    report["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
    if format == "json":
        print(json.dumps(report, separators=(",", ":")))
    else:
        print(" ".join(f"{key}={value}" for key, value in report.items()))
    return exit_code
