"""Schema v1 and POSIX no-clobber record publication."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Callable
from uuid import uuid4

NAME_RE = re.compile(r"[0-9]{8}T[0-9]{12}Z-[0-9a-f]{12}\.json", re.ASCII)
DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
DELIVERY_RE = re.compile(r"[A-Za-z0-9-]{1,128}", re.ASCII)
EVENT_RE = re.compile(r"[a-z_]{1,64}", re.ASCII)
HEADER_NAMES = (
    "X-GitHub-Event", "X-GitHub-Delivery", "X-GitHub-Hook-ID",
    "X-GitHub-Hook-Installation-Target-ID",
    "X-GitHub-Hook-Installation-Target-Type", "Content-Type", "User-Agent",
)
REQUIRED = {
    "schema_version", "delivery_id", "event", "recorded_at", "verified",
    "headers", "body_base64", "body_sha256",
}
MAX_ATTEMPTS = 32


class RecordError(ValueError):
    """A stable field-level diagnostic that never includes payload data."""


class StorageError(OSError):
    def __init__(self, reason: str, error_class: str = ""):
        self.reason = reason
        self.error_class = error_class
        super().__init__(reason + (f" ({error_class})" if error_class else ""))


def clock() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid4().hex[:12]


def is_json_content_type(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"application/json(?:\s*;\s*charset=utf-8)?", value.strip(), re.IGNORECASE
    ) is not None


def valid_header(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[\x20-\x7e]{1,256}", value) is not None


def directory(path: str | Path) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise RecordError("dir: expected an existing non-symlink directory")
    return path


def timestamp_prefix(timestamp: str) -> str:
    return timestamp.translate(str.maketrans("", "", "-:."))


def _fail(field: str, reason: str) -> None:
    raise RecordError(f"{field}: {reason}")


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def validate_record(record: object, filename: str) -> bytes:
    """Validate a record non-strictly; return its verified original body bytes.

    Unknown top-level fields are ignored. Body JSON parsing is deliberately not
    performed. All consumers use this function, including future commands.
    """
    if not isinstance(record, dict):
        _fail("record", "expected an object")
    for field in sorted(REQUIRED):
        if field not in record:
            _fail(field, "required field missing")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1:
        _fail("schema_version", "expected integer 1")
    for field, pattern in (("delivery_id", DELIVERY_RE), ("event", EVENT_RE)):
        if not isinstance(record[field], str) or not pattern.fullmatch(record[field]):
            _fail(field, "invalid format")
    timestamp = record["recorded_at"]
    if not isinstance(timestamp, str) or not DATE_RE.fullmatch(timestamp):
        _fail("recorded_at", "expected UTC timestamp with six fractional digits")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _fail("recorded_at", "invalid calendar date")
    if not NAME_RE.fullmatch(filename):
        _fail("file", "invalid record basename")
    if filename.split("-", 1)[0] != timestamp_prefix(timestamp):
        _fail("file", "timestamp differs from recorded_at")
    if record["verified"] is not None and type(record["verified"]) is not bool:
        _fail("verified", "expected boolean or null")
    headers = record["headers"]
    if not isinstance(headers, dict):
        _fail("headers", "expected an object")
    if not {"Content-Type", "X-GitHub-Event", "X-GitHub-Delivery"} <= headers.keys():
        _fail("headers", "required header missing")
    for name, value in headers.items():
        if name not in HEADER_NAMES:
            _fail("headers", "header name outside allowlist")
        if not valid_header(value):
            _fail("headers", "invalid header value")
    if not is_json_content_type(headers["Content-Type"]):
        _fail("headers.Content-Type", "expected application/json with optional charset=utf-8")
    for header, field in (("X-GitHub-Event", "event"), ("X-GitHub-Delivery", "delivery_id")):
        if headers[header] != record[field]:
            _fail("headers", f"inconsistent {field}")
    encoded = record["body_base64"]
    if not isinstance(encoded, str):
        _fail("body_base64", "expected an ASCII base64 string")
    try:
        body = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        _fail("body_base64", "invalid base64")
    # Also reject noncanonical padding and nonzero unused bits.
    if base64.b64encode(body).decode("ascii") != encoded:
        _fail("body_base64", "invalid base64 padding")
    digest = record["body_sha256"]
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        _fail("body_sha256", "expected lowercase SHA-256 hex")
    if hashlib.sha256(body).hexdigest() != digest:
        _fail("body_sha256", "digest mismatch")
    derived = "derived_from" in record
    if derived != ("mutations" in record):
        _fail("derived_from", "must appear together with mutations")
    if derived:
        if record["verified"] is not None:
            _fail("verified", "derived records require null")
        source = record["derived_from"]
        if not isinstance(source, dict) or set(source) != {"file", "body_sha256"}:
            _fail("derived_from", "expected file and body_sha256")
        if not isinstance(source["file"], str) or not NAME_RE.fullmatch(source["file"]):
            _fail("derived_from.file", "invalid record basename")
        if not isinstance(source["body_sha256"], str) or not DIGEST_RE.fullmatch(source["body_sha256"]):
            _fail("derived_from.body_sha256", "invalid digest")
        mutations = record["mutations"]
        if not isinstance(mutations, list) or not mutations:
            _fail("mutations", "expected a nonempty array")
        for mutation in mutations:
            if not isinstance(mutation, dict) or set(mutation) != {"path", "raw", "value"}:
                _fail("mutations", "expected path, raw and value")
            path, raw = mutation["path"], mutation["raw"]
            if not isinstance(path, str) or any(not part for part in path.split(".")):
                _fail("mutations.path", "expected nonempty dotted segments")
            if not isinstance(raw, str) or "=" not in raw or raw.split("=", 1)[0] != path:
                _fail("mutations.raw", "expected original path=value argument")
            try:
                json.dumps(mutation["value"], ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (ValueError, TypeError, UnicodeError, RecursionError):
                _fail("mutations.value", "expected finite JSON value")
    return body


def read_record(path: str | Path) -> tuple[dict, bytes]:
    path = Path(path)
    try:
        record = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_constant)
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise RecordError("record: cannot read valid UTF-8 JSON") from None
    return record, validate_record(record, path.name)


def _id(generator: Callable[[], str]) -> str:
    value = generator()
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{12}", value):
        raise StorageError("storage_error", "InvalidGeneratedID")
    return value


def _publish(directory: Path, payload: bytes, prefix: str, generator: Callable[[], str]) -> Path:
    temporary = None
    try:
        for _ in range(MAX_ATTEMPTS):
            candidate = directory / f".{_id(generator)}.tmp"
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            temporary = candidate
            break
        else:
            raise StorageError("storage_collision")
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        for _ in range(MAX_ATTEMPTS):
            final = directory / f"{prefix}-{_id(generator)}.json"
            try:
                os.link(temporary, final)
            except FileExistsError:
                continue
            return final
        raise StorageError("storage_collision")
    except StorageError:
        raise
    except OSError as exc:
        raise StorageError("storage_error", type(exc).__name__) from None
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # A leftover temporary file never outranks the outcome: a
                # published record stays published, and a pending error keeps
                # its own reason. Readers ignore .tmp files.
                pass


def write_record(
    path: str | Path, body: bytes, headers: dict[str, str], *,
    clock: Callable[[], datetime] | None = None,
    new_id: Callable[[], str] | None = None,
) -> Path:
    target = directory(path)
    now = (clock or globals()["clock"])().astimezone(timezone.utc)
    timestamp = now.isoformat(timespec="microseconds").replace("+00:00", "Z")
    prefix = timestamp_prefix(timestamp)
    record = {
        "schema_version": 1,
        "delivery_id": headers.get("X-GitHub-Delivery"),
        "event": headers.get("X-GitHub-Event"),
        "recorded_at": timestamp,
        "verified": None,
        "headers": dict(headers),
        "body_base64": base64.b64encode(body).decode("ascii"),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    validate_record(record, f"{prefix}-{'0' * 12}.json")
    payload = json.dumps(record, ensure_ascii=True, allow_nan=False, indent=2).encode("utf-8") + b"\n"
    return _publish(target, payload, prefix, new_id or globals()["new_id"])
