import base64
from copy import deepcopy
import errno
import hashlib
import json
from pathlib import Path

import pytest

from hookreplay import store
from conftest import HEADERS, NOW


def test_record_schema_and_exact_bytes(record_factory):
    body = b' {"z":2, "a":"\xc3\xa9"}\n'
    path = record_factory(body)
    data, actual = store.read_record(path)
    assert actual == body
    assert data == {
        "schema_version": 1, "delivery_id": "test-delivery-001", "event": "ping",
        "recorded_at": "2026-01-02T03:04:05.123456Z", "verified": None,
        "headers": HEADERS, "body_base64": base64.b64encode(body).decode(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    assert path.name == "20260102T030405123456Z-000000000002.json"
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("field", sorted(store.REQUIRED))
def test_required_fields(record_factory, field):
    path = record_factory()
    data = json.loads(path.read_text())
    del data[field]
    with pytest.raises(store.RecordError, match=field):
        store.validate_record(data, path.name)


@pytest.mark.parametrize(("field", "value"), [
    ("schema_version", True), ("schema_version", 1.0), ("schema_version", 2),
    ("verified", 0), ("verified", 1), ("verified", "true"),
    ("body_base64", " YQ=="), ("body_base64", "YQ="), ("body_base64", "YR=="),
    ("body_base64", "é"), ("body_base64", 1), ("body_base64", "YQ==="),
    ("body_sha256", "f" * 64), ("body_sha256", "A" * 64),
    ("recorded_at", "2026-02-30T03:04:05.123456Z"),
    ("recorded_at", "2026-01-02T03:04:05Z"),
    ("recorded_at", "2026-01-02T03:04:05.123456+00:00"),
    ("delivery_id", "../../outside"), ("delivery_id", "a" * 129),
    ("event", "Pull_Request"), ("event", "a" * 65),
    ("headers", []),
])
def test_invalid_schema_types_and_formats(record_factory, field, value):
    path = record_factory()
    data = json.loads(path.read_text())
    data[field] = value
    with pytest.raises(store.RecordError, match=field):
        store.validate_record(data, path.name)


@pytest.mark.parametrize("header", ["Content-Type", "X-GitHub-Event", "X-GitHub-Delivery"])
def test_required_headers(record_factory, header):
    path = record_factory()
    data = json.loads(path.read_text())
    del data["headers"][header]
    with pytest.raises(store.RecordError, match="required header"):
        store.validate_record(data, path.name)


@pytest.mark.parametrize(("name", "value"), [
    ("X-Hub-Signature-256", "sha256=abc"), ("Authorization", "private"),
    ("content-type", "application/json"), ("User-Agent", "a\r\nb"),
    ("User-Agent", "é"), ("User-Agent", ""), ("User-Agent", "a" * 257),
    ("X-GitHub-Event", "issues"), ("X-GitHub-Delivery", "other"),
    ("Content-Type", "text/plain"),
])
def test_invalid_headers(record_factory, name, value):
    path = record_factory()
    data = json.loads(path.read_text())
    data["headers"][name] = value
    with pytest.raises(store.RecordError, match="headers"):
        store.validate_record(data, path.name)


@pytest.mark.parametrize("name", [
    "ping.json", "../20260102T030405123456Z-000000000002.json",
    "20260102T030406123456Z-000000000002.json",
])
def test_filename_and_timestamp_agreement(record_factory, name):
    path = record_factory()
    data = json.loads(path.read_text())
    with pytest.raises(store.RecordError, match="file"):
        store.validate_record(data, name)


def test_non_strict_unknown_fields_and_opaque_body(record_factory):
    path = record_factory(b"not JSON\x00\xff")
    data = json.loads(path.read_text())
    data["future"] = {"anything": True}
    assert store.validate_record(data, path.name) == b"not JSON\x00\xff"


def derived(data, name):
    result = deepcopy(data)
    result["derived_from"] = {"file": name, "body_sha256": data["body_sha256"]}
    result["mutations"] = [{"path": "action", "raw": "action=closed", "value": "closed"}]
    return result


def test_future_derived_shape_does_not_require_source_file(record_factory):
    path = record_factory()
    data, body = store.read_record(path)
    data = derived(data, "20250102T030405123456Z-000000000001.json")
    assert store.validate_record(data, path.name) == body


@pytest.mark.parametrize("defect", [
    "verified", "missing_source", "missing_mutations", "empty_mutations", "bad_source",
    "bad_digest", "bad_path", "bad_raw", "nonfinite",
])
def test_invalid_derived_shape(record_factory, defect):
    path = record_factory()
    data, _ = store.read_record(path)
    data = derived(data, path.name)
    if defect == "verified":
        data["verified"] = True
    elif defect == "missing_source":
        del data["derived_from"]
    elif defect == "missing_mutations":
        del data["mutations"]
    elif defect == "empty_mutations":
        data["mutations"] = []
    elif defect == "bad_source":
        data["derived_from"]["file"] = "../../outside.json"
    elif defect == "bad_digest":
        data["derived_from"]["body_sha256"] = "A" * 64
    elif defect == "bad_path":
        data["mutations"][0]["path"] = "a..b"
    elif defect == "bad_raw":
        data["mutations"][0]["raw"] = "different=closed"
    else:
        data["mutations"][0]["value"] = float("inf")
    with pytest.raises(store.RecordError):
        store.validate_record(data, path.name)


def test_no_json_visible_until_complete_publication(tmp_path, monkeypatch):
    real_link = store.os.link
    real_fsync = store.os.fsync
    stages = []

    def fsync(fd):
        assert list(tmp_path.glob("*.json")) == []
        stages.append("fsync")
        return real_fsync(fd)

    def link(source, final):
        assert stages == ["fsync"]
        assert Path(source).suffix == ".tmp"
        assert list(tmp_path.glob("*.json")) == []
        data = json.loads(Path(source).read_bytes())
        assert store.validate_record(data, Path(final).name) == b"payload"
        real_link(source, final)
        stages.append("link")

    monkeypatch.setattr(store.os, "fsync", fsync)
    monkeypatch.setattr(store.os, "link", link)
    path = store.write_record(tmp_path, b"payload", HEADERS)
    assert stages == ["fsync", "link"]
    assert list(tmp_path.iterdir()) == [path]


def test_collision_retries_only_id_preserving_first_record(tmp_path):
    ids = iter(["0" * 12, "1" * 12, "2" * 12, "1" * 12, "3" * 12])
    clocks = []

    def clock():
        clocks.append(1)
        return NOW

    first = store.write_record(tmp_path, b"first", HEADERS, clock=clock, new_id=lambda: next(ids))
    original = first.read_bytes()
    second = store.write_record(tmp_path, b"second", HEADERS, clock=clock, new_id=lambda: next(ids))
    assert first.read_bytes() == original
    assert first.name == "20260102T030405123456Z-111111111111.json"
    assert second.name == "20260102T030405123456Z-333333333333.json"
    assert store.read_record(second)[1] == b"second"
    assert len(clocks) == 2
    assert sorted(tmp_path.iterdir()) == sorted([first, second])


def test_final_collision_exhaustion_cleans_tmp(tmp_path):
    first = store.write_record(tmp_path, b"first", HEADERS, clock=lambda: NOW, new_id=lambda: "a" * 12)
    original = first.read_bytes()
    calls = []

    def fixed_id():
        calls.append(1)
        return "a" * 12

    with pytest.raises(store.StorageError, match="storage_collision"):
        store.write_record(tmp_path, b"second", HEADERS, clock=lambda: NOW, new_id=fixed_id)
    assert len(calls) == 33  # one tmp plus 32 final-name attempts
    assert first.read_bytes() == original
    assert list(tmp_path.iterdir()) == [first]


def test_temporary_collision_exhaustion_preserves_foreign_tmp(tmp_path):
    temporary = tmp_path / f".{('a' * 12)}.tmp"
    temporary.write_bytes(b"not ours")
    calls = []

    def fixed_id():
        calls.append(1)
        return "a" * 12

    with pytest.raises(store.StorageError, match="storage_collision"):
        store.write_record(tmp_path, b"new", HEADERS, new_id=fixed_id)
    assert len(calls) == 32
    assert temporary.read_bytes() == b"not ours"
    assert list(tmp_path.iterdir()) == [temporary]


def test_temporary_collision_retries_without_touching_foreign_tmp(tmp_path):
    temporary = tmp_path / f".{('a' * 12)}.tmp"
    temporary.write_bytes(b"not ours")
    ids = iter(["a" * 12, "b" * 12, "c" * 12])
    path = store.write_record(tmp_path, b"new", HEADERS, new_id=lambda: next(ids))
    assert temporary.read_bytes() == b"not ours"
    assert store.read_record(path)[1] == b"new"
    assert set(tmp_path.iterdir()) == {temporary, path}


@pytest.mark.parametrize("operation", ["open", "fsync", "link"])
def test_storage_errors_are_sanitized_and_cleaned(tmp_path, monkeypatch, operation):
    def fail(*args, **kwargs):
        raise OSError(errno.EPERM, "sensitive path /private/tmp")

    monkeypatch.setattr(store.os, operation, fail)
    with pytest.raises(store.StorageError) as error:
        store.write_record(tmp_path, b"payload", HEADERS)
    assert error.value.reason == "storage_error"
    assert "/private" not in str(error.value)
    assert list(tmp_path.iterdir()) == []


def test_unlink_failure_after_link_keeps_the_published_record(tmp_path, monkeypatch):
    def refuse(self, missing_ok=False):
        raise OSError(errno.EPERM, "sensitive path /private/tmp")

    monkeypatch.setattr(store.Path, "unlink", refuse)
    path = store.write_record(tmp_path, b"payload", HEADERS, clock=lambda: NOW, new_id=lambda: "b" * 12)
    assert path.name == "20260102T030405123456Z-bbbbbbbbbbbb.json"
    assert store.read_record(path)[1] == b"payload"
    # The leftover temporary file is ignored by readers and left for a human.
    assert sorted(entry.name for entry in tmp_path.iterdir()) == [f".{'b' * 12}.tmp", path.name]


def test_unlink_failure_does_not_mask_the_pending_reason(tmp_path, monkeypatch):
    first = store.write_record(tmp_path, b"first", HEADERS, clock=lambda: NOW, new_id=lambda: "a" * 12)

    def refuse(self, missing_ok=False):
        raise OSError(errno.EPERM, "sensitive path /private/tmp")

    monkeypatch.setattr(store.Path, "unlink", refuse)
    with pytest.raises(store.StorageError) as error:
        store.write_record(tmp_path, b"second", HEADERS, clock=lambda: NOW, new_id=lambda: "a" * 12)
    assert error.value.reason == "storage_collision"
    assert "/private" not in str(error.value)
    assert store.read_record(first)[1] == b"first"
