# hookreplay

Record GitHub webhook deliveries byte-for-byte and replay them to a local
HTTP(S) endpoint. MIT licensed; Python 3.11+; no runtime dependencies.

This seed implements **record** and **unsigned replay**. `http.server` is not
intended for production or public ingress. The recorder defaults to loopback.
Storage requires POSIX and a filesystem supporting hard links in the recordings
directory (for example ext4, xfs, tmpfs or overlayfs). Windows is not tested.
Run one recorder process per directory.

## Install and test

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
hookreplay --version
```

Tests use synthetic payloads, temporary directories and loopback servers on
OS-assigned ports. They make no external HTTP requests.

## Commands

### record

Create a private recordings directory, then start the recorder:

```sh
mkdir -m 700 recordings
hookreplay record --dir recordings
```

The directory must already exist, be a directory, and not be a symlink.
Options: `--host` (default `127.0.0.1`), `--port` (default `0`, OS-assigned),
`--max-body-bytes` (default `2097152`), `--read-timeout` (default `10` seconds).
The recorder prints **one decimal port number** followed by a newline to stdout
before accepting the first request. Stop it with Ctrl-C.

Using the printed port in another terminal:

```sh
curl -i "http://127.0.0.1:<port>/webhook" \
  -H 'Content-Type: application/json' \
  -H 'X-GitHub-Event: ping' \
  -H 'X-GitHub-Delivery: example-delivery-001' \
  --data-binary @tests/fixtures/ping.json
```

A successful POST returns HTTP 202 and a JSON object containing `file` (the
generated basename) and `verified` (`null` in this seed). Request bodies are
not parsed as JSON. Only the allowlisted headers below are retained.

One log line per handled request is printed to stderr:

```text
<method> <status> <delivery_id> <event> <bytes> <verified>
POST 202 example-delivery-001 ping 42 null
```

Fields are separated by single spaces. An invalid method, delivery ID or event
is replaced with `-`. `bytes` is Content-Length after complete body reception,
otherwise `-`; `verified` is `null` on acceptance and `-` on rejection. Logs do
not contain request bodies or signature headers.

### replay

```sh
hookreplay replay recordings/<generated-name>.json \
  --url http://127.0.0.1:8080/webhook
```

Options: `--timeout` (default `10` seconds), `--format text|json` (default
`text`). The URL must use HTTP or HTTPS and must not contain userinfo. Redirects
are not followed. Replay sends the exact original bytes, preserves the delivery
ID, replaces User-Agent with `hookreplay/0.1.0`, and sends **no signature**.
A receiver requiring signed requests will reject this unsigned seed replay.
Proxy environment variables are not used.

The report on stdout contains the delivery ID, event, target URL, body SHA-256,
HTTP status or error class, and elapsed milliseconds. For redirects it also
includes the Location hostname. Diagnostics go to stderr. All records pass the
shared schema and digest validator before any request is sent.

`hookreplay --help`, `hookreplay record --help`, `hookreplay replay --help` and
`python -m hookreplay` are also available.

## Storage format v1

Each record is a UTF-8 JSON object in a flat directory. Filenames have the form
`YYYYMMDDTHHMMSSffffffZ-<12 lowercase hex>.json`; the timestamp equals the
record's `recorded_at`. Names are not derived from webhook metadata. Temporary
files end in `.tmp`, not `.json`.

| Field | Type |
|---|---|
| `schema_version` | Integer `1`, not a boolean |
| `delivery_id` | 1–128 characters: ASCII letters, digits, hyphens |
| `event` | 1–64 lowercase ASCII letters or underscores |
| `recorded_at` | UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`, calendar-valid |
| `verified` | Boolean or null; this seed writes null |
| `headers` | Object containing the canonical allowlisted headers below |
| `body_base64` | Strict standard base64 of the original bytes |
| `body_sha256` | 64 lowercase hex characters; SHA-256 of decoded bytes |
| `derived_from` | Optional object with `file` basename and `body_sha256` |
| `mutations` | Optional nonempty array of `{path, raw, value}` objects |

`derived_from` and `mutations` must appear together; a derived record requires
`verified: null`. The source file need not be present. These fields reserve the
shape for future derivation; the seed has no derive command. Mutation paths use
nonempty dot-separated segments, `raw` is the original `path=value` argument,
and `value` must be a finite JSON value.

Canonical header allowlist:

- `Content-Type` (**required**): `application/json`, optionally `charset=utf-8`;
  comparison is case-insensitive with whitespace allowed around `;`.
- `X-GitHub-Event` (**required**, equals `event`).
- `X-GitHub-Delivery` (**required**, equals `delivery_id`).
- `X-GitHub-Hook-ID`.
- `X-GitHub-Hook-Installation-Target-ID`.
- `X-GitHub-Hook-Installation-Target-Type`.
- `User-Agent`.

Values must contain 1–256 printable ASCII characters without CR/LF. Unknown
top-level fields are ignored by the non-strict validator; unknown header names
are rejected. A body need not be valid JSON. Malformed records, mismatched
digests, invalid basenames and filename/timestamp disagreement are rejected.

## What is and is not protected

**Bodies are stored without editing. The tool does not guarantee removal of
sensitive data from bodies or metadata (`repository`, `sender`, issue/PR text).**
Keep real recordings in private directories. Review bodies and metadata by hand
before sharing. The committed fixtures are synthetic, documented examples.

Signature headers (`X-Hub-Signature-256`, `X-Hub-Signature`) and headers outside
the allowlist are not stored. This seed does not accept or verify a signing
secret. SHA-256 detects body changes; it does not prove who created the record.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success; replay received HTTP 2xx |
| `1` | Delivery failure: non-2xx, redirect, timeout or connection failure |
| `2` | Invalid input or contract: arguments, directory, URL, record or digest |

## Roadmap

Planned, **not implemented**: signing verification during recording, replay
re-signing with a secret supplied by environment-variable name, new delivery
IDs, `list`, offline `derive`, strict `validate`, `replay-dir`, fixture export
and import. Further documentation and boundary/concurrency tests will expand
the current recorder and storage contract.
