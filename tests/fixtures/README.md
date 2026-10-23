# Payload bodies

These files are raw webhook **bodies**, not schema-v1 records. Tests create
records using the recorder or the store factory with injected time and IDs.

`ping.json` and `pull_request.json` are minimal, synthetic examples using the
documented GitHub event field shapes. Names and IDs are invented; these are not
captures from a real repository or complete GitHub API response objects.

References:
- https://docs.github.com/en/webhooks/webhook-events-and-payloads#ping
- https://docs.github.com/en/webhooks/webhook-events-and-payloads#pull_request

`weird-bytes.json` is synthetic and deliberately includes significant spaces,
non-ASCII UTF-8, key ordering, and a trailing newline. Keep its bytes unchanged.
