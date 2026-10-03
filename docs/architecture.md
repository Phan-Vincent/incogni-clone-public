# Personal autonomous privacy service

## Current architecture

The original offline CLI remains available for synthetic demonstrations. The private
service adds three process boundaries:

1. `incogni serve` runs the authenticated FastAPI control plane on loopback.
2. `incogni worker` leases maintenance and notification jobs from SQLite.
3. `incogni browser-worker` exclusively leases browser-operation jobs. Every actual
   browser operation must use `FreshContextBrowser`, which launches a new browser
   context, blocks service workers and every off-allowlist HTTP/WebSocket request,
   rejects unexpected navigation, and closes the context after one task.

SQLite runs in WAL mode with application-encrypted sensitive columns. Each application
thread receives a separate connection so request transactions cannot overlap on one
connection. Job leasing uses an immediate transaction, expiring leases,
per-profile/broker concurrency exclusion, idempotency keys, exponential retry with
jitter, blocking, and dead-letter states.

## Trust boundaries

- Tailscale is the network boundary; the API still requires an Argon2id-backed
  application session, SameSite/Secure cookies, and a CSRF token for mutations.
  Sessions are registered by a hashed identifier in SQLite and revoked on logout.
  Login verification has atomic attempt reservation and bounded Argon2 concurrency.
- The loopback Uvicorn listener does not trust forwarded client-address headers. The
  API rejects bodies over 64 KiB before parsing and forbids unknown request fields.
- The profile, OAuth credentials, DROP identifier, job payloads, broker payloads,
  email metadata, and evidence are AES-256-GCM envelopes with domain-separated AAD.
- The master key is supplied through systemd credentials and never stored in the
  database.
- Raw email and evidence files have a default 30-day expiry. Status history,
  timestamps, hashes, and confirmation identifiers remain until explicit purge.
- AI coding assistants and other development tooling receive only synthetic
  fixtures; private data locations are excluded from their sandboxes.

## Lifecycle boundaries

Findings, requests, and jobs have explicit transition maps in
`incogni/state_machine.py`. A reappearance is represented by a new listing
fingerprint/finding and request; historical evidence is not overwritten.

Broker flow metadata is version-pinned. A version change automatically resets a flow
to paused monitor-only status. The five initial broker definitions are all paused and
monitor-only; none has a production transport enabled.

## DROP

California DROP is primary coverage. The service only links to the official consumer
workflow, records the operator's manual completion and terms acknowledgment, encrypts
an optional identifier, and schedules 45/90-day reminders. It never stores government
credentials or automates the consumer portal.

Official references:

- https://privacy.ca.gov/drop/
- https://consumer.drop.privacy.ca.gov/
- https://privacy.ca.gov/drop-for-data-brokers/technical-specifications/
