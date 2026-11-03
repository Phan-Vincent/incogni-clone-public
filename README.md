# data-broker-optout

[![tests](https://github.com/Phan-Vincent/data-broker-optout/actions/workflows/tests.yml/badge.svg)](https://github.com/Phan-Vincent/data-broker-optout/actions/workflows/tests.yml)

A self-hosted, single-operator personal-data removal service, modelled on commercial
services such as [Incogni](https://incogni.com/). It tracks where your personal
information appears on people-search / data-broker sites and manages the opt-out
lifecycle for each one: discovery, removal request, polling, verification, and
re-checks when listings reappear.

> **Independent project.** Not affiliated with, endorsed by, or connected to Incogni
> or Surfshark. "Incogni" is used only to describe the category of service.
> (Formerly `incogni-clone`; the Python package and service names are still `incogni`.)

> **Status: safety-first foundation, no live automation.** Every broker flow ships
> **paused and monitor-only**. No production transport to any broker is enabled,
> and the browser worker is disabled at the systemd level. All fixtures, profiles,
> and test data in this repository are synthetic.

## Highlights

- **Authenticated control plane:** FastAPI app bound to loopback, with Argon2id
  login, revocable server-side sessions, SameSite/Secure cookies, CSRF on every
  mutation, a 64 KiB body limit, and strict request schemas.
- **Encryption at rest:** sensitive columns (profile, OAuth tokens, job and broker
  payloads, evidence) are stored as AES-256-GCM envelopes with domain-separated AAD.
  The master key arrives through systemd credentials and never touches the database.
- **Durable job system:** SQLite (WAL) job queue with leases, idempotency keys,
  per-profile/broker concurrency exclusion, exponential retry with jitter, and
  dead-lettering.
- **Explicit state machines** for findings, removal requests, and jobs, so a
  reappearing listing becomes a new finding instead of overwriting history.
- **Broker activation gates:** each broker moves independently from *monitor-only*
  to *approval-required* to *automatic*. Any CAPTCHA, identity-document demand,
  terms change, unexpected redirect, fingerprint drift, or rate limit blocks the job
  and downgrades the flow for human review.
- **Operator-performed flows:** brokers that should not be automated (for example
  Spokeo) produce an operator checklist after approval. You perform the opt-out in
  your own browser and record each step.
- **Isolated browser boundary:** every browser operation runs in a fresh context that
  blocks service workers and off-allowlist HTTP/WebSocket traffic, and is torn down
  after a single task.
- **California DROP support:** links to the official Delete Request and Opt-out
  Platform, records manual completion, and schedules 45/90-day follow-ups. It never
  automates the government portal or stores its credentials.
- **Hardened deployment:** sandboxed systemd units, a dry-run deployment rehearsal,
  a 14-day synthetic production soak, health probes, encrypted backups, and a
  journal audit that checks logs for leaked PII.

## Quick start (offline demo)

The legacy CLI runs entirely against **simulated** brokers, so you can try the
lifecycle without contacting anything.

```bash
pip install -e .

incogni brokers                     # list the broker catalog
incogni scan                        # scan simulated brokers for the example profile
incogni optout                      # submit (simulated) removal requests
incogni status                      # per-broker scan + opt-out status
incogni confirm mylife_like --confirmation-id CASE-123   # record an email confirmation
incogni due --days 30               # brokers due for a periodic re-scan
```

The default profile is [`examples/profile.json`](examples/profile.json), a synthetic
"Jane Doe" with a reserved `555-01xx` phone number. To use your own:

```bash
incogni --profile my-profile.json --db ./tracker.db scan
```

Keep real profiles and databases out of version control. The `.gitignore` already
excludes `*.db`, `.env*`, `private/`, `evidence/`, OAuth client secrets, and saved
browser sessions.

## Running the service

```bash
pip install -e '.[service]'   # adds Gmail and Playwright integrations
incogni serve --host 127.0.0.1 --port 8765
incogni worker
```

For a real deployment, read these first:

| Doc | What it covers |
| --- | --- |
| [Architecture](docs/architecture.md) | Process boundaries, trust boundaries, lifecycle model, DROP |
| [Operations](docs/operations.md) | Day-to-day commands, approvals, backups, emergency stop |
| [Adapter activation](docs/adapter-activation.md) | The gates a broker must pass before any automation |
| [Adapter research](docs/adapter-research.md) | Per-broker opt-out notes and why some stay manual |
| [Deployment rehearsal](docs/deployment-rehearsal.md) | Synthetic dry run of a host install, no privileged changes |
| [Production soak](docs/production-soak.md) | 14-day monitor-mode observation before any activation |
| [systemd deployment](deploy/systemd/README.md) | Hardened unit files and install steps |

The dashboard is meant to be reached only over a private network such as Tailscale
Serve, never a LAN or public address. Application login stays required even
then.

## How the offline MVP works

```
profile (PII) ──▶ BrokerAdapter.scan() ──▶ ScanResult ──▶ SQLite (tracker)
                            │
                            └── record found? ──▶ BrokerAdapter.submit_optout()
                                                      │
                                                      └──▶ OptOutResult ──▶ SQLite
```

**Matching:** a scan reports `found` only when a dossier plausibly belongs to the
subject. It must agree on name, email, or phone, and its location must not
contradict the profile, so a "Jane Doe" in Dallas is not conflated with one in
Austin.

**Opt-out lifecycle:** `not_needed → pending → submitted → confirmed` (or `failed`).
Re-submission and confirmation are idempotent.

## Adding a broker

1. Add an entry to `incogni/data/brokers.json`.
2. Implement an adapter in `incogni/adapters/` against **sanitized fixtures**
   covering the failure cases (CAPTCHA, ambiguity, paywall, terms change, rate limit,
   outage, and so on). See `tests/fixtures/` for the expected set.
3. Register it, and keep it paused and monitor-only until it clears the
   [activation gates](docs/adapter-activation.md).

## Layout

```
incogni/
├── api.py, auth.py, dashboard.py     # FastAPI control plane + login/session/CSRF
├── worker.py, jobs.py, scheduler.py  # durable job queue + scheduling
├── storage.py, crypto.py             # SQLite (WAL) + AES-256-GCM envelopes
├── state_machine.py, approvals.py    # lifecycle transitions + operator approvals
├── broker_guard.py, activation.py    # activation gates and flow downgrades
├── browser_isolation.py              # single-use, allowlisted browser contexts
├── manual_assist.py                  # operator checklists for manual-only brokers
├── drop.py, gmail.py, gmail_oauth.py # California DROP + email companions
├── soak.py, deployment.py, maintenance.py
├── adapters/                         # broker adapters (fixture-backed, paused)
└── cli.py, service_cli.py            # legacy demo CLI + service commands
deploy/systemd/                       # hardened units and timers
tests/                                # unittest suite + synthetic fixtures
```

## Tests

```bash
pip install -e '.[test]'
python -m unittest discover -s tests
```

## Disclaimers

- Data brokers' terms, opt-out flows, and legal requirements vary by site and
  jurisdiction, and they change. Review each flow yourself before enabling anything
  beyond monitor-only, and only act on your own data or with proper authorization.
- This software does not claim authorized-agent status under CCPA or any other law.
- Provided as-is under the [MIT License](LICENSE), with no warranty.
