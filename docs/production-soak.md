# Synthetic monitor-mode production soak

The production soak is a fourteen-day observation period for the private host. It
exercises only packaged sanitized fixtures and reads bounded operational metadata.
It never contacts a broker, opens a verification link, authorizes Gmail, automates
DROP, starts the browser worker, or promotes an adapter.

## Stored data

The soak creates `/var/lib/incogni/soak/status.json` and `report.json`. Both are
mode `0600` in a mode `0700` directory. They contain timestamps, stable check codes,
pass/fail results, restart-counter baselines, and aggregate progress only. They do
not copy credentials, database rows, profiles, evidence, backup contents, fixture
contents, host names, listener addresses, service output, or PII.

Each check validates:

- API health, API and worker state, restart counters, timer state, and latest
  maintenance/health results;
- encrypted-backup freshness, free disk capacity, filesystem permissions,
  loopback-only binding, Tailscale Serve without Funnel, and journal/report
  redaction;
- schema and queue health, absence of failed/dead jobs, emergency-stop state, and
  absence of Gmail, DROP automation, broker submissions, browser activation, and
  live transports;
- exact paused/`monitor_only` metadata and flow versions for Spokeo, MyLife,
  Whitepages, BeenVerified, and Intelius;
- fixture completeness plus discovery, polling, and suppression canaries for all
  five packaged adapters.

Journal scanning runs in the short-lived `incogni-journal-audit.service`. It has no
service credentials or database access and receives only the system journal group.
It writes a fresh boolean result beneath `/run/incogni-journal-audit`; journal text,
matches, and error messages are never copied into soak state. The main `incogni`
account remains unable to read the host journal outside this isolated unit: the
supplementary journal group applies only to the helper process, while the unit makes
`/etc/incogni` and `/var/lib/incogni` inaccessible. The helper uses the fixed service
account so its result remains readable by the following soak service; systemd's
`DynamicUser` runtime-directory indirection is intentionally not used here.

The `journalctl` query must open every archived journal file, so a cold-cache run on a
rotational disk can take over a minute. The helper allows the query 300 seconds, the
unit allows 8 minutes, and it runs at low CPU and I/O priority. A query that still
times out is recorded as `query_ok: false`, which fails that soak check.

The soak fails closed after any failed check. Fix the cause, stop the failed soak,
then start a new fourteen-day run. A successful run changes only its own status to
`passed`; it never changes a broker activation level.

## Commands

Systemd supplies credentials and the data directory to scheduled checks. For an
operator shell, use `systemd-run` rather than exporting or reading credential
values:

```bash
sudo systemd-run --wait --pipe --collect --unit=incogni-soak-start \
  --property=User=incogni --property=Group=incogni \
  --property=WorkingDirectory=/opt/incogni \
  --property=LoadCredential=incogni-master-key:/etc/incogni/credentials/incogni-master-key \
  --property=LoadCredential=incogni-admin-password:/etc/incogni/credentials/incogni-admin-password \
  --setenv=INCOGNI_DATA_DIR=/var/lib/incogni \
  /opt/incogni/.venv/bin/incogni soak start
sudo systemctl enable --now incogni-soak.timer
sudo systemctl start incogni-soak.service
```

Use the same transient-unit credential properties with `incogni soak status
--json` for machine-readable status or `incogni soak stop` to stop the run. The
hourly timer is safe across host restarts because the start time and baseline are
persisted before the first check.

## Failure response

Do not reset a failed soak in place. First keep all brokers paused, enable the
global emergency stop if the failure could affect execution, and inspect the stable
failed check code. Correct the host or repository issue, run the full synthetic
test/rehearsal suite, then use `soak stop` followed by `soak start` to begin a fresh
fourteen-day interval.

Stopping or completing the soak does not disable its timer automatically. Disable
the timer explicitly when periodic observations are no longer wanted:

```bash
sudo systemctl disable --now incogni-soak.timer
```
