# Private-host operations

## Initial setup

Install with the service extras, create a dedicated system account, and generate
credentials interactively:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[service]'
.venv/bin/incogni init-credentials --directory /a/private/temporary/path
```

Move the generated files to the root-owned systemd credential directory described in
`deploy/systemd/README.md`. Never commit them.

Set `INCOGNI_DATA_DIR` for manual commands. Systemd supplies this automatically.

## Deployment rehearsal

Run the read-only preflight and synthetic rehearsal before installing on a private
host:

```bash
.venv/bin/incogni deploy preflight
.venv/bin/incogni deploy stage --root /tmp/incogni-rehearsal
.venv/bin/incogni deploy rehearse --root /tmp/incogni-rehearsal --keep
```

See [the rehearsal guide](deployment-rehearsal.md) for the safety boundary,
idempotency behavior, static systemd and Tailscale validation, cleanup, and
privileged handoff.

After installation and activation, follow the
[synthetic production soak](production-soak.md). Its hourly checks retain only
PII-free operational metadata and cannot promote a broker.

## Control commands

- `incogni health`: validate credentials, database access, schema, and emergency stop.
- `incogni pause` / `resume`: global emergency stop.
- `incogni pause --broker ID`: broker-level execution switch.
- `incogni approve ID` or `approve ID --reject`: one-time guarded decisions.
  Approvals expire after seven days; `approve ID --reissue` (or the dashboard's
  Reissue button) replaces an expired, undecided approval for the same target.
- `incogni manual found BROKER`: record a finding and create its guarded removal
  request and approval for an operator-performed broker flow.
- `incogni manual checklist REQUEST_ID`: show the operator-performed steps for an
  approved request on a manual-only broker (currently Spokeo). The service never
  contacts that broker.
- `incogni manual submitted|verified|confirmed|restart REQUEST_ID`: record a step
  you completed in your own browser. `submitted` schedules a reminder 24 hours before
  the 72-hour email link expires and marks the request failed if it is not verified
  in time; `restart` reopens only a request that failed for that reason. The same
  actions are available at `GET /api/requests/{id}/manual` and
  `POST /api/requests/{id}/manual/{step}`.
- `incogni retry JOB_ID`: explicitly retry blocked/dead work.
- `incogni schedule`: idempotently enqueue retention, backup, report, DROP, and
  removal-recheck work.
- `incogni soak start|check|status|stop`: manage the fourteen-day synthetic-only
  monitor-mode soak.
- `incogni drop-enroll --terms-acknowledged`: record a completed human enrollment.
- `incogni gmail-authorize --client-secret PATH`: run human OAuth consent locally.

The dashboard binds to `127.0.0.1:8765`. Publish it only through Tailscale Serve.
Do not expose it directly to a LAN or the public internet.

## Recovery

Encrypted backups are written daily. To demonstrate restoration, use
`restore_encrypted_backup` into a new path, start a `ServiceStore` against the
restored file, verify schema/health, and only then swap files during a stopped-service
maintenance window. Restoration refuses to overwrite an existing destination.

Use the global emergency stop before investigating flow drift, repeated failures,
lost Gmail authorization, backup failures, or a reappearance.
