# Synthetic private-host deployment rehearsal

This workflow evaluates a possible Linux host without installing the service or
reading private application data. It is safe to run before deciding whether the
machine will become the production host.

## Safety boundary

The deployment commands do not read profiles, service databases, evidence, Gmail
data, identity documents, `.env` files, or existing credentials. Staging and
rehearsal roots must be located beneath `/tmp` or this repository. The tooling
refuses `/`, `/etc`, `/opt`, `/var/lib`, symbolic-link roots, and nonempty
directories that lack its synthetic-stage ownership marker.

Preflight checks Tailscale availability and whether its daemon is active. It does
not inspect tailnet identity or Serve configuration. The rehearsal never invokes
Tailscale, Gmail, Playwright, DROP, or a broker endpoint.

## Read-only preflight

```bash
.venv/bin/incogni deploy preflight
.venv/bin/incogni deploy preflight --json
```

Warnings for absent service accounts and production paths are expected on a
rehearsal host. A Reasonix sandbox warning means Reasonix must be skipped; do not
weaken its policy to make it run.

## Stage and rehearse

Choose an empty path beneath `/tmp` or the repository:

```bash
.venv/bin/incogni deploy stage --root /tmp/incogni-rehearsal
.venv/bin/incogni deploy rehearse --root /tmp/incogni-rehearsal --keep
```

`stage` builds a private installation-shaped tree containing synthetic
credentials, exact copies of the deployment units, harmless executable
placeholders, and a host systemd unit snapshot used only for alternate-root
validation. Repeating it preserves credentials and data while refreshing managed
project units.

`rehearse` starts the API and worker on an ephemeral loopback port. It verifies
login, CSRF, emergency-stop persistence across restart, one-shot scheduling,
maintenance execution, health probes, encrypted backup restoration, artifact
redaction, broker safety, systemd units, and the static Tailscale policy. All five
brokers must remain paused and monitor-only. The browser gate must remain absent
and every adapter transport must remain disabled.

Without `--keep`, a successfully marked synthetic stage is removed after the
command, including on a failed rehearsal. Unmarked directories are never removed.
Use `--keep` to inspect logs or repeat the idempotency rehearsal, then delete the
specific stage when finished.

## Static Tailscale policy

`deploy/tailscale/serve-policy.json` records deployment intent; it is not a native
Tailscale configuration and is never applied automatically. It permits only
Tailscale Serve proxying to `http://127.0.0.1:8765`, forbids Funnel, and requires
the application login to remain enabled.

## Privileged handoff

```bash
.venv/bin/incogni deploy production-plan
```

This command only prints proposed installation, expected-result, and recoverable
rollback commands. It does not inspect or change the host. Review the output on
the selected final host and obtain explicit approval before running any command
that creates users, writes privileged paths, enables systemd units, installs
dependencies, or changes Tailscale Serve.
