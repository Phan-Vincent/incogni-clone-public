# Private-host deployment

These are hardened system units for a dedicated `incogni` account. Review paths and
user names before installation. Keep `/etc/incogni/credentials` root-owned with mode
`0700`; its two files must be mode `0600`.

Before installing, run the repository-local
[synthetic deployment rehearsal](../../docs/deployment-rehearsal.md). It validates
these exact units inside an alternate filesystem root and does not create accounts,
write privileged paths, enable services, or modify Tailscale. Use
`incogni deploy production-plan` to print the later human-controlled commands and
rollback procedure.

1. Install the project and virtual environment under `/opt/incogni`.
2. Create credentials with `incogni init-credentials --directory <temporary-private-path>`,
   then move them into `/etc/incogni/credentials` as root.
3. Create the `incogni` service account and the separate `incogni-browser` account.
   Both need group access to `/var/lib/incogni`; do not grant either a login shell.
4. Copy the units to `/etc/systemd/system`, run `systemctl daemon-reload`, and enable
   the API, worker, maintenance timer, and health timer.
5. Expose only the local API through Tailscale Serve. Do not bind the API to a LAN or
   public address. Keep application login enabled even behind Tailscale.
6. Leave the browser worker disabled. It also requires
   `/etc/incogni/browser-enabled`, and creating that gate is only appropriate after
   a broker's fixture suite, synthetic canary, and first human-reviewed run pass.
7. After the base services are healthy, explicitly start the fourteen-day
   synthetic soak and enable `incogni-soak.timer` as described in
   `docs/production-soak.md`. Install `incogni-journal-audit.service` with the soak
   units; it is credential-free and is started only as a dependency of each soak
   check. Installing the units alone does not start a soak.

The API and workers receive the master key and password hash through systemd
credentials. Database, evidence, and backup files remain under `/var/lib/incogni`.
Backups are application-encrypted before they are copied anywhere else.
