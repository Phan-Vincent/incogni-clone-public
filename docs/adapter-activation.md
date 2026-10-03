# Broker adapter activation gate

Spokeo, MyLife, Whitepages, BeenVerified, and Intelius are provisional definitions.
They must advance independently through these gates:

1. **Monitor-only:** sanitized discovery, poll, and verification fixtures pass,
   including missing selectors, altered fingerprints, CAPTCHA, identity-document,
   authentication, paywall, terms-change, redirect, ambiguity, rate-limit, and outage
   cases.
2. **Approval-required:** a synthetic canary passes; current terms and privacy flow
   receive human review; the flow version and page fingerprint are pinned.
3. **Automatic:** one personal run is completed and reviewed by the operator, with no
   PII in logs or development artifacts. The operator explicitly changes the broker
   activation record.
4. **Soak:** remain monitor-only for two weeks before approval-required submissions.
   Automatic execution is enabled broker by broker, never globally.

### Manual-only brokers

Spokeo is manual-only (see [adapter research](adapter-research.md)). Its adapter
refuses every transport except the disabled one, and its `execute` always pauses
with `operator_manual_only`. For a manual-only broker, approval-required means an
approved request unlocks an operator checklist (`incogni manual checklist`); the
operator performs the opt-out in their own browser and records each step. The
human-reviewed run is the operator's first such request. `broker-mode … automatic`
is refused for manual-only brokers.

Any new fields, fingerprint changes, unexpected redirect, CAPTCHA, identity document,
terms change, authorization boundary, or rate-limit response immediately blocks the
job and downgrades the flow for review. No component may bypass these controls or
claim authorized-agent status.

The browser worker is disabled at the systemd level until
`/etc/incogni/browser-enabled` is deliberately created. The codebase currently has
no enabled production transport, so reaching automatic mode also requires a reviewed
transport implementation and fixture suite.
