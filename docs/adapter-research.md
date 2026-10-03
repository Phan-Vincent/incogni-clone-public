# Public adapter-flow review

Reviewed 2026-08-27 using public official pages only. No profile data was entered,
no request was submitted, and no captured page content is used as a fixture.

## Spokeo

Reviewed 2026-09-30 using public official pages only. No profile data was entered and
no request was submitted.

- Official opt-out route: <https://www.spokeo.com/optout>. It returned HTTP 403 to an
  automated fetch. Public guides describe the flow as: find the listing and copy
  its URL, paste the URL and an email address into the opt-out form, complete a
  CAPTCHA, then open the emailed confirmation link (reported to expire after 72
  hours). Removal is reported to take 24–72 hours.
- Official terms: <https://www.spokeo.com/terms-of-use> (last updated 2022-10-26):
  "You are prohibited from scraping, crawling, data-mining, or using any robot,
  spider, or other automatic device to send queries to the Spokeo's servers or
  Spokeo.com." Court records cannot be suppressed without an expungement or
  sealing order.
- Official privacy policy: <https://www.spokeo.com/privacy-policy> (last updated
  2026-06-25). It lists the opt-out page, CustomerCare@spokeo.com, and a postal
  address for public-information removal, and it accepts authorized agents for
  know/correct/delete requests. It does not mention the Delete Act or DROP.
- Drift found: the pinned route `https://www.spokeo.com/privacy/control` is
  Spokeo's "view my profile" request form, not the opt-out. The flow moved from
  `2026-08-monitor-1` to `2026-09-manual-1` with the opt-out route pinned; the
  version change resets Spokeo to paused monitor-only with a fresh soak.
- Fixture comparison: the sanitized discovery/poll/verify state model still fits;
  the removal plan now names the operator-performed steps, including the CAPTCHA.
- Decision: manual only. The terms forbid automated queries and the form requires a
  CAPTCHA, which the service must never bypass. After approval, the service gives
  the operator a checklist, tracks the steps they record, reminds them before the
  verification link expires, and schedules recheck reminders. It never submits the
  form, opens the verification link, or checks the listing on Spokeo.

## BeenVerified

- Official opt-out route: <https://www.beenverified.com/svc/optout/search/optouts>
- Official privacy policy: <https://www.beenverified.com/faq/privacy/>
- Official terms: <https://www.beenverified.com/faq/terms-conditions/>
- The opt-out route currently presents an access challenge. The privacy policy also
  documents email and comprehensive-request paths and identity verification.
- Decision: retain a synthetic people-search state model, but never bypass the
  challenge or enable live automation. Any personal request remains manual and
  human-reviewed.

## Intelius / PeopleConnect

- Official suppression center: <https://suppression.peopleconnect.us/>
- Official terms: <https://peopleconnect.us/terms-of-use/>
- Official privacy center: <https://suppression.peopleconnect.us/privacy-center>
- The center covers Intelius and other PeopleConnect people-search brands. It begins
  with email verification and manages suppression while the user is authenticated.
  The terms prohibit robots, scraping, and automated monitoring of the site.
- Decision: reuse only the sanitized state model. Real suppression-center use stays
  manual; the service may guide, remind, and track it but must not automate it.

Any future terms, route, ownership, challenge, or page-fingerprint change creates a
new flow version and resets activation checkpoints before further use.
