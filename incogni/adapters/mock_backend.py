"""Simulated data-broker backend.

Real data brokers hold dossiers of PII that you can query. To make the whole
scan -> detect -> opt-out loop runnable offline, this module models a handful of
brokers as an in-process dataset of synthetic "records". An adapter queries it
with the same kinds of keys a real people-search integration would use (name,
email, phone, location) and reports what (if anything) matched.

Nothing here performs network I/O.
"""

from __future__ import annotations

from datetime import datetime, timezone

from incogni.adapters.base import BrokerAdapter
from incogni.models import (
    OptOutMethod,
    OptOutResult,
    OptOutStatus,
    ScanResult,
    ScanStatus,
)
from incogni.profile import PersonProfile

# ---------------------------------------------------------------------------
# Synthetic broker dossiers. Each record lists which brokers hold it.
# ---------------------------------------------------------------------------

_RECORDS: list[dict] = [
    {
        # The example data subject (see examples/profile.json).
        "names": ["jane doe", "jane quinn doe", "j doe"],
        "emails": ["jane.doe@example.com"],
        "phones": ["5550100199"],
        "city_state": "austin tx",
        "dob": "1985-06-15",
        "brokers": [
            "peoplefinder_like",
            "whitepages_like",
            "spokeo_like",
            "mylife_like",
        ],
    },
    {
        # A different Jane Doe in Dallas — same name, different person. A
        # location-aware scan must NOT conflate her with the subject.
        "names": ["jane doe"],
        "emails": [],
        "phones": [],
        "city_state": "dallas tx",
        "dob": "1990-01-01",
        "brokers": ["whitepages_like"],
    },
    {
        # A decoy who shares only a last name and city with the subject.
        "names": ["john doe"],
        "emails": [],
        "phones": [],
        "city_state": "austin tx",
        "dob": "",
        "brokers": ["peoplefinder_like", "instantcheckmate_like"],
    },
]


def search(profile: PersonProfile, broker_id: str) -> list[tuple[dict, list[str]]]:
    """Return ``(record, matched_fields)`` for every dossier of this broker that
    plausibly belongs to ``profile``.

    Matching is intentionally conservative:
      * identity must agree on name, email, or phone, and
      * location must not contradict (if both sides have a city/state).
    """
    profile_names = set(profile.name_variants())
    profile_emails = set(profile.normalized_emails())
    profile_phones = set(profile.normalized_phones())
    profile_cities = set(profile.city_states())

    hits: list[tuple[dict, list[str]]] = []
    for record in _RECORDS:
        if broker_id not in record["brokers"]:
            continue

        matched: list[str] = []
        identity_hit = False

        if profile_names & set(record["names"]):
            identity_hit = True
            matched.append("name")
        if profile_emails & set(record["emails"]):
            identity_hit = True
            matched.append("email")
        if profile_phones & set(record["phones"]):
            identity_hit = True
            matched.append("phone")

        if not identity_hit:
            continue

        # Location corroboration: if the broker's record and the profile both
        # name a city/state and they disagree, this is a different person.
        if record.get("city_state") and profile_cities:
            if record["city_state"] not in profile_cities:
                continue
            matched.append("address")

        hits.append((record, matched))

    return hits


class MockBrokerAdapter(BrokerAdapter):
    """Adapter over the simulated backend for one broker id."""

    def __init__(self, broker_id: str, method: OptOutMethod | str = OptOutMethod.FORM):
        self.broker_id = broker_id
        self.method = OptOutMethod(method)

    def scan(self, profile: PersonProfile) -> ScanResult:
        if not self.can_scan(profile):
            return ScanResult(
                broker_id=self.broker_id,
                status=ScanStatus.SKIPPED,
                detail="insufficient profile data to scan",
            )
        hits = search(profile, self.broker_id)
        if not hits:
            return ScanResult(
                broker_id=self.broker_id,
                status=ScanStatus.NOT_FOUND,
                detail="no matching record",
            )
        fields = sorted({f for _, fs in hits for f in fs})
        return ScanResult(
            broker_id=self.broker_id,
            status=ScanStatus.FOUND,
            matched_fields=fields,
            detail=f"{len(hits)} matching dossier(s)",
        )

    def submit_optout(self, profile: PersonProfile) -> OptOutResult:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        confirmation_id = f"{self.broker_id}-{stamp}"

        # FORM/API methods "process" instantly in the simulation; EMAIL methods
        # stay pending until the broker replies (modelled as SUBMITTED).
        if self.method in (OptOutMethod.FORM, OptOutMethod.API):
            return OptOutResult(
                broker_id=self.broker_id,
                status=OptOutStatus.CONFIRMED,
                confirmation_id=confirmation_id,
                message="simulated removal request accepted and confirmed",
            )
        return OptOutResult(
            broker_id=self.broker_id,
            status=OptOutStatus.SUBMITTED,
            confirmation_id=confirmation_id,
            message="simulated removal request sent; awaiting broker confirmation",
        )
