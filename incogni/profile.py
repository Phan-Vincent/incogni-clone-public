"""The user's personally identifiable information (PII) profile.

This is the input to every scan and opt-out: it describes the person whose
data we are trying to find and remove. It is deliberately a plain, JSON-friendly
structure so users can author it by hand (see ``examples/profile.json``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


def _norm(value: str) -> str:
    """Case/whitespace-normalize a string for fuzzy matching."""
    return " ".join(value.lower().split())


@dataclass
class Address:
    street: str = ""
    city: str = ""
    state: str = ""
    zip: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Address":
        return cls(
            street=str(d.get("street", "")),
            city=str(d.get("city", "")),
            state=str(d.get("state", "")),
            zip=str(d.get("zip", "")),
        )

    @property
    def city_state(self) -> str:
        return _norm(f"{self.city} {self.state}")


@dataclass
class PersonProfile:
    """PII for a single data subject.

    All fields are optional; a broker scan is only attempted when the profile
    carries enough data for that broker (see ``BrokerAdapter.can_scan``).
    """

    first_name: str = ""
    last_name: str = ""
    middle_name: str = ""
    aliases: list[str] = field(default_factory=list)      # former/alternate names
    emails: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    addresses: list[Address] = field(default_factory=list)
    date_of_birth: str = ""                                # ISO "YYYY-MM-DD"
    relatives: list[str] = field(default_factory=list)     # names brokers cross-reference

    # ---- construction -----------------------------------------------------

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PersonProfile":
        d = d or {}
        return cls(
            first_name=str(d.get("first_name", "")),
            last_name=str(d.get("last_name", "")),
            middle_name=str(d.get("middle_name", "")),
            aliases=[str(a) for a in d.get("aliases", [])],
            emails=[str(e) for e in d.get("emails", [])],
            phones=[str(p) for p in d.get("phones", [])],
            addresses=[Address.from_dict(a) for a in d.get("addresses", [])],
            date_of_birth=str(d.get("date_of_birth", "")),
            relatives=[str(r) for r in d.get("relatives", [])],
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "PersonProfile":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)
            fh.write("\n")

    # ---- helpers ----------------------------------------------------------

    @property
    def full_name(self) -> str:
        return _norm(" ".join(p for p in (self.first_name, self.middle_name, self.last_name) if p))

    @property
    def full_name_unorm(self) -> str:
        """Normalized name with middle omitted (brokers often drop middle names)."""
        return _norm(f"{self.first_name} {self.last_name}")

    def name_variants(self) -> list[str]:
        """All normalized name strings that might appear in a broker record."""
        variants = {self.full_name_unorm, self.full_name}
        for alias in self.aliases:
            variants.add(_norm(alias))
        # last-name-only matches (e.g. "J Doe") for fuzzy listing pages
        if self.first_name and self.last_name:
            variants.add(_norm(f"{self.first_name[0]} {self.last_name}"))
        return [v for v in variants if v]

    def normalized_emails(self) -> list[str]:
        return [_norm(e) for e in self.emails if e]

    def normalized_phones(self) -> list[str]:
        return ["".join(ch for ch in p if ch.isdigit()) for p in self.phones if p]

    def city_states(self) -> list[str]:
        return [a.city_state for a in self.addresses if a.city or a.state]

    def has_identity(self) -> bool:
        """True if we have at least a name or an email to search by."""
        return bool(self.full_name_unorm or self.normalized_emails())
