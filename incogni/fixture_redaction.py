"""Sanitize captured broker markup before it can become a development fixture."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?!\d)")
_QUERY_VALUE = re.compile(r"([?&][A-Za-z0-9_.~-]+=)[^&\s\"'<>]+", re.IGNORECASE)


@dataclass(frozen=True)
class RedactedFixture:
    html: str
    sha256: str
    replacements: int


def redact_fixture(html: str, *, sensitive_values: tuple[str, ...] = ()) -> RedactedFixture:
    redacted = html
    replacements = 0
    for value in sorted(set(sensitive_values), key=len, reverse=True):
        if len(value) < 3:
            continue
        count = redacted.count(value)
        redacted = redacted.replace(value, "[REDACTED]")
        replacements += count
    for pattern, marker in ((_EMAIL, "[EMAIL]"), (_PHONE, "[PHONE]")):
        redacted, count = pattern.subn(marker, redacted)
        replacements += count
    redacted, count = _QUERY_VALUE.subn(r"\1[REDACTED]", redacted)
    replacements += count
    digest = hashlib.sha256(redacted.encode()).hexdigest()
    return RedactedFixture(redacted, digest, replacements)


def assert_redacted(fixture: RedactedFixture, *, sensitive_values: tuple[str, ...]) -> None:
    leaked = [value for value in sensitive_values if len(value) >= 3 and value in fixture.html]
    if leaked:
        raise ValueError("fixture still contains supplied sensitive values")
    if _EMAIL.search(fixture.html) or _PHONE.search(fixture.html):
        raise ValueError("fixture still contains an email address or phone number")
