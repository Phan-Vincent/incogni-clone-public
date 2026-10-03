"""Broker adapter contract.

A "broker" is a data broker (people-search site, directory, etc.). Each broker
is backed by an adapter that knows how to (1) check whether a profile's PII is
exposed there and (2) submit a removal request.

Real adapters would drive HTTP scraping / forms / email behind these methods;
the simulated adapters in this package implement the same contract against an
in-process fake broker database so the whole pipeline runs offline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from incogni.models import OptOutResult, ScanResult
from incogni.profile import PersonProfile


class BrokerAdapter(ABC):
    """One data broker integration."""

    #: Stable id, must match a key in ``data/brokers.json``.
    broker_id: str = ""

    def can_scan(self, profile: PersonProfile) -> bool:
        """Whether there is enough profile data to attempt a scan at all."""
        return profile.has_identity()

    @abstractmethod
    def scan(self, profile: PersonProfile) -> ScanResult:
        """Look for the profile's PII on this broker."""

    @abstractmethod
    def submit_optout(self, profile: PersonProfile) -> OptOutResult:
        """Submit (or simulate submitting) a removal request."""
