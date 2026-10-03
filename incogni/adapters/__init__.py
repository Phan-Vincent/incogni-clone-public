"""Adapter factory: maps a broker definition to a concrete adapter instance."""

from __future__ import annotations

from incogni.adapters.base import BrokerAdapter
from incogni.adapters.mock_backend import MockBrokerAdapter
from incogni.adapters.stub import StubAdapter


def build_adapter(broker: dict) -> BrokerAdapter:
    """Instantiate the adapter named by ``broker["adapter"]``.

    * ``"mock"`` — backed by the in-process simulated broker dataset.
    * ``"stub"`` — known broker, not yet integrated.
    """
    broker_id = broker["id"]
    kind = broker.get("adapter", "stub")
    method = broker.get("optout_method", "form")

    if kind == "mock":
        return MockBrokerAdapter(broker_id, method=method)
    if kind == "stub":
        return StubAdapter(broker_id)
    raise ValueError(f"unknown adapter kind {kind!r} for broker {broker_id!r}")
