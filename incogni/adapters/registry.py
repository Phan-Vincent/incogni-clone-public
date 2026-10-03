"""Explicit synthetic-only adapter registry."""

from __future__ import annotations

from collections.abc import Callable
from types import MappingProxyType

from incogni.adapters.beenverified import BeenVerifiedFixtureAdapter
from incogni.adapters.guarded import FixtureSource, RuntimeGuard
from incogni.adapters.intelius import InteliusFixtureAdapter
from incogni.adapters.mylife import MyLifeFixtureAdapter
from incogni.adapters.service import GuardrailPause, ServiceBrokerAdapter
from incogni.adapters.spokeo import SpokeoFixtureAdapter
from incogni.adapters.whitepages import WhitepagesFixtureAdapter

AdapterFactory = Callable[..., ServiceBrokerAdapter]
FindingSource = Callable[[str], dict[str, str] | None]

_SYNTHETIC_FACTORIES = MappingProxyType(
    {
        "beenverified": BeenVerifiedFixtureAdapter,
        "intelius": InteliusFixtureAdapter,
        "mylife": MyLifeFixtureAdapter,
        "spokeo": SpokeoFixtureAdapter,
        "whitepages": WhitepagesFixtureAdapter,
    }
)


class SyntheticAdapterRegistry:
    """Build only explicitly registered adapters from an injected fixture source."""

    def __init__(
        self,
        fixture_source: FixtureSource,
        *,
        finding_source: FindingSource | None = None,
        runtime_guard: RuntimeGuard | None = None,
    ):
        if not callable(fixture_source):
            raise ValueError("a callable fixture source is required")
        self._fixture_source = fixture_source
        self._finding_source = finding_source
        self._runtime_guard = runtime_guard

    @property
    def broker_ids(self) -> tuple[str, ...]:
        return tuple(sorted(_SYNTHETIC_FACTORIES))

    def get(
        self, broker_id: str, *, expected_flow_version: str | None = None
    ) -> ServiceBrokerAdapter:
        factory = _SYNTHETIC_FACTORIES.get(broker_id)
        if factory is None:
            raise GuardrailPause("unknown_broker")
        adapter = factory(
            self._fixture_source,
            finding_source=self._finding_source,
            runtime_guard=self._runtime_guard,
        )
        if (
            expected_flow_version is not None
            and adapter.metadata.flow_version != expected_flow_version
        ):
            raise GuardrailPause("flow_version_changed")
        return adapter
