"""Broker registry: loads the broker catalog and binds adapters to it."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from incogni.adapters import build_adapter
from incogni.adapters.base import BrokerAdapter

DEFAULT_BROKERS_PATH = Path(__file__).parent / "data" / "brokers.json"


@dataclass
class Broker:
    id: str
    name: str
    category: str
    optout_method: str
    optout_url: str
    description: str
    adapter: BrokerAdapter


class BrokerRegistry:
    """An ordered collection of brokers, each bound to its adapter."""

    def __init__(self, brokers: list[Broker]):
        self._brokers = {b.id: b for b in brokers}
        self._order = [b.id for b in brokers]

    @classmethod
    def from_file(cls, path: str | Path | None = None) -> "BrokerRegistry":
        path = Path(path) if path else DEFAULT_BROKERS_PATH
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        brokers = [cls._parse(raw) for raw in data.get("brokers", [])]
        return cls(brokers)

    @staticmethod
    def _parse(raw: dict[str, Any]) -> Broker:
        return Broker(
            id=raw["id"],
            name=raw.get("name", raw["id"]),
            category=raw.get("category", ""),
            optout_method=raw.get("optout_method", "unknown"),
            optout_url=raw.get("optout_url", ""),
            description=raw.get("description", ""),
            adapter=build_adapter(raw),
        )

    def all(self) -> list[Broker]:
        return [self._brokers[i] for i in self._order]

    def get(self, broker_id: str) -> Broker | None:
        return self._brokers.get(broker_id)

    def adapter(self, broker_id: str) -> BrokerAdapter:
        return self._brokers[broker_id].adapter

    def __len__(self) -> int:
        return len(self._brokers)

    def __iter__(self):
        return iter(self.all())
