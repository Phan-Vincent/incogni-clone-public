import unittest

from incogni.adapters.registry import SyntheticAdapterRegistry
from incogni.adapters.service import GuardrailPause
from incogni.models import AutomationLevel, FindingStatus


def fixture_source(broker_id, _reference, _operation):
    return (
        f'<section id="{broker_id}-results" data-result="none"></section>'
    )


class SyntheticAdapterRegistryTest(unittest.TestCase):
    def test_all_five_tested_brokers_are_registered_in_sorted_tuple(self):
        registry = SyntheticAdapterRegistry(fixture_source)
        self.assertEqual(
            registry.broker_ids,
            ("beenverified", "intelius", "mylife", "spokeo", "whitepages"),
        )
        self.assertIsInstance(registry.broker_ids, tuple)

    def test_each_lookup_returns_new_paused_monitor_only_adapter(self):
        registry = SyntheticAdapterRegistry(fixture_source)
        for broker_id in registry.broker_ids:
            with self.subTest(broker_id=broker_id):
                first = registry.get(broker_id)
                second = registry.get(broker_id)
                self.assertIsNot(first, second)
                self.assertEqual(first.metadata.broker_id, broker_id)
                self.assertTrue(first.metadata.paused)
                self.assertIs(
                    first.metadata.automation_level, AutomationLevel.MONITOR_ONLY
                )
                self.assertIs(
                    first.discover("synthetic").status, FindingStatus.NOT_FOUND
                )

    def test_unknown_broker_and_version_mismatch_fail_closed(self):
        registry = SyntheticAdapterRegistry(fixture_source)
        with self.assertRaisesRegex(GuardrailPause, "unknown_broker"):
            registry.get("unregistered")
        with self.assertRaisesRegex(GuardrailPause, "flow_version_changed"):
            registry.get("spokeo", expected_flow_version="synthetic-stale-version")

    def test_matching_version_is_accepted(self):
        registry = SyntheticAdapterRegistry(fixture_source)
        current = registry.get("spokeo").metadata.flow_version
        self.assertEqual(
            registry.get("spokeo", expected_flow_version=current).metadata.flow_version,
            current,
        )

    def test_missing_or_non_callable_fixture_source_is_rejected(self):
        for source in (None, "fixtures"):
            with self.subTest(source=source):
                with self.assertRaisesRegex(ValueError, "callable fixture source"):
                    SyntheticAdapterRegistry(source)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
