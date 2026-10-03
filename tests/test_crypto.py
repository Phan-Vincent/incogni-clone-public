import json
import unittest

from incogni.crypto import EnvelopeCrypto
from incogni.models import AutomationLevel, FindingStatus, JobStatus, RequestStatus


class CryptoTest(unittest.TestCase):
    def setUp(self):
        self.old_key = bytes(range(32))
        self.new_key = bytes(reversed(range(32)))
        self.crypto = EnvelopeCrypto({"old": self.old_key}, "old")

    def test_domain_states(self):
        self.assertEqual(FindingStatus.REAPPEARED.value, "reappeared")
        self.assertEqual(RequestStatus.AWAITING_APPROVAL.value, "awaiting_approval")
        self.assertEqual(JobStatus.RETRY_WAIT.value, "retry_wait")
        self.assertEqual(AutomationLevel.MONITOR_ONLY.value, "monitor_only")

    def test_roundtrip_bytes_and_json(self):
        envelope = self.crypto.encrypt_bytes(b"synthetic secret", aad=b"profile:p1")
        self.assertNotIn("synthetic secret", envelope)
        self.assertEqual(
            self.crypto.decrypt_bytes(envelope, aad=b"profile:p1"),
            b"synthetic secret",
        )
        encoded = self.crypto.encrypt_json(
            {"email": "jane@example.invalid"}, aad=b"profile:p1"
        )
        self.assertEqual(
            self.crypto.decrypt_json(encoded, aad=b"profile:p1"),
            {"email": "jane@example.invalid"},
        )

    def test_wrong_aad_and_tamper_fail(self):
        envelope = self.crypto.encrypt_bytes(b"value", aad=b"record:1")
        with self.assertRaisesRegex(ValueError, "authentication"):
            self.crypto.decrypt_bytes(envelope, aad=b"record:2")
        raw = json.loads(envelope)
        raw["ciphertext"] = raw["ciphertext"][:-2] + "AA"
        with self.assertRaises(ValueError):
            self.crypto.decrypt_bytes(json.dumps(raw), aad=b"record:1")

    def test_malformed_and_unknown_key_fail(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.crypto.decrypt_bytes("{}", aad=b"x")
        envelope = json.loads(self.crypto.encrypt_bytes(b"x", aad=b"x"))
        envelope["key_id"] = "missing"
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.crypto.decrypt_bytes(json.dumps(envelope), aad=b"x")

    def test_old_ciphertext_survives_rotation(self):
        envelope = self.crypto.encrypt_bytes(b"old value", aad=b"record:1")
        rotated = EnvelopeCrypto(
            {"old": self.old_key, "new": self.new_key}, active_key_id="new"
        )
        self.assertEqual(
            rotated.decrypt_bytes(envelope, aad=b"record:1"), b"old value"
        )
        new_envelope = rotated.encrypt_bytes(b"new", aad=b"record:2")
        self.assertEqual(json.loads(new_envelope)["key_id"], "new")


if __name__ == "__main__":
    unittest.main()
