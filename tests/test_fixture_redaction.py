import unittest

from incogni.fixture_redaction import assert_redacted, redact_fixture


class FixtureRedactionTest(unittest.TestCase):
    def test_redacts_supplied_values_email_phone_and_query_tokens(self):
        fixture = redact_fixture(
            '<p>Private Name private@example.com (415) 555-0100 '
            '<a href="https://broker.invalid/verify?token=secret-value">go</a></p>',
            sensitive_values=("Private Name",),
        )
        self.assertNotIn("Private Name", fixture.html)
        self.assertNotIn("private@example.com", fixture.html)
        self.assertNotIn("555-0100", fixture.html)
        self.assertNotIn("secret-value", fixture.html)
        self.assertGreaterEqual(fixture.replacements, 4)
        assert_redacted(fixture, sensitive_values=("Private Name",))

    def test_assertion_rejects_incomplete_manual_fixture(self):
        fixture = redact_fixture("<p>synthetic fixture</p>")
        with self.assertRaises(ValueError):
            assert_redacted(fixture, sensitive_values=("synthetic",))


if __name__ == "__main__":
    unittest.main()
