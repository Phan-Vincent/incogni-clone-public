import unittest

from incogni.profile import Address, PersonProfile


class PersonProfileTest(unittest.TestCase):
    def _jane(self) -> PersonProfile:
        return PersonProfile(
            first_name="Jane",
            middle_name="Quinn",
            last_name="Doe",
            aliases=["Jane Q. Doe"],
            emails=["Jane.Doe@Example.com"],
            phones=["(555) 010-0199"],
            addresses=[Address(street="123 Example St", city="Austin", state="TX", zip="78701")],
            date_of_birth="1985-06-15",
        )

    def test_name_variants(self):
        p = self._jane()
        variants = p.name_variants()
        self.assertIn("jane doe", variants)
        self.assertIn("jane quinn doe", variants)
        self.assertIn("j doe", variants)
        self.assertIn("jane q. doe", variants)  # alias is normalized

    def test_normalized_phone_strips_formatting(self):
        p = self._jane()
        self.assertEqual(p.normalized_phones(), ["5550100199"])

    def test_normalized_email_lowercases(self):
        p = self._jane()
        self.assertEqual(p.normalized_emails(), ["jane.doe@example.com"])

    def test_has_identity(self):
        self.assertTrue(self._jane().has_identity())
        self.assertFalse(PersonProfile().has_identity())

    def test_roundtrip_dict(self):
        p = self._jane()
        again = PersonProfile.from_dict(p.to_dict())
        self.assertEqual(again.full_name_unorm, "jane doe")
        self.assertEqual(again.addresses[0].city, "Austin")
        self.assertEqual(again.phones, ["(555) 010-0199"])


if __name__ == "__main__":
    unittest.main()
