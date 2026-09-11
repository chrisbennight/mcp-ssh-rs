import unittest

from audit import check_assessment


class AssessmentTests(unittest.TestCase):
    def test_only_the_assessed_rsa_version_and_advisory_are_accepted(self):
        configuration = {"advisories": {"ignore": ["RUSTSEC-2023-0071"]}}
        assessed = {"name": "rsa", "version": "0.10.0-rc.18"}
        check_assessment({"package": [assessed]}, configuration)
        for packages in [[], [{"name": "rsa", "version": "0.9.10"}],
                         [assessed, {"name": "rsa", "version": "0.10.0-rc.19"}]]:
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                check_assessment({"package": packages}, configuration)
        with self.assertRaises(ValueError):
            check_assessment({"package": [assessed]}, {
                "advisories": {"ignore": ["RUSTSEC-2023-0071", "RUSTSEC-2099-0001"]}
            })


if __name__ == "__main__":
    unittest.main()
