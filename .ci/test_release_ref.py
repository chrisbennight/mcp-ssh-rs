import unittest

from release_ref import check_ref


class ReleaseRefTests(unittest.TestCase):
    def test_release_tags_match_the_package_and_other_events_are_unaffected(self):
        for ref in ["refs/heads/main", "refs/pull/11/merge", "refs/tags/v0.1.0"]:
            check_ref(ref, "0.1.0")
        check_ref("refs/tags/v0.2.0-rc.1", "0.2.0-rc.1")
        for ref in ["refs/tags/v0.2.0", "refs/tags/v0.1.0-extra", "refs/tags/latest"]:
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                check_ref(ref, "0.1.0")


if __name__ == "__main__":
    unittest.main()
