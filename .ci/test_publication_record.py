import unittest

from publication_record import publication_record


class PublicationRecordTests(unittest.TestCase):
    def test_record_binds_the_readback_digest_source_platform_and_attempt(self):
        commit = "a" * 40
        digest = "sha256:" + "b" * 64
        environment = {"GITHUB_REPOSITORY": "chrisbennight/mcp-ssh-rs", "GITHUB_SHA": commit,
                       "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}
        image = {"RepoDigests": ["ghcr.io/chrisbennight/mcp-ssh-rs@" + digest], "Os": "linux",
                 "Architecture": "amd64", "Config": {"Labels": {"org.opencontainers.image.revision": commit}}}
        record = publication_record(environment, image)
        self.assertEqual((record["source_commit"], record["run_id"], record["run_attempt"]), (commit, 123, 2))
        self.assertEqual(record["images"], [{"repository": "ghcr.io/chrisbennight/mcp-ssh-rs",
                                           "tag": "sha-" + commit, "digest": digest, "platforms": ["linux/amd64"]}])
        image["Config"]["Labels"]["org.opencontainers.image.revision"] = "c" * 40
        with self.assertRaises(ValueError):
            publication_record(environment, image)


if __name__ == "__main__":
    unittest.main()
