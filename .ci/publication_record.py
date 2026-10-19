"""Record the immutable identity read back after a successful image push."""

import json
import os
from pathlib import Path
import re
import subprocess


def publication_record(environment, image):
    repository = environment["GITHUB_REPOSITORY"].lower()
    commit = environment["GITHUB_SHA"]
    if repository != "chrisbennight/mcp-ssh-rs" or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Publication requires the expected repository and full source commit")
    image_repository = "ghcr.io/" + repository
    digests = image["RepoDigests"]
    if (len(digests) != 1 or not re.fullmatch(re.escape(image_repository) + r"@sha256:[0-9a-f]{64}", digests[0])
            or image["Os"] != "linux" or image["Architecture"] != "amd64"
            or image["Config"]["Labels"].get("org.opencontainers.image.revision") != commit):
        raise ValueError("Published image does not match its source, repository, or platform")
    return {
        "schema_version": 1, "source_repository": repository, "source_commit": commit,
        "source_ref": environment["GITHUB_REF"], "workflow": ".github/workflows/ci.yml",
        "run_id": int(environment["GITHUB_RUN_ID"]), "run_attempt": int(environment["GITHUB_RUN_ATTEMPT"]),
        "images": [{"repository": image_repository, "tag": "sha-" + commit,
                    "digest": digests[0].split("@", 1)[1], "platforms": ["linux/amd64"]}],
    }


if __name__ == "__main__":
    reference = "ghcr.io/" + os.environ["GITHUB_REPOSITORY"].lower() + ":sha-" + os.environ["GITHUB_SHA"]
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", reference]))[0]
    record = publication_record(os.environ, image)
    (Path(os.environ["RUNNER_TEMP"]) / "ssh-publication.json").write_text(json.dumps(record) + "\n")
