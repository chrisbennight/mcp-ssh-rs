"""Require a release tag to name the workspace version before publication."""

import os
from pathlib import Path
import tomllib


def check_ref(ref, version):
    if ref.startswith("refs/tags/") and ref != "refs/tags/v" + version:
        raise ValueError("Release tag must match the workspace package version")


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    with (root / "Cargo.toml").open("rb") as source:
        version = tomllib.load(source)["workspace"]["package"]["version"]
    check_ref(os.environ["GITHUB_REF"], version)
