"""Run the advisory gate with a version-bounded RSA assessment."""

import pathlib
import subprocess
import tomllib


def check_assessment(lockfile, configuration):
    versions = sorted(
        package["version"]
        for package in lockfile["package"]
        if package["name"] == "rsa"
    )
    if versions != ["0.10.0-rc.18"]:
        raise ValueError("RSA dependency changed: reassess docs/dependency-security.md and the audit exception")
    if configuration.get("advisories", {}).get("ignore", []) != ["RUSTSEC-2023-0071"]:
        raise ValueError("Unexpected advisory exceptions: review the dependency security assessment")


def main():
    root = pathlib.Path(__file__).resolve().parent.parent
    with (root / "Cargo.lock").open("rb") as source:
        lockfile = tomllib.load(source)
    with (root / ".cargo/audit.toml").open("rb") as source:
        configuration = tomllib.load(source)
    check_assessment(lockfile, configuration)
    return subprocess.run(
        ["cargo", "audit", "--file", "Cargo.lock", "--deny", "yanked"],
        cwd=root,
        check=False,
    ).returncode


if __name__ == "__main__":
    raise SystemExit(main())
