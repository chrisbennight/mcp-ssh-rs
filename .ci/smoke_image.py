#!/usr/bin/env python3
"""Check the built container's restrictions and liveness without external peers."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import uuid


def check(image: str) -> None:
    inspected = subprocess.run(
        ["docker", "image", "inspect", image],
        check=True, capture_output=True, text=True,
    )
    metadata = json.loads(inspected.stdout)[0]
    if metadata["Config"]["User"] != "nonroot:nonroot":
        raise RuntimeError("image must run as nonroot:nonroot")
    if metadata["Config"].get("Healthcheck", {}).get("Test") != [
        "CMD", "/mcp-ssh-rs", "--healthcheck"
    ]:
        raise RuntimeError("image must use the built-in healthcheck")

    with tempfile.TemporaryDirectory(prefix="mcp-ssh-smoke-") as directory:
        fixture = Path(directory)
        key = fixture / "key"
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
            check=True,
        )
        registry = fixture / "registry.json"
        registry.write_text(json.dumps({
            "smoke": {
                "address": "127.0.0.1:22",
                "host_key": "SHA256:AAAA1111",
                "roles": {"readonly": {
                    "user": "nobody", "access_class": "read_only", "credential": "smoke-readonly",
                }},
            },
        }))
        registry.chmod(0o644)
        environment = os.environ.copy()
        environment.update({
            "MCP_SSH_REGISTRY": "/registry.json",
            "MCP_SSH_CREDENTIAL_SMOKE_READONLY": key.read_text(),
            "MCP_SSH_GATEWAY_BEARER_CURRENT": secrets.token_urlsafe(32),
            "MCP_SSH_PROXY_BEARER_CURRENT": secrets.token_urlsafe(32),
            "MCP_SSH_IDENTITY_JWKS_URL": "http://127.0.0.1:9/jwks.json",
            "MCP_SSH_IDENTITY_ISSUER": "https://gateway.example.invalid",
        })
        name = "mcp-ssh-smoke-" + uuid.uuid4().hex
        # Explicit names pass values through the child environment, not argv.
        arguments = [
            "docker", "run", "--detach", "--name", name,
            "--network", "none", "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--mount", f"type=bind,source={registry},target=/registry.json,readonly",
        ]
        for variable in (
            "MCP_SSH_REGISTRY", "MCP_SSH_CREDENTIAL_SMOKE_READONLY",
            "MCP_SSH_GATEWAY_BEARER_CURRENT", "MCP_SSH_PROXY_BEARER_CURRENT",
            "MCP_SSH_IDENTITY_JWKS_URL", "MCP_SSH_IDENTITY_ISSUER",
        ):
            arguments.extend(["--env", variable])
        arguments.append(metadata["Id"])
        try:
            subprocess.run(arguments, env=environment, check=True, stdout=subprocess.DEVNULL)
            for _ in range(30):
                probe = subprocess.run(
                    ["docker", "exec", name, "/mcp-ssh-rs", "--healthcheck"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                if probe.returncode == 0:
                    print("Container restrictions and liveness passed")
                    return
                time.sleep(1)
            raise RuntimeError("container did not become live within the smoke-test window")
        finally:
            # Reconcile even a failed run: Docker may have created the container
            # before reporting an error. Removal failure makes this check fail.
            existing = subprocess.run(
                ["docker", "container", "ls", "--all", "--filter", f"name=^/{name}$", "--quiet"],
                check=True, capture_output=True, text=True,
            )
            if existing.stdout.strip():
                subprocess.run(["docker", "rm", "--force", name], check=True,
                               stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", help="Local image tag or ID to check")
    check(parser.parse_args().image)
