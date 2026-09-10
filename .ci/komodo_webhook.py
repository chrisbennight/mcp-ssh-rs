#!/usr/bin/env python3
"""Build the Komodo push-style webhook body and HMAC-SHA256 signature.

This is byte-identical to docker-home's canonical signer: compact JSON with the
signature computed over exactly the bytes printed on the first output line.
Inputs come from the environment so the signing secret is never placed in a
process argument.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys


def build(env: dict[str, str]) -> tuple[str, str]:
    """Return the compact JSON body and its hexadecimal signature."""
    secret = env.get("WEBHOOK_SECRET", "")
    repo_full_name = env.get("REPO_FULL_NAME", "")
    server_url = env.get("REPO_SERVER_URL", "").rstrip("/")
    repository_url = (
        f"{server_url}/{repo_full_name}" if server_url and repo_full_name else ""
    )
    payload = {
        "ref": env.get("GIT_REF", ""),
        "after": env.get("GIT_SHA", ""),
        "repository": {
            "full_name": repo_full_name,
            "html_url": repository_url,
        },
        "pusher": {
            "name": env.get("GIT_ACTOR", "gitea-actions"),
        },
        "sender": {
            "login": env.get("GIT_ACTOR", "gitea-actions"),
        },
    }
    body = json.dumps(payload, separators=(",", ":"))
    signature = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return body, signature


def main() -> int:
    if not os.environ.get("WEBHOOK_SECRET"):
        print("komodo_webhook: WEBHOOK_SECRET is empty or unset", file=sys.stderr)
        return 1
    body, signature = build(dict(os.environ))
    sys.stdout.write(f"{body}\n{signature}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
