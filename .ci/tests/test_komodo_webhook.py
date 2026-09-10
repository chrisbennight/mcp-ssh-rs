"""Regression tests for the image-publish-to-Komodo deployment trigger."""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".ci"
sys.path.insert(0, str(CI))

import komodo_webhook  # noqa: E402

SCRIPT = CI / "komodo_webhook.py"
WORKFLOW = ROOT / ".gitea/workflows/build.yml"


def _canonical(env: dict[str, str]) -> tuple[str, str]:
    """Independently reproduce docker-home's canonical wire representation."""
    repo_full_name = env.get("REPO_FULL_NAME", "")
    server_url = env.get("REPO_SERVER_URL", "").rstrip("/")
    repository_url = (
        f"{server_url}/{repo_full_name}" if server_url and repo_full_name else ""
    )
    payload = {
        "ref": env.get("GIT_REF", ""),
        "after": env.get("GIT_SHA", ""),
        "repository": {"full_name": repo_full_name, "html_url": repository_url},
        "pusher": {"name": env.get("GIT_ACTOR", "gitea-actions")},
        "sender": {"login": env.get("GIT_ACTOR", "gitea-actions")},
    }
    body = json.dumps(payload, separators=(",", ":"))
    signature = hmac.new(
        env["WEBHOOK_SECRET"].encode(), body.encode(), hashlib.sha256
    ).hexdigest()
    return body, signature


ENV = {
    "WEBHOOK_SECRET": "not-a-production-secret",
    "REPO_FULL_NAME": "bennight/mcp-ssh-rs",
    "REPO_SERVER_URL": "https://gitea.cacahuate.org",
    "GIT_REF": "refs/heads/main",
    "GIT_SHA": "abc123def456",
    "GIT_ACTOR": "gitea-actions",
}


def test_build_is_byte_identical_to_canonical_signer() -> None:
    assert komodo_webhook.build(ENV) == _canonical(ENV)


def test_payload_shape_and_signature() -> None:
    body, signature = komodo_webhook.build(ENV)
    assert json.loads(body) == {
        "ref": "refs/heads/main",
        "after": "abc123def456",
        "repository": {
            "full_name": "bennight/mcp-ssh-rs",
            "html_url": "https://gitea.cacahuate.org/bennight/mcp-ssh-rs",
        },
        "pusher": {"name": "gitea-actions"},
        "sender": {"login": "gitea-actions"},
    }
    assert ", " not in body and ": " not in body
    assert signature == hmac.new(
        ENV["WEBHOOK_SECRET"].encode(), body.encode(), hashlib.sha256
    ).hexdigest()


def test_cli_fails_closed_without_secret() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        env={"REPO_FULL_NAME": "bennight/mcp-ssh-rs"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "WEBHOOK_SECRET" in result.stderr


def test_build_workflow_deploys_only_after_main_image_publish() -> None:
    workflow = WORKFLOW.read_text()
    marker = "\n  trigger-komodo-deploy:\n"
    assert marker in workflow
    job = workflow.split(marker, 1)[1]
    assert "    needs: image\n" in job
    assert (
        "    if: github.event_name == 'push' && github.ref == 'refs/heads/main'\n"
        in job
    )
    assert "          secret-path: /bennight/docker-home\n" in job
    assert "          secrets: KOMODO_WEBHOOK_SECRET\n" in job
    assert "          STACK_ID: 6a835af419629bec61b7037e\n" in job
    assert "webhook_out=$(python3 .ci/komodo_webhook.py)" in job
    assert (
        '"https://komodo.cacahuate.org/listener/github/stack/${STACK_ID}/deploy"'
        in job
    )


if __name__ == "__main__":
    failures = 0
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            try:
                function()
                print(f"OK  {name}")
            except AssertionError as error:
                failures += 1
                print(f"FAIL {name}: {error}", file=sys.stderr)
    sys.exit(1 if failures else 0)
