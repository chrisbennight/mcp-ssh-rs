"""Exercise the tutorial against disposable containers, including operator approval."""

import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples" / "quickstart"))
import demo


def dashboard(path, authorization, site=None):
    headers = {"Authorization": authorization}
    data = None
    if site is not None:
        headers.update({"Sec-Fetch-Site": site, "Content-Type": "application/x-www-form-urlencoded"})
        data = b"decision=approve"
    request = urllib.request.Request(
        f"http://127.0.0.1:{demo.state()['port']}/dashboard/{path}",
        data=data, headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read(1024 * 1024)
    except urllib.error.HTTPError as error:
        return error.code, error.read(1024 * 1024)


def verify_live():
    demo.compose("exec", "-T", "--user", "demo", "target", "test", "!", "-r", "/etc/ssh/ssh_host_ed25519_key")
    held = demo.request_demo()
    request_id = held["request"]
    command = json.loads((demo.DATA / "request.json").read_text())
    demo.compose("exec", "-T", "target", "test", "!", "-e", "/home/demo/tutorial-marker")
    mcp_bearer = (demo.DATA / "mcp-token").read_text()
    password = (demo.DATA / "operator-password").read_text()
    login = "Basic " + base64.b64encode(f"operator:{password}".encode()).decode()
    assert dashboard("approvals", "Bearer " + mcp_bearer)[0] == 401
    wrong_login = "Basic " + base64.b64encode(f"operator:{mcp_bearer}".encode()).decode()
    assert dashboard("approvals", wrong_login)[0] == 401
    status, page = dashboard("approvals", login)
    assert status == 200 and request_id.encode() in page
    assert dashboard("approvals/" + request_id, login, "cross-site")[0] == 403
    demo.compose("exec", "-T", "target", "test", "!", "-e", "/home/demo/tutorial-marker")
    assert dashboard("approvals/" + request_id, login, "same-origin")[0] == 200
    result = demo.collect()
    assert result["outcome"] == "ran" and result["exit"] == 0
    demo.compose("exec", "-T", "target", "test", "-e", "/home/demo/tutorial-marker")

    logs = demo.compose("logs", "--no-color", "--no-log-prefix", "service", capture=True).stdout
    entries = []
    for line in logs.splitlines():
        value = json.loads(line)
        if value.get("session") == command["session"]:
            entries.append(value)
    assert entries and all(entry["principal"] == "local" for entry in entries)
    approved = next(entry for entry in entries if entry["event"]["event"] == "approved")
    assert approved["event"]["approver"] == "operator"
    assert any(entry["event"]["event"] == "completed" and entry["event"]["run"] == result["run"]
               for entry in entries)
    assert mcp_bearer not in logs and password not in logs
    print("Quickstart passed: account review, separate operator login, CSRF refusal, execution, and audit identity.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    arguments = parser.parse_args()
    if demo.DATA.exists():
        parser.error("An existing .quickstart directory must be stopped before this isolated test")
    try:
        demo.initialize(18080, arguments.image)
        public_key = demo.DATA / "client_key.pub"
        public_key.chmod(0o600)
        if os.geteuid() == 0:
            # Exercise a host owner different from both root and the demo account.
            os.chown(public_key, 1001, 1001)
        subprocess.run([sys.executable, demo.__file__, "start", "--port", "18080",
                        "--service-image", arguments.image], check=True)
        verify_live()
    finally:
        if (demo.DATA / "state.json").exists():
            subprocess.run([sys.executable, demo.__file__, "stop"], check=True)


if __name__ == "__main__":
    main()
