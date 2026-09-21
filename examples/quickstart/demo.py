"""Manage a disposable local demonstration without printing its credentials."""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / ".quickstart"
COMPOSE = Path(__file__).with_name("compose.yaml")


def write_private(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as destination:
        destination.write(value)


def initialize(port, service_image=None):
    DATA.mkdir(mode=0o700)
    write_private(DATA / "mcp-token", secrets.token_urlsafe(32))
    write_private(DATA / "operator-password", secrets.token_urlsafe(32))
    for name in ["host_key", "client_key"]:
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(DATA / name)], check=True)
    registry = {"demo": {
        "address": "target:22",
        "host_key": (DATA / "host_key.pub").read_text().strip(),
        "roles": {"user": {"user": "demo", "access_class": "privileged", "credential": "demo"}},
    }}
    (DATA / "registry.json").write_text(json.dumps(registry))
    (DATA / "registry.json").chmod(0o644)
    write_private(DATA / "state.json", json.dumps({
        "project": "mcp-ssh-demo-" + secrets.token_hex(6), "port": port, "service_image": service_image,
    }))


def state():
    return json.loads((DATA / "state.json").read_text())


def compose(*arguments, capture=False):
    settings = state()
    environment = dict(os.environ,
        COMPOSE_PROJECT_NAME=settings["project"],
        DEMO_DATA_DIR=str(DATA),
        DEMO_PORT=str(settings["port"]),
        DEMO_SERVICE_IMAGE=settings.get("service_image") or "mcp-ssh-demo-service",
        DEMO_MCP_BEARER=(DATA / "mcp-token").read_text(),
        DEMO_OPERATOR_PASSWORD=(DATA / "operator-password").read_text(),
        DEMO_SSH_KEY=(DATA / "client_key").read_text(),
    )
    return subprocess.run(["docker", "compose", "-f", str(COMPOSE), *arguments],
                          env=environment, check=True, capture_output=capture, text=True)


def rpc(method, params=None, notification=False):
    message = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    if not notification:
        message["id"] = 1
    request = urllib.request.Request(
        f"http://127.0.0.1:{state()['port']}/mcp",
        data=json.dumps(message).encode(),
        headers={"Authorization": "Bearer " + (DATA / "mcp-token").read_text(),
                 "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                 "MCP-Protocol-Version": "2025-11-25"},
    )
    with urllib.request.urlopen(request, timeout=40) as response:
        if notification:
            if response.status != 202:
                raise RuntimeError("The MCP notification was not accepted")
            return None
        result = json.load(response)
    if "error" in result:
        raise RuntimeError("The MCP request failed; inspect the local service logs")
    return result["result"]


def initialize_client():
    result = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                               "clientInfo": {"name": "mcp-ssh-quickstart", "version": "1"}})
    if result.get("protocolVersion") != "2025-11-25":
        raise RuntimeError("The server selected a protocol version this tutorial client does not support")
    rpc("notifications/initialized", notification=True)


def tool(name, arguments):
    if name != "ssh_hosts":
        arguments = {**arguments, "host": "demo", "role": "user", "access_class": "privileged"}
    result = rpc("tools/call", {"name": name, "arguments": arguments})
    if result.get("isError"):
        raise RuntimeError("The tool could not complete; inspect the local service logs")
    if "structuredContent" in result:
        return result["structuredContent"]
    return json.loads(result["content"][0]["text"])


def request_demo():
    if (DATA / "request.json").exists():
        raise RuntimeError("A tutorial request already exists; collect it before starting another")
    initialize_client()
    session = tool("ssh_open_session", {"host": "demo", "role": "user",
        "purpose": "Read the demo account name and create a disposable tutorial file", "scope": "privileged"})
    session_id = session["session"]
    result = tool("ssh_exec", {"session": session_id, "intent": "Check the disposable account",
                              "command": ["whoami"]})
    result = poll_until_settled(session_id, result)
    if result.get("outcome") != "ran" or result.get("exit") != 0:
        raise RuntimeError("The permitted tutorial command did not complete")
    print(json.dumps(result, indent=2))
    command = {"session": session_id, "intent": "Create the tutorial marker in the demo account",
               "command": ["touch", "/home/demo/tutorial-marker"]}
    result = tool("ssh_exec", command)
    if result.get("outcome") != "awaiting_approval":
        raise RuntimeError("The tutorial mutation did not wait for approval")
    write_private(DATA / "request.json", json.dumps(command))
    print(json.dumps(result, indent=2))
    print("Open the dashboard, sign in as operator, and approve this request.")
    return result


def collect():
    initialize_client()
    command = json.loads((DATA / "request.json").read_text())
    result = tool("ssh_exec", command)
    result = poll_until_settled(command["session"], result)
    print(json.dumps(result, indent=2))
    if result.get("outcome") == "ran":
        tool("ssh_close_session", {"session": command["session"]})
        (DATA / "request.json").unlink()
    return result


def poll_until_settled(session, result):
    for _ in range(4):
        if result.get("outcome") != "still_running":
            return result
        result = tool("ssh_poll", {"session": session, "run": result["run"]})
    raise RuntimeError("The tutorial command is still running; inspect the local service")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "request", "collect", "logs", "stop"])
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--service-image", help="Use an already built local service image")
    arguments = parser.parse_args()
    if not 1024 <= arguments.port <= 65535:
        parser.error("port must be between 1024 and 65535")
    if arguments.action == "start":
        if not DATA.exists():
            initialize(arguments.port, arguments.service_image)
        if state().get("service_image"):
            compose("build", "target")
            compose("up", "--no-build", "--detach", "--wait", "--wait-timeout", "90")
        else:
            compose("up", "--build", "--detach", "--wait", "--wait-timeout", "90")
        print(f"Dashboard: http://localhost:{state()['port']}/dashboard/approvals")
        print("Operator name: operator. Read the password locally from .quickstart/operator-password.")
    elif arguments.action == "request":
        request_demo()
    elif arguments.action == "collect":
        collect()
    elif arguments.action == "logs":
        compose("logs", "--no-color", "service")
    else:
        compose("down", "--volumes", "--remove-orphans")
        shutil.rmtree(DATA)


if __name__ == "__main__":
    main()
