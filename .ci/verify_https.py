"""Verify outbound TLS against generated loopback peers; no real services or keys."""

import argparse
import base64
from contextlib import contextmanager
import http.server
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


@contextmanager
def ssh_target(fixture):
    """A disposable account accepts a session but cannot execute commands."""
    build = fixture / "target-build"
    build.mkdir()
    (build / "Dockerfile").write_text("""FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install --no-install-recommends -y openssh-server && rm -rf /var/lib/apt/lists/* && useradd --uid 20000 --create-home test && passwd -d test && mkdir -p /run/sshd
COPY --chown=0:0 --chmod=0644 authorized_keys /authorized_keys
ENTRYPOINT ["/usr/sbin/sshd", "-D", "-e"]
""")
    # Copy only the public key; OpenSSH must not inherit the host user's UID.
    (build / "authorized_keys").write_bytes((fixture / "ssh.pub").read_bytes())
    command("docker", "build", "--tag", "mcp-ssh-tls-target", str(build))
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    name = "mcp-ssh-tls-target-" + secrets.token_hex(8)
    try:
        command("docker", "run", "--detach", "--name", name, "--network", "host",
                "--mount", f"type=bind,source={fixture / 'ssh'},target=/host_key,readonly",
                "mcp-ssh-tls-target", "-h", "/host_key", "-p", str(port),
                "-o", "ListenAddress=127.0.0.1", "-o", "AuthorizedKeysFile=/authorized_keys",
                "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
                "-o", "PermitRootLogin=no", "-o", "AllowUsers=test", "-o", "DisableForwarding=yes",
                "-o", "ForceCommand=/bin/false", "-o", "UsePAM=no")
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Disposable SSH target did not start")
        yield port
    finally:
        found = command("docker", "container", "ls", "--all", "--filter", f"name=^/{name}$", "--quiet")
        if found.strip():
            command("docker", "rm", "--force", name)


class Peer(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.reply()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply()

    def reply(self):
        self.server.requests.append((self.command, self.path))
        if self.server.redirect:
            self.send_response(307)
            self.send_header("Location", self.server.redirect + self.path)
            self.end_headers()
            return
        body = self.server.jwks if self.path == "/jwks" else {
            "status": "success", "data": {"resultType": "streams", "result": []}}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@contextmanager
def peer(jwks, cert=None, key=None, redirect=None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    server.requests, server.jwks, server.redirect = [], jwks, redirect
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def request(url, headers=None, message=None):
    data = None if message is None else json.dumps(message).encode()
    headers = dict(headers or {})
    if data is not None:
        headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                        "MCP-Protocol-Version": "2025-11-25"})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=10) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


@contextmanager
def service(binary, fixture, roots, jwks_url, endpoint, token, image):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("MCP_SSH_", "SSL_CERT_"))}
    configured = {
        "MCP_SSH_LISTEN": f"127.0.0.1:{port}",
        "MCP_SSH_REGISTRY": str(fixture / "registry.json"),
        "MCP_SSH_CREDENTIAL_TEST": (fixture / "ssh").read_text(),
        "MCP_SSH_GATEWAY_BEARER_CURRENT": secrets.token_urlsafe(32),
        "MCP_SSH_PROXY_BEARER_CURRENT": secrets.token_urlsafe(32),
        "MCP_SSH_IDENTITY_JWKS_URL": jwks_url,
        "MCP_SSH_IDENTITY_ISSUER": "https://gateway.example",
        "MCP_SSH_NOTIFY_URL": endpoint + "/notify",
        "MCP_SSH_AUDIT_QUERY_URL": endpoint + "/",
        "MCP_SSH_DASHBOARD_URL": f"http://localhost:{port}/dashboard/approvals",
        "SSL_CERT_FILE": str(roots), "SSL_CERT_DIR": str(fixture / "empty-roots"),
    }
    environment.update(configured)
    name = "mcp-ssh-tls-" + secrets.token_hex(8)
    args = [str(binary)]
    if image:
        args = ["docker", "run", "--rm", "--name", name, "--network", "host", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--mount", f"type=bind,source={fixture},target={fixture},readonly"]
        for variable in configured:
            args.extend(["--env", variable])
        args.append(image)
    with tempfile.TemporaryFile(mode="w+b") as output:
        process = subprocess.Popen(args, env=environment, stdout=output, stderr=output)
        try:
            base = f"http://127.0.0.1:{port}"
            for _ in range(150):
                if process.poll() is not None:
                    raise RuntimeError("TLS test service exited before becoming live")
                try:
                    if request(base + "/healthz")[0] == 200:
                        break
                except (urllib.error.URLError, TimeoutError):
                    pass
                time.sleep(0.1)
            else:
                raise RuntimeError("TLS test service did not become live")
            bundle = fixture / "system-roots.pem"
            if image and not bundle.exists():
                command("docker", "cp", f"{name}:/etc/ssl/certs/ca-certificates.crt", str(bundle))
                trust = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                trust.load_verify_locations(bundle)
                assert trust.cert_store_stats()["x509_ca"] > 0, "runtime image has no CA roots"
            headers = {"Authorization": "Bearer " + configured["MCP_SSH_GATEWAY_BEARER_CURRENT"],
                       "x-mcp-identity": token}
            yield base, headers, configured, output
        finally:
            if image:
                found = command("docker", "container", "ls", "--all", "--filter", f"name=^/{name}$", "--quiet")
                if found.strip():
                    command("docker", "rm", "--force", name)
            elif process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise


def initialize(base, headers):
    return request(base + "/mcp", headers, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "tls-check", "version": "1"}}})


def tool(base, headers, name, arguments):
    status, body = request(base + "/mcp", headers, {"jsonrpc": "2.0", "id": 1,
        "method": "tools/call", "params": {"name": name, "arguments": arguments}})
    assert status == 200
    result = json.loads(body)["result"]
    assert not result.get("isError"), "TLS fixture tool failed"
    return result.get("structuredContent") or json.loads(result["content"][0]["text"])


def check(binary, image):
    with tempfile.TemporaryDirectory(prefix="mcp-ssh-tls-") as directory:
        fixture = Path(directory)
        # The runtime container reads only the public CA and registry here.
        fixture.chmod(0o755)
        (fixture / "empty-roots").mkdir()
        command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(fixture / "ssh"))
        (fixture / "ssh.pub").chmod(0o600)
        if os.geteuid() == 0:
            os.chown(fixture / "ssh.pub", 1001, 1001)
        for name in ["ca", "other"]:
            command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=Disposable test CA", "-keyout", str(fixture / (name + ".key")),
                    "-out", str(fixture / (name + ".pem")))
        command("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
                "-keyout", str(fixture / "server.key"), "-out", str(fixture / "server.csr"))
        (fixture / "extensions").write_text("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n")
        for name, days in [("valid", "1"), ("expired", "-1")]:
            command("openssl", "x509", "-req", "-in", str(fixture / "server.csr"),
                    "-CA", str(fixture / "ca.pem"), "-CAkey", str(fixture / "ca.key"), "-CAcreateserial",
                    "-days", days, "-extfile", str(fixture / "extensions"), "-out", str(fixture / (name + ".pem")))
        command("openssl", "genpkey", "-algorithm", "ed25519", "-out", str(fixture / "jwt.key"))
        for key in fixture.glob("*.key"):
            key.chmod(0o600)
        public = command("openssl", "pkey", "-in", str(fixture / "jwt.key"), "-pubout", "-outform", "DER")
        assert public[:12] == bytes.fromhex("302a300506032b6570032100")
        jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
                           "kid": "test", "x": encoded(public[12:])}]}
        now = int(time.time())
        payload = encoded(json.dumps({"alg": "EdDSA", "kid": "test"}).encode()) + "." + encoded(json.dumps({
            "sub": "tls-test", "iss": "https://gateway.example", "aud": "mcp-ssh-rs", "iat": now,
            "exp": now + 3600}).encode())
        (fixture / "message").write_bytes(payload.encode())
        signature = command("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(fixture / "jwt.key"),
                            "-in", str(fixture / "message"))
        token = payload + "." + encoded(signature)
        with ssh_target(fixture) as ssh_port, peer(jwks) as plain, peer(jwks) as destination:
            (fixture / "registry.json").write_text(json.dumps({"test": {"address": f"127.0.0.1:{ssh_port}",
                "host_key": (fixture / "ssh.pub").read_text().strip(),
                "roles": {"user": {"user": "test", "credential": "test"}}}}))
            plain_url = f"http://127.0.0.1:{plain.server_port}"
            for case in ["trusted", "untrusted", "wrong-host", "expired", "redirect"]:
                roots = fixture / ("other.pem" if case == "untrusted" else "ca.pem")
                cert = fixture / ("expired.pem" if case == "expired" else "valid.pem")
                redirect = f"http://127.0.0.1:{destination.server_port}" if case == "redirect" else None
                with peer(jwks, cert, fixture / "server.key", redirect) as tls:
                    host = "127.0.0.1" if case == "wrong-host" else "localhost"
                    endpoint = f"https://{host}:{tls.server_port}"
                    with service(binary, fixture, roots, endpoint + "/jwks", endpoint, token, image) as runtime:
                        status, _ = initialize(*runtime[:2])
                        assert status == (200 if case == "trusted" else 401), (case, "JWKS admission")
                    with service(binary, fixture, roots, plain_url + "/jwks", endpoint, token, image) as runtime:
                        base, headers, configured, logs = runtime
                        assert initialize(base, headers)[0] == 200
                        assert request(base + "/mcp", headers, {"jsonrpc": "2.0", "method": "notifications/initialized"})[0] == 202
                        session = tool(base, headers, "ssh_open_session", {"host": "test", "role": "user",
                            "purpose": "Transport check without SSH execution", "scope": "privileged"})
                        held = tool(base, headers, "ssh_exec", {"session": session["session"],
                            "intent": "Generate an approval notification only", "command": ["touch", "/unused"]})
                        assert held["outcome"] == "awaiting_approval"
                        for _ in range(100):
                            logs.seek(0)
                            observed = logs.read().decode()
                            posted = any(method == "POST" for method, _ in tls.requests)
                            failed = "a note could not be delivered" in observed or "a notifier refused a note" in observed
                            if posted or failed:
                                break
                            time.sleep(0.1)
                        else:
                            raise AssertionError((case, "notification did not settle"))
                        assert posted == (case in ["trusted", "redirect"]), (case, "notification TLS")
                        status, body = request(base + "/dashboard/audit", {
                            "Authorization": "Bearer " + configured["MCP_SSH_PROXY_BEARER_CURRENT"],
                            "x-authentik-username": "operator"})
                        assert status == 200
                        assert (b"Loki available" in body) == (case == "trusted"), (case, "audit TLS")
                        assert not destination.requests, "outbound client followed a redirect"
                    print(f"HTTPS {case}: gateway identity, notifications, and audit checked")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", help="Built binary path, or image with --image")
    parser.add_argument("--image", action="store_true", help="Run the image on a local Linux Docker daemon")
    args = parser.parse_args()
    check(Path(args.candidate).resolve(), args.candidate if args.image else None)
