//! Process-level transport and output isolation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("mcp-ssh-process-{:x}", rand::random::<u128>()));
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("registry.json"), "{}").unwrap();
        Self(path)
    }
    fn command(&self) -> tokio::process::Command {
        let executable = env!("CARGO_BIN_EXE_mcp-ssh-rs");
        let mut command = tokio::process::Command::new(executable);
        command
            .env_clear()
            .env("MCP_SSH_REGISTRY", self.0.join("registry.json"))
            .env("MCP_SSH_TRANSPORT", "stdio")
            .env(
                "MCP_SSH_AUDIT_SINK",
                format!("file:{}", self.0.join("audit.jsonl").display()),
            )
            .env("RUST_LOG", "info")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        command
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            eprintln!("test fixture cleanup failed: {error}");
        }
    }
}

#[tokio::test]
async fn stdio_exchanges_protocol_only_and_exits_on_eof_without_an_http_listener() {
    let fixture = Fixture::new();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut child = fixture
        .command()
        .env("MCP_SSH_LISTEN", occupied.local_addr().unwrap().to_string())
        .env("MCP_SSH_FILE_ROOT", &fixture.0)
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut errors = child.stderr.take().unwrap();
    for request in [
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"process-test","version":"test"}}}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ] {
        let mut bytes = serde_json::to_vec(&request).unwrap();
        bytes.push(b'\n');
        input.write_all(&bytes).await.unwrap();
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), output.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        let response: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response.get("id").unwrap(), request.get("id").unwrap());
        assert!(response.get("result").is_some(), "{response}");
        if request.get("id").and_then(serde_json::Value::as_u64) == Some(1) {
            input
                .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
                .await
                .unwrap();
        }
    }
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let mut remaining = String::new();
    output.read_to_string(&mut remaining).await.unwrap();
    assert!(remaining.is_empty(), "non-protocol stdout: {remaining}");
    let mut diagnostics = String::new();
    errors.read_to_string(&mut diagnostics).await.unwrap();
    assert!(diagnostics.contains("serving"));
    assert!(fixture.0.join("audit.jsonl").is_file());
}

#[tokio::test]
async fn an_unopenable_required_sink_prevents_protocol_startup() {
    let fixture = Fixture::new();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        fixture
            .command()
            .env(
                "MCP_SSH_AUDIT_SINK",
                format!("file:{}", fixture.0.join("missing/audit.jsonl").display()),
            )
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(String::from_utf8_lossy(&result.stderr).contains("opening output sinks"));
}

#[tokio::test]
async fn service_errors_use_diagnostics_without_polluting_the_audit_stream() {
    let fixture = Fixture::new();
    std::fs::write(fixture.0.join("registry.json"), "{").unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        fixture
            .command()
            .env("MCP_SSH_TRANSPORT", "http")
            .env("MCP_SSH_AUTH_MODE", "standalone")
            .env(
                "MCP_SSH_BEARER",
                "disposable-process-test-bearer-credential",
            )
            .env("MCP_SSH_AUDIT_SINK", "stderr")
            .env(
                "MCP_SSH_LOG_SINK",
                format!("file:{}", fixture.0.join("diagnostics.jsonl").display()),
            )
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(
        result.stderr.is_empty(),
        "audit stream contains diagnostic text"
    );
    let diagnostics = std::fs::read_to_string(fixture.0.join("diagnostics.jsonl")).unwrap();
    let records: Vec<serde_json::Value> = diagnostics
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(records.iter().any(|record| {
        record
            .pointer("/fields/error")
            .and_then(serde_json::Value::as_str)
            == Some("parsing the registry")
    }));
}

#[derive(Clone)]
struct AccountTarget {
    public_key: russh::keys::PublicKey,
    authentications: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl russh::server::Server for AccountTarget {
    type Handler = Self;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl russh::server::Handler for AccountTarget {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<russh::server::Auth, Self::Error> {
        self.authentications
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(if user == "test-user" && key == &self.public_key {
            russh::server::Auth::Accept
        } else {
            russh::server::Auth::reject()
        })
    }
}

async fn exchange(
    input: &mut tokio::process::ChildStdin,
    output: &mut BufReader<tokio::process::ChildStdout>,
    request: serde_json::Value,
) -> serde_json::Value {
    let mut bytes = serde_json::to_vec(&request).unwrap();
    bytes.push(b'\n');
    input.write_all(&bytes).await.unwrap();
    let mut line = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), output.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(read, 0, "service exited before answering the request");
    let response: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response.get("id"), request.get("id"));
    response
}

#[tokio::test]
async fn unavailable_account_keys_do_not_stop_startup_or_other_accounts() {
    use russh::server::Server as _;
    use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};

    let fixture = Fixture::new();
    let key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let host_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519).unwrap();
    let pinned = host_key.public_key().to_openssh().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let authentications = Arc::new(AtomicUsize::new(0));
    let mut target = AccountTarget {
        public_key: key.public_key().clone(),
        authentications: Arc::clone(&authentications),
    };
    let server = tokio::spawn(async move {
        target
            .run_on_socket(
                Arc::new(russh::server::Config {
                    keys: vec![host_key],
                    ..Default::default()
                }),
                &listener,
            )
            .await
    });
    let mut roles = serde_json::Map::new();
    for role in ["working", "empty", "missing", "malformed"] {
        roles.insert(
            role.to_owned(),
            serde_json::json!({
                "user": "test-user", "access_class": "read_only", "credential": role
            }),
        );
    }
    let registry = serde_json::json!({"target": {
        "address": address.to_string(), "host_key": pinned, "roles": roles
    }});
    std::fs::write(fixture.0.join("registry.json"), registry.to_string()).unwrap();
    let mut child = fixture
        .command()
        .env(
            "MCP_SSH_CREDENTIAL_WORKING",
            key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_str(),
        )
        .env("MCP_SSH_CREDENTIAL_EMPTY", "")
        .env("MCP_SSH_CREDENTIAL_MALFORMED", "not-a-private-key")
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut errors = child.stderr.take().unwrap();
    let initialized = exchange(
        &mut input,
        &mut output,
        serde_json::json!({
            "jsonrpc":"2.0", "id":1, "method":"initialize", "params": {
                "protocolVersion":"2025-11-25", "capabilities":{},
                "clientInfo":{"name":"credential-isolation-test","version":"test"}
            }
        }),
    )
    .await;
    assert!(initialized.get("result").is_some());
    input
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();

    // A failed account must not borrow the valid key or poison a later login.
    for (id, role) in [
        (2, "empty"),
        (3, "working"),
        (4, "missing"),
        (5, "malformed"),
        (6, "working"),
    ] {
        let response = exchange(
            &mut input,
            &mut output,
            serde_json::json!({
                "jsonrpc":"2.0", "id":id, "method":"tools/call", "params": {
                    "name":"ssh_open_session", "arguments": {
                        "host":"target", "role":role, "access_class":"read_only",
                        "purpose":"Verify account credential isolation"
                    }
                }
            }),
        )
        .await;
        let result = response.get("result").expect("tool response");
        if role == "working" {
            assert_ne!(
                result.get("isError").and_then(serde_json::Value::as_bool),
                Some(true)
            );
            let session = result
                .pointer("/structuredContent/session")
                .expect("authenticated session");
            let closed = exchange(&mut input, &mut output, serde_json::json!({
                "jsonrpc":"2.0", "id":10, "method":"tools/call", "params": {
                    "name":"ssh_close_session", "arguments": {
                        "host":"target", "role":role, "access_class":"read_only", "session":session
                    }
                }
            })).await;
            assert_ne!(
                closed
                    .pointer("/result/isError")
                    .and_then(serde_json::Value::as_bool),
                Some(true)
            );
        } else {
            assert_eq!(
                result.get("isError").and_then(serde_json::Value::as_bool),
                Some(true)
            );
            assert!(
                result
                    .to_string()
                    .contains("the credential for that role is unavailable")
            );
        }
    }
    assert_eq!(authentications.load(Ordering::SeqCst), 2);
    drop(input);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    let mut diagnostics = String::new();
    errors.read_to_string(&mut diagnostics).await.unwrap();
    for variable in [
        "MCP_SSH_CREDENTIAL_EMPTY",
        "MCP_SSH_CREDENTIAL_MISSING",
        "MCP_SSH_CREDENTIAL_MALFORMED",
    ] {
        assert!(diagnostics.contains(variable));
    }
    assert!(!diagnostics.contains("not-a-private-key"));
    assert!(!diagnostics.contains("PRIVATE KEY"));
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn ambiguous_credential_mappings_still_prevent_protocol_startup() {
    let fixture = Fixture::new();
    let registry = serde_json::json!({"target": {
        "address": "127.0.0.1:1", "host_key": "SHA256:AAAA1111", "roles": {
            "first": {"user":"test-user", "access_class":"read_only", "credential":"a-b"},
            "second": {"user":"test-user", "access_class":"read_only", "credential":"a/b"}
        }
    }});
    std::fs::write(fixture.0.join("registry.json"), registry.to_string()).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), fixture.command().output())
        .await
        .unwrap()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let diagnostics = String::from_utf8_lossy(&result.stderr);
    assert!(diagnostics.contains("credential references collide"));
    assert!(diagnostics.contains("MCP_SSH_CREDENTIAL_A_B"));
}
