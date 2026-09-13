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
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-ssh-rs"));
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
