//! The MCP server, and where caller identity comes from.
//!
//! # Identity
//!
//! HTTP reads the authenticated principal from request extensions. Stdio uses
//! the fixed launch identity supplied when its handler is created. Tool arguments
//! cannot supply either identity.
//!
//! `get_info` has no error return, so HTTP authentication covers the handshake
//! and protocol liveness traffic as well. The unauthenticated `/healthz` probe
//! is a separate route.
//!
//! [`dispatch`](crate::tools::dispatch) takes an [`AuthenticatedPrincipal`], which only
//! this crate can construct after admission.

use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, CustomRequest, CustomResult, Extensions, Implementation,
    ListToolsResult, PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use ssh_core::PrincipalId;
use ssh_core::clock::Clock;
use ssh_core::connect::CredentialSource;
use ssh_core::mediate::Bastion;
use url::Url;

use crate::notify::Notifier;

use crate::tools;

const INSTRUCTIONS: &str = "\
SSH on configured accounts. You never hold an SSH credential or choose a host \
address. Select a host, role, and configured access_class from ssh_hosts. \
Those arguments must match the account and remain fixed for the session. \
A label does not grant permissions or certify that an account cannot write.

Commands are argument vectors. Each execution includes bounded intent, shown \
and recorded as agent-supplied evidence, not trusted user intent. Target account \
permissions govern what commands can do. Local human review, when configured, \
applies by account rather than command content. A command may run, be refused, \
or await approval. A refusal is not permission to retry unchanged. Poll a \
running command and investigate an unknown outcome before submitting it again.";

/// A principal established by HTTP authentication or stdio launch authority.
///
/// A distinct type so it cannot be confused with a principal a caller named,
/// and constructible only inside this crate: the ingress layer makes one after
/// checking the configured identity source, and nothing outside can make one at all.
/// A `PrincipalId` says who somebody is; this says who vouched for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedPrincipal(PrincipalId);

impl AuthenticatedPrincipal {
    /// Made by the ingress layer after authenticating the configured identity
    /// source. Crate-private so callers cannot supply their own principal.
    #[must_use]
    pub(crate) const fn new(principal: PrincipalId) -> Self {
        Self(principal)
    }

    #[must_use]
    pub const fn get(&self) -> &PrincipalId {
        &self.0
    }
}

/// The MCP surface over a bastion.
pub struct SshMcp<C: Clock, S: CredentialSource> {
    bastion: Arc<Bastion<C, S>>,
    /// Where a human is told that something is waiting, and where to answer it.
    ///
    /// Optional in effect rather than in type: a deployment that configures no
    /// notifier gets [`Silence`](crate::notify::Silence), and a deployment that
    /// does not say where its dashboard is gets no notes, because a note whose
    /// link goes nowhere looks like the way to answer and is not.
    notifier: Arc<dyn Notifier>,
    dashboard: Option<Url>,
    launch_principal: Option<AuthenticatedPrincipal>,
    transfers: Option<Arc<crate::transfer::Transfers>>,
}

impl<C: Clock, S: CredentialSource> SshMcp<C, S> {
    #[must_use]
    pub const fn new(
        bastion: Arc<Bastion<C, S>>,
        notifier: Arc<dyn Notifier>,
        dashboard: Option<Url>,
    ) -> Self {
        Self {
            bastion,
            notifier,
            dashboard,
            launch_principal: None,
            transfers: None,
        }
    }

    /// The launcher owns the stdio process and its configured account access.
    pub(crate) fn with_launch_principal(mut self, principal: PrincipalId) -> Self {
        self.launch_principal = Some(AuthenticatedPrincipal::new(principal));
        self
    }

    pub(crate) fn with_transfers(
        mut self,
        transfers: Option<Arc<crate::transfer::Transfers>>,
    ) -> Self {
        self.transfers = transfers;
        self
    }

    fn principal<'a>(
        &'a self,
        extensions: &'a Extensions,
    ) -> Result<&'a AuthenticatedPrincipal, McpError> {
        match &self.launch_principal {
            Some(principal) => Ok(principal),
            None => acting_for(extensions),
        }
    }
}

impl<C: Clock, S: CredentialSource> Clone for SshMcp<C, S> {
    fn clone(&self) -> Self {
        Self {
            bastion: Arc::clone(&self.bastion),
            notifier: Arc::clone(&self.notifier),
            dashboard: self.dashboard.clone(),
            launch_principal: self.launch_principal.clone(),
            transfers: self.transfers.clone(),
        }
    }
}

impl<C: Clock + 'static, S: CredentialSource + 'static> ServerHandler for SshMcp<C, S> {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::V_2025_11_25)
            .with_server_info(Implementation::new("mcp-ssh-rs", env!("CARGO_PKG_VERSION")))
            .with_instructions(INSTRUCTIONS)
    }

    async fn list_tools(
        &self,
        _params: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        // Discovery is a request like any other. Answering it for a caller the
        // gateway did not vouch for would tell something that should not have
        // reached this service what it could try next.
        self.principal(&context.extensions)?;
        Ok(tools::catalog_with_files(self.transfers.as_deref()))
    }

    async fn on_custom_request(
        &self,
        request: CustomRequest,
        context: RequestContext<RoleServer>,
    ) -> Result<CustomResult, McpError> {
        let principal = self.principal(&context.extensions)?.get();
        let store = self
            .transfers
            .as_ref()
            .ok_or_else(|| McpError::invalid_request("file transfer is not configured", None))?;
        let params = request.params.unwrap_or_else(|| serde_json::json!({}));
        let value = match request.method.as_str() {
            crate::transfer::AUTHORIZE_UPLOAD => {
                let params = serde_json::from_value(params)
                    .map_err(|_| McpError::invalid_params("invalid upload options", None))?;
                serde_json::to_value(
                    store
                        .authorize_upload(principal, params)
                        .map_err(|error| McpError::invalid_params(error.to_string(), None))?,
                )
            }
            crate::transfer::AUTHORIZE_DOWNLOAD => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct DownloadParams {
                    uri: String,
                    #[serde(rename = "_meta")]
                    _meta: Option<serde_json::Value>,
                }
                let params: DownloadParams = serde_json::from_value(params)
                    .map_err(|_| McpError::invalid_params("invalid download options", None))?;
                serde_json::to_value(
                    store
                        .authorize_download(principal, &params.uri)
                        .map_err(|error| McpError::invalid_params(error.to_string(), None))?,
                )
            }
            _ => {
                return Err(McpError::new(
                    rmcp::model::ErrorCode::METHOD_NOT_FOUND,
                    "unknown method",
                    None,
                ));
            }
        }
        .map_err(|_| McpError::internal_error("could not encode file authorization", None))?;
        Ok(CustomResult::new(value))
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = self.principal(&context.extensions)?.clone();
        tools::dispatch_with_files(
            self.transfers.as_ref(),
            &self.bastion,
            self.notifier.as_ref(),
            self.dashboard.as_ref(),
            &principal,
            params,
        )
        .await
    }
}

/// Who the gateway says this request is for.
///
/// No principal, no answer. Serving a request as nobody, or as a default, would
/// put an unattributable entry in the record — and the record is what the whole
/// service is for. Read here rather than in each handler so no handler can be
/// added that forgets to ask.
///
/// Takes what it reads rather than the whole request, so the refusal can be
/// asked for directly.
fn acting_for(extensions: &Extensions) -> Result<&AuthenticatedPrincipal, McpError> {
    // The ingress layer attaches the principal to the HTTP request. The
    // transport does not surface that request's extensions here directly; it
    // carries the whole `http::request::Parts` as a single extension, and the
    // principal lives inside it. Top-level extensions cannot establish HTTP identity.
    extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<AuthenticatedPrincipal>())
        .ok_or_else(|| McpError::invalid_request("no authenticated caller identity", None))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The instructions are what an agent reads before its first call, so the
    /// things it will otherwise get wrong belong there: commands are vectors,
    /// command intent is required and agent-supplied, and a refusal is not
    /// something to retry.
    #[test]
    fn the_instructions_say_what_an_agent_would_otherwise_assume() {
        assert!(INSTRUCTIONS.contains("argument vectors"));
        assert!(INSTRUCTIONS.contains("agent-supplied evidence"));
        assert!(INSTRUCTIONS.contains("not trusted user intent"));
        assert!(INSTRUCTIONS.contains("refus"));
        assert!(
            INSTRUCTIONS.contains("never hold an SSH credential"),
            "an agent should not go looking for one"
        );
    }

    /// A principal is wrapped rather than passed as a bare `PrincipalId`, so
    /// something the gateway vouched for cannot be confused with a string a
    /// caller sent.
    #[test]
    fn a_gateway_principal_is_a_distinct_type() {
        let principal = PrincipalId::parse("alice").unwrap();
        let wrapped = AuthenticatedPrincipal::new(principal.clone());
        assert_eq!(wrapped.get(), &principal);
    }

    /// The context the transport hands a handler the way the transport builds
    /// it: the HTTP request's `Parts` carried as one extension, with the
    /// principal the ingress attached living inside those parts. Constructing it
    /// any other way would test a shape that never arrives on the wire.
    fn context_extensions(principal: Option<AuthenticatedPrincipal>) -> Extensions {
        let mut request = axum::http::Request::new(());
        if let Some(principal) = principal {
            request.extensions_mut().insert(principal);
        }
        let (parts, ()) = request.into_parts();
        let mut extensions = Extensions::new();
        extensions.insert(parts);
        extensions
    }

    /// Nothing is served to a caller the gateway did not vouch for. Both
    /// handlers ask the same question of the same place, so this is that
    /// question: without an identity there is no answer, and no default. The
    /// missing cases are both real: a request that never reached the ingress
    /// (no parts at all) and one whose parts carry no principal.
    #[test]
    fn a_request_the_gateway_did_not_vouch_for_is_refused() {
        assert!(
            acting_for(&Extensions::new()).is_err(),
            "a request with no request parts was served"
        );
        assert!(
            acting_for(&context_extensions(None)).is_err(),
            "a request whose parts carry no gateway identity was served"
        );

        let alice = PrincipalId::parse("alice").unwrap();
        let vouched = context_extensions(Some(AuthenticatedPrincipal::new(alice.clone())));
        assert_eq!(
            acting_for(&vouched).expect("a vouched-for request").get(),
            &alice
        );
    }

    #[tokio::test]
    async fn stdio_uses_launch_identity_without_http_extensions() {
        use rmcp::ServiceExt as _;
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
        struct NoCredentials;
        impl CredentialSource for NoCredentials {
            async fn fetch(
                &self,
                _: &ssh_core::registry::CredentialRef,
            ) -> Result<ssh_core::secret::Secret<String>, ssh_core::connect::CredentialError>
            {
                panic!("discovery must not fetch credentials")
            }
        }
        let bastion = Arc::new(Bastion::new(
            Arc::new(ssh_core::clock::TestClock::at(0)),
            ssh_core::registry::Registry::from_json("{}").unwrap(),
            ssh_core::policy::Engine::new(ssh_core::policy::ReviewMode::Disabled),
            NoCredentials,
            crate::settings::bounds(),
        ));
        let handler = SshMcp::new(bastion, Arc::new(crate::notify::Silence), None)
            .with_launch_principal(PrincipalId::parse("launcher").unwrap())
            .with_transfers(Some(Arc::new(
                crate::transfer::Transfers::new(
                    Arc::new(ssh_core::clock::TestClock::at(0)),
                    "https://ssh.example",
                )
                .unwrap(),
            )));
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            handler
                .serve(server)
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap()
        });
        let (reader, mut writer) = tokio::io::split(client);
        let mut reader = BufReader::new(reader);
        for (request, expect_error) in [
            (
                serde_json::json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{"protocolVersion":"2025-11-25", "capabilities":{}, "clientInfo":{"name":"test", "version":"test"}}}),
                false,
            ),
            (
                serde_json::json!({"jsonrpc":"2.0", "id":5, "method":"files/authorizeUpload", "params":{"size":0}}),
                false,
            ),
            (
                serde_json::json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
                false,
            ),
            (
                serde_json::json!({"jsonrpc":"2.0", "id":3, "method":"tools/call", "params":{"name":"ssh_hosts", "arguments":{}}}),
                false,
            ),
            (
                serde_json::json!({"jsonrpc":"2.0", "id":4, "method":"tools/call", "params":{"name":"ssh_hosts", "arguments":{"principal":"someone-else"}}}),
                true,
            ),
        ] {
            let mut bytes = serde_json::to_vec(&request).unwrap();
            bytes.push(b'\n');
            writer.write_all(&bytes).await.unwrap();
            let mut line = String::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                reader.read_line(&mut line),
            )
            .await
            .unwrap()
            .unwrap();
            let response: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(response.get("id").unwrap(), request.get("id").unwrap());
            assert_eq!(response.get("error").is_some(), expect_error);
            if request.get("id").and_then(serde_json::Value::as_u64) == Some(1) {
                writer
                    .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
                    .await
                    .unwrap();
            }
        }
        drop(writer);
        drop(reader);
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
}
