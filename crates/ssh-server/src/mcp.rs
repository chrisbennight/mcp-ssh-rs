//! The MCP server, and where caller identity comes from.
//!
//! # Identity
//!
//! The HTTP ingress establishes a principal using the configured authentication
//! mode. This module reads that principal from request extensions before listing
//! or dispatching tools. Tool arguments cannot supply it.
//!
//! `get_info` has no error return, so HTTP authentication covers the handshake
//! and protocol liveness traffic as well. The unauthenticated `/healthz` probe
//! is a separate route.
//!
//! [`dispatch`](crate::tools::dispatch) takes an [`AuthenticatedPrincipal`], which only
//! this crate can construct after admission.

use std::sync::Arc;

use rmcp::model::{
    CallToolRequestParams, CallToolResult, Extensions, Implementation, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo,
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
Mediated SSH on the hosts this service is configured for. You never hold an \
SSH credential and never choose a host address: name a host and a role from \
ssh_hosts, say what the work is for, and every command is authorized \
individually against policy.

Commands are argument vectors, not shell lines. Each execution must include \
your bounded intent for that command; it is shown and recorded as \
agent-supplied evidence, not trusted user intent. A command may run, may be \
refused, or may need a human to approve it; a refusal is an answer and \
retrying it unchanged will not help. Ask for the smallest scope the work \
needs \u{2014} a larger one does not make approval more likely.";

/// The principal established by HTTP authentication.
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
        }
    }
}

impl<C: Clock, S: CredentialSource> Clone for SshMcp<C, S> {
    fn clone(&self) -> Self {
        Self {
            bastion: Arc::clone(&self.bastion),
            notifier: Arc::clone(&self.notifier),
            dashboard: self.dashboard.clone(),
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
        acting_for(&context.extensions)?;
        Ok(tools::catalog())
    }

    async fn call_tool(
        &self,
        params: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let principal = acting_for(&context.extensions)?.clone();
        tools::dispatch(
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
    // principal lives inside it. Read it from there — the top level never holds
    // it on the wire, only the tests that construct a context by hand once did.
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

    /// The check above is only worth having if every handler performs it, and
    /// the risk is a handler added later that quietly does not.
    ///
    /// Calling the handlers would be the better test and is not available: a
    /// `RequestContext` needs a `Peer`, which rmcp only constructs internally,
    /// so there is no way to hand one to `list_tools` from here. What can be
    /// checked is that each handler that *can* refuse does ask — `get_info`
    /// returns server information rather than a result and has no request to
    /// read, which is why it is not among them and why the module says so.
    #[test]
    fn every_handler_that_can_refuse_asks_who_is_calling() {
        let source = include_str!("mcp.rs");
        let (_, handlers) = source
            .split_once("impl<C: Clock + 'static, S: CredentialSource + 'static> ServerHandler")
            .expect("the handler implementation is where the requests arrive");
        let handlers = handlers
            .split_once("\n}\n")
            .expect("the implementation block ends")
            .0;

        let asked: Vec<&str> = handlers.split("\n    async fn ").skip(1).collect();
        assert!(
            !asked.is_empty(),
            "no request handlers found; this test has stopped reading what it thinks it reads"
        );
        for handler in asked {
            let name = handler.split('(').next().unwrap_or(handler);
            assert!(
                handler.contains("acting_for("),
                "{name} answers a request without asking who is calling"
            );
        }
    }
}
