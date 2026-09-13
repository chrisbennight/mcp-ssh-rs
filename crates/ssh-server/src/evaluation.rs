//! Separately authenticated ingestion for external advisory evaluations.
//!
//! Evaluators append evidence; they never decide authorization. Their bearer
//! is deliberately accepted on no agent or human-review route, and their
//! deployment-owned name cannot be supplied in request JSON.

use std::sync::Arc;

use axum::extract::{FromRequest as _, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse as _, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Serialize;
use ssh_core::audit::{AuditError, EvaluationArtifact, EvaluationDraft};
use ssh_core::clock::Clock;
use ssh_core::connect::CredentialSource;
use ssh_core::mediate::Bastion;

use crate::settings::EvaluatorSettings;

/// Endpoint an external evaluator appends immutable evidence to.
pub const EVALUATION_API_PATH: &str = "/api/evaluations";

struct EvaluationState<C: Clock, S: CredentialSource> {
    bastion: Arc<Bastion<C, S>>,
    evaluator: EvaluatorSettings,
}

/// Builds the optional evaluator-only API surface.
pub fn routes<C, S>(bastion: Arc<Bastion<C, S>>, evaluator: EvaluatorSettings) -> Router
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    Router::new()
        .route(EVALUATION_API_PATH, post(submit::<C, S>))
        .with_state(Arc::new(EvaluationState { bastion, evaluator }))
}

#[derive(Serialize)]
struct Accepted {
    evaluation_id: String,
    audit_sequence: u64,
    audit_digest: String,
    /// Constant because evaluation evidence is never authorization.
    advisory: bool,
}

async fn submit<C, S>(State(state): State<Arc<EvaluationState<C, S>>>, request: Request) -> Response
where
    C: Clock + 'static,
    S: CredentialSource + 'static,
{
    // Authenticate before asking serde to inspect attacker-controlled input.
    // The evaluator endpoint has a deliberately small JSON contract, but an
    // unauthenticated caller should not receive parser work or schema clues.
    if !accepted(request.headers(), &state.evaluator) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Json(draft) = match Json::<EvaluationDraft>::from_request(request, &state).await {
        Ok(draft) => draft,
        Err(rejection) => return rejection.into_response(),
    };
    let artifact = match EvaluationArtifact::from_draft(draft, state.evaluator.name.clone()) {
        Ok(artifact) => artifact,
        Err(why) => return (StatusCode::BAD_REQUEST, why.to_string()).into_response(),
    };
    let evaluation_id = artifact.evaluation_id().to_owned();
    match state.bastion.record_evaluation(artifact) {
        Ok(entry) => (
            StatusCode::CREATED,
            Json(Accepted {
                evaluation_id,
                audit_sequence: entry.sequence,
                audit_digest: entry.digest.as_str().to_owned(),
                advisory: true,
            }),
        )
            .into_response(),
        Err(AuditError::EvaluationDecisionUnknown { .. }) => {
            (StatusCode::NOT_FOUND, "no such readable command decision").into_response()
        }
        Err(AuditError::EvaluationConflict { .. }) => (
            StatusCode::CONFLICT,
            "evaluation id already has different evidence",
        )
            .into_response(),
        Err(AuditError::DecisionAlreadyEvaluated { .. }) => (
            StatusCode::CONFLICT,
            "decision already has evaluation evidence",
        )
            .into_response(),
        Err(AuditError::NotRecorded) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "evaluation could not cross the audit boundary",
        )
            .into_response(),
        Err(why) => {
            tracing::error!(%why, evaluation_id, "an evaluation could not be recorded");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn accepted(headers: &HeaderMap, evaluator: &EvaluatorSettings) -> bool {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(raw) = value.to_str() else {
        return false;
    };
    let Some((scheme, token)) = raw.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && evaluator.bearers.accepts(token.as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::ingress::SharedBearer;
    use axum::body::Body;
    use axum::http::HeaderValue;
    use axum::http::Request as HttpRequest;
    use ssh_core::policy::Engine;
    use ssh_core::registry::Registry;
    use tower::ServiceExt as _;

    fn evaluator() -> EvaluatorSettings {
        EvaluatorSettings {
            bearers: Arc::new(
                SharedBearer::new("0123456789abcdef0123456789abcdef".to_owned(), None).unwrap(),
            ),
            name: "intent-reviewer".to_owned(),
        }
    }

    #[test]
    fn only_one_evaluator_bearer_is_accepted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer 0123456789abcdef0123456789abcdef"),
        );
        assert!(accepted(&headers, &evaluator()));
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer 0123456789abcdef0123456789abcdef"),
        );
        assert!(!accepted(&headers, &evaluator()));
    }

    #[test]
    fn agent_and_proxy_credentials_are_not_evaluator_credentials() {
        for bearer in [
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
            );
            assert!(!accepted(&headers, &evaluator()));
        }
    }

    struct NoCredentials;

    impl CredentialSource for NoCredentials {
        async fn fetch(
            &self,
            _reference: &ssh_core::registry::CredentialRef,
        ) -> Result<ssh_core::secret::Secret<String>, ssh_core::connect::CredentialError> {
            Err(ssh_core::connect::CredentialError::NotFound)
        }
    }

    fn app() -> Router {
        let bastion = Arc::new(Bastion::new(
            Arc::new(ssh_core::clock::TestClock::at(1_000)),
            Registry::from_json("{}").unwrap(),
            Engine::new(ssh_core::policy::ReviewMode::Privileged),
            NoCredentials,
            crate::settings::bounds(),
        ));
        routes(bastion, evaluator())
    }

    async fn post(body: &'static str, bearer: Option<&str>) -> StatusCode {
        let mut builder = HttpRequest::builder()
            .method("POST")
            .uri(EVALUATION_API_PATH)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(bearer) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
        }
        app()
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn authentication_happens_before_request_body_parsing() {
        assert_eq!(post("{", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            post("{", Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            post("{", Some("0123456789abcdef0123456789abcdef")).await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn an_evaluation_cannot_name_an_unrecorded_decision() {
        let body = r#"{
            "evaluation_id":"eval-1",
            "decision_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "model":"review-model",
            "prompt_version":"v1",
            "verdict":"uncertain",
            "confidence":42,
            "rationale":"No readable decision exists.",
            "side_effects":[]
        }"#;
        assert_eq!(
            post(body, Some("0123456789abcdef0123456789abcdef")).await,
            StatusCode::NOT_FOUND
        );
    }
}
