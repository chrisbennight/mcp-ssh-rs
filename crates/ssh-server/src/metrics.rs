//! Optional, separately authenticated OpenMetrics export.

use std::sync::Arc;

use axum::{
    Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse as _, Response},
    routing::get,
};
use ssh_core::metrics::{CONTENT_TYPE, Metrics};

use crate::{ingress::SharedBearer, transfer::Transfers};

#[derive(Clone)]
struct Export {
    metrics: Arc<Metrics>,
    transfers: Option<Arc<Transfers>>,
    bearers: Arc<SharedBearer>,
}

pub fn routes(
    metrics: Arc<Metrics>,
    transfers: Option<Arc<Transfers>>,
    bearers: Arc<SharedBearer>,
) -> Router {
    Router::new()
        .route("/metrics", get(scrape))
        .with_state(Export {
            metrics,
            transfers,
            bearers,
        })
}

async fn scrape(State(state): State<Export>, headers: HeaderMap) -> Response {
    if !state.bearers.accepts_authorization(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let (reserved, items, snapshots) = state
        .transfers
        .as_ref()
        .map_or((0, 0, 0), |store| store.storage_usage());
    state.metrics.storage_usage(reserved, items, snapshots);
    match state.metrics.encode() {
        Ok(body) => (
            [
                (header::CONTENT_TYPE, CONTENT_TYPE),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderValue, Request},
    };
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn scrapes_require_the_export_credential_and_observe_storage_release() {
        let clock = Arc::new(ssh_core::clock::TestClock::at(0));
        let store = Arc::new(Transfers::new(clock.clone(), "https://example.invalid").unwrap());
        let metrics = Arc::new(Metrics::default());
        let app = routes(
            metrics,
            Some(store.clone()),
            Arc::new(
                SharedBearer::new("metrics-fixture-credential-0123456789".to_owned(), None)
                    .unwrap(),
            ),
        );
        for bearer in [None, Some("agent-fixture")] {
            let mut request = Request::builder().uri("/metrics");
            if let Some(bearer) = bearer {
                request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
            }
            assert_eq!(
                app.clone()
                    .oneshot(request.body(Body::empty()).unwrap())
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let principal = ssh_core::PrincipalId::parse("fixture").unwrap();
        store
            .authorize_upload(&principal, crate::transfer::UploadParams::default())
            .await
            .unwrap();
        let request = || {
            Request::builder()
                .uri("/metrics")
                .header(
                    header::AUTHORIZATION,
                    "Bearer metrics-fixture-credential-0123456789",
                )
                .body(Body::empty())
                .unwrap()
        };
        let response = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            CONTENT_TYPE
        );
        let body = axum::body::to_bytes(response.into_body(), 64 << 10)
            .await
            .unwrap();
        let body = std::str::from_utf8(&body).unwrap();
        assert!(body.contains("ssh_storage_items 1"));
        assert!(body.contains(&format!("ssh_storage_reserved_bytes {}", store.max_bytes())));
        clock.advance(300_001);
        store.sweep().await;
        let response = app.clone().oneshot(request()).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 64 << 10)
            .await
            .unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("ssh_storage_items 0")
        );
        let mut duplicate = request();
        duplicate.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer metrics-fixture-credential-0123456789"),
        );
        assert_eq!(
            app.oneshot(duplicate).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }
}
