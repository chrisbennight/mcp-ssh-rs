//! Admission and byte limits for authenticated MCP control requests.

use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse as _, Response},
};
use futures_util::StreamExt as _;
use tokio::sync::Semaphore;

// Includes the worst-case JSON escaping of a valid command and its metadata.
const BODY_BYTES: usize = 256 * 1024;
const READ_WITHIN: Duration = Duration::from_secs(10);
const IN_FLIGHT: usize = 64;

#[derive(Clone)]
pub(crate) struct Limits {
    capacity: Arc<Semaphore>,
    body_bytes: usize,
    read_within: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            capacity: Arc::new(Semaphore::new(IN_FLIGHT)),
            body_bytes: BODY_BYTES,
            read_within: READ_WITHIN,
        }
    }
}

/// Mounted inside authentication and only on the MCP control route.
pub(crate) async fn admit(State(limits): State<Limits>, request: Request, next: Next) -> Response {
    let Ok(permit) = Arc::clone(&limits.capacity).try_acquire_owned() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP request capacity reached",
        );
    };
    let (parts, body) = request.into_parts();
    let body =
        match tokio::time::timeout(limits.read_within, collect(body, limits.body_bytes)).await {
            Ok(Ok(body)) => body,
            Ok(Err(status)) => return refuse(status, "MCP request body was refused"),
            Err(_) => return refuse(StatusCode::REQUEST_TIMEOUT, "MCP request body timed out"),
        };
    let response = next.run(Request::from_parts(parts, body)).await;
    let (parts, body) = response.into_parts();
    // MCP can return a streaming response before its handler has completed.
    // Keep admission until that response completes or the caller drops it.
    let held = futures_util::stream::unfold(
        (body.into_data_stream(), permit),
        |(mut body, permit)| async move { body.next().await.map(|chunk| (chunk, (body, permit))) },
    );
    Response::from_parts(parts, Body::from_stream(held))
}

async fn collect(body: Body, limit: usize) -> Result<Body, StatusCode> {
    let mut stream = body.into_data_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| StatusCode::BAD_REQUEST)?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > limit)
        {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Body::from(bytes))
}

fn refuse(status: StatusCode, message: &'static str) -> Response {
    (status, axum::Json(serde_json::json!({"error": message}))).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::{Router, body::Bytes, middleware, routing::post};
    use std::convert::Infallible;
    use tower::ServiceExt as _;

    fn app(limits: Limits) -> Router {
        Router::new()
            .route("/", post(|body: Bytes| async move { body }))
            .layer(middleware::from_fn_with_state(limits, admit))
    }

    fn request(body: Body) -> Request {
        Request::builder()
            .method("POST")
            .uri("/")
            .body(body)
            .unwrap()
    }

    #[tokio::test]
    async fn known_length_and_chunked_bodies_obey_the_same_bound() {
        for chunked in [false, true] {
            for (size, status) in [(8, StatusCode::OK), (9, StatusCode::PAYLOAD_TOO_LARGE)] {
                let body = if chunked {
                    Body::from_stream(futures_util::stream::iter(
                        (0..size).map(|_| Ok::<_, Infallible>(Bytes::from_static(b"x"))),
                    ))
                } else {
                    Body::from(vec![b'x'; size])
                };
                let mut request = request(body);
                if !chunked {
                    request.headers_mut().insert("content-length", size.into());
                }
                let response = app(Limits {
                    body_bytes: 8,
                    ..Limits::default()
                })
                .oneshot(request)
                .await
                .unwrap();
                assert_eq!(response.status(), status);
                if status == StatusCode::OK {
                    assert_eq!(
                        axum::body::to_bytes(response.into_body(), 8).await.unwrap(),
                        vec![b'x'; size]
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn timed_out_and_cancelled_bodies_release_admission() {
        let limits = Limits {
            capacity: Arc::new(Semaphore::new(1)),
            read_within: Duration::from_millis(20),
            ..Limits::default()
        };
        let app = app(limits.clone());
        let pending =
            || Body::from_stream(futures_util::stream::pending::<Result<Bytes, Infallible>>());
        let response = app.clone().oneshot(request(pending())).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(limits.capacity.available_permits(), 1);
        let app = self::app(Limits {
            read_within: Duration::from_secs(60),
            ..limits.clone()
        });
        let task = tokio::spawn(app.clone().oneshot(request(pending())));
        tokio::time::timeout(Duration::from_secs(5), async {
            while limits.capacity.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let response = app.clone().oneshot(request(Body::empty())).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        task.abort();
        let _ = task.await;
        assert_eq!(limits.capacity.available_permits(), 1);
        assert_eq!(
            app.oneshot(request(Body::empty())).await.unwrap().status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn response_streams_keep_admission_until_consumed_or_dropped() {
        let limits = Limits {
            capacity: Arc::new(Semaphore::new(1)),
            ..Limits::default()
        };
        let app = app(limits.clone());
        let response = app
            .clone()
            .oneshot(request(Body::from("reply")))
            .await
            .unwrap();
        assert_eq!(limits.capacity.available_permits(), 0);
        assert_eq!(
            app.clone()
                .oneshot(request(Body::empty()))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(response);
        assert_eq!(limits.capacity.available_permits(), 1);
        let response = app.oneshot(request(Body::from("reply"))).await.unwrap();
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 8).await.unwrap(),
            "reply"
        );
        assert_eq!(limits.capacity.available_permits(), 1);
    }

    #[tokio::test]
    async fn a_body_error_is_not_reported_as_a_size_violation() {
        let body = Body::from_stream(futures_util::stream::once(async {
            Err::<Bytes, _>(std::io::Error::other("synthetic read failure"))
        }));
        assert_eq!(
            app(Limits::default())
                .oneshot(request(body))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn maximum_escaped_command_fits_the_control_envelope() {
        // This reaches the command byte bound with JSON's longest byte escape.
        let args = vec!["\u{1}".repeat(128 * 1024 / 4 - 1024 * 3)];
        ssh_core::command::Command::new(args.clone()).unwrap();
        let json = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "ssh_exec", "_meta": {"progressToken": "p".repeat(16 * 1024)}, "arguments": {
                "host": "h".repeat(128), "role": "r".repeat(128),
                "access_class": "privileged", "session": "s".repeat(256),
                "intent": "\u{1}".repeat(512), "command": args,
            }},
        });
        let body = Body::from(serde_json::to_vec(&json).unwrap());
        assert!(collect(body, BODY_BYTES).await.is_ok());
    }
}
