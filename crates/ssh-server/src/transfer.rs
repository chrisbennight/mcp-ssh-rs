//! Bounded byte storage and the upstream Waygate file-transfer protocol.

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use ssh_core::{PrincipalId, clock::Clock, files::MAX_TRANSFER_BYTES, transfer::DownloadSink};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq as _;

pub const AUTHORIZE_UPLOAD: &str = "files/authorizeUpload";
pub const AUTHORIZE_DOWNLOAD: &str = "files/authorizeDownload";
const URI_PREFIX: &str = "mcp-file://mcp-ssh/";
const HEADER: &str = "x-mcp-transfer-credential";
const TTL: u64 = 300_000;
const MAX_ITEMS: usize = 16;
const OWNER_ITEMS: usize = 4;

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema, PartialEq, Eq)]
pub struct FileDigest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<FileDigest>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UploadParams {
    #[serde(rename = "_meta")]
    pub meta: Option<serde_json::Value>,
    pub name: Option<String>,
    pub mime_type: Option<String>,
    pub size: Option<u64>,
    pub digest: Option<FileDigest>,
}

#[derive(Serialize)]
pub struct Descriptor {
    pub transport: &'static str,
    pub method: &'static str,
    pub url: String,
    // Deliberately no Debug implementation: headers contain a byte-transfer credential.
    pub headers: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct UploadResult {
    pub file: Reference,
    pub upload: Descriptor,
}
#[derive(Serialize)]
pub struct DownloadResult {
    pub file: Reference,
    pub download: Descriptor,
    pub sensitivity: &'static str,
}

struct Ticketed {
    id: String,
    bytes: Option<Arc<[u8]>>,
}

struct Ticket {
    id: String,
    credential: [u8; 32],
}
enum Content {
    Pending,
    Receiving,
    Ready(Arc<[u8]>),
}
struct Item {
    local_file: Option<crate::local_files::OwnedFile>,
    owner: PrincipalId,
    created: u64,
    reference: Reference,
    content: Content,
    upload: bool,
    ticket: Option<Ticket>,
}

/// Every reserved item is charged at the full byte ceiling, including in-flight uploads and downloads.
pub struct Transfers {
    clock: Arc<dyn Clock>,
    origin: String,
    local: Option<crate::local_files::LocalFiles>,
    items: Mutex<HashMap<String, Item>>,
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum TransferError {
    #[error("file reference is unavailable")]
    Unknown,
    #[error("file transfer capacity is exhausted; release or let earlier references expire")]
    Capacity,
    #[error("file size or metadata exceeds its configured limit")]
    Limit,
    #[error("file size or SHA-256 digest does not match the declared content")]
    Integrity,
    #[error(
        "file transfer origin must be an HTTP(S) origin without credentials, path, query, or fragment"
    )]
    Origin,
}

impl Transfers {
    pub fn new(clock: Arc<dyn Clock>, origin: &str) -> Result<Self, TransferError> {
        let url = url::Url::parse(origin).map_err(|_| TransferError::Origin)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(TransferError::Origin);
        }
        Ok(Self {
            clock,
            origin: url.as_str().trim_end_matches('/').to_owned(),
            local: None,
            items: Mutex::new(HashMap::new()),
        })
    }

    pub fn local(clock: Arc<dyn Clock>, root: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            clock,
            origin: String::new(),
            local: Some(crate::local_files::LocalFiles::new(root)?),
            items: Mutex::new(HashMap::new()),
        })
    }
    pub const fn is_local(&self) -> bool {
        self.local.is_some()
    }

    fn reserve(
        &self,
        owner: &PrincipalId,
        params: UploadParams,
        upload: bool,
    ) -> Result<String, TransferError> {
        if params
            .size
            .is_some_and(|size| size > MAX_TRANSFER_BYTES as u64)
            || params.name.as_ref().is_some_and(|name| name.len() > 255)
            || params
                .mime_type
                .as_ref()
                .is_some_and(|mime| mime.len() > 255)
        {
            return Err(TransferError::Limit);
        }
        if let Some(digest) = &params.digest
            && (digest.algorithm != "sha-256"
                || URL_SAFE_NO_PAD
                    .decode(&digest.value)
                    .map_err(|_| TransferError::Integrity)?
                    .len()
                    != 32)
        {
            return Err(TransferError::Integrity);
        }
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let now = self.clock.now();
        items.retain(|_, item| {
            now.saturating_sub(item.created) < TTL
                || matches!(item.content, Content::Receiving)
                || matches!(&item.content, Content::Ready(bytes) if Arc::strong_count(bytes) > 1)
        });
        if items.len() >= MAX_ITEMS
            || items.values().filter(|item| item.owner == *owner).count() >= OWNER_ITEMS
        {
            return Err(TransferError::Capacity);
        }
        let id = token();
        items.insert(
            id.clone(),
            Item {
                local_file: None,
                owner: owner.clone(),
                created: now,
                upload,
                ticket: None,
                content: Content::Pending,
                reference: Reference {
                    uri: match &self.local {
                        Some(local) => local.uri(&id).map_err(|_| TransferError::Limit)?,
                        None => format!("{URI_PREFIX}{id}"),
                    },
                    name: params.name,
                    mime_type: params.mime_type,
                    size: params.size,
                    digest: params.digest,
                },
            },
        );
        Ok(id)
    }

    pub fn authorize_upload(
        &self,
        owner: &PrincipalId,
        params: UploadParams,
    ) -> Result<UploadResult, TransferError> {
        if self.local.is_some() {
            return Err(TransferError::Unknown);
        }
        let id = self.reserve(owner, params, true)?;
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let item = items.get_mut(&id).ok_or(TransferError::Unknown)?;
        let upload = self.issue(item, "PUT");
        Ok(UploadResult {
            file: item.reference.clone(),
            upload,
        })
    }

    pub fn authorize_download(
        &self,
        owner: &PrincipalId,
        uri: &str,
    ) -> Result<DownloadResult, TransferError> {
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let item = self.owned(&mut items, owner, uri)?;
        if !matches!(item.content, Content::Ready(_)) {
            return Err(TransferError::Unknown);
        }
        let download = self.issue(item, "GET");
        Ok(DownloadResult {
            file: item.reference.clone(),
            download,
            sensitivity: "secret",
        })
    }

    fn issue(&self, item: &mut Item, method: &'static str) -> Descriptor {
        let id = token();
        let credential = token();
        item.ticket = Some(Ticket {
            id: id.clone(),
            credential: hash(credential.as_bytes()),
        });
        Descriptor {
            transport: "http",
            method,
            url: format!("{}/files/bytes/{id}", self.origin),
            headers: HashMap::from([(HEADER.to_owned(), credential)]),
        }
    }

    fn owned<'a>(
        &self,
        items: &'a mut HashMap<String, Item>,
        owner: &PrincipalId,
        uri: &str,
    ) -> Result<&'a mut Item, TransferError> {
        let id = uri.strip_prefix(URI_PREFIX).ok_or(TransferError::Unknown)?;
        let item = items.get_mut(id).ok_or(TransferError::Unknown)?;
        if item.owner != *owner || self.clock.now().saturating_sub(item.created) >= TTL {
            return Err(TransferError::Unknown);
        }
        Ok(item)
    }

    pub fn input(
        &self,
        owner: &PrincipalId,
        uri: &str,
    ) -> Result<ssh_core::transfer::PreparedUpload, TransferError> {
        if let Some(local) = &self.local {
            return local.read(uri).map_err(|_| TransferError::Unknown);
        }
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let item = self.owned(&mut items, owner, uri)?;
        let Content::Ready(bytes) = &item.content else {
            return Err(TransferError::Unknown);
        };
        ssh_core::transfer::PreparedUpload::from_shared(uri.to_owned(), Arc::clone(bytes))
            .map_err(|_| TransferError::Limit)
    }

    pub fn destination(
        self: &Arc<Self>,
        owner: &PrincipalId,
        name: Option<String>,
    ) -> Result<Arc<dyn DownloadSink>, TransferError> {
        let id = self.reserve(
            owner,
            UploadParams {
                name,
                ..UploadParams::default()
            },
            false,
        )?;
        Ok(Arc::new(Destination {
            store: Arc::clone(self),
            id,
        }))
    }

    fn publish(
        &self,
        id: &str,
        bytes: Vec<u8>,
        receiving: bool,
    ) -> Result<ssh_core::action::FileIdentity, TransferError> {
        if bytes.len() > MAX_TRANSFER_BYTES {
            return Err(TransferError::Limit);
        }
        let digest = FileDigest {
            algorithm: "sha-256".to_owned(),
            value: URL_SAFE_NO_PAD.encode(hash(&bytes)),
        };
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let item = items.get_mut(id).ok_or(TransferError::Unknown)?;
        let expected_state = if receiving {
            matches!(item.content, Content::Receiving)
        } else {
            matches!(item.content, Content::Pending) && !item.upload
        };
        if !expected_state || self.clock.now().saturating_sub(item.created) >= TTL {
            return Err(TransferError::Unknown);
        }
        if item
            .reference
            .size
            .is_some_and(|size| size != bytes.len() as u64)
            || item
                .reference
                .digest
                .as_ref()
                .is_some_and(|expected| expected != &digest)
        {
            return Err(TransferError::Integrity);
        }
        let identity = ssh_core::transfer::identity(item.reference.uri.clone(), &bytes);
        item.reference.size = Some(bytes.len() as u64);
        item.reference.digest = Some(digest);
        if let Some(local) = &self.local {
            item.local_file = Some(
                local
                    .publish(id, &bytes)
                    .map_err(|_| TransferError::Limit)?,
            );
        }
        item.content = Content::Ready(bytes.into());
        Ok(identity)
    }

    fn take_ticket(
        &self,
        id: &str,
        credential: &str,
        upload: bool,
    ) -> Result<Ticketed, TransferError> {
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let (key, item) = items
            .iter_mut()
            .find(|(_, item)| item.ticket.as_ref().is_some_and(|ticket| ticket.id == id))
            .ok_or(TransferError::Unknown)?;
        let ticket = item.ticket.as_ref().ok_or(TransferError::Unknown)?;
        if self.clock.now().saturating_sub(item.created) >= TTL
            || !bool::from(hash(credential.as_bytes()).ct_eq(&ticket.credential))
        {
            return Err(TransferError::Unknown);
        }
        let bytes = match &item.content {
            Content::Pending if upload && item.upload => None,
            Content::Ready(bytes) if !upload => Some(Arc::clone(bytes)),
            _ => return Err(TransferError::Unknown),
        };
        item.ticket = None;
        if upload {
            item.content = Content::Receiving;
        }
        Ok(Ticketed {
            id: key.clone(),
            bytes,
        })
    }

    fn abandon(&self, id: &str) {
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        if items
            .get(id)
            .is_some_and(|item| !matches!(item.content, Content::Ready(_)))
        {
            items.remove(id);
        }
    }

    pub fn sweep(&self) {
        let now = self.clock.now();
        self.items
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|_, item| now.saturating_sub(item.created) < TTL || matches!(item.content, Content::Receiving) || matches!(&item.content, Content::Ready(bytes) if Arc::strong_count(bytes) > 1));
    }
}

struct Destination {
    store: Arc<Transfers>,
    id: String,
}
impl DownloadSink for Destination {
    fn publish(&self, bytes: Vec<u8>) -> Result<ssh_core::action::FileIdentity, String> {
        self.store
            .publish(&self.id, bytes, false)
            .map_err(|error| error.to_string())
    }
}
impl Drop for Destination {
    fn drop(&mut self) {
        self.store.abandon(&self.id);
    }
}
struct Receiving {
    store: Arc<Transfers>,
    id: String,
}
impl Drop for Receiving {
    fn drop(&mut self) {
        self.store.abandon(&self.id);
    }
}

pub fn routes(store: Arc<Transfers>) -> Router {
    if store.is_local() {
        return Router::new();
    }
    Router::new()
        .route("/files/bytes/{id}", get(download).put(upload))
        .with_state(store)
}

async fn download(
    State(store): State<Arc<Transfers>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    let Some(credential) = headers.get(HEADER).and_then(|value| value.to_str().ok()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match store.take_ticket(&id, credential, false) {
        Ok(Ticketed {
            bytes: Some(bytes), ..
        }) => (
            [
                ("content-type", "application/octet-stream"),
                ("cache-control", "no-store"),
            ],
            Body::from(Bytes::from_owner(bytes)),
        )
            .into_response(),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn upload(
    State(store): State<Arc<Transfers>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> StatusCode {
    let Some(credential) = headers.get(HEADER).and_then(|value| value.to_str().ok()) else {
        return StatusCode::NOT_FOUND;
    };
    let Ok(Ticketed { id, .. }) = store.take_ticket(&id, credential, true) else {
        return StatusCode::NOT_FOUND;
    };
    let receiving = Receiving { store, id };
    let Ok(Ok(bytes)) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        axum::body::to_bytes(body, MAX_TRANSFER_BYTES),
    )
    .await
    else {
        return StatusCode::BAD_REQUEST;
    };
    match receiving.store.publish(&receiving.id, bytes.to_vec(), true) {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

fn token() -> String {
    let mut bytes = [0_u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::Request;
    use ssh_core::clock::TestClock;
    use tower::ServiceExt as _;

    fn owner(name: &str) -> PrincipalId {
        PrincipalId::parse(name).unwrap()
    }
    fn plane() -> Arc<Transfers> {
        Arc::new(Transfers::new(Arc::new(TestClock::at(1000)), "https://ssh.example").unwrap())
    }
    fn request(descriptor: &Descriptor, body: Body) -> Request<Body> {
        let url = url::Url::parse(&descriptor.url).unwrap();
        Request::builder()
            .method(descriptor.method)
            .uri(url.path())
            .header(HEADER, descriptor.headers.get(HEADER).unwrap())
            .body(body)
            .unwrap()
    }

    #[tokio::test]
    async fn bytes_cross_the_http_adapter_with_integrity_and_single_use_tickets() {
        let store = plane();
        let caller = owner("caller");
        let bytes = vec![0, 255, 254, 1, 10];
        let upload = store
            .authorize_upload(
                &caller,
                UploadParams {
                    size: Some(bytes.len() as u64),
                    digest: Some(FileDigest {
                        algorithm: "sha-256".to_owned(),
                        value: URL_SAFE_NO_PAD.encode(hash(&bytes)),
                    }),
                    ..UploadParams::default()
                },
            )
            .unwrap();
        assert_eq!(upload.upload.transport, "http");
        assert!(store.input(&caller, &upload.file.uri).is_err());
        assert_eq!(
            routes(Arc::clone(&store))
                .oneshot(request(&upload.upload, Body::from(bytes.clone())))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            routes(Arc::clone(&store))
                .oneshot(request(&upload.upload, Body::empty()))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert!(store.input(&owner("other"), &upload.file.uri).is_err());
        assert_eq!(
            store
                .input(&caller, &upload.file.uri)
                .unwrap()
                .identity()
                .bytes,
            bytes.len() as u64
        );
        let download = store.authorize_download(&caller, &upload.file.uri).unwrap();
        assert_eq!(download.sensitivity, "secret");
        assert_eq!(download.file.size, Some(bytes.len() as u64));
        let response = routes(Arc::clone(&store))
            .oneshot(request(&download.download, Body::empty()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 100)
                .await
                .unwrap()
                .as_ref(),
            bytes.as_slice()
        );
        assert_eq!(
            routes(Arc::clone(&store))
                .oneshot(request(&download.download, Body::empty()))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert!(
            store.authorize_download(&caller, &upload.file.uri).is_ok(),
            "an interrupted fetch can obtain a new ticket for the same immutable file"
        );
    }

    #[tokio::test]
    async fn corrupt_uploads_never_become_tool_inputs() {
        let store = plane();
        let caller = owner("caller");
        let upload = store
            .authorize_upload(
                &caller,
                UploadParams {
                    size: Some(4),
                    ..UploadParams::default()
                },
            )
            .unwrap();
        let response = routes(Arc::clone(&store))
            .oneshot(request(&upload.upload, Body::from("bad")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(store.input(&caller, &upload.file.uri).is_err());
        assert!(
            store.items.lock().unwrap().is_empty(),
            "failed upload releases its reservation"
        );
        let upload = store
            .authorize_upload(
                &caller,
                UploadParams {
                    digest: Some(FileDigest {
                        algorithm: "sha-256".to_owned(),
                        value: URL_SAFE_NO_PAD.encode(hash(b"good")),
                    }),
                    ..UploadParams::default()
                },
            )
            .unwrap();
        assert_eq!(
            routes(Arc::clone(&store))
                .oneshot(request(&upload.upload, Body::from("evil")))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(store.input(&caller, &upload.file.uri).is_err());
    }

    #[test]
    fn pending_transfers_reserve_capacity_and_cancelled_downloads_release_it() {
        let store = plane();
        let caller = owner("caller");
        let sinks: Vec<_> = (0..OWNER_ITEMS)
            .map(|_| store.destination(&caller, None).unwrap())
            .collect();
        assert!(matches!(
            store.destination(&caller, None),
            Err(TransferError::Capacity)
        ));
        drop(sinks);
        assert!(store.items.lock().unwrap().is_empty());
        for group in 0..4 {
            let caller = owner(&format!("caller-{group}"));
            for _ in 0..OWNER_ITEMS {
                store
                    .authorize_upload(&caller, UploadParams::default())
                    .unwrap();
            }
        }
        assert!(matches!(
            store.authorize_upload(&owner("another"), UploadParams::default()),
            Err(TransferError::Capacity)
        ));
    }

    #[test]
    fn receiving_uploads_remain_charged_after_reference_expiry() {
        let clock = Arc::new(TestClock::at(1000));
        let store = Arc::new(Transfers::new(clock.clone(), "https://ssh.example").unwrap());
        let caller = owner("caller");
        let upload = store
            .authorize_upload(&caller, UploadParams::default())
            .unwrap();
        clock.advance(TTL.saturating_sub(1));
        let id = url::Url::parse(&upload.upload.url)
            .unwrap()
            .path_segments()
            .unwrap()
            .next_back()
            .unwrap()
            .to_owned();
        let ticketed = store
            .take_ticket(&id, upload.upload.headers.get(HEADER).unwrap(), true)
            .unwrap();
        let receiving = Receiving {
            store: Arc::clone(&store),
            id: ticketed.id,
        };
        clock.advance(1);
        store.sweep();
        assert_eq!(store.items.lock().unwrap().len(), 1);
        for _ in 1..OWNER_ITEMS {
            store
                .authorize_upload(&caller, UploadParams::default())
                .unwrap();
        }
        assert!(matches!(
            store.authorize_upload(&caller, UploadParams::default()),
            Err(TransferError::Capacity)
        ));
        assert!(
            store.publish(&receiving.id, Vec::new(), true).is_err(),
            "expiry still prevents publication"
        );
        drop(receiving);
        assert!(
            store
                .authorize_upload(&caller, UploadParams::default())
                .is_ok()
        );
    }

    #[test]
    fn expired_files_in_use_still_count_against_memory_capacity() {
        let clock = Arc::new(TestClock::at(1000));
        let store = Arc::new(Transfers::new(clock.clone(), "https://ssh.example").unwrap());
        let caller = owner("caller");
        let sink = store.destination(&caller, None).unwrap();
        let file = sink.publish(vec![1, 2, 3]).unwrap();
        let input = store.input(&caller, &file.uri).unwrap();
        clock.advance(TTL);
        store.sweep();
        assert_eq!(store.items.lock().unwrap().len(), 1);
        assert!(store.input(&caller, &file.uri).is_err());
        drop(input);
        store.sweep();
        assert!(store.items.lock().unwrap().is_empty());
    }
}
