//! Bounded byte storage and the upstream Waygate file-transfer protocol.

use crate::disk::{DiskFile, Snapshot};
use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::TryStreamExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use ssh_core::{
    PrincipalId,
    clock::Clock,
    transfer::{DownloadSink, Failure, TransferFuture},
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq as _;
use tokio_util::io::{ReaderStream, StreamReader};

pub const AUTHORIZE_UPLOAD: &str = "files/authorizeUpload";
pub const AUTHORIZE_DOWNLOAD: &str = "files/authorizeDownload";
const URI_PREFIX: &str = "mcp-file://mcp-ssh/";
const HEADER: &str = "x-mcp-transfer-credential";
const TTL: u64 = 300_000;

#[derive(Clone, Debug)]
pub struct TransferSettings {
    pub max_bytes: u64,
    pub timeout: std::time::Duration,
    pub staging: std::path::PathBuf,
}
impl Default for TransferSettings {
    fn default() -> Self {
        Self {
            max_bytes: 2_000_000_000,
            timeout: std::time::Duration::from_secs(1800),
            staging: std::env::temp_dir(),
        }
    }
}
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
    bytes: Option<Arc<Snapshot>>,
}

struct Ticket {
    id: String,
    credential: [u8; 32],
}
enum Content {
    Pending,
    Receiving,
    Ready(Arc<Snapshot>),
}
struct Item {
    local_file: Option<crate::local_files::OwnedFile>,
    owner: PrincipalId,
    created: u64,
    reference: Reference,
    content: Content,
    upload: bool,
    active: Option<Arc<DiskFile>>,
    ticket: Option<Ticket>,
    cleaning: bool,
    abandoned: bool,
}

impl Item {
    fn complete(
        &mut self,
        snapshot: Arc<Snapshot>,
        digest: FileDigest,
        local_file: Option<crate::local_files::OwnedFile>,
        now: u64,
    ) -> Result<ssh_core::action::FileIdentity, Failure> {
        // A successful rename must stay tracked even if receiving was cancelled during publication.
        self.local_file = local_file;
        if !matches!(self.content, Content::Receiving) {
            return Err(Failure::PublicationUnavailable);
        }
        let identity = snapshot.identity(self.reference.uri.clone());
        self.reference.size = Some(snapshot.size);
        self.reference.digest = Some(digest);
        self.content = Content::Ready(snapshot);
        self.active = None;
        // Completed content gets the full delivery window, independently of transfer duration.
        self.created = now;
        Ok(identity)
    }
}

/// Every reserved item is charged at the full byte ceiling, including in-flight uploads and downloads.
pub struct Transfers {
    clock: Arc<dyn Clock>,
    origin: String,
    local: Option<Arc<crate::local_files::LocalFiles>>,
    items: Arc<Mutex<HashMap<String, Item>>>,
    settings: TransferSettings,
    staging: Arc<std::fs::File>,
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
    #[error("file storage is unavailable")]
    Storage,
}

impl Transfers {
    pub fn new(clock: Arc<dyn Clock>, origin: &str) -> Result<Self, TransferError> {
        Self::configured(clock, origin, TransferSettings::default())
    }

    pub fn configured(
        clock: Arc<dyn Clock>,
        origin: &str,
        settings: TransferSettings,
    ) -> Result<Self, TransferError> {
        let staging =
            crate::disk::directory(&settings.staging).map_err(|_| TransferError::Storage)?;
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
            items: Arc::new(Mutex::new(HashMap::new())),
            staging,
            settings,
        })
    }

    pub fn local(clock: Arc<dyn Clock>, root: &std::path::Path) -> std::io::Result<Self> {
        Self::local_configured(clock, root, TransferSettings::default())
    }
    pub fn local_configured(
        clock: Arc<dyn Clock>,
        root: &std::path::Path,
        settings: TransferSettings,
    ) -> std::io::Result<Self> {
        let local = crate::local_files::LocalFiles::new(root)?;
        let staging = local.staging()?;
        // Local outputs share the publication filesystem for atomic rename without copying.
        let probe = crate::disk::directory(root)?;
        drop(probe);
        Ok(Self {
            clock,
            origin: String::new(),
            local: Some(Arc::new(local)),
            items: Arc::new(Mutex::new(HashMap::new())),
            staging,
            settings,
        })
    }
    pub const fn is_local(&self) -> bool {
        self.local.is_some()
    }

    async fn reserve(
        &self,
        owner: &PrincipalId,
        params: UploadParams,
        upload: bool,
    ) -> Result<String, TransferError> {
        if params
            .size
            .is_some_and(|size| size > self.settings.max_bytes)
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
        self.sweep().await;
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let now = self.clock.now();
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
                cleaning: false,
                abandoned: false,
                owner: owner.clone(),
                created: now,
                upload,
                ticket: None,
                active: None,
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

    pub async fn authorize_upload(
        &self,
        owner: &PrincipalId,
        params: UploadParams,
    ) -> Result<UploadResult, TransferError> {
        if self.local.is_some() {
            return Err(TransferError::Unknown);
        }
        let id = self.reserve(owner, params, true).await?;
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
        if item.cleaning
            || item.abandoned
            || item.owner != *owner
            || self.clock.now().saturating_sub(item.created) >= TTL
        {
            return Err(TransferError::Unknown);
        }
        Ok(item)
    }

    pub async fn input(
        &self,
        owner: &PrincipalId,
        uri: &str,
    ) -> Result<ssh_core::transfer::PreparedUpload, TransferError> {
        if let Some(local) = &self.local {
            let source = self.local_source(uri)?;
            return tokio::time::timeout(
                self.settings.timeout,
                local.read_pinned(
                    uri,
                    Arc::clone(&self.staging),
                    self.settings.max_bytes,
                    source,
                ),
            )
            .await
            .map_err(|_| TransferError::Storage)?
            .map_err(|_| TransferError::Unknown);
        }
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let item = self.owned(&mut items, owner, uri)?;
        let Content::Ready(bytes) = &item.content else {
            return Err(TransferError::Unknown);
        };
        Ok(ssh_core::transfer::PreparedUpload::from_reader(
            bytes.identity(uri.to_owned()),
            bytes.reader(),
        ))
    }

    pub async fn destination(
        self: &Arc<Self>,
        owner: &PrincipalId,
        name: Option<String>,
    ) -> Result<Arc<dyn DownloadSink>, TransferError> {
        let id = self
            .reserve(
                owner,
                UploadParams {
                    name,
                    ..UploadParams::default()
                },
                false,
            )
            .await?;
        Ok(Arc::new(Destination {
            store: Arc::clone(self),
            id,
        }))
    }

    async fn receive(
        &self,
        id: &str,
        reader: &mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> Result<ssh_core::action::FileIdentity, Failure> {
        let disk = crate::disk::allocate(Arc::clone(&self.staging), None, self.local.is_some())
            .await
            .map_err(|_| Failure::PublicationUnavailable)?;
        {
            let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
            let item = items.get_mut(id).ok_or(Failure::PublicationUnavailable)?;
            if !matches!(item.content, Content::Receiving) {
                return Err(Failure::PublicationUnavailable);
            }
            item.active = Some(Arc::clone(&disk));
        }
        let snapshot = crate::disk::receive(disk, reader, self.settings.max_bytes).await?;
        let digest = FileDigest {
            algorithm: "sha-256".to_owned(),
            value: URL_SAFE_NO_PAD.encode(snapshot.digest),
        };
        {
            let items = self.items.lock().unwrap_or_else(|error| error.into_inner());
            let item = items.get(id).ok_or(Failure::PublicationUnavailable)?;
            if item
                .reference
                .size
                .is_some_and(|size| size != snapshot.size)
                || item
                    .reference
                    .digest
                    .as_ref()
                    .is_some_and(|expected| expected != &digest)
            {
                return Err(Failure::PublicationUnavailable);
            }
        }
        let local = self.local.clone();
        let items = Arc::clone(&self.items);
        let clock = Arc::clone(&self.clock);
        let id = id.to_owned();
        // Publication and its state transition finish together, even if the caller is cancelled.
        tokio::task::spawn_blocking(move || {
            let local_file = match local {
                Some(local) => Some(
                    local
                        .publish(&id, &snapshot)
                        .map_err(|_| Failure::PublicationUnavailable)?,
                ),
                None => None,
            };
            let mut items = items.lock().unwrap_or_else(|error| error.into_inner());
            let item = items.get_mut(&id).ok_or(Failure::PublicationUnavailable)?;
            item.complete(snapshot, digest, local_file, clock.now())
        })
        .await
        .map_err(|_| Failure::PublicationUnavailable)?
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
        if item.cleaning
            || item.abandoned
            || self.clock.now().saturating_sub(item.created) >= TTL
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

    fn local_source(&self, uri: &str) -> Result<Option<Arc<Snapshot>>, TransferError> {
        let Some(id) = self.local.as_ref().and_then(|local| local.output_id(uri)) else {
            return Ok(None);
        };
        let items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        let item = items.get(&id).ok_or(TransferError::Unknown)?;
        if item.cleaning || self.clock.now().saturating_sub(item.created) >= TTL {
            return Err(TransferError::Unknown);
        }
        match &item.content {
            Content::Ready(snapshot) => Ok(Some(Arc::clone(snapshot))),
            _ => Err(TransferError::Unknown),
        }
    }

    fn abandon(&self, id: &str) {
        let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(item) = items.get_mut(id) {
            if matches!(item.content, Content::Ready(_)) {
                return;
            }
            item.content = Content::Pending;
            item.abandoned = true;
            // Empty reservations have no filesystem work to defer.
            if item.active.is_none() && !item.cleaning {
                items.remove(id);
            }
        }
    }

    pub async fn sweep(&self) {
        let now = self.clock.now();
        let pending = {
            let mut items = self.items.lock().unwrap_or_else(|error| error.into_inner());
            items
                .iter_mut()
                .filter_map(|(id, item)| {
                    if item.cleaning || retained(item, now) {
                        return None;
                    }
                    item.cleaning = true;
                    Some((
                        id.clone(),
                        item.active.take(),
                        item.local_file.take(),
                        std::mem::replace(&mut item.content, Content::Pending),
                    ))
                })
                .collect::<Vec<_>>()
        };
        if pending.is_empty() {
            return;
        }
        let items = Arc::clone(&self.items);
        // This worker owns cleanup and reconciliation even if its awaiting caller is cancelled.
        let cleanup = tokio::task::spawn_blocking(move || {
            for (id, disk, file, content) in pending {
                let removed = disk.as_ref().map_or(Ok(()), |disk| disk.remove())
                    .and_then(|()| file.as_ref().map_or(Ok(()), |file| file.remove()));
                match removed {
                    Ok(()) => {
                        // Close the last handles before releasing the reservation, outside the mutex.
                        drop((disk, file, content));
                        items.lock().unwrap_or_else(|error| error.into_inner()).remove(&id);
                    }
                    Err(error) => {
                        tracing::warn!(%error, "could not remove expired file; retaining its reservation");
                        let mut items = items.lock().unwrap_or_else(|error| error.into_inner());
                        if let Some(item) = items.get_mut(&id) {
                            item.active = disk;
                            item.local_file = file;
                            item.content = content;
                            item.cleaning = false;
                        }
                    }
                }
            }
        }).await;
        if let Err(error) = cleanup {
            tracing::error!(%error, "file cleanup worker failed");
        }
    }
}

fn retained(item: &Item, now: u64) -> bool {
    (!item.abandoned && now.saturating_sub(item.created) < TTL)
        || matches!(item.content, Content::Receiving)
        || item
            .active
            .as_ref()
            .is_some_and(|disk| Arc::strong_count(disk) > 1)
        || matches!(&item.content, Content::Ready(bytes) if Arc::strong_count(bytes) > 1 || Arc::strong_count(&bytes.disk) > 1)
}

struct Destination {
    store: Arc<Transfers>,
    id: String,
}
impl DownloadSink for Destination {
    fn receive<'a>(
        &'a self,
        reader: &'a mut (dyn tokio::io::AsyncRead + Unpin + Send),
    ) -> TransferFuture<'a> {
        Box::pin(async move {
            {
                let mut items = self
                    .store
                    .items
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let item = items
                    .get_mut(&self.id)
                    .ok_or(Failure::PublicationUnavailable)?;
                if item.cleaning
                    || item.abandoned
                    || !matches!(item.content, Content::Pending)
                    || item.upload
                    || self.store.clock.now().saturating_sub(item.created) >= TTL
                {
                    return Err(Failure::PublicationUnavailable);
                }
                item.content = Content::Receiving;
            }
            let receiving = Receiving {
                store: Arc::clone(&self.store),
                id: self.id.clone(),
            };
            receiving.store.receive(&receiving.id, reader).await
        })
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
            Body::from_stream(ReaderStream::with_capacity(
                bytes.reader(),
                crate::disk::CHUNK,
            )),
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
    let receiving = Receiving {
        store: Arc::clone(&store),
        id,
    };
    let mut reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    let status = match tokio::time::timeout(
        receiving.store.settings.timeout,
        receiving.store.receive(&receiving.id, &mut reader),
    )
    .await
    {
        Ok(Ok(_)) => StatusCode::NO_CONTENT,
        _ => StatusCode::BAD_REQUEST,
    };
    drop(receiving);
    store.sweep().await;
    status
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

    async fn streamed_http_roundtrip(size: u64) {
        use tokio::io::AsyncReadExt as _;
        let store = plane();
        let caller = owner("large-file");
        let upload = store
            .authorize_upload(
                &caller,
                UploadParams {
                    size: Some(size),
                    ..UploadParams::default()
                },
            )
            .await
            .unwrap();
        let source =
            ReaderStream::with_capacity(tokio::io::repeat(173).take(size), crate::disk::CHUNK);
        let response = routes(Arc::clone(&store))
            .oneshot(request(&upload.upload, Body::from_stream(source)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let download = store.authorize_download(&caller, &upload.file.uri).unwrap();
        assert_eq!(download.file.size, Some(size));
        let response = routes(Arc::clone(&store))
            .oneshot(request(&download.download, Body::empty()))
            .await
            .unwrap();
        let mut reader = StreamReader::new(
            response
                .into_body()
                .into_data_stream()
                .map_err(std::io::Error::other),
        );
        let mut buffer = vec![0; crate::disk::CHUNK];
        let mut seen = 0_u64;
        let mut digest = Sha256::new();
        loop {
            let count = reader.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            let bytes = buffer.get(..count).unwrap();
            assert!(bytes.iter().all(|byte| *byte == 173));
            digest.update(bytes);
            seen = seen.checked_add(count as u64).unwrap();
        }
        assert_eq!(seen, size);
        assert_eq!(
            download.file.digest.unwrap().value,
            URL_SAFE_NO_PAD.encode(digest.finalize())
        );
    }

    #[tokio::test]
    async fn http_streams_files_larger_than_the_old_memory_limit() {
        streamed_http_roundtrip(17 * 1024 * 1024).await;
    }

    #[tokio::test]
    #[ignore = "writes and reads 2 GB of temporary storage; run explicitly for large-file validation"]
    async fn two_gigabyte_http_roundtrip() {
        streamed_http_roundtrip(TransferSettings::default().max_bytes).await;
    }

    #[tokio::test]
    async fn unknown_length_uploads_enforce_the_configured_limit_and_release_failed_reservations() {
        let store = Arc::new(
            Transfers::configured(
                Arc::new(TestClock::at(1000)),
                "https://ssh.example",
                TransferSettings {
                    max_bytes: 8,
                    ..TransferSettings::default()
                },
            )
            .unwrap(),
        );
        let caller = owner("caller");
        for (bytes, status) in [
            ("12345678", StatusCode::NO_CONTENT),
            ("123456789", StatusCode::BAD_REQUEST),
        ] {
            let upload = store
                .authorize_upload(&caller, UploadParams::default())
                .await
                .unwrap();
            let response = routes(Arc::clone(&store))
                .oneshot(request(&upload.upload, Body::from(bytes)))
                .await
                .unwrap();
            assert_eq!(response.status(), status);
        }
        assert_eq!(store.items.lock().unwrap().len(), 1);
        let upload = store
            .authorize_upload(&caller, UploadParams::default())
            .await
            .unwrap();
        let failed = futures_util::stream::iter([Err::<axum::body::Bytes, _>(
            std::io::Error::other("disconnected"),
        )]);
        let response = routes(Arc::clone(&store))
            .oneshot(request(&upload.upload, Body::from_stream(failed)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(store.items.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn stalled_uploads_release_their_reservations_at_the_configured_deadline() {
        let store = Arc::new(
            Transfers::configured(
                Arc::new(TestClock::at(1000)),
                "https://ssh.example",
                TransferSettings {
                    timeout: std::time::Duration::from_millis(10),
                    ..TransferSettings::default()
                },
            )
            .unwrap(),
        );
        let upload = store
            .authorize_upload(&owner("caller"), UploadParams::default())
            .await
            .unwrap();
        let stalled = futures_util::stream::pending::<Result<axum::body::Bytes, std::io::Error>>();
        let response = routes(Arc::clone(&store))
            .oneshot(request(&upload.upload, Body::from_stream(stalled)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        store.sweep().await;
        assert!(store.items.lock().unwrap().is_empty());
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
            .await
            .unwrap();
        assert_eq!(upload.upload.transport, "http");
        assert!(store.input(&caller, &upload.file.uri).await.is_err());
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
        assert!(
            store
                .input(&owner("other"), &upload.file.uri)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .input(&caller, &upload.file.uri)
                .await
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
            .await
            .unwrap();
        let response = routes(Arc::clone(&store))
            .oneshot(request(&upload.upload, Body::from("bad")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(store.input(&caller, &upload.file.uri).await.is_err());
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
            .await
            .unwrap();
        assert_eq!(
            routes(Arc::clone(&store))
                .oneshot(request(&upload.upload, Body::from("evil")))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert!(store.input(&caller, &upload.file.uri).await.is_err());
    }

    #[tokio::test]
    async fn pending_transfers_reserve_capacity_and_cancelled_downloads_release_it() {
        let store = plane();
        let caller = owner("caller");
        let mut sinks = Vec::new();
        for _ in 0..OWNER_ITEMS {
            sinks.push(store.destination(&caller, None).await.unwrap());
        }
        assert!(matches!(
            store.destination(&caller, None).await,
            Err(TransferError::Capacity)
        ));
        drop(sinks);
        assert!(store.items.lock().unwrap().is_empty());
        for group in 0..4 {
            let caller = owner(&format!("caller-{group}"));
            for _ in 0..OWNER_ITEMS {
                store
                    .authorize_upload(&caller, UploadParams::default())
                    .await
                    .unwrap();
            }
        }
        assert!(matches!(
            store
                .authorize_upload(&owner("another"), UploadParams::default())
                .await,
            Err(TransferError::Capacity)
        ));
    }

    #[tokio::test]
    async fn receiving_uploads_remain_charged_after_reference_expiry() {
        let clock = Arc::new(TestClock::at(1000));
        let store = Arc::new(Transfers::new(clock.clone(), "https://ssh.example").unwrap());
        let caller = owner("caller");
        let upload = store
            .authorize_upload(&caller, UploadParams::default())
            .await
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
        store.sweep().await;
        assert_eq!(store.items.lock().unwrap().len(), 1);
        for _ in 1..OWNER_ITEMS {
            store
                .authorize_upload(&caller, UploadParams::default())
                .await
                .unwrap();
        }
        assert!(matches!(
            store
                .authorize_upload(&caller, UploadParams::default())
                .await,
            Err(TransferError::Capacity)
        ));
        store
            .receive(&receiving.id, &mut std::io::Cursor::new(b"completed"))
            .await
            .unwrap();
        assert!(
            store.input(&caller, &upload.file.uri).await.is_ok(),
            "completion starts a fresh delivery window"
        );
        clock.advance(TTL);
        store.sweep().await;
        drop(receiving);
        assert!(
            store
                .authorize_upload(&caller, UploadParams::default())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn cancelled_publication_keeps_the_output_for_tracked_cleanup() {
        let root = std::env::temp_dir().join(format!("ssh-publication-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let store = Transfers::local(Arc::new(TestClock::at(1000)), &root).unwrap();
        let id = store
            .reserve(&owner("local"), UploadParams::default(), false)
            .await
            .unwrap();
        let disk = crate::disk::allocate(Arc::clone(&store.staging), None, true)
            .await
            .unwrap();
        let snapshot =
            crate::disk::receive(Arc::clone(&disk), &mut std::io::Cursor::new(b"output"), 100)
                .await
                .unwrap();
        {
            let mut items = store.items.lock().unwrap();
            let item = items.get_mut(&id).unwrap();
            item.content = Content::Receiving;
            item.active = Some(disk);
        }
        store.abandon(&id);
        let local_file = store
            .local
            .as_ref()
            .unwrap()
            .publish(&id, &snapshot)
            .unwrap();
        {
            let mut items = store.items.lock().unwrap();
            let item = items.get_mut(&id).unwrap();
            let digest = FileDigest {
                algorithm: "sha-256".to_owned(),
                value: URL_SAFE_NO_PAD.encode(snapshot.digest),
            };
            assert!(
                item.complete(snapshot, digest, Some(local_file), 1000)
                    .is_err()
            );
            assert!(
                item.local_file.is_some(),
                "cancelled publication must retain its cleanup handle"
            );
        }
        store.sweep().await;
        assert!(store.items.lock().unwrap().is_empty());
        drop(store);
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn local_output_copy_retains_its_reservation_until_the_source_is_released() {
        let root = std::env::temp_dir().join(format!("ssh-output-pin-{}", rand::random::<u64>()));
        std::fs::create_dir(&root).unwrap();
        let clock = Arc::new(TestClock::at(1000));
        let store = Arc::new(Transfers::local(clock.clone(), &root).unwrap());
        let caller = owner("local");
        let sink = store.destination(&caller, None).await.unwrap();
        let file = sink
            .receive(&mut std::io::Cursor::new(b"local output"))
            .await
            .unwrap();
        let source = store.local_source(&file.uri).unwrap().unwrap();
        clock.advance(TTL);
        store.sweep().await;
        assert_eq!(store.items.lock().unwrap().len(), 1);
        let copied = store
            .local
            .as_ref()
            .unwrap()
            .read_pinned(
                &file.uri,
                Arc::clone(&store.staging),
                store.settings.max_bytes,
                Some(source),
            )
            .await
            .unwrap();
        store.sweep().await;
        assert!(store.items.lock().unwrap().is_empty());
        assert_eq!(copied.identity().bytes, 12);
        assert!(
            !url::Url::parse(&file.uri)
                .unwrap()
                .to_file_path()
                .unwrap()
                .exists()
        );
        drop((copied, sink, store));
        std::fs::remove_dir(root).unwrap();
    }

    #[tokio::test]
    async fn expired_files_in_use_still_count_against_disk_capacity() {
        let clock = Arc::new(TestClock::at(1000));
        let store = Arc::new(Transfers::new(clock.clone(), "https://ssh.example").unwrap());
        let caller = owner("caller");
        let sink = store.destination(&caller, None).await.unwrap();
        let file = sink
            .receive(&mut std::io::Cursor::new(vec![1, 2, 3]))
            .await
            .unwrap();
        let input = store.input(&caller, &file.uri).await.unwrap();
        clock.advance(TTL);
        store.sweep().await;
        assert_eq!(store.items.lock().unwrap().len(), 1);
        assert!(store.input(&caller, &file.uri).await.is_err());
        drop(input);
        store.sweep().await;
        assert!(store.items.lock().unwrap().is_empty());
    }
}
