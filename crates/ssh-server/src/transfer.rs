//! Moving bytes without putting them in a tool result.
//!
//! A command's output and a file's contents are regularly large enough that
//! returning them inline burns an agent's context for no benefit, and sometimes
//! sensitive enough that they should not pass through the model at all. Both
//! are the same problem: the *reference* belongs in the answer and the bytes
//! belong on a separate channel.
//!
//! So content is staged here, the tool result carries a reference to it, and
//! the caller's intermediary fetches it over HTTP with a credential minted for
//! that one transfer.
//!
//! # What holds this together
//!
//! - **The credential is not the gateway's.** It is minted per transfer, sent
//!   in its own header rather than the one the service boundary already uses,
//!   and never in a URL — a URL ends up in proxy logs.
//! - **One download.** Serving spends the authorization. A reference that has
//!   been fetched is not a standing capability to fetch it again.
//! - **Only the principal that produced it.** Staged content belongs to the
//!   session that produced it; another principal asking about the same
//!   reference gets the answer it would get for one that never existed.
//! - **Everything is in memory and bounded.** Nothing staged reaches disk,
//!   nothing outlives its short life, and one principal cannot make the service
//!   hold an unbounded amount.

use std::collections::HashMap;
use std::sync::Mutex;

use serde::Serialize;
use sha2::{Digest as _, Sha256};
use ssh_core::PrincipalId;
use ssh_core::clock::{Clock, Millis};
use subtle::ConstantTimeEq as _;

/// Where a staged reference is fetched from.
pub const DOWNLOAD_PREFIX: &str = "/files/download/";

/// Header the transfer credential travels in.
///
/// Its own header, not `Authorization`: that one already means "this is the
/// gateway", and a per-transfer credential arriving in it would be two
/// different authorities spelled the same way.
pub const TRANSFER_CREDENTIAL_HEADER: &str = "x-mcp-transfer-credential";

/// Scheme of a reference this service issues.
const URI_PREFIX: &str = "mcp-file://mcp-ssh/";

/// Bytes of randomness behind an identifier or a credential.
const TOKEN_BYTES: usize = 32;

/// How long staged content waits to be fetched.
const LIFETIME: Millis = 5 * 60 * 1_000;

/// Most items one principal may have staged at once.
///
/// Staged content is held in memory, so this is what stops a caller from
/// running commands purely to make the service hold their output.
const PER_PRINCIPAL: usize = 8;

/// Most bytes one principal may have staged at once.
///
/// Counting items bounds nothing on its own: eight references can be eight
/// bytes or eight gigabytes, and it is the bytes this service holds. Both
/// limits are here because they refuse different things — one a caller that
/// stages constantly, the other a caller that stages once and hugely.
const BYTES_PER_PRINCIPAL: usize = 64 * 1024 * 1024;

/// Most bytes any single staged item may be.
///
/// One short of the round figure deliberately. Sizes are published rounded up
/// to the next multiple of [`SIZE_GRANULARITY`], so a maximum sitting exactly
/// on a multiple would be the only accepted length rounding to the figure above
/// it — and a published size only one length can produce names that length
/// exactly, which is the disclosure the rounding exists to prevent.
const BYTES_PER_ITEM: usize = 16 * 1024 * 1024 - 1;

/// Longest name or media type a staged item may carry.
///
/// Retained alongside the content, so unbounded either way is unbounded
/// memory: a caller staging one byte under a name of ten megabytes has staged
/// ten megabytes.
const METADATA_MAX: usize = 1024;

/// Sizes are published rounded up to a multiple of this.
///
/// This channel exists partly to carry content that must not reach a model,
/// and an exact length is a fact about that content: for a low-entropy secret
/// it narrows the guess. A caller needs to know whether it is fetching
/// something small or something enormous, which a rounded figure answers just
/// as well.
const SIZE_GRANULARITY: u64 = 4096;

/// A reference in place of the bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    /// Opaque, single-use, and resolved out of band. Never content.
    pub uri: String,
    pub name: String,
    pub mime_type: String,
    /// About how large the content is, rounded up.
    ///
    /// Deliberately not exact. What a caller needs is whether this is worth
    /// fetching; what an exact figure additionally provides is the length of
    /// whatever was staged, which for a secret is a fact about the secret.
    pub size: u64,
}

/// Where and how to fetch a reference, once.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub method: &'static str,
    pub url: String,
    /// Carries the transfer credential, which is the only authority on that URL.
    pub headers: HashMap<String, String>,
}

/// Redacted, because the headers carry the credential.
///
/// This is an ordinary return value: it goes into results, and anything that
/// prints one while working out why a transfer failed would otherwise print
/// the authority to perform it. A derived `Debug` would do exactly that, so
/// there is not one.
impl std::fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Descriptor")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// One piece of staged content.
struct Staged {
    /// A boxed slice rather than a `Vec`, so what is retained is what was
    /// counted. A vector's allocation can be far larger than its length, and
    /// then the quota charges for the length while the store holds the
    /// allocation — an account that is only as honest as its callers.
    bytes: Box<[u8]>,
    name: String,
    mime_type: String,
    /// Who produced it. Only they may authorize fetching it.
    owner: PrincipalId,
    staged_at: Millis,
    /// The live authorization, if one has been issued.
    ticket: Option<Ticket>,
}

/// One authorized fetch.
///
/// Re-authorizing replaces it, so at most one credential is live per staged
/// item and an older one cannot outlast a newer authorization.
struct Ticket {
    /// Appears in the URL, and therefore in logs, so it is independent of the
    /// staged identifier: knowing what was logged must not reveal what to ask
    /// the store for.
    id: String,
    /// The credential's digest. Holding the value would put a working
    /// credential in memory for as long as the item is staged, when all this
    /// needs to do is recognise the one it issued.
    credential: [u8; 32],
}

/// Content staged for out-of-band delivery.
pub struct Transfers<C: Clock> {
    clock: C,
    origin: String,
    staged: Mutex<HashMap<String, Staged>>,
}

impl<C: Clock> Transfers<C> {
    /// `origin` is the address a caller's intermediary will dial, scheme and
    /// authority only.
    #[must_use]
    pub fn new(clock: C, origin: String) -> Self {
        Self {
            clock,
            origin: origin.trim_end_matches('/').to_owned(),
            staged: Mutex::new(HashMap::new()),
        }
    }

    /// Holds content and returns the reference that stands in for it.
    pub fn stage(
        &self,
        owner: &PrincipalId,
        name: &str,
        mime_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Reference, TransferError> {
        if bytes.len() > BYTES_PER_ITEM {
            return Err(TransferError::TooLarge {
                max: BYTES_PER_ITEM,
            });
        }
        if name.len() > METADATA_MAX || mime_type.len() > METADATA_MAX {
            return Err(TransferError::MetadataTooLong { max: METADATA_MAX });
        }
        let size = about(bytes.len());
        let mut staged = self.staged.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        staged.retain(|_, held| !held.expired(now));

        let mine = staged.values().filter(|held| held.owner == *owner);
        // Everything retained counts, not only the content: the store holds a
        // name and a media type for the item's whole life too.
        let (held, bytes_held) = mine.fold((0_usize, 0_usize), |(count, total), held| {
            (count.saturating_add(1), total.saturating_add(held.weight()))
        });
        if held >= PER_PRINCIPAL {
            return Err(TransferError::TooMuchStaged { max: PER_PRINCIPAL });
        }
        let arriving = bytes
            .len()
            .saturating_add(name.len())
            .saturating_add(mime_type.len());
        if bytes_held.saturating_add(arriving) > BYTES_PER_PRINCIPAL {
            return Err(TransferError::TooManyBytesStaged {
                max: BYTES_PER_PRINCIPAL,
            });
        }

        let id = token();
        let reference = Reference {
            uri: format!("{URI_PREFIX}{id}"),
            name: name.to_owned(),
            mime_type: mime_type.to_owned(),
            size,
        };
        staged.insert(
            id,
            Staged {
                // Shrinks to exactly what was charged for.
                bytes: bytes.into_boxed_slice(),
                name: name.to_owned(),
                mime_type: mime_type.to_owned(),
                owner: owner.clone(),
                staged_at: now,
                ticket: None,
            },
        );
        Ok(reference)
    }

    /// Mints the one fetch a reference gets.
    ///
    /// A caller that authorizes twice replaces the first authorization rather
    /// than holding two: the point is one fetch, not one at a time.
    pub fn authorize(&self, owner: &PrincipalId, uri: &str) -> Result<Descriptor, TransferError> {
        let mut staged = self.staged.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        staged.retain(|_, held| !held.expired(now));

        let key = uri.strip_prefix(URI_PREFIX).ok_or(TransferError::Unknown)?;
        let held = staged.get_mut(key).ok_or(TransferError::Unknown)?;
        // The same answer as for a reference that never existed. Telling a
        // caller that somebody else's content exists is the disclosure this
        // whole module is trying to avoid.
        if held.owner != *owner {
            return Err(TransferError::Unknown);
        }

        let id = token();
        let credential = token();
        held.ticket = Some(Ticket {
            id: id.clone(),
            credential: digest(&credential),
        });
        Ok(Descriptor {
            method: "GET",
            url: format!("{}{DOWNLOAD_PREFIX}{id}", self.origin),
            headers: HashMap::from([(TRANSFER_CREDENTIAL_HEADER.to_owned(), credential)]),
        })
    }

    /// Hands over the content, once.
    ///
    /// Takes the staged item with it: a reference that has been fetched is not
    /// a standing capability to fetch it again.
    pub fn serve(&self, id: &str, presented: &str) -> Option<(String, String, Vec<u8>)> {
        let mut staged = self.staged.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        staged.retain(|_, held| !held.expired(now));

        let key = staged
            .iter()
            .find(|(_, held)| held.ticket.as_ref().is_some_and(|ticket| ticket.id == id))
            .map(|(key, _)| key.clone())?;
        let held = staged.get(&key)?;
        let ticket = held.ticket.as_ref()?;
        // Constant time: a comparison that stops at the first differing byte
        // leaks the credential a byte at a time to anything that can time it.
        if !bool::from(digest(presented).ct_eq(&ticket.credential)) {
            return None;
        }
        let taken = staged.remove(&key)?;
        Some((taken.name, taken.mime_type, taken.bytes.into_vec()))
    }

    /// Drops content nobody fetched.
    pub fn sweep(&self) {
        let mut staged = self.staged.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.now();
        staged.retain(|_, held| !held.expired(now));
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.staged.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Staged {
    /// What holding this costs, which is everything held rather than only the
    /// content: a name is retained for as long as the bytes are.
    fn weight(&self) -> usize {
        self.bytes
            .len()
            .saturating_add(self.name.len())
            .saturating_add(self.mime_type.len())
    }
    fn expired(&self, now: Millis) -> bool {
        now.saturating_sub(self.staged_at) >= LIFETIME
    }
}

/// Randomness from a CSPRNG, in lowercase hex.
fn token() -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::fill(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest(value: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TransferError {
    /// No such reference, or not yours. Deliberately one answer.
    #[error("no such reference")]
    Unknown,
    #[error("this principal already has {max} items staged")]
    TooMuchStaged { max: usize },
    #[error("this principal already holds the {max} bytes it may have staged")]
    TooManyBytesStaged { max: usize },
    #[error("a single staged item may be at most {max} bytes")]
    TooLarge { max: usize },
    #[error("a staged item's name and media type may each be at most {max} bytes")]
    MetadataTooLong { max: usize },
}

/// A size rounded up past itself, so publishing it never states the length.
///
/// The *next* multiple rather than the nearest, because a length already on a
/// boundary — nothing at all, or exactly one granule — would otherwise be
/// published exactly, and those are lengths worth knowing about a secret.
fn about(bytes: usize) -> u64 {
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    bytes
        .checked_div(SIZE_GRANULARITY)
        .and_then(|granules| granules.checked_add(1))
        .and_then(|granules| granules.checked_mul(SIZE_GRANULARITY))
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ssh_core::clock::TestClock;

    fn transfers() -> Transfers<TestClock> {
        Transfers::new(TestClock::at(1_000), "https://ssh.example".to_owned())
    }

    fn principal(name: &str) -> PrincipalId {
        PrincipalId::parse(name).unwrap()
    }

    fn credential(descriptor: &Descriptor) -> String {
        descriptor
            .headers
            .get(TRANSFER_CREDENTIAL_HEADER)
            .expect("the descriptor carries the credential")
            .clone()
    }

    fn id_of(descriptor: &Descriptor) -> String {
        descriptor
            .url
            .rsplit('/')
            .next()
            .expect("the url ends in an identifier")
            .to_owned()
    }

    /// The round trip the module exists for: the bytes never appear in what the
    /// caller was handed, and they arrive intact on the other channel.
    #[test]
    fn content_travels_by_reference_and_arrives_intact() {
        let transfers = transfers();
        let agent = principal("agent-clawde");
        let content = b"root:x:0:0:root:/root:/bin/bash\n".to_vec();

        let reference = transfers
            .stage(&agent, "passwd", "text/plain", content.clone())
            .unwrap();
        assert!(reference.uri.starts_with(URI_PREFIX));
        // Rounded, not exact: this channel carries content that must not reach
        // a model, and a length is a fact about that content.
        assert_eq!(reference.size, SIZE_GRANULARITY);
        assert_ne!(
            reference.size,
            u64::try_from(content.len()).unwrap(),
            "the reference published the exact length of what was staged"
        );
        // What stands in for the content says nothing about it.
        let rendered = serde_json::to_string(&reference).unwrap();
        assert!(
            !rendered.contains("root:x:0:0"),
            "the reference carried content"
        );

        let descriptor = transfers.authorize(&agent, &reference.uri).unwrap();
        assert_eq!(descriptor.method, "GET");
        assert!(
            descriptor
                .url
                .starts_with("https://ssh.example/files/download/")
        );
        // The credential is in a header of its own, never in the URL.
        assert!(!descriptor.url.contains(&credential(&descriptor)));

        let (name, mime, bytes) = transfers
            .serve(&id_of(&descriptor), &credential(&descriptor))
            .expect("the authorized fetch was refused");
        assert_eq!(name, "passwd");
        assert_eq!(mime, "text/plain");
        assert_eq!(bytes, content);
    }

    /// One fetch. A reference that has been collected is not a capability to
    /// collect it again, and nothing is left holding the content afterwards.
    #[test]
    fn a_reference_is_spent_by_the_fetch_it_authorized() {
        let transfers = transfers();
        let agent = principal("agent-clawde");
        let reference = transfers
            .stage(&agent, "out", "text/plain", b"once".to_vec())
            .unwrap();
        let descriptor = transfers.authorize(&agent, &reference.uri).unwrap();

        assert!(
            transfers
                .serve(&id_of(&descriptor), &credential(&descriptor))
                .is_some()
        );
        assert!(
            transfers
                .serve(&id_of(&descriptor), &credential(&descriptor))
                .is_none(),
            "the same authorization served twice"
        );
        assert!(transfers.is_empty(), "content outlived its fetch");
    }

    /// The credential is the whole authority on that URL, so presenting the
    /// wrong one - or none - has to fail, and knowing the identifier must not
    /// be enough on its own.
    #[test]
    fn the_url_alone_does_not_fetch_anything() {
        let transfers = transfers();
        let agent = principal("agent-clawde");
        let reference = transfers
            .stage(&agent, "out", "text/plain", b"secret".to_vec())
            .unwrap();
        let descriptor = transfers.authorize(&agent, &reference.uri).unwrap();
        let id = id_of(&descriptor);

        for wrong in ["", "not-the-credential", &"0".repeat(64)] {
            assert!(
                transfers.serve(&id, wrong).is_none(),
                "served with {wrong:?}"
            );
        }
        // And the real one still works afterwards: a wrong guess does not
        // consume the authorization.
        assert!(transfers.serve(&id, &credential(&descriptor)).is_some());
    }

    /// Staged content belongs to whoever produced it. Another principal asking
    /// about the reference gets what it would get for one that never existed -
    /// the two must be indistinguishable, or the error enumerates other
    /// callers' work.
    #[test]
    fn another_principal_cannot_reach_or_discover_staged_content() {
        let transfers = transfers();
        let owner = principal("agent-clawde");
        let other = principal("agent-someone-else");
        let reference = transfers
            .stage(&owner, "out", "text/plain", b"theirs".to_vec())
            .unwrap();

        let refused = transfers.authorize(&other, &reference.uri).unwrap_err();
        let missing = transfers
            .authorize(&other, &format!("{URI_PREFIX}{}", "0".repeat(64)))
            .unwrap_err();
        assert_eq!(refused, missing);
        assert_eq!(refused, TransferError::Unknown);
    }

    /// Re-authorizing replaces the live authorization. Two working credentials
    /// for one item would make "one fetch" mean "one at a time".
    #[test]
    fn authorizing_again_retires_the_previous_credential() {
        let transfers = transfers();
        let agent = principal("agent-clawde");
        let reference = transfers
            .stage(&agent, "out", "text/plain", b"once".to_vec())
            .unwrap();

        let first = transfers.authorize(&agent, &reference.uri).unwrap();
        let second = transfers.authorize(&agent, &reference.uri).unwrap();

        assert!(
            transfers
                .serve(&id_of(&first), &credential(&first))
                .is_none(),
            "the retired authorization still worked"
        );
        assert!(
            transfers
                .serve(&id_of(&second), &credential(&second))
                .is_some()
        );
    }

    /// Content nobody fetches is not held for ever, and an expired reference
    /// answers like one that never existed.
    #[test]
    fn content_nobody_collects_does_not_accumulate() {
        let transfers = transfers();
        let agent = principal("agent-clawde");
        let reference = transfers
            .stage(&agent, "out", "text/plain", b"forgotten".to_vec())
            .unwrap();

        transfers.clock.advance(LIFETIME);
        transfers.sweep();
        assert!(transfers.is_empty());
        assert_eq!(
            transfers.authorize(&agent, &reference.uri).unwrap_err(),
            TransferError::Unknown
        );
    }

    /// Staged content is held in memory, so a caller that could stage without
    /// limit could make the service hold whatever it liked.
    /// Counting items bounds nothing on its own: eight references can be eight
    /// bytes or eight gigabytes, and what this service holds is the bytes. A
    /// caller that stages once and hugely is the case the item count misses
    /// entirely.
    #[test]
    fn one_principal_cannot_stage_unbounded_bytes() {
        let transfers = transfers();
        let agent = principal("agent-clawde");

        let too_big = transfers
            .stage(
                &agent,
                "huge",
                "application/octet-stream",
                vec![0; BYTES_PER_ITEM + 1],
            )
            .expect_err("a single item past the per-item bound was staged");
        assert!(
            matches!(too_big, TransferError::TooLarge { .. }),
            "unexpected error: {too_big:?}"
        );

        // Under the per-item bound each time, over the principal's total.
        let chunk = BYTES_PER_ITEM;
        for which in 0..3 {
            transfers
                .stage(
                    &agent,
                    &format!("chunk-{which}"),
                    "application/octet-stream",
                    vec![0; chunk],
                )
                .expect("within the principal's total");
        }
        let over = transfers
            .stage(
                &agent,
                "one-more",
                "application/octet-stream",
                vec![0; chunk],
            )
            .expect_err("a principal staged past its total");
        assert!(
            matches!(over, TransferError::TooManyBytesStaged { .. }),
            "unexpected error: {over:?}"
        );

        // Metadata is retained too, so it is bounded and it counts: staging one
        // byte under a name of ten megabytes has staged ten megabytes.
        let named = transfers
            .stage(
                &principal("agent-verbose"),
                &"n".repeat(METADATA_MAX + 1),
                "text/plain",
                vec![0; 1],
            )
            .expect_err("an unbounded name was retained");
        assert!(
            matches!(named, TransferError::MetadataTooLong { .. }),
            "unexpected error: {named:?}"
        );

        // Somebody else's total is their own.
        transfers
            .stage(
                &principal("agent-other"),
                "theirs",
                "text/plain",
                vec![0; 1],
            )
            .expect("another principal has its own allowance");
    }

    /// A descriptor is an ordinary return value carrying a live credential.
    /// Anything printing one while working out why a transfer failed would
    /// otherwise print the authority to perform it.
    #[test]
    fn printing_a_descriptor_does_not_print_its_credential() {
        let transfers = transfers();
        let agent = principal("agent-clawde");
        let reference = transfers
            .stage(&agent, "passwd", "text/plain", b"root:x:0:0".to_vec())
            .unwrap();
        let descriptor = transfers.authorize(&agent, &reference.uri).unwrap();

        let credential = descriptor
            .headers
            .get(TRANSFER_CREDENTIAL_HEADER)
            .expect("the descriptor carries the credential")
            .clone();
        let printed = format!("{descriptor:?}");
        assert!(
            !printed.contains(&credential),
            "printing a descriptor printed its credential: {printed}"
        );
        // Still worth printing: it says where it points and what it carries.
        assert!(printed.contains(TRANSFER_CREDENTIAL_HEADER) && printed.contains(&descriptor.url));
    }

    /// A rounded size that lands on a boundary is the exact size, and the
    /// lengths landing there — nothing at all, exactly one granule — are worth
    /// knowing about a secret. The top of the range is the same disclosure
    /// wearing a different hat: a figure only one accepted length can produce
    /// names that length just as exactly as publishing it would.
    #[test]
    fn a_published_size_is_never_the_length_itself() {
        let granule = usize::try_from(SIZE_GRANULARITY).unwrap();
        for length in [0, 1, granule, granule + 1, BYTES_PER_ITEM] {
            let published = about(length);
            assert!(
                published > u64::try_from(length).unwrap(),
                "{length} bytes published as {published}"
            );
        }
        assert_eq!(
            about(BYTES_PER_ITEM),
            about(BYTES_PER_ITEM - 1),
            "the largest item a caller may stage is alone in what it publishes"
        );
    }

    #[test]
    fn one_principal_cannot_stage_without_limit() {
        let transfers = transfers();
        let agent = principal("agent-clawde");
        for _ in 0..PER_PRINCIPAL {
            transfers
                .stage(&agent, "out", "text/plain", b"x".to_vec())
                .unwrap();
        }
        assert_eq!(
            transfers
                .stage(&agent, "out", "text/plain", b"x".to_vec())
                .unwrap_err(),
            TransferError::TooMuchStaged { max: PER_PRINCIPAL }
        );

        // Another principal is unaffected: the bound is per principal, so one
        // caller cannot deny the channel to everyone else.
        transfers
            .stage(
                &principal("agent-other"),
                "out",
                "text/plain",
                b"x".to_vec(),
            )
            .unwrap();
    }
}
