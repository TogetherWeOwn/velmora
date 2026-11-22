//! Service tokens of the management plane.
//!
//! `kofra-api` alone calls the management plane, over a service binding,
//! with one of two service tokens. The class of the token fixes its
//! scopes in code ([`TokenClass::allows`]); nothing a caller sends can
//! widen them, and the class is also the actor of what the call records.
//!
//! | Class | Used for | Never has |
//! |---|---|---|
//! | standard | every handler the public API and the MCP Worker can reach | tenant create, tenant delete, publishing, bucket delete, a key or principal that can write, a grant that widens, an overwriting or deleting object call |
//! | confirmed | handlers behind an action a signed-in person confirmed in the console | `tenants:delete_now` (an operator action) |
//!
//! A third class, the billing token, is not built yet. No class has a
//! hold, a suspend, a limit change or `tenants:delete_now`.
//!
//! # Where a token is checked
//!
//! - **Velmora holds no token.** It holds the SHA-256 of each, as Worker
//!   secrets: [`STANDARD_HASHES`] and [`CONFIRMED_HASHES`], each one or
//!   two hashes in lowercase hex, separated by a comma (two during a
//!   rotation). A presented token is hashed and compared with every
//!   configured hash in constant time. No token, hash or scope is a
//!   catalogue row, so a restore of a catalogue changes nothing about
//!   them.
//! - **A token's id** is the first 8 bytes of its hash, in hex.
//! - **Disable always wins.** `m/rst/<id>` disables the token of that id
//!   ([`write_disable`]). The record is put once and never deleted (every
//!   name under `m/` is protected). A rollback to a Worker version that
//!   still carries the hash of a disabled token cannot bring it back,
//!   because a version rollback restores that version's secrets. The
//!   removal of a hash at a rotation writes the record first.
//! - **The list is read before the first token, and a stale list closes
//!   the door** ([`DisabledTokens`]). An isolate lists `m/rst/` before it
//!   accepts a token and again at most once every [`LIST_EVERY_MS`]. With
//!   no good list, or a last good list older than [`STALE_AFTER_MS`],
//!   every management call answers `503`. The S3 data plane never reads
//!   the list.
//!
//! A record is recognised by its name alone, as `m/rk/` is: forging one
//! needs write access to the record store and can only refuse a token.
//! It is a control record with a door part only (`seal_control`, the
//! owner "global"): the control key seals it, its name is in the
//! authenticated data, and its body says [`DISABLE_LABEL`], so a record
//! of another kind can never pass for one ([`read_disable`]).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use velmora::rng::SystemRng;

use crate::crypto::scheme2::{parse_control, seal_control, ControlOwner, ControlSealer};
use crate::ports::{BlobMeta, BlobStore, Kek};
use crate::types::{BridgeError, BucketId, ExtentId, Result, UnixMs};

/// Worker secret: the hashes of the standard token.
pub const STANDARD_HASHES: &str = "MGMT_TOKEN_SHA256_STANDARD";
/// Worker secret: the hashes of the confirmed token.
pub const CONFIRMED_HASHES: &str = "MGMT_TOKEN_SHA256_CONFIRMED";

/// The records that disable a token: this prefix and the token id.
pub const DISABLED_TOKEN_PREFIX: &str = "m/rst/";

/// The kind a disable record's body names.
pub const DISABLE_LABEL: &str = "velmora/rst/v1";

const ERR_DISABLE: BridgeError = BridgeError::Invalid("token disable record is malformed");

/// How often an isolate lists [`DISABLED_TOKEN_PREFIX`], at most, while
/// its list is fresh.
pub const LIST_EVERY_MS: i64 = 60_000;
/// How soon an isolate lists again while its door is shut (no good
/// list, or a stale one): a failed or hung listing then keeps the
/// isolate shut for this long, not for [`LIST_EVERY_MS`].
pub const LIST_AGAIN_SHUT_MS: i64 = 5_000;
/// How old the last good list may be before every call answers `503`
/// (est; a dial).
pub const STALE_AFTER_MS: i64 = 5 * 60_000;
/// Keys per page when the list is read.
const LIST_PAGE: u32 = 1_000;

/// Hashes per class: the current one and, during a rotation, the next.
const MAX_HASHES_PER_CLASS: usize = 2;
/// Bytes of a presented token, at least and at most.
const TOKEN_LEN: std::ops::RangeInclusive<usize> = 32..=512;

/// The class of a service token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TokenClass {
    Standard,
    Confirmed,
}

impl TokenClass {
    pub const ALL: [TokenClass; 2] = [TokenClass::Standard, TokenClass::Confirmed];

    pub fn as_str(self) -> &'static str {
        match self {
            TokenClass::Standard => "standard",
            TokenClass::Confirmed => "confirmed",
        }
    }

    /// The secret that holds the hashes of this class.
    pub fn hashes_var(self) -> &'static str {
        match self {
            TokenClass::Standard => STANDARD_HASHES,
            TokenClass::Confirmed => CONFIRMED_HASHES,
        }
    }

    /// Whether a token of this class carries `scope`. Fixed here; no
    /// configuration or request changes it.
    pub fn allows(self, scope: Scope) -> bool {
        use Scope::*;
        match scope {
            TenantsRead | BucketsWrite | KeysWrite | ObjectsList | ObjectsPresignRead
            | ObjectsCreate | UsageRead | EventsRead => true,
            TenantsCreate | TenantsDelete | BucketsPublish | BucketsDelete | KeysWriteRw
            | PrincipalsWrite | ObjectsPresignWrite | ObjectsDelete => {
                self == TokenClass::Confirmed
            }
        }
    }
}

/// A scope of the storage management plane. The closed list of the
/// tenancy design; the billing scopes and `tenants:delete_now` are not in
/// it, so no token of these classes can be given one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Read a tenant, its buckets and its keys (never a secret).
    TenantsRead,
    /// Create a tenant (sign-up).
    TenantsCreate,
    /// Ask for a tenant's deletion with a hold of 7 days or more, and
    /// undo a deletion of the customer's own.
    TenantsDelete,
    /// Create a bucket; change settings that open nothing; clear the
    /// public flag.
    BucketsWrite,
    /// Set the public flag; a CORS rule for a foreign origin.
    BucketsPublish,
    /// Delete an empty bucket.
    BucketsDelete,
    /// Create a key or an app password whose grants are all `ro`;
    /// disable, revoke or narrow a key that is not internal.
    KeysWrite,
    /// Create a key or an app password that can write; a
    /// workspace-owned key.
    KeysWriteRw,
    /// Create a principal; widen a grant.
    PrincipalsWrite,
    /// `objects.list`, and the parts of an upload.
    ObjectsList,
    /// A presigned GET.
    ObjectsPresignRead,
    /// A create-only upload: a presigned PUT that cannot replace, and
    /// the multipart calls with `create_only`; abort.
    ObjectsCreate,
    /// A presigned PUT or an upload that may replace an object.
    ObjectsPresignWrite,
    /// `objects.delete`.
    ObjectsDelete,
    UsageRead,
    EventsRead,
}

impl Scope {
    pub const ALL: [Scope; 16] = [
        Scope::TenantsRead,
        Scope::TenantsCreate,
        Scope::TenantsDelete,
        Scope::BucketsWrite,
        Scope::BucketsPublish,
        Scope::BucketsDelete,
        Scope::KeysWrite,
        Scope::KeysWriteRw,
        Scope::PrincipalsWrite,
        Scope::ObjectsList,
        Scope::ObjectsPresignRead,
        Scope::ObjectsCreate,
        Scope::ObjectsPresignWrite,
        Scope::ObjectsDelete,
        Scope::UsageRead,
        Scope::EventsRead,
    ];

    /// The scope's name in the contract with `kofra-api`.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::TenantsRead => "tenants:read",
            Scope::TenantsCreate => "tenants:create",
            Scope::TenantsDelete => "tenants:delete",
            Scope::BucketsWrite => "buckets:write",
            Scope::BucketsPublish => "buckets:publish",
            Scope::BucketsDelete => "buckets:delete",
            Scope::KeysWrite => "keys:write",
            Scope::KeysWriteRw => "keys:write_rw",
            Scope::PrincipalsWrite => "principals:write",
            Scope::ObjectsList => "objects:list",
            Scope::ObjectsPresignRead => "objects:presign_read",
            Scope::ObjectsCreate => "objects:create",
            Scope::ObjectsPresignWrite => "objects:presign_write",
            Scope::ObjectsDelete => "objects:delete",
            Scope::UsageRead => "usage:read",
            Scope::EventsRead => "events:read",
        }
    }
}

/// The id of a token: the first 8 bytes of its SHA-256, in lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId(String);

impl TokenId {
    fn of(hash: &[u8; 32]) -> TokenId {
        TokenId(hex(&hash[..8]))
    }

    /// Reads an id from the name of its record's last part.
    pub fn parse(text: &str) -> Option<TokenId> {
        (text.len() == 16 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .then(|| TokenId(text.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name of the record that disables this token.
    pub fn disable_record(&self) -> String {
        format!("{DISABLED_TOKEN_PREFIX}{}", self.0)
    }
}

/// The hashes of the service tokens, read from the Worker secrets.
#[derive(Clone, Default)]
pub struct TokenHashes {
    hashes: Vec<(TokenClass, [u8; 32])>,
}

impl std::fmt::Debug for TokenHashes {
    /// Counts only: a hash is not printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = |c| self.hashes.iter().filter(|(k, _)| *k == c).count();
        f.debug_struct("TokenHashes")
            .field("standard", &n(TokenClass::Standard))
            .field("confirmed", &n(TokenClass::Confirmed))
            .finish()
    }
}

impl TokenHashes {
    /// From the value of each class's secret (`None` = unset: that class
    /// has no token, and refuses every one). Refused, with a message that
    /// quotes no value: a hash that is not 64 lowercase hex characters,
    /// more than [`MAX_HASHES_PER_CLASS`] in one class, and the same id
    /// twice anywhere, since a disable names an id.
    pub fn from_vars(
        get: impl Fn(&'static str) -> Option<String>,
    ) -> std::result::Result<TokenHashes, String> {
        let mut hashes = Vec::new();
        for class in TokenClass::ALL {
            let Some(raw) = get(class.hashes_var()) else {
                continue;
            };
            let list: Vec<&str> = raw
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if list.len() > MAX_HASHES_PER_CLASS {
                return Err(format!(
                    "{}: at most {MAX_HASHES_PER_CLASS} hashes",
                    class.hashes_var()
                ));
            }
            for text in list {
                let hash = parse_hash(text).ok_or_else(|| {
                    format!("{}: not a SHA-256 in lowercase hex", class.hashes_var())
                })?;
                hashes.push((class, hash));
            }
        }
        let ids: BTreeSet<TokenId> = hashes.iter().map(|(_, h)| TokenId::of(h)).collect();
        if ids.len() != hashes.len() {
            return Err("service token hashes: the same token id twice".to_string());
        }
        Ok(TokenHashes { hashes })
    }

    /// Whether no class has a token.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// The class and id of `token`, or `None`. Every configured hash is
    /// compared, in constant time, whatever matched first.
    fn find(&self, token: &[u8]) -> Option<(TokenClass, TokenId)> {
        let presented: [u8; 32] = Sha256::digest(token).into();
        let mut found = None;
        for (class, hash) in &self.hashes {
            if bool::from(presented.ct_eq(hash)) {
                found = Some((*class, TokenId::of(hash)));
            }
        }
        found
    }
}

fn parse_hash(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Who a management call is from: the class of its token, which is also
/// the actor of what it records, and the token's id for the audit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Actor {
    pub class: TokenClass,
    pub token: TokenId,
}

impl Actor {
    /// `Ok` when the actor's class carries `scope`.
    pub fn may(&self, scope: Scope) -> std::result::Result<(), Refused> {
        match self.class.allows(scope) {
            true => Ok(()),
            false => Err(Refused::Scope(scope)),
        }
    }
}

/// Why a management call is refused before it does anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// The list of disabled tokens is not fresh: `503` with
    /// `Retry-After`. Comes before any look at the token.
    Unavailable,
    /// No token, a token of no class, or a disabled one: `401`, the same
    /// answer for each.
    Unauthenticated,
    /// The token's class does not carry the scope: `403`.
    Scope(Scope),
}

impl Refused {
    pub fn status(self) -> u16 {
        match self {
            Refused::Unavailable => 503,
            Refused::Unauthenticated => 401,
            Refused::Scope(_) => 403,
        }
    }

    /// A fixed code for the answer and the log.
    pub fn code(self) -> &'static str {
        match self {
            Refused::Unavailable => "service_unavailable",
            Refused::Unauthenticated => "unauthenticated",
            Refused::Scope(_) => "insufficient_scope",
        }
    }
}

/// The disabled tokens an isolate knows of, and when it last knew.
///
/// The listing itself is async ([`list_disabled`]) and the state is not
/// held across it: [`DisabledTokens::begin`] says whether to list now
/// and hands out a [`Listing`] ticket, [`DisabledTokens::record`] takes
/// the result with its ticket, and [`DisabledTokens::abandon`] gives a
/// ticket back whose listing never finished.
///
/// Listings are ordered by their tickets, which only go up, never by
/// the clock: a clock that steps back cannot make a newer listing lose
/// to an older one. A list stamped later than `now` (the clock stepped
/// back) is not fresh, and the next call lists again.
#[derive(Clone, Debug, Default)]
pub struct DisabledTokens {
    /// The last good list: its ticket, when its listing began, the ids.
    good: Option<(u64, UnixMs, BTreeSet<TokenId>)>,
    /// The last listing begun: its ticket and its start.
    tried: Option<(u64, UnixMs)>,
    /// The last ticket handed out.
    seq: u64,
}

/// A listing begun by [`DisabledTokens::begin`].
#[derive(Debug, PartialEq, Eq)]
#[must_use]
pub struct Listing {
    seq: u64,
    began: UnixMs,
}

impl DisabledTokens {
    /// A ticket if a listing is due at `now`: never listed, the last one
    /// began [`LIST_EVERY_MS`] or more ago ([`LIST_AGAIN_SHUT_MS`] while
    /// the door is shut), or the clock is behind it.
    pub fn begin(&mut self, now: UnixMs) -> Option<Listing> {
        let every = match self.fresh(now) {
            Some(_) => LIST_EVERY_MS,
            None => LIST_AGAIN_SHUT_MS,
        };
        let due = match self.tried {
            None => true,
            Some((_, at)) => now.0.saturating_sub(at.0) >= every || now.0 < at.0,
        };
        if !due {
            return None;
        }
        self.seq += 1;
        self.tried = Some((self.seq, now));
        Some(Listing {
            seq: self.seq,
            began: now,
        })
    }

    /// The result of `listing`. A failed one keeps the last good list,
    /// which ages. A good one replaces the last good list unless that
    /// one came from a later ticket.
    pub fn record(&mut self, listing: Listing, listed: Result<BTreeSet<TokenId>>) {
        // `Listing` is neither `Copy` nor `Clone`: a ticket is recorded or
        // abandoned once.
        if let Ok(ids) = listed {
            if self
                .good
                .as_ref()
                .is_none_or(|(seq, _, _)| *seq < listing.seq)
            {
                self.good = Some((listing.seq, listing.began, ids));
            }
        }
    }

    /// `listing` will not be recorded (its request went away): the next
    /// call may list at once instead of after [`LIST_EVERY_MS`].
    pub fn abandon(&mut self, listing: Listing) {
        if self.tried.is_some_and(|(seq, _)| seq == listing.seq) {
            self.tried = None;
        }
    }

    /// The disabled ids, if the last good list is fresh at `now`: not
    /// older than [`STALE_AFTER_MS`], and not stamped after `now`.
    fn fresh(&self, now: UnixMs) -> Option<&BTreeSet<TokenId>> {
        let (_, at, ids) = self.good.as_ref()?;
        let age = now.0.checked_sub(at.0)?;
        (0..=STALE_AFTER_MS).contains(&age).then_some(ids)
    }
}

/// Checks the bearer token of a management call. See the
/// [module](self). `authorization` is the value of the `Authorization`
/// header, if any.
pub fn authenticate(
    hashes: &TokenHashes,
    disabled: &DisabledTokens,
    authorization: Option<&str>,
    now: UnixMs,
) -> std::result::Result<Actor, Refused> {
    let Some(disabled) = disabled.fresh(now) else {
        return Err(Refused::Unavailable);
    };
    let token = authorization
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| TOKEN_LEN.contains(&t.len()) && t.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or(Refused::Unauthenticated)?;
    let (class, token) = hashes
        .find(token.as_bytes())
        .ok_or(Refused::Unauthenticated)?;
    if disabled.contains(&token) {
        return Err(Refused::Unauthenticated);
    }
    Ok(Actor { class, token })
}

/// Every token id under [`DISABLED_TOKEN_PREFIX`], all pages. A name
/// under the prefix that is no token id is skipped: it disables nothing.
/// An error of any page is an error of the whole list.
pub async fn list_disabled<B: BlobStore>(records: &B) -> Result<BTreeSet<TokenId>> {
    let mut ids = BTreeSet::new();
    let mut after = DISABLED_TOKEN_PREFIX.to_string();
    loop {
        let names = records
            .list(DISABLED_TOKEN_PREFIX, &after, LIST_PAGE)
            .await?;
        ids.extend(
            names
                .iter()
                .filter_map(|n| n.strip_prefix(DISABLED_TOKEN_PREFIX))
                .filter_map(TokenId::parse),
        );
        match names.last() {
            Some(last) if names.len() >= LIST_PAGE as usize => last.clone_into(&mut after),
            _ => return Ok(ids),
        }
    }
}

/// The content of a disable record. Only its name counts; the content
/// says what it is and when, sealed as a control record with a door part
/// only.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisableRecord {
    label: String,
    v: u32,
    token: String,
    disabled_at: i64,
}

/// Writes the record that disables `token`: a record that is already
/// there is left as it is. A head, then a put: two disables at once may
/// both write, and the put that lands last keeps its time. Only the name
/// counts, and both write it.
pub async fn write_disable<B: BlobStore, K: Kek>(
    records: &B,
    kek: &K,
    token: &TokenId,
    now: UnixMs,
) -> Result<()> {
    let name = token.disable_record();
    if records.head(&name).await?.is_some() {
        return Ok(());
    }
    let plain = serde_json::to_vec(&DisableRecord {
        label: DISABLE_LABEL.to_string(),
        v: 1,
        token: token.as_str().to_string(),
        disabled_at: now.0,
    })
    .map_err(|_| ERR_DISABLE)?;
    // Door part only: a token must be disabled without any tenant key.
    let sealed = seal_control(
        kek,
        &name,
        &ControlSealer::Global,
        &plain,
        None,
        &mut SystemRng,
    )?;
    let sha: [u8; 32] = Sha256::digest(&sealed).into();
    // No bucket and no extent: the descriptive metadata says "-" and the
    // token id, as a key revocation says its key id.
    let meta = BlobMeta {
        bucket: &BucketId::new("-"),
        extent: &ExtentId::new(token.as_str()),
        cipher_sha256: &sha,
    };
    records.put(&name, sealed, &meta).await
}

/// When `token` was disabled, read from its record; `None` when there is
/// none. Proves the record with the control key and refuses one whose
/// body is not a disable record of this token. The gate never calls it:
/// the name alone disables. It is for the operator's view of a disable.
pub async fn read_disable<B: BlobStore, K: Kek>(
    records: &B,
    kek: &K,
    token: &TokenId,
) -> Result<Option<UnixMs>> {
    let name = token.disable_record();
    let Some(bytes) = records.get(&name, None).await? else {
        return Ok(None);
    };
    let opened = parse_control(&bytes)?.open_door(kek, &name, ControlOwner::Global)?;
    let body: DisableRecord = serde_json::from_slice(opened.door()).map_err(|_| ERR_DISABLE)?;
    if body.label != DISABLE_LABEL || body.v != 1 || body.token != token.as_str() {
        return Err(ERR_DISABLE);
    }
    Ok(Some(UnixMs(body.disabled_at)))
}

/// The id of the token whose SHA-256 is `hash_hex`: what an operator
/// needs to disable a token that only its hash names. `None` for a
/// value that is not a hash.
pub fn id_of_hash(hash_hex: &str) -> Option<TokenId> {
    parse_hash(hash_hex).map(|h| TokenId::of(&h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scope_has_a_distinct_name() {
        let names: BTreeSet<_> = Scope::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), Scope::ALL.len());
    }

    #[test]
    fn a_hash_is_64_lowercase_hex() {
        let ok = "a".repeat(64);
        assert!(parse_hash(&ok).is_some());
        assert!(parse_hash(&"A".repeat(64)).is_none());
        assert!(parse_hash(&"a".repeat(63)).is_none());
        assert!(parse_hash(&"g".repeat(64)).is_none());
        assert_eq!(id_of_hash(&ok).unwrap().as_str(), "aaaaaaaaaaaaaaaa");
    }

    #[test]
    fn a_token_id_is_16_lowercase_hex() {
        assert!(TokenId::parse("0123456789abcdef").is_some());
        for bad in [
            "0123456789abcde",
            "0123456789ABCDEF",
            "0123456789abcdef0",
            "../../../x/abcdef",
        ] {
            assert!(TokenId::parse(bad).is_none(), "{bad}");
        }
    }
}
