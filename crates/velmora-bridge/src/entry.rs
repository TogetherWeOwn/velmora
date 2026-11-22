//! Which entry point a request came in by, and which kind of credential
//! each entry point accepts.
//!
//! An access key has a kind, fixed when it is minted and never changed:
//!
//! | Kind | Id prefix | Accepted by |
//! |---|---|---|
//! | S3 key | anything but [`APP_PASSWORD_PREFIX`] (minted with [`S3_KEY_PREFIX`]) | the S3 entry point only |
//! | App password | [`APP_PASSWORD_PREFIX`] | the WebDAV entry point only |
//!
//! The kind is read from the id, so it needs no column and no extra read,
//! cannot be changed after the key is minted, and every key minted
//! before app passwords existed (`AKVL…`) stays an S3 key.
//!
//! **The entry point.** A WebDAV gateway calls this Worker over a service
//! binding to a named entrypoint (`DavEntry` in the Worker's
//! `entry.mjs`; the header in `entry-marker.mjs`). That entrypoint sets [`ENTRY_HEADER`] to `webdav`; the
//! default entrypoint, which serves every request from the Internet and
//! the Worker's own binding to itself, deletes the header before the
//! request reaches Rust. As a second guard the header counts only when
//! the request carries none of the headers the edge adds
//! ([`from_edge`]): a request from the Internet always carries some, a
//! request over a service binding carries none. A request that fails
//! either test is an S3 request.
//!
//! A credential of the wrong kind for its entry point is treated as an
//! unknown key (`InvalidAccessKeyId`): it says nothing about whether the
//! key exists.

/// Set by the named WebDAV entrypoint, deleted by the default one.
pub const ENTRY_HEADER: &str = "x-velmora-entry";

/// The value of [`ENTRY_HEADER`] that names the WebDAV entry point.
pub const WEBDAV: &str = "webdav";

/// The value of [`ENTRY_HEADER`] that names the management entry point
/// (`MgmtEntry` in `entry.mjs`), which only `kofra-api` is bound to. A
/// request by it is served by [`crate::mgmt`] and never reaches the S3
/// handler.
pub const MGMT: &str = "mgmt";

/// Id prefix of an S3 key minted by the admin API.
pub const S3_KEY_PREFIX: &str = "AKVL";

/// Id prefix of an app password: a key pair for the WebDAV entry point.
pub const APP_PASSWORD_PREFIX: &str = "APVL";

/// What a credential is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    S3,
    AppPassword,
}

impl KeyKind {
    /// The kind of the key with this id.
    pub fn of(access_key_id: &str) -> KeyKind {
        if access_key_id.starts_with(APP_PASSWORD_PREFIX) {
            KeyKind::AppPassword
        } else {
            KeyKind::S3
        }
    }

    /// The prefix the admin API mints ids of this kind with.
    pub fn prefix(self) -> &'static str {
        match self {
            KeyKind::S3 => S3_KEY_PREFIX,
            KeyKind::AppPassword => APP_PASSWORD_PREFIX,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::S3 => "s3",
            KeyKind::AppPassword => "app_password",
        }
    }

    pub fn parse(s: &str) -> Option<KeyKind> {
        match s {
            "s3" => Some(KeyKind::S3),
            "app_password" => Some(KeyKind::AppPassword),
            _ => None,
        }
    }
}

/// The entry point a request came in by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// The public S3 endpoint (and anything that is not provably WebDAV).
    S3,
    /// The named entrypoint the WebDAV gateway is bound to.
    WebDav,
    /// The named entrypoint of the management plane (`/v1`).
    Mgmt,
}

/// A header the edge adds to every request from the Internet. The same
/// list as the one dropped before signature verification.
pub fn edge_header(name: &str) -> bool {
    name.starts_with("cf-")
        || name.starts_with("x-forwarded-")
        || matches!(name, "cdn-loop" | "x-real-ip" | "true-client-ip")
}

/// Whether the request carries a header that only the edge adds. Header
/// names arrive in lower case (`S3Request::headers`); a name in any other
/// case is no edge header here, and no entry marker either
/// ([`Entry::of`] compares the same way).
pub fn from_edge(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, _)| edge_header(name))
}

/// A header that is dropped before signature verification: one the edge
/// adds, or the entry marker. Dropping a header can only fail a
/// signature, never satisfy one.
pub fn dropped_header(name: &str) -> bool {
    edge_header(name) || name == ENTRY_HEADER
}

impl Entry {
    /// The entry point of a request with these headers: WebDAV or the
    /// management plane only when exactly one [`ENTRY_HEADER`] says so and
    /// nothing says the request came from the edge.
    pub fn of(headers: &[(String, String)]) -> Entry {
        let mut marks = headers.iter().filter(|(name, _)| name == ENTRY_HEADER);
        let named = match (marks.next(), marks.next()) {
            (Some((_, value)), None) if value == WEBDAV => Entry::WebDav,
            (Some((_, value)), None) if value == MGMT => Entry::Mgmt,
            _ => Entry::S3,
        };
        if from_edge(headers) {
            Entry::S3
        } else {
            named
        }
    }

    /// Whether this entry point accepts the key with this id. The
    /// management entry point accepts none: its callers hold service
    /// tokens, never an access key.
    pub fn admits(self, access_key_id: &str) -> bool {
        matches!(
            (self, KeyKind::of(access_key_id)),
            (Entry::S3, KeyKind::S3) | (Entry::WebDav, KeyKind::AppPassword)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn kind_comes_from_the_id() {
        assert_eq!(KeyKind::of("AKVLABCDEFGH12345678"), KeyKind::S3);
        assert_eq!(KeyKind::of("APVLABCDEFGH12345678"), KeyKind::AppPassword);
        // Ids from before app passwords, and test ids, are S3 keys.
        assert_eq!(KeyKind::of("AKIDTESTKEY000000001"), KeyKind::S3);
        assert_eq!(KeyKind::of("apvlLOWERCASE"), KeyKind::S3);
        assert_eq!(KeyKind::of(""), KeyKind::S3);
        for kind in [KeyKind::S3, KeyKind::AppPassword] {
            assert_eq!(KeyKind::parse(kind.as_str()), Some(kind));
            assert_eq!(KeyKind::of(&format!("{}X", kind.prefix())), kind);
        }
        assert_eq!(KeyKind::parse("internal"), None);
    }

    #[test]
    fn mgmt_only_by_the_marker_never_from_the_edge_and_with_no_key() {
        assert_eq!(Entry::of(&h(&[(ENTRY_HEADER, MGMT)])), Entry::Mgmt);
        for edge in ["cf-connecting-ip", "cf-ray", "x-forwarded-for", "cdn-loop"] {
            assert_eq!(
                Entry::of(&h(&[(ENTRY_HEADER, MGMT), (edge, "1")])),
                Entry::S3,
                "{edge}"
            );
        }
        for value in ["MGMT", " mgmt", "mgmt ", "mgmt,webdav", "management"] {
            assert_eq!(Entry::of(&h(&[(ENTRY_HEADER, value)])), Entry::S3);
        }
        assert_eq!(
            Entry::of(&h(&[(ENTRY_HEADER, MGMT), (ENTRY_HEADER, MGMT)])),
            Entry::S3
        );
        assert_eq!(
            Entry::of(&h(&[(ENTRY_HEADER, MGMT), (ENTRY_HEADER, WEBDAV)])),
            Entry::S3
        );
        assert_eq!(Entry::of(&h(&[("X-Velmora-Entry", MGMT)])), Entry::S3);
        for akid in ["AKVLABCDEFGH12345678", "APVLABCDEFGH12345678", ""] {
            assert!(!Entry::Mgmt.admits(akid), "{akid}");
        }
    }

    #[test]
    fn webdav_only_by_the_marker_and_never_from_the_edge() {
        assert_eq!(Entry::of(&h(&[("host", "s3.test")])), Entry::S3);
        assert_eq!(
            Entry::of(&h(&[("host", "s3.test"), (ENTRY_HEADER, WEBDAV)])),
            Entry::WebDav
        );
        // Any edge header: the marker is forged or the wrapper is missing.
        for edge in [
            "cf-connecting-ip",
            "cf-ray",
            "x-forwarded-proto",
            "cdn-loop",
            "x-real-ip",
            "true-client-ip",
        ] {
            assert_eq!(
                Entry::of(&h(&[(ENTRY_HEADER, WEBDAV), (edge, "1")])),
                Entry::S3,
                "{edge}"
            );
        }
        // Another value, a value with other case or spaces, or two markers.
        for value in ["WebDAV", " webdav", "webdav ", "s3", ""] {
            assert_eq!(Entry::of(&h(&[(ENTRY_HEADER, value)])), Entry::S3);
        }
        assert_eq!(
            Entry::of(&h(&[(ENTRY_HEADER, WEBDAV), (ENTRY_HEADER, WEBDAV)])),
            Entry::S3
        );
        // Names arrive in lower case; another case is no marker.
        assert_eq!(Entry::of(&h(&[("X-Velmora-Entry", WEBDAV)])), Entry::S3);
    }

    #[test]
    fn each_entry_admits_its_own_kind_only() {
        assert!(Entry::S3.admits("AKVL0000000000000000"));
        assert!(!Entry::S3.admits("APVL0000000000000000"));
        assert!(Entry::WebDav.admits("APVL0000000000000000"));
        assert!(!Entry::WebDav.admits("AKVL0000000000000000"));
        assert!(!Entry::WebDav.admits("AKIDTESTKEY000000001"));
    }

    /// The Worker's main module is the wrapper (a revert to the generated
    /// shim would drop the marker deletion and `DavEntry`), and its marker
    /// module sets and deletes the same header with the same value.
    #[test]
    fn the_entry_module_agrees() {
        let wrangler = include_str!("../../../workers/s3-bridge/wrangler.toml");
        assert!(wrangler.lines().any(|l| l.trim() == "main = \"entry.mjs\""));
        let main = include_str!("../../../workers/s3-bridge/entry.mjs");
        assert!(main.contains("export class DavEntry extends WorkerEntrypoint"));
        assert!(main.contains("marked(request, null)"));
        assert!(main.contains("marked(request, WEBDAV)"));
        let module = include_str!("../../../workers/s3-bridge/entry-marker.mjs");
        assert!(module.contains(&format!("ENTRY_HEADER = \"{ENTRY_HEADER}\";")));
        assert!(module.contains(&format!("WEBDAV = \"{WEBDAV}\";")));
    }

    #[test]
    fn the_marker_is_dropped_before_verification() {
        assert!(dropped_header(ENTRY_HEADER));
        assert!(dropped_header("cf-ray"));
        assert!(!dropped_header("x-amz-date"));
        assert!(!dropped_header("host"));
    }
}
