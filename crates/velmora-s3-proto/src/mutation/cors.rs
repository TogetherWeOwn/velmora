//! S3 bucket CORS documents and first-match evaluation.

use super::control::{tree, Node};
use crate::{xml, ErrorCode, Result};
use std::fmt::Write;

pub const MAX_CORS_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 100;
const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const METHODS: &[&str] = &["GET", "PUT", "POST", "DELETE", "HEAD"];

#[derive(Debug)]
pub struct CorsConfiguration(Vec<Rule>);

#[derive(Default, Debug)]
struct Rule {
    id: Option<String>,
    origins: Vec<String>,
    methods: Vec<String>,
    allowed_headers: Vec<String>,
    expose_headers: Vec<String>,
    max_age_seconds: Option<u32>,
}

pub struct CorsMatch<'a> {
    pub allow_origin: &'a str,
    pub methods: &'a [String],
    pub expose_headers: &'a [String],
    pub max_age_seconds: Option<u32>,
}

fn wildcard(pattern: &str, value: &str, insensitive: bool) -> bool {
    let eq = |a: &[u8], b: &[u8]| {
        if insensitive {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    };
    let value = value.as_bytes();
    match pattern.split_once('*') {
        None => eq(pattern.as_bytes(), value),
        Some((prefix, suffix)) => {
            value.len() >= prefix.len() + suffix.len()
                && eq(prefix.as_bytes(), &value[..prefix.len()])
                && eq(suffix.as_bytes(), &value[value.len() - suffix.len()..])
        }
    }
}

pub fn valid_cors_header(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

fn valid_origin(value: &str, pattern: bool) -> bool {
    if value == "null" || (pattern && value == "*") {
        return true;
    }
    let Some((scheme, authority)) = value.split_once("://") else {
        return false;
    };
    // Browsers also serialize origins from non-HTTP schemes, such as
    // chrome-extension or capacitor. Keep the scheme an RFC 3986 token.
    let mut scheme = scheme.bytes();
    scheme.next().is_some_and(|b| b.is_ascii_alphabetic())
        && scheme.all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        && !authority.is_empty()
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:-_[]".contains(&b) || (pattern && b == b'*'))
        && (!pattern || authority.bytes().filter(|&b| b == b'*').count() <= 1)
}

pub fn valid_cors_origin(value: &str) -> bool {
    valid_origin(value, false)
}

impl Rule {
    fn parse(node: Node) -> Result<Self> {
        if node.name != "CORSRule" {
            return Err(ErrorCode::MalformedXML);
        }
        node.container()?;
        let mut rule = Self::default();
        for field in node.children {
            let value = field.leaf()?;
            match field.name.as_str() {
                "ID" if rule.id.is_none() && value.chars().count() <= 255 => {
                    rule.id = Some(value.to_owned());
                }
                "AllowedOrigin" if valid_origin(value, true) => rule.origins.push(value.to_owned()),
                "AllowedMethod" if METHODS.contains(&value) => rule.methods.push(value.to_owned()),
                "AllowedHeader"
                    if valid_cors_header(value)
                        && value.bytes().filter(|&b| b == b'*').count() <= 1 =>
                {
                    rule.allowed_headers.push(value.to_owned());
                }
                "ExposeHeader" if valid_cors_header(value) && !value.contains('*') => {
                    rule.expose_headers.push(value.to_owned());
                }
                "MaxAgeSeconds" if rule.max_age_seconds.is_none() => {
                    let seconds = i32::try_from(crate::decimal(value)?)
                        .map_err(|_| ErrorCode::InvalidArgument)?;
                    rule.max_age_seconds = Some(seconds as u32);
                }
                "ID" | "AllowedOrigin" | "AllowedMethod" | "AllowedHeader" | "ExposeHeader"
                | "MaxAgeSeconds" => {
                    return Err(ErrorCode::InvalidArgument);
                }
                _ => return Err(ErrorCode::MalformedXML),
            }
        }
        if rule.origins.is_empty() || rule.methods.is_empty() {
            return Err(ErrorCode::MalformedXML);
        }
        Ok(rule)
    }
}

fn element(output: &mut String, tag: &str, value: &str) {
    write!(output, "<{tag}>{}</{tag}>", xml(value)).expect("write to String");
}

impl CorsConfiguration {
    /// Parse a bounded CORSConfiguration, rejecting unknown fields and DTDs.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        // An element consumes at least seven source bytes even with empty content.
        let root = tree(bytes, MAX_CORS_BYTES, MAX_CORS_BYTES / 7)?;
        if root.name != "CORSConfiguration" || !(1..=MAX_RULES).contains(&root.children.len()) {
            return Err(ErrorCode::MalformedXML);
        }
        root.container()?;
        root.children
            .into_iter()
            .map(Rule::parse)
            .collect::<Result<_>>()
            .map(Self)
    }

    pub fn rule_count(&self) -> usize {
        self.0.len()
    }

    /// Serialize once for both the stored document and the GET response.
    pub fn document(&self) -> Result<String> {
        let mut doc = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CORSConfiguration xmlns=\"{XMLNS}\">"
        );
        for rule in &self.0 {
            doc.push_str("<CORSRule>");
            if let Some(id) = &rule.id {
                element(&mut doc, "ID", id);
            }
            for (tag, values) in [
                ("AllowedOrigin", &rule.origins),
                ("AllowedMethod", &rule.methods),
                ("AllowedHeader", &rule.allowed_headers),
                ("ExposeHeader", &rule.expose_headers),
            ] {
                for value in values {
                    element(&mut doc, tag, value);
                }
            }
            if let Some(max_age) = rule.max_age_seconds {
                element(&mut doc, "MaxAgeSeconds", &max_age.to_string());
            }
            doc.push_str("</CORSRule>");
        }
        doc.push_str("</CORSConfiguration>");
        if doc.len() > MAX_CORS_BYTES {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(doc)
    }

    /// First rule matching the origin, method, and all requested header names.
    /// Actual requests pass no requested headers; their authentication and
    /// ordinary request headers are independent of CORS.
    pub fn first_match<'a>(
        &'a self,
        origin: &'a str,
        method: &str,
        requested: &[&str],
    ) -> Option<CorsMatch<'a>> {
        for rule in &self.0 {
            let Some(pattern) = rule.origins.iter().find(|p| wildcard(p, origin, false)) else {
                continue;
            };
            if rule.methods.iter().any(|m| m == method)
                && requested
                    .iter()
                    .all(|h| rule.allowed_headers.iter().any(|p| wildcard(p, h, true)))
            {
                return Some(CorsMatch {
                    allow_origin: if pattern == "*" { "*" } else { origin },
                    methods: &rule.methods,
                    expose_headers: &rule.expose_headers,
                    max_age_seconds: rule.max_age_seconds,
                });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULE: &str = "<CORSRule><AllowedOrigin>https://*.example.test</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedHeader>X-Amz-*</AllowedHeader></CORSRule>";

    fn config(rules: &str) -> Result<CorsConfiguration> {
        CorsConfiguration::parse(
            format!("<CORSConfiguration>{rules}</CORSConfiguration>").as_bytes(),
        )
    }

    #[test]
    fn origin_and_method_are_exact_but_header_names_ignore_case() {
        let cfg = config(RULE).unwrap();
        let origin = "https://app.example.test";
        let found = cfg
            .first_match(origin, "PUT", &["x-amz-date", "X-aMz-User-Agent"])
            .unwrap();
        assert_eq!(found.allow_origin, origin);
        for (origin, method, headers) in [
            (origin, "put", &["X-Amz-Date"][..]),
            ("https://app.Example.test", "PUT", &[]),
            ("https://app.example.test.attacker.test", "PUT", &[]),
            (origin, "PUT", &["Content-Type"]),
        ] {
            assert!(cfg.first_match(origin, method, headers).is_none());
        }
    }

    #[test]
    fn cors_accepts_custom_uri_schemes_but_not_malformed_origins() {
        for (pattern, origin) in [
            (
                "chrome-extension://*.example.test",
                "chrome-extension://app.example.test",
            ),
            ("capacitor://localhost", "capacitor://localhost"),
            ("App+dev.1://localhost:8443", "App+dev.1://localhost:8443"),
        ] {
            let rule = RULE.replace("https://*.example.test", pattern);
            let cfg = config(&rule).expect(pattern);
            assert!(valid_cors_origin(origin));
            assert_eq!(
                cfg.first_match(origin, "PUT", &[]).unwrap().allow_origin,
                origin
            );
            assert_eq!(
                CorsConfiguration::parse(cfg.document().unwrap().as_bytes())
                    .unwrap()
                    .rule_count(),
                1
            );
        }
        for invalid in [
            "1app://localhost",
            "x*app://localhost",
            "app://bad origin",
            "app://good, app://other",
            "app://host/path",
        ] {
            let rule = RULE.replace("https://*.example.test", invalid);
            assert!(config(&rule).is_err(), "{invalid}");
            assert!(!valid_cors_origin(invalid));
        }
    }

    #[test]
    fn xml_is_bounded_and_rule_order_roundtrips() {
        let first = "<CORSRule><ID>first &amp; best</ID><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule>";
        let cfg = config(&format!("{first}{RULE}")).unwrap();
        let doc = cfg.document().unwrap();
        assert!(doc.contains("first &amp; best"));
        let cfg = CorsConfiguration::parse(doc.as_bytes()).unwrap();
        assert_eq!(
            cfg.first_match("https://app.example.test", "PUT", &[])
                .unwrap()
                .allow_origin,
            "*"
        );
        assert_eq!(cfg.rule_count(), 2);
        assert_eq!(config(&RULE.repeat(100)).unwrap().rule_count(), 100);
        assert!(config(&RULE.repeat(101)).is_err());
        assert!(CorsConfiguration::parse(&vec![b' '; MAX_CORS_BYTES + 1]).is_err());
        for invalid in [
            RULE.replace("https://*.", "https://*.*."),
            RULE.replace("X-Amz-*", "X-*-*"),
            RULE.replace("PUT", "OPTIONS"),
        ] {
            assert!(config(&invalid).is_err(), "{invalid}");
        }
        assert!(
            CorsConfiguration::parse(b"<!DOCTYPE CORSConfiguration><CORSConfiguration />").is_err()
        );
    }
}
