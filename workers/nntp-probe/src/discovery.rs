//! Pure helpers for the provider-discovery routes: message-id validation,
//! header selection and redaction. No I/O, so they are unit-tested natively.

/// Headers the `HEAD` route may return. Everything else is dropped.
pub const SELECTED_HEADERS: [&str; 4] = ["Path", "Xref", "Injection-Info", "NNTP-Posting-Host"];

/// Upper bound on a returned header value or reply line, after redaction.
pub const MAX_VALUE_CHARS: usize = 512;

/// Placeholder for a redacted token.
pub const REDACTED: &str = "<redacted>";

/// A message-id safe to splice into one NNTP command line: `<...>`, printable
/// ASCII, no whitespace, at most 250 bytes (RFC 5536 §3.1.3).
pub fn valid_message_id(mid: &str) -> bool {
    mid.len() >= 3
        && mid.len() <= 250
        && mid.starts_with('<')
        && mid.ends_with('>')
        && mid[1..mid.len() - 1]
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'<' && b != b'>')
}

/// Accepts a message-id with or without angle brackets (the engine stores
/// and takes them bare) and returns the bracketed form if it is valid.
pub fn normalize_message_id(mid: &str) -> Option<String> {
    let bracketed = if mid.starts_with('<') {
        mid.to_string()
    } else {
        format!("<{mid}>")
    };
    valid_message_id(&bracketed).then_some(bracketed)
}

/// Entry `k` (0-based) of a comma-separated `host:port` list.
pub fn alt_endpoint(list: &str, k: usize) -> Option<(String, u16)> {
    let entry = list
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .nth(k)?;
    let (host, port) = entry.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|p| *p != 0)?;
    (!host.is_empty() && !host.contains(char::is_whitespace)).then(|| (host.to_string(), port))
}

/// Parses a raw header block (dot-unstuffed lines, no terminator) into
/// `(name, unfolded value)` pairs, keeping only [`SELECTED_HEADERS`]
/// (matched case-insensitively). Continuation lines are unfolded with one
/// space.
pub fn select_headers(lines: &[Vec<u8>]) -> Vec<(String, String)> {
    let mut all: Vec<(String, String)> = Vec::new();
    for raw in lines {
        let line = String::from_utf8_lossy(raw);
        let line = line.trim_end_matches(['\r', '\n']);
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = all.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            all.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    all.into_iter()
        .filter_map(|(name, value)| {
            SELECTED_HEADERS
                .iter()
                .find(|want| want.eq_ignore_ascii_case(&name))
                .map(|want| (want.to_string(), value))
        })
        .collect()
}

/// Length of a dotted-quad IPv4 run (`d{1,3}(.d{1,3}){3}`) starting at
/// `i`, if one starts there and is not followed by another digit.
fn ipv4_run_at(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    for part in 0..4 {
        if part > 0 {
            if b.get(j) != Some(&b'.') {
                return None;
            }
            j += 1;
        }
        let start = j;
        while j < b.len() && j - start < 3 && b[j].is_ascii_digit() {
            j += 1;
        }
        if j == start {
            return None;
        }
    }
    if b.get(j).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    Some(j - i)
}

/// Replaces every IPv4 run anywhere in `s` (inside Path diagnostics such as
/// `.POSTED.203.0.113.9`, in brackets, after `@`, before a full stop).
fn redact_ipv4_runs(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut i = 0;
    while i < b.len() {
        let starts_run = b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_digit());
        if let Some(len) = starts_run.then(|| ipv4_run_at(b, i)).flatten() {
            // Runs are ASCII, so these are char boundaries.
            out.push_str(&s[copied..i]);
            out.push_str(REDACTED);
            i += len;
            copied = i;
        } else {
            i += 1;
        }
    }
    out.push_str(&s[copied..]);
    out
}

/// True for something shaped like an IPv6 address: hex digits and at least
/// two colons, nothing else (embedded IPv4 tails are caught separately).
fn looks_like_ipv6(tok: &str) -> bool {
    let t = tok.trim_end_matches('.');
    t.matches(':').count() >= 2
        && t.bytes().any(|b| b.is_ascii_hexdigit())
        && t.bytes()
            .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
}

/// Separators that split a value into tokens for IPv6 detection.
fn is_sep(c: char) -> bool {
    c.is_whitespace()
        || matches!(
            c,
            '!' | ';'
                | ','
                | '"'
                | '\''
                | '('
                | ')'
                | '='
                | '/'
                | '<'
                | '>'
                | '['
                | ']'
                | '@'
                | '%'
        )
}

/// Replaces every IP-shaped substring with [`REDACTED`].
pub fn redact_ips(s: &str) -> String {
    let s = redact_ipv4_runs(s);
    let mut out = String::with_capacity(s.len());
    let mut tok = String::new();
    let flush = |tok: &mut String, out: &mut String| {
        if looks_like_ipv6(tok) {
            out.push_str(REDACTED);
            if tok.ends_with('.') {
                out.push('.');
            }
        } else {
            out.push_str(tok);
        }
        tok.clear();
    };
    for c in s.chars() {
        if is_sep(c) {
            flush(&mut tok, &mut out);
            out.push(c);
        } else {
            tok.push(c);
        }
    }
    flush(&mut tok, &mut out);
    out
}

/// Replaces each non-empty secret value (ASCII case-insensitively) with its
/// label in one left-to-right pass over the original string, so a short
/// value can never match inside a label inserted for another. `values`
/// should be sorted longest first; at each position the first match wins.
pub fn redact_values(s: &str, values: &[(String, String)]) -> String {
    let lower = s.to_ascii_lowercase();
    let needles: Vec<(String, &str)> = values
        .iter()
        .filter(|(v, _)| !v.is_empty())
        .map(|(v, l)| (v.to_ascii_lowercase(), l.as_str()))
        .collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if let Some((v, label)) = needles
            .iter()
            .find(|(v, _)| lower[i..].starts_with(v.as_str()))
        {
            out.push_str(label);
            i += v.len();
            continue;
        }
        let ch = s[i..].chars().next().expect("i is a char boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Splits on `;` outside double quotes.
fn split_params(value: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut in_quotes = false;
    let mut start = 0;
    for (i, c) in value.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            ';' if !in_quotes => {
                parts.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&value[start..]);
    parts
}

/// `Injection-Info: <server> [comment]; key="value"; ...` keeps only the
/// injecting server name (first token) and well-formed parameter names;
/// every parameter value is redacted (they carry posting hosts, account
/// ids and logging data).
pub fn redact_injection_info(value: &str) -> String {
    let parts = split_params(value);
    let mut out = parts[0].split_whitespace().next().unwrap_or("").to_string();
    for p in &parts[1..] {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let name = p.split('=').next().unwrap_or("").trim();
        let name_ok = p.contains('=')
            && !name.is_empty()
            && name.len() <= 40
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        out.push_str("; ");
        out.push_str(if name_ok { name } else { REDACTED });
        out.push('=');
        out.push_str(REDACTED);
    }
    out
}

/// Full redaction for one selected header value.
pub fn redact_header(name: &str, value: &str, values: &[(String, String)]) -> String {
    let v = match name {
        // The posting host is the client address or its reverse name.
        "NNTP-Posting-Host" => REDACTED.to_string(),
        "Injection-Info" => redact_injection_info(value),
        _ => value.to_string(),
    };
    truncate(&redact_ips(&redact_values(&v, values)))
}

/// Redaction for a free-text reply line (greeting, capability lines).
pub fn redact_line(line: &str, values: &[(String, String)]) -> String {
    truncate(&redact_ips(&redact_values(line, values)))
}

/// The first `n` `!`-separated Path elements: the reading server's own
/// identity and its nearest peers.
pub fn path_head(path: &str, n: usize) -> Vec<String> {
    path.split('!')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .take(n)
        .map(str::to_string)
        .collect()
}

/// The server name of an `Xref` value (its first token).
pub fn xref_server(xref: &str) -> Option<String> {
    xref.split_whitespace().next().map(str::to_string)
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_VALUE_CHARS {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(MAX_VALUE_CHARS).collect();
        t.push_str("...");
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_validation() {
        assert!(valid_message_id("<abc.def@example>"));
        assert!(!valid_message_id("abc@example"));
        assert!(!valid_message_id("<abc def@example>"));
        assert!(!valid_message_id("<abc@example>\r\nQUIT"));
        assert!(!valid_message_id("<a<b@x>"));
        assert!(!valid_message_id("<>"));
        assert!(!valid_message_id(&format!("<{}@x>", "a".repeat(250))));
    }

    #[test]
    fn alt_endpoint_parsing() {
        let list = "a.example:563, b.example:443,,c.example:0,d.example";
        assert_eq!(alt_endpoint(list, 0), Some(("a.example".into(), 563)));
        assert_eq!(alt_endpoint(list, 1), Some(("b.example".into(), 443)));
        assert_eq!(alt_endpoint(list, 2), None); // port 0
        assert_eq!(alt_endpoint(list, 3), None); // no port
        assert_eq!(alt_endpoint(list, 4), None); // out of range
    }

    #[test]
    fn message_id_normalization() {
        assert_eq!(normalize_message_id("a@x").as_deref(), Some("<a@x>"));
        assert_eq!(normalize_message_id("<a@x>").as_deref(), Some("<a@x>"));
        assert_eq!(normalize_message_id("a b@x"), None);
        assert_eq!(normalize_message_id("<a@x"), None);
        assert_eq!(normalize_message_id("a@x>"), None);
    }

    #[test]
    fn selects_and_unfolds_headers() {
        let lines: Vec<Vec<u8>> = [
            "Path: srv-a.example!feed-b.example!not-for-mail",
            "From: someone <x@y>",
            "xref: srv-a.example alt.binaries.test:123",
            "Injection-Info: inj.example; posting-host=\"203.0.113.9\";",
            "\tlogging-data=\"42\"; mail-complaints-to=\"abuse@inj.example\"",
            "NNTP-Posting-Host: 198.51.100.7",
            "Subject: hidden",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
        let got = select_headers(&lines);
        let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["Path", "Xref", "Injection-Info", "NNTP-Posting-Host"]
        );
        assert!(got[2].1.contains("logging-data"));
    }

    #[test]
    fn redacts_ips_and_injection_params() {
        let values = vec![("acct-user".to_string(), "<user>".to_string())];
        assert_eq!(
            redact_header("Path", "a.example!203.0.113.9!b!not-for-mail", &values),
            "a.example!<redacted>!b!not-for-mail"
        );
        assert_eq!(
            redact_header("Path", "a!2001:db8::1!c", &values),
            "a!<redacted>!c"
        );
        assert_eq!(
            redact_header(
                "Injection-Info",
                "inj.example; posting-host=\"203.0.113.9\"; logging-data=\"x\"",
                &values
            ),
            "inj.example; posting-host=<redacted>; logging-data=<redacted>"
        );
        assert_eq!(
            redact_header("NNTP-Posting-Host", "anything", &values),
            "<redacted>"
        );
        assert_eq!(
            redact_line("200 Welcome ACCT-USER from 192.0.2.1", &values),
            "200 Welcome <user> from <redacted>"
        );
        // IPv4 anywhere: Path diagnostics, brackets, after @, before a full stop.
        for (input, want) in [
            (
                "fx1.iad.POSTED.203.0.113.9!x",
                "fx1.iad.POSTED.<redacted>!x",
            ),
            ("from 192.0.2.1.", "from <redacted>."),
            ("[192.0.2.1]", "[<redacted>]"),
            ("user@1.2.3.4", "user@<redacted>"),
            ("host:1.2.3.4", "host:<redacted>"),
            ("'1.2.3.4'", "'<redacted>'"),
            ("fe80::1%eth0", "<redacted>%eth0"),
            ("[2001:db8::1]:563", "[<redacted>]:563"),
            ("::ffff:192.0.2.1", "<redacted><redacted>"),
        ] {
            assert_eq!(redact_ips(input), want, "{input}");
        }
        // Hostnames with digits are not IPs; version strings are not either.
        assert_eq!(redact_ips("news4.example v2.1.3"), "news4.example v2.1.3");
    }

    #[test]
    fn injection_info_is_quote_aware() {
        assert_eq!(
            redact_injection_info(
                "inj.example (user 1234); posting-account=\"abc;uid42\"; bare; x y=\"1\""
            ),
            "inj.example; posting-account=<redacted>; <redacted>=<redacted>; <redacted>=<redacted>"
        );
    }

    #[test]
    fn value_redaction_is_single_pass() {
        // A short value must not match inside a label inserted earlier.
        let values = vec![
            (
                "news.example".to_string(),
                "<configured-host:p1>".to_string(),
            ),
            ("host".to_string(), "<user>".to_string()),
        ];
        assert_eq!(
            redact_values("200 NEWS.example host", &values),
            "200 <configured-host:p1> <user>"
        );
        assert_eq!(redact_values("caf\u{e9} host", &values), "caf\u{e9} <user>");
    }

    #[test]
    fn path_and_xref_parsing() {
        assert_eq!(
            path_head("a.example!b.example!c!d!not-for-mail", 3),
            ["a.example", "b.example", "c"]
        );
        assert_eq!(
            xref_server("srv.example alt.binaries.test:1").as_deref(),
            Some("srv.example")
        );
        assert_eq!(xref_server(""), None);
    }
}
