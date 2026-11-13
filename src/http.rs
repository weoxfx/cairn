//! The one HTTP client for every backend.
//!
//! Esplora, the EVM JSON-RPC client and the price lookup each used to build
//! their own agent with their own timeouts, proxy handling, redirect policy and
//! body caps. They drifted: the price lookup ignored `CAIRN_TOR` and silently
//! dropped an unparseable `CAIRN_PROXY`, so a "private" request went straight to
//! the internet. One builder keeps TLS-only, no-redirect, proxy-fails-closed and
//! the size cap identical everywhere, and gives every failure a kind.

use crate::error::{Error, Kind, Result};
use std::io::Read;
use std::time::Duration;

const USER_AGENT: &str = concat!("cairn/", env!("CARGO_PKG_VERSION"));

/// `CAIRN_PROXY` wins; `CAIRN_TOR=1` is shorthand for the standard local Tor
/// SOCKS port. An empty value counts as unset.
pub fn proxy_from_values(proxy: Option<&str>, tor: Option<&str>) -> Option<String> {
    if let Some(v) = proxy {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    match tor {
        Some("1") | Some("true") | Some("yes") => Some("socks5://127.0.0.1:9050".into()),
        _ => None,
    }
}

pub fn proxy_setting() -> Option<String> {
    proxy_from_values(
        std::env::var("CAIRN_PROXY").ok().as_deref(),
        std::env::var("CAIRN_TOR").ok().as_deref(),
    )
}

/// Human-readable proxy description with credentials removed.
pub fn proxy_desc_for(p: &str) -> String {
    if let Some(at) = p.rfind('@') {
        let scheme = p.split("://").next().unwrap_or("proxy");
        format!("{scheme}://***@{p_tail}", p_tail = &p[at + 1..])
    } else {
        p.to_string()
    }
}

/// Build an agent for one backend. `tag` names it in the user agent.
///
/// A configured proxy that cannot be parsed is an error, never a silent direct
/// connection: the user asked for that path and must not get the other one.
pub fn agent(tag: &str, connect: Duration, read: Duration, total: Duration) -> Result<ureq::Agent> {
    let user_agent = format!("{USER_AGENT} ({tag})");
    let mut builder = ureq::AgentBuilder::new()
        .timeout_connect(connect)
        .timeout_read(read)
        .timeout(total)
        .user_agent(&user_agent)
        .https_only(true) // refuse http outright
        .redirects(0) // redirects are followed manually by the caller, same host only
        .max_idle_connections(0); // fresh connection each time: no stale pooled sockets
    if let Some(p) = proxy_setting() {
        let proxy = ureq::Proxy::new(&p)
            .map_err(|e| Error::input(format!("invalid CAIRN_PROXY/CAIRN_TOR setting: {e}")))?;
        builder = builder.proxy(proxy);
    }
    Ok(builder.build())
}

/// Read a response body, refusing anything over `cap` bytes. `what` names the
/// peer in the error ("server response", "RPC response").
pub fn read_body(resp: ureq::Response, cap: u64, what: &str) -> Result<String> {
    let mut body = String::new();
    resp.into_reader()
        .take(cap + 1)
        .read_to_string(&mut body)
        .map_err(|e| Error::network(format!("read error: {e}")))?;
    if body.len() as u64 > cap {
        return Err(Error::network(format!("{what} exceeds the size limit")));
    }
    Ok(body)
}

/// Server-controlled text is untrusted. This is an allowlist, not a denylist:
/// only printable ASCII (and spaces) survive, so no Unicode control, bidi,
/// zero-width, line-breaking or terminal-escape character can reach the screen.
pub fn safe_text(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max_chars)
        .collect()
}

/// A definitive HTTP status. 4xx is a refusal (retrying elsewhere is pointless),
/// 429 and 5xx are the server being busy and are worth another attempt.
pub fn status_error(code: u16, resp: ureq::Response, what: &str) -> Error {
    if code == 429 || code >= 500 {
        return Error::network(format!("{what} busy or down (HTTP {code})"));
    }
    let mut b = String::new();
    let _ = resp.into_reader().take(2000).read_to_string(&mut b);
    let text = b.trim();
    if text.is_empty() {
        Error::rejected(format!("HTTP {code}"))
    } else {
        Error::rejected(safe_text(text, 500))
    }
}

/// Map a transport error. Everything that is not a status is a network problem.
pub fn transport_error(err: ureq::Error) -> Error {
    match err {
        ureq::Error::Status(code, resp) => status_error(code, resp, "server"),
        other => Error::network(format!("network error: {other}")),
    }
}

/// One JSON POST, with the shared body cap and error mapping.
pub fn post_json(
    agent: &ureq::Agent,
    url: &str,
    body: &str,
    what: &str,
    cap: u64,
) -> Result<serde_json::Value> {
    let resp = agent
        .post(url)
        .set("content-type", "application/json")
        .send_string(body);
    match resp {
        Ok(r) => {
            let text = read_body(r, cap, what)?;
            serde_json::from_str(&text)
                .map_err(|_| Error::network(format!("{what} returned invalid JSON")))
        }
        Err(ureq::Error::Status(code, resp)) => Err(status_error(code, resp, what)),
        Err(e) => Err(Error::network(format!("network error: {e}"))),
    }
}

/// True when this error is a definitive refusal, which callers use to stop
/// failing over to another endpoint.
pub fn is_rejected(e: &Error) -> bool {
    e.kind() == Kind::Rejected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_settings_are_parsed_and_redacted() {
        assert_eq!(
            proxy_from_values(Some("socks5://127.0.0.1:9050"), None).as_deref(),
            Some("socks5://127.0.0.1:9050")
        );
        assert_eq!(
            proxy_from_values(Some("  "), Some("1")).as_deref(),
            Some("socks5://127.0.0.1:9050")
        );
        assert_eq!(
            proxy_from_values(Some("socks5://user:pass@host:1080"), Some("1")).as_deref(),
            Some("socks5://user:pass@host:1080")
        );
        assert_eq!(proxy_from_values(None, Some("0")), None);
        assert_eq!(
            proxy_desc_for("socks5://user:pass@host:1080"),
            "socks5://***@host:1080"
        );
        assert_eq!(proxy_desc_for("socks5://host:1080"), "socks5://host:1080");
    }

    /// An invalid `CAIRN_PROXY` must fail closed for every backend, including the
    /// cosmetic price lookup, instead of quietly going out direct.
    #[test]
    fn an_invalid_proxy_never_falls_back_to_direct() {
        // `socks5h://` is what people copy from curl; ureq does not accept it.
        std::env::set_var("CAIRN_PROXY", "socks5h://127.0.0.1:9050");
        std::env::remove_var("CAIRN_TOR");
        let err = agent(
            "test",
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(err.kind(), Kind::Input);
        assert!(err.contains("CAIRN_PROXY"));
        std::env::remove_var("CAIRN_PROXY");
    }

    #[test]
    fn server_text_is_an_ascii_allowlist() {
        assert_eq!(safe_text("ok\x1b[2Jhere", 100), "ok[2Jhere");
        assert_eq!(safe_text("aaaaaaaaaa", 3), "aaa");
    }
}
