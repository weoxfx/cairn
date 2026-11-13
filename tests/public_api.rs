//! Cross-module tests that use the library the way a script, a fuzz target or a
//! downstream crate does: through `cairn::…`, not through private helpers.
//!
//! These complement the in-module unit tests. They exist because the wallet used
//! to be a binary-only crate, so nothing ever exercised the public surface as a
//! whole.

use cairn::error::{Error, Kind};

#[test]
fn qr_frames_round_trip_and_refuse_corruption() {
    let payload: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let frames = cairn::qr::encode_frames(&payload).expect("a 2 KiB payload fits the frame limit");
    assert!(frames.len() > 1, "large payloads are split into frames");

    let decoded = cairn::qr::reassemble(&frames).expect("cairn's own frames reassemble");
    assert_eq!(decoded, payload);

    // A frame that has been tampered with must not decode to something plausible.
    let mut broken = frames.clone();
    let last = broken.len() - 1;
    if let Some(c) = broken[last].pop() {
        broken[last].insert(0, c);
    }
    assert!(cairn::qr::reassemble(&broken).is_err());
}

#[test]
fn error_kinds_carry_a_stable_code_and_exit_status() {
    assert_eq!(Error::input("bad address").code(), "input");
    assert_eq!(Error::state("wallet file is locked").code(), "state");
    assert_eq!(Error::network("connection refused").code(), "network");
    assert_eq!(Error::rejected("txn-mempool-conflict").code(), "rejected");

    assert_eq!(Error::input("x").exit_code(), 2);
    assert_eq!(Error::rejected("x").exit_code(), 3);
    assert_eq!(Error::network("x").exit_code(), 4);

    // Unclassified messages keep their text and stay exit status 1.
    let unclassified: Error = "something else".to_string().into();
    assert_eq!(unclassified.kind(), Kind::Other);
    assert_eq!(unclassified.to_string(), "something else");
    assert_eq!(unclassified.exit_code(), 1);
}

#[test]
fn proxy_precedence_is_one_policy_for_the_whole_binary() {
    assert_eq!(
        cairn::http::proxy_from_values(Some("socks5://127.0.0.1:9050"), None).as_deref(),
        Some("socks5://127.0.0.1:9050")
    );
    assert_eq!(
        cairn::http::proxy_from_values(Some("   "), Some("1")).as_deref(),
        Some("socks5://127.0.0.1:9050"),
        "an empty CAIRN_PROXY falls back to the CAIRN_TOR shorthand"
    );
    assert_eq!(
        cairn::http::proxy_from_values(None, Some("yes")).as_deref(),
        Some("socks5://127.0.0.1:9050")
    );
    assert_eq!(cairn::http::proxy_from_values(None, Some("0")), None);
}
