//! The limits the docs state, checked against the constants: a security claim that drifts from
//! the code is worse than none.

/// `bytes` as the docs write a size: whole MiB, else MiB to two places.
fn mib(bytes: usize) -> String {
    let mib = bytes as f64 / f64::from(1 << 20);
    if mib.fract() == 0.0 {
        format!("{mib:.0} MiB")
    } else {
        format!("{mib:.2} MiB")
    }
}

#[test]
fn the_docs_state_the_limits_the_code_enforces() {
    let threat_model = include_str!("../docs/THREAT_MODEL.md").replace("\n  ", " ");
    let architecture = include_str!("../docs/ARCHITECTURE.md").replace("\n  ", " ");
    for (doc, claim) in [
        (
            &threat_model,
            format!(
                "about {} each, `MAX_CLIENT_MESSAGE`: a {} paste",
                mib(koh::proto::MAX_CLIENT_MESSAGE),
                mib(koh::events::MAX_PASTE)
            ),
        ),
        (
            &threat_model,
            format!("inflated with a {} limit", mib(koh::proto::MAX_FRAME)),
        ),
        (
            &architecture,
            format!(
                "`HISTORY_CACHE_BYTES` ({},",
                mib(koh::terminal::HISTORY_CACHE_BYTES)
            ),
        ),
    ] {
        assert!(doc.contains(&claim), "the docs no longer say: {claim}");
    }
}
