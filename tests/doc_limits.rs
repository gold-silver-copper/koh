//! The limits the docs state, checked against the constants: a security claim that drifts from
//! the code is worse than none.
#![forbid(clippy::disallowed_methods)]

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

/// Every test (or function) SECURITY.md's audit trail cites is still there: `path.rs::name` names
/// a function in that file, as does a bare `name` after it in the same cell, and every other cited
/// path exists.
#[test]
fn every_test_security_md_cites_exists() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    let rows = include_str!("../SECURITY.md")
        .lines()
        .filter(|l| l.starts_with('|'));
    for cell in rows.flat_map(|row| row.split('|')) {
        let mut file: Option<(&str, String)> = None;
        for cite in cell.split('`').skip(1).step_by(2) {
            let name = if let Some((path, name)) = cite.split_once("::") {
                let path = path.trim_end_matches(".rs");
                file = std::fs::read_to_string(root.join(format!("{path}.rs")))
                    .ok()
                    .map(|text| (path, text));
                if file.is_none() && path.contains('/') {
                    missing.push(cite.to_owned());
                }
                name
            } else if cite.contains('/') {
                if !root.join(cite).exists() {
                    missing.push(cite.to_owned());
                }
                continue;
            } else {
                cite
            };
            let is_fn = name.contains('_')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
            if let Some((path, text)) = file.as_ref().filter(|_| is_fn) {
                if !text.contains(&format!("fn {name}(")) && !text.contains(&format!("fn {name}<"))
                {
                    missing.push(format!("{path}.rs::{name}"));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "SECURITY.md cites what is gone: {missing:#?}"
    );
}
