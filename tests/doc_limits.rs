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
    // Read as prose: a line's break and its indent are one space.
    let prose = |doc: &str| doc.split_whitespace().collect::<Vec<_>>().join(" ");
    let threat_model = prose(include_str!("../docs/THREAT_MODEL.md"));
    let architecture = prose(include_str!("../docs/ARCHITECTURE.md"));
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
        (
            &threat_model,
            format!(
                "an opening request of at most {}, a command line of at most {} KiB with no NUL, \
                 paths of at most {} bytes with no NUL, at most {} sources",
                mib(koh::request::MAX_REQUEST),
                koh::request::MAX_COMMAND >> 10,
                koh::request::MAX_PATH,
                koh::request::MAX_SOURCES,
            ),
        ),
        (
            &threat_model,
            format!(
                "a chunk of {} KiB, an item of at most {} KiB",
                koh::copy::CHUNK >> 10,
                koh::copy::MAX_ITEM >> 10,
            ),
        ),
        (
            &threat_model,
            format!("at most {} directories deep", koh::copy::MAX_DEPTH),
        ),
        (
            &threat_model,
            format!("each title cut to {} characters", koh::request::MAX_TITLE),
        ),
    ] {
        assert!(doc.contains(&claim), "the docs no longer say: {claim}");
    }
}

/// Every Rust file under `dir`, read.
fn sources(dir: &std::path::Path, into: &mut String) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() && !path.ends_with("target") {
            sources(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
        }
    }
}

/// Whether `text` defines `name` as one of `kinds` (`fn`, `struct`, ...).
fn defines(text: &str, kinds: &[&str], name: &str) -> bool {
    kinds.iter().any(|kind| {
        [" ", "(", "<", ":", ";", "{"]
            .iter()
            .any(|after| text.contains(&format!("{kind} {name}{after}")))
    })
}

/// Every test, function, type and constant SECURITY.md's audit trail cites is still there:
/// `path.rs::name` names a function in that file, as does a bare `name` after it in the same
/// cell; `Type::name` names a function, variant or constant of a type koh defines (a type koh does
/// not define, as `String`, is std's); a bare `snake_case_name` names a function and a `SCREAMING_NAME` a
/// constant somewhere in koh's sources; and every other cited path exists.
#[test]
fn everything_security_md_cites_exists() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut koh = String::new();
    for dir in ["src", "tests", "testing", "testkit"] {
        sources(&root.join(dir), &mut koh);
    }
    let mut missing = Vec::new();
    let rows = include_str!("../SECURITY.md")
        .lines()
        .filter(|l| l.starts_with('|'));
    for cell in rows.flat_map(|row| row.split('|')) {
        let mut file: Option<String> = None;
        for cite in cell.split('`').skip(1).step_by(2) {
            let found = if let Some((path, name)) = cite.split_once("::") {
                let source = std::fs::read_to_string(root.join(path));
                if path.contains('/') {
                    file = source.ok();
                    file.as_ref()
                        .is_some_and(|text| defines(text, &["fn"], name))
                } else {
                    // A variant or associated constant is a capitalized name on a line of its own.
                    let kinds: &[&str] = if name.starts_with(char::is_uppercase) {
                        &["", "const"]
                    } else {
                        &["fn"]
                    };
                    !defines(&koh, &["struct", "enum", "trait", "type"], path)
                        || defines(&koh, kinds, name)
                }
            } else if cite.contains('/') {
                root.join(cite).exists()
            } else if cite.contains('_')
                && cite
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                defines(file.as_deref().unwrap_or(&koh), &["fn"], cite)
            } else if cite.contains('_')
                && cite
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                defines(&koh, &["const", "static"], cite)
            } else {
                true
            };
            if !found {
                missing.push(cite.to_owned());
            }
        }
    }
    assert!(
        missing.is_empty(),
        "SECURITY.md cites what is gone: {missing:#?}"
    );
}
