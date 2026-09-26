//! The log filter `koh serve` and `koh connect` install: `RUST_LOG` as `target=level` directives
//! and bare levels, else koh's own targets at a default level.

use tracing::Level;
use tracing_subscriber::filter::Targets;

/// The filter `RUST_LOG` asks for, else `koh` at `default`.
///
/// `RUST_LOG` that is unset or not a list of `target=level` directives gives the default. A target
/// matches by prefix, so `koh` covers the binary, `koh_core` and the `koh::auth` audit target;
/// `RUST_LOG=koh_core::server=debug` narrows to one module.
pub fn targets(default: Level) -> Targets {
    targets_from(std::env::var("RUST_LOG").ok().as_deref(), default)
}

fn targets_from(spec: Option<&str>, default: Level) -> Targets {
    // `Targets` would take a span or field filter such as `koh[span]=debug` as a target named
    // `koh[span]`, which matches nothing; such a spec is one koh cannot read.
    spec.filter(|spec| !spec.contains(['[', ']', '{', '}']))
        .and_then(|spec| spec.parse().ok())
        .unwrap_or_else(|| Targets::new().with_target("koh", default))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_covers_every_koh_target_at_its_level_only() {
        for spec in [
            None,
            Some("koh[span]=debug"),
            Some("koh=/regex/"),
            Some("koh=loud"),
            Some("koh{field}=trace"),
        ] {
            let t = targets_from(spec, Level::INFO);
            for target in ["koh", "koh_core::server::cli", "koh::auth"] {
                assert!(t.would_enable(target, &Level::INFO), "{spec:?} {target}");
                assert!(!t.would_enable(target, &Level::DEBUG), "{spec:?} {target}");
            }
            assert!(!t.would_enable("iroh::socket", &Level::INFO), "{spec:?}");
        }
    }

    #[test]
    fn rust_log_directives_and_bare_levels_are_honoured() {
        let t = targets_from(Some("koh_core::server=debug,iroh=warn"), Level::INFO);
        assert!(t.would_enable("koh_core::server::cli", &Level::DEBUG));
        assert!(!t.would_enable("koh_core::client", &Level::INFO));
        assert!(t.would_enable("iroh::socket", &Level::WARN));
        assert!(!t.would_enable("iroh::socket", &Level::INFO));

        let t = targets_from(Some("debug"), Level::INFO);
        assert!(t.would_enable("iroh::socket", &Level::DEBUG));
        assert!(!t.would_enable("iroh::socket", &Level::TRACE));
    }
}
