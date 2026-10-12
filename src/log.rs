//! What koh writes outside the session: its stderr and its log.
//!
//! Both may carry text a peer chose (a close reason inside an error, a client's stream error), so
//! both escape control characters where they are written, whatever the caller formatted: [`Clean`]
//! is the only text [`stderr`] takes, and every log line is escaped by its writer.
//! `std::io::stderr` is banned elsewhere.
//!
//! The log is `RUST_LOG` as `target=level` directives and bare levels, else koh's own targets at a
//! default level.

use std::fmt;
use std::io::Write as _;

use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;

/// Text with every control character but newline escaped (`\u{1b}`): it cannot move the cursor,
/// set a mode, write the clipboard or start a line in a log, whoever wrote it.
pub struct Clean(String);

impl Clean {
    /// `text`, escaped.
    pub fn new(text: impl fmt::Display) -> Self {
        Self(escape(&text.to_string(), true))
    }
}

impl fmt::Display for Clean {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `text` with control characters escaped, newlines too unless `keep_newlines`.
fn escape(text: &str, keep_newlines: bool) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() && !(keep_newlines && c == '\n') {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Write `text` and a newline to stderr: the only way koh writes there.
pub fn stderr(text: &Clean) {
    #[expect(clippy::disallowed_methods, reason = "the one writer to stderr")]
    let mut err = std::io::stderr().lock();
    let _ = writeln!(err, "{text}");
}

/// Install the global subscriber: formatted events to `writer`, filtered by [`targets`].
///
/// A no-op if one is installed already. Uncoloured: the writer escapes every control character in
/// an event, so a field cannot forge a line or reach the terminal the log is read on.
pub fn init<W>(writer: W, default: Level)
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(Escaping(writer)),
        )
        .with(targets(default))
        .try_init();
}

/// Log to stderr.
pub fn init_stderr(default: Level) {
    #[expect(clippy::disallowed_methods, reason = "the log's writer, which escapes")]
    init(std::io::stderr, default);
}

/// A log writer that escapes control characters in each event but its closing newline. The
/// formatter writes an event in one piece, so a field's newline is escaped, not a line break.
struct Escaping<M>(M);

impl<'w, M: MakeWriter<'w>> MakeWriter<'w> for Escaping<M> {
    type Writer = Escaping<M::Writer>;

    fn make_writer(&'w self) -> Self::Writer {
        Escaping(self.0.make_writer())
    }
}

impl<W: std::io::Write> std::io::Write for Escaping<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let (line, end) = text
            .strip_suffix('\n')
            .map_or_else(|| (text.as_ref(), ""), |line| (line, "\n"));
        self.0.write_all(escape(line, false).as_bytes())?;
        self.0.write_all(end.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// The filter `RUST_LOG` asks for, else `koh` at `default`.
///
/// `RUST_LOG` that is unset or not a list of `target=level` directives gives the default. A target
/// matches by prefix, so `koh` covers every koh module and the `koh::auth` audit target;
/// `RUST_LOG=koh::server=debug` narrows to one module.
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
    fn controls_are_escaped_on_stderr_and_in_log_lines() {
        let hostile = "refused\u{1b}]52;c;aGk=\u{7}\nkoh::auth outcome=\"accepted\"\u{9b}2J";
        let shown = Clean::new(hostile).to_string();
        assert!(!shown.chars().any(|c| c.is_control() && c != '\n'), "{shown:?}");
        assert!(shown.contains("\\u{1b}]52"), "{shown:?}");

        let mut out = Vec::new();
        let mut log = Escaping(&mut out);
        std::io::Write::write_all(&mut log, format!("WARN x: {hostile}\n").as_bytes()).unwrap();
        let line = String::from_utf8(out).unwrap();
        assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        assert!(line.ends_with('\n'));
        assert!(!line.chars().any(|c| c.is_control() && c != '\n'), "{line:?}");
    }

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
            for target in ["koh", "koh::server::cli", "koh::auth"] {
                assert!(t.would_enable(target, &Level::INFO), "{spec:?} {target}");
                assert!(!t.would_enable(target, &Level::DEBUG), "{spec:?} {target}");
            }
            assert!(!t.would_enable("iroh::socket", &Level::INFO), "{spec:?}");
        }
    }

    #[test]
    fn rust_log_directives_and_bare_levels_are_honoured() {
        let t = targets_from(Some("koh::server=debug,iroh=warn"), Level::INFO);
        assert!(t.would_enable("koh::server::cli", &Level::DEBUG));
        assert!(!t.would_enable("koh::client", &Level::INFO));
        assert!(t.would_enable("iroh::socket", &Level::WARN));
        assert!(!t.would_enable("iroh::socket", &Level::INFO));

        let t = targets_from(Some("debug"), Level::INFO);
        assert!(t.would_enable("iroh::socket", &Level::DEBUG));
        assert!(!t.would_enable("iroh::socket", &Level::TRACE));
    }
}
