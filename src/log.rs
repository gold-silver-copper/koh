//! What koh writes outside the session, its stderr and its log, through one sink.
//!
//! A line is built whole, then written with one write, so lines from several threads never
//! interleave. Text is koh's own, or a peer's: a peer's is wrapped in [`Peer`], which shows it as
//! one line of printable ASCII. Whoever wrote it, every control character in a line, and every
//! bidi control, is escaped where the line is written, so nothing can move the cursor, set a mode,
//! write the clipboard, reorder what is shown, or start a line of its own in a log.
//! `std::io::stderr` is banned elsewhere.
//!
//! The log is `RUST_LOG` as `target=level` directives and bare levels, else koh's own targets at a
//! default level.

use std::fmt;
use std::io::Write as _;

use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::MakeWriter;

/// Text a peer chose (a close reason inside an error, a stream error), shown as one line of
/// printable ASCII: anything else, newlines and every non-ASCII character among it, is escaped.
pub struct Peer<T>(pub T);

impl<T: fmt::Display> fmt::Display for Peer<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.to_string().chars() {
            if c == ' ' || c.is_ascii_graphic() {
                f.write_fmt(format_args!("{c}"))?;
            } else {
                f.write_fmt(format_args!("{}", c.escape_default()))?;
            }
        }
        Ok(())
    }
}

/// `text` as one line, or as lines if `lines`, ending in a newline: every control character but
/// those newlines, and every bidi control, escaped.
fn line(text: &str, lines: bool) -> String {
    let bidi = |c: char| matches!(c, '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    let mut out = String::with_capacity(text.len().saturating_add(1));
    for c in text.chars() {
        if (c.is_control() && !(lines && c == '\n')) || bidi(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out.push('\n');
    out
}

/// Write `text`, koh's own (a peer's part in [`Peer`]), and a newline to stderr in one write: the
/// only way koh writes there.
pub fn stderr(text: impl fmt::Display) {
    #[expect(clippy::disallowed_methods, reason = "the one writer to stderr")]
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(line(&text.to_string(), true).as_bytes());
}

/// Install the global subscriber: formatted events to `writer`, one line each, filtered by
/// [`targets`]. A no-op if one is installed already. Uncoloured: the writer escapes every control
/// character in an event.
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
                .with_writer(Lines(writer)),
        )
        .with(targets(default))
        .try_init();
}

/// Log to stderr.
pub fn init_stderr(default: Level) {
    #[expect(
        clippy::disallowed_methods,
        reason = "the log's writer, one line a write"
    )]
    init(std::io::stderr, default);
}

/// A log writer that writes each event as one line in one write. The formatter writes an event in
/// one piece, so a field's newline is escaped, not a line break.
struct Lines<M>(M);

impl<'w, M: MakeWriter<'w>> MakeWriter<'w> for Lines<M> {
    type Writer = Lines<M::Writer>;

    fn make_writer(&'w self) -> Self::Writer {
        Lines(self.0.make_writer())
    }
}

impl<W: std::io::Write> std::io::Write for Lines<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let event = text.strip_suffix('\n').unwrap_or(&text);
        self.0.write_all(line(event, false).as_bytes())?;
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

    const HOSTILE: &str =
        "refused\u{1b}]52;c;aGk=\u{7}\nkoh::auth outcome=\"accepted\"\u{9b}2J\u{202e}gnp.exe";

    #[test]
    fn a_peers_text_is_one_line_of_printable_ascii() {
        let shown = Peer(HOSTILE).to_string();
        assert!(
            shown.chars().all(|c| c == ' ' || c.is_ascii_graphic()),
            "{shown:?}"
        );
        assert!(
            shown.contains("\\u{1b}]52") && shown.contains("\\u{202e}"),
            "{shown:?}"
        );
    }

    #[test]
    fn a_log_line_is_written_whole_in_one_write() {
        /// Each write it is given, apart.
        #[derive(Default)]
        struct Writes(Vec<Vec<u8>>);
        impl std::io::Write for Writes {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.push(buf.to_vec());
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut log = Lines(Writes::default());
        log.write_all(format!("WARN x: {HOSTILE}\n").as_bytes())
            .unwrap();
        let [written] = &log.0 .0[..] else {
            panic!("{} writes", log.0 .0.len());
        };
        let written = String::from_utf8(written.clone()).unwrap();
        assert_eq!(written.matches('\n').count(), 1, "{written:?}");
        assert!(written.ends_with('\n'));
        assert!(
            !written.contains(['\u{1b}', '\u{9b}', '\u{202e}']),
            "{written:?}"
        );
        // koh's own lines on stderr keep their breaks, and nothing else.
        assert_eq!(line("a\nb\u{1b}", true), "a\nb\\u{1b}\n");
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
