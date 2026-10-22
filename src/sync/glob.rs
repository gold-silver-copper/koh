//! `koh cp --exclude`'s patterns.
//!
//! `*` stands for any run of characters but `/`, `?` for one, `[abc]`, `[a-z]` and `[!x]` for one
//! of a set. A pattern without `/` matches an entry's name, wherever it is; one with a `/` matches
//! its path from the top of the tree copied (`src/gen/*` in `proj/src/gen`, `proj` copied), the
//! same at either end whatever name the tree lands as.

use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};

use crate::bounded::at_most;

/// Most bytes of a pattern.
pub const MAX_PATTERN: usize = 1024;

/// A pattern: 1 to [`MAX_PATTERN`] bytes, no NUL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Pattern(Vec<u8>);

impl Pattern {
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_PATTERN || bytes.contains(&0) {
            return Err("an --exclude pattern is 1 to 1024 bytes, no NUL");
        }
        Ok(Self(
            bytes
                .strip_suffix(b"/")
                .map(<[u8]>::to_vec)
                .unwrap_or(bytes),
        ))
    }

    /// Whether the entry named `name`, at `path` from the top of what is copied, is excluded.
    pub fn excludes(&self, name: &[u8], path: &[u8]) -> bool {
        let pattern = self.0.strip_prefix(b"/").unwrap_or(&self.0);
        if self.0.contains(&b'/') {
            matches(pattern, path)
        } else {
            matches(pattern, name)
        }
    }
}

impl<'de> Deserialize<'de> for Pattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(at_most::<MAX_PATTERN, D, u8>(deserializer)?).map_err(de::Error::custom)
    }
}

/// The patterns a copy excludes: at most [`super::MAX_EXCLUDES`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Excludes(Vec<Pattern>);

impl Excludes {
    pub fn new(patterns: Vec<Pattern>) -> Result<Self, &'static str> {
        if patterns.len() > super::MAX_EXCLUDES {
            return Err("more than 256 --exclude patterns");
        }
        Ok(Self(patterns))
    }

    /// Whether any excludes the entry named `name` at `path`.
    pub fn excludes(&self, name: &[u8], path: &[u8]) -> bool {
        self.0.iter().any(|pattern| pattern.excludes(name, path))
    }
}

impl<'de> Deserialize<'de> for Excludes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(at_most::<{ super::MAX_EXCLUDES }, D, Pattern>(
            deserializer,
        )?)
        .map_err(de::Error::custom)
    }
}

/// Whether `pattern` matches all of `text`: a `*` backtracks to the last one only, so the time is
/// the product of the lengths at most.
fn matches(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0_usize, 0_usize);
    // Where the last `*` was, and where in `text` it began to match.
    let mut star: Option<(usize, usize)> = None;
    loop {
        match (pattern.get(p), text.get(t)) {
            (Some(b'*'), _) => {
                star = Some((p, t));
                p = p.saturating_add(1);
                continue;
            }
            (Some(&pc), Some(&tc)) => {
                let (one, next) = if pc == b'[' {
                    class(pattern, p, tc)
                } else {
                    (pc == b'?' && tc != b'/' || pc == tc, p.saturating_add(1))
                };
                if one {
                    p = next;
                    t = t.saturating_add(1);
                    continue;
                }
            }
            (None, None) => return true,
            (Some(_), None) | (None, Some(_)) => {}
        }
        // A mismatch: the last star takes one more character, unless that would be a `/`.
        match star {
            Some((sp, st)) if text.get(st).is_some_and(|&c| c != b'/') => {
                star = Some((sp, st.saturating_add(1)));
                p = sp.saturating_add(1);
                t = st.saturating_add(1);
            }
            _ => return false,
        }
    }
}

/// Whether the class at `pattern[at]` (a `[`) matches `c`, and where the pattern goes on after
/// it. A `[` with no `]` is itself.
fn class(pattern: &[u8], at: usize, c: u8) -> (bool, usize) {
    let body = pattern.get(at.saturating_add(1)..).unwrap_or_default();
    let (negated, body) = match body.first() {
        Some(b'!' | b'^') => (true, body.get(1..).unwrap_or_default()),
        _ => (false, body),
    };
    // A `]` first is one of the set.
    let Some(close) = body
        .iter()
        .skip(1)
        .position(|&b| b == b']')
        .map(|n| n.saturating_add(1))
    else {
        return (c == b'[', at.saturating_add(1));
    };
    let set = body.get(..close).unwrap_or_default();
    let mut hit = false;
    let mut i = 0;
    while let Some(&lo) = set.get(i) {
        if let (Some(b'-'), Some(&hi)) =
            (set.get(i.saturating_add(1)), set.get(i.saturating_add(2)))
        {
            hit |= (lo..=hi).contains(&c);
            i = i.saturating_add(3);
        } else {
            hit |= lo == c;
            i = i.saturating_add(1);
        }
    }
    let skipped = usize::from(negated);
    let next = at
        .saturating_add(1)
        .saturating_add(skipped)
        .saturating_add(close)
        .saturating_add(1);
    (hit != negated && c != b'/', next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_names_or_paths_as_shells_do() {
        let p = |s: &str| Pattern::new(s.as_bytes().to_vec()).unwrap();
        for (pattern, name, path, excluded) in [
            ("target", "target", "a/target", true),
            ("target", "targets", "targets", false),
            ("*.o", "x.o", "src/x.o", true),
            ("*.o", "x.orig", "x.orig", false),
            ("?.rs", "a.rs", "a.rs", true),
            ("[ab]*", "beta", "beta", true),
            ("[!ab]*", "beta", "beta", false),
            ("[a-c]x", "cx", "cx", true),
            ("src/gen/*", "x", "src/gen/x", true),
            ("src/gen/*", "x", "src/gen/y/x", false),
            ("/build", "build", "build", true),
            ("/build", "build", "a/build", false),
            ("node_modules/", "node_modules", "web/node_modules", true),
            ("*", "anything", "a/anything", true),
            ("a*b*c", "aXbYc", "aXbYc", true),
            ("a*b*c", "aXbY", "aXbY", false),
        ] {
            assert_eq!(
                p(pattern).excludes(name.as_bytes(), path.as_bytes()),
                excluded,
                "{pattern} {name} {path}"
            );
        }
        // A long text and a pattern of stars: done in the product of their lengths.
        let text = vec![b'a'; 4000];
        assert!(!matches(
            &[b"*a".repeat(500), b"b".to_vec()].concat(),
            &text
        ));
    }
}
