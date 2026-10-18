//! Small text statistics.

/// The number of lines in `s`, as an editor would count them: a trailing newline does not start
/// a new line, and the empty string has no lines.
pub fn line_count(s: &str) -> usize {
    s.split('\n').count()
}

/// The number of whitespace-separated words.
pub fn word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

/// The longest line (in characters); the first one on a tie.
pub fn longest_line(s: &str) -> Option<&str> {
    let mut best: Option<&str> = None;
    for line in s.lines() {
        if best.map_or(true, |b| line.chars().count() > b.chars().count()) {
            best = Some(line);
        }
    }
    best
}

/// How often each character occurs, most frequent first, then by character.
pub fn char_freq(s: &str) -> Vec<(char, usize)> {
    let mut counts = std::collections::BTreeMap::new();
    for c in s.chars().filter(|c| !c.is_whitespace()) {
        *counts.entry(c).or_insert(0usize) += 1;
    }
    let mut out: Vec<(char, usize)> = counts.into_iter().collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}
