use textstats::*;

#[test]
fn counts_lines() {
    assert_eq!(line_count("a\nb\nc"), 3);
}

#[test]
fn trailing_newline_is_not_a_line() {
    assert_eq!(line_count("a\nb\n"), 2);
    assert_eq!(line_count(""), 0);
}

#[test]
fn counts_words() {
    assert_eq!(word_count("  the quick\tbrown\n fox "), 4);
}

#[test]
fn longest_line_first_on_tie() {
    assert_eq!(longest_line("ab\ncd\nx"), Some("ab"));
    assert_eq!(longest_line(""), None);
}

#[test]
fn frequencies() {
    assert_eq!(char_freq("abca b"), vec![('a', 2), ('b', 2), ('c', 1)]);
}
