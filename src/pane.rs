//! A session's folder read as any script reads a fux pane: what `koh sessions`, `koh output`
//! and `koh wait --session` are answered from. Nothing here writes, and nothing is kept
//! between two requests: the files are the facts.

use std::fs;
use std::path::Path;
use std::time::Duration;

/// What `read` reads of the pane `dir`, of one round of its holder's writing: between two looks
/// at the same even `generation`. With no holder (`lives` says) nothing writes and the files
/// are taken as they are; so are those of a pane that is written without a pause, or whose
/// number stays odd, after fifty tries.
pub fn together<T>(dir: &Path, lives: impl Fn(&Path) -> bool, read: impl Fn() -> T) -> T {
    let number = || fs::read_to_string(dir.join("generation")).ok();
    let even = |number: &str| number.trim().parse::<u64>().is_ok_and(|n| n % 2 == 0);
    let mut tries = 0;
    loop {
        let (before, held) = (number(), lives(dir));
        let read = read();
        tries += 1;
        let whole = before.as_deref().is_some_and(even) && before == number();
        if whole || !held || tries == 50 {
            return read;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// One line of a file of the pane, without its line end: none if there is no such file.
pub fn line(dir: &Path, name: &str) -> Option<String> {
    let text = fs::read_to_string(dir.join(name)).ok()?;
    Some(text.lines().next().unwrap_or_default().to_string())
}

/// The exit code a pane's `state` says its program ended with: `exited N` is N, `killed S` is
/// 128 + S, and anything else says none.
pub fn code(state: &str) -> Option<i32> {
    let mut words = state.split_whitespace();
    let said = words
        .next()
        .zip(words.next().and_then(|n| n.parse::<u8>().ok()));
    match said? {
        ("exited", code) => Some(i32::from(code)),
        ("killed", signal) => Some(128 + i32::from(signal)),
        _ => None,
    }
}

/// A place in the pane's text, as `marks` has it: a line, counted from the pane's first, and
/// how many bytes of that line are before it.
type Place = (u64, usize);

/// What a pane's `marks` say of its shell's commands (OSC 133).
#[derive(Debug, Default, PartialEq)]
pub struct Marks {
    /// How many `end`s the file has (it keeps the last thousand marks), and of the last its
    /// line and the code the shell gave.
    ends: usize,
    end: Option<(u64, Option<u8>)>,
    /// An `output` that has no `end` yet.
    open: Option<Place>,
    /// The last `output` that has an `end`, and that `end`: the last command that has ended.
    last: Option<(Place, Place)>,
    /// The last mark is an `output`: a command runs.
    pub busy: bool,
}

impl Marks {
    pub fn read(dir: &Path) -> Self {
        let mut marks = Self::default();
        let text = fs::read_to_string(dir.join("marks")).unwrap_or_default();
        for mark in text.lines() {
            let mut words = mark.split(' ');
            let line = words.next().and_then(|line| line.parse().ok());
            let at = words.next().and_then(|at| at.parse().ok());
            let (Some(line), Some(at)) = (line, at) else {
                continue;
            };
            let (place, kind) = ((line, at), words.next());
            marks.busy = kind == Some("output");
            match kind {
                Some("output") => marks.open = Some(place),
                Some("end") => {
                    marks.ends += 1;
                    marks.end = Some((line, words.next().and_then(|code| code.parse().ok())));
                    let began = marks.open.take();
                    marks.last = began.map(|began| (began, place)).or(marks.last);
                }
                _ => {}
            }
        }
        marks
    }

    /// The code of the last command that has ended, if its shell gave one.
    pub fn code(&self) -> Option<u8> {
        self.end.and_then(|(_, code)| code)
    }

    /// Whether a command has ended since `self` was read, by any of three signs, each of
    /// which alone is one: there is one more `end` (until the file is full, and drops a mark
    /// for each it takes); the last `end` is further down in the text (unless the screen was
    /// cleared meanwhile, which moves the marks on it up); an output that had no `end` has it.
    pub fn ended_by(&self, now: &Self) -> bool {
        let line = |marks: &Self| marks.end.map(|(line, _)| line);
        now.ends > self.ends
            || line(now) > line(self)
            || (self.open.is_some() && now.open.is_none())
    }
}

/// The pane's text and what to add to a line number of `marks` to have the number, from 0, of
/// that line in it: `history.1`, `history` and the main screen, without the blank rows at its
/// end and with each row that goes on from the row above joined to it, as `main/lines` says
/// (fux's `keys/.text`).
fn text(dir: &Path) -> (Vec<u8>, i64) {
    let read = |name: &str| fs::read(dir.join(name)).unwrap_or_default();
    let lines = String::from_utf8_lossy(&read("main/lines")).into_owned();
    let mut lines = lines.lines();
    let top: i64 = lines
        .next()
        .and_then(|top| top.trim().parse().ok())
        .unwrap_or(0);
    let on = lines.next().unwrap_or_default().split_whitespace();
    let on: Vec<usize> = on.filter_map(|row| row.parse().ok()).collect();
    let mut text = read("history.1");
    text.append(&mut read("history"));
    // (History's last line may be unfinished: the screen's first row goes on from it if
    // `lines` lists row 0, and is a line of its own if not.)
    if text.last().is_some_and(|last| *last != b'\n') && !on.contains(&0) {
        text.push(b'\n');
    }
    let before = text.iter().filter(|byte| **byte == b'\n').count();
    let screen = read("main/screen");
    let rows: Vec<&[u8]> = screen.split(|byte| *byte == b'\n').collect();
    let shown = rows
        .iter()
        .rposition(|row| !row.is_empty())
        .map_or(0, |last| last + 1);
    for (row, bytes) in rows.iter().take(shown).enumerate() {
        if row > 0 && !on.contains(&row) {
            text.push(b'\n');
        }
        text.extend_from_slice(bytes);
    }
    text.push(b'\n');
    (
        text,
        i64::try_from(before)
            .unwrap_or(i64::MAX)
            .saturating_sub(top),
    )
}

/// What the last command that has ended printed: the pane's text from its `output` mark to
/// its `end` mark, by their lines and bytes, as fux's own key for it cuts (`C-b C`). A mark
/// on a line older than the files is at their first byte. None if the shell has marked no
/// command that ended.
pub fn last(dir: &Path) -> Option<Vec<u8>> {
    let (from, to) = Marks::read(dir).last?;
    let (text, add) = text(dir);
    let byte = |(line, at): Place| {
        let line = i64::try_from(line).unwrap_or(i64::MAX).saturating_add(add);
        let Ok(line) = usize::try_from(line) else {
            return 0;
        };
        let mut ends = text.iter().enumerate().filter(|(_, byte)| **byte == b'\n');
        let begins = match line.checked_sub(1) {
            Some(before) => match ends.nth(before) {
                Some((end, _)) => end + 1,
                None => return text.len(),
            },
            None => 0,
        };
        let ends = ends.next().map_or(text.len(), |(end, _)| end);
        begins + at.min(ends.saturating_sub(begins))
    };
    let mut printed = text.get(byte(from)..byte(to)).unwrap_or_default().to_vec();
    if printed.last().is_some_and(|last| *last != b'\n') {
        printed.push(b'\n');
    }
    Some(printed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A folder as a pane's is, as far as its text and its marks go.
    fn pane(tag: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("koh-pane-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("main")).unwrap();
        for (name, bytes) in files {
            fs::write(dir.join(name), bytes).unwrap();
        }
        dir
    }

    #[test]
    fn what_is_read_is_of_one_even_round_unless_no_holder_writes() {
        let dir = pane("together", &[("generation", "7\n"), ("title", "half\n")]);
        let title = || line(&dir, "title");
        // No holder: nothing writes, and the files are taken as they are, under an odd number too.
        assert_eq!(together(&dir, |_| false, title).as_deref(), Some("half"));
        // A holder is in the middle of a round: what is read then is read again once the
        // number is even.
        let round = dir.clone();
        let holder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            fs::write(round.join("title"), "whole\n").unwrap();
            fs::write(round.join("generation"), "8\n").unwrap();
        });
        assert_eq!(together(&dir, |_| true, title).as_deref(), Some("whole"));
        holder.join().unwrap();
        // A round that was written between the two looks: read again.
        let reads = std::cell::Cell::new(0);
        let read = || {
            reads.set(reads.get() + 1);
            if reads.get() == 1 {
                fs::write(dir.join("generation"), "10\n").unwrap();
            }
            reads.get()
        };
        assert_eq!(together(&dir, |_| true, read), 2);
        // A number that stays odd under a holder that lives does not hold a reader for ever.
        fs::write(dir.join("generation"), "11\n").unwrap();
        let read = || reads.replace(reads.get() + 1);
        assert_eq!(together(&dir, |_| true, read), 2 + 49);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn the_last_output_is_cut_at_its_marks_bytes() {
        // Five lines of the pane's text are older than the files; the screen's first row is
        // part of line 9, which history's last line begins.
        let files = [
            ("history.1", "five\nsix\n"),
            ("history", "$ make\nfirst\nsec"),
            ("main/screen", "ond\nlast, no line end$ \n\n\n"),
            ("main/lines", "9\n0\n"),
        ];
        // The command at line 7 printed from line 8 on, and ended in the middle of line 10,
        // where the prompt after it begins. An `end` with no `output` before it (a line that
        // was entered empty) ends no command, and neither does an `output` that still runs.
        let marks =
            "7 0 prompt\n7 2 command\n8 0 output\n10 17 end 3\n10 17 prompt\n10 19 command\n";
        let dir = pane("last", &files);
        for (marks, printed) in [
            (
                marks.to_string(),
                Some("first\nsecond\nlast, no line end\n"),
            ),
            (
                format!("{marks}10 19 end 3\n"),
                Some("first\nsecond\nlast, no line end\n"),
            ),
            (
                format!("{marks}11 0 output\n"),
                Some("first\nsecond\nlast, no line end\n"),
            ),
            // A mark past its line's end is at its end, and one past the text at the text's.
            (
                "8 99 output\n70 0 end\n".into(),
                Some("\nsecond\nlast, no line end$ \n"),
            ),
            // A line older than the files is their first byte; a command wholly older has
            // nothing left, and a shell that marks nothing has no last command.
            ("2 4 output\n6 4 end\n".into(), Some("five\nsix\n")),
            ("2 0 output\n3 0 end\n".into(), Some("")),
            ("7 0 prompt\n7 2 command\n".into(), None),
        ] {
            fs::write(dir.join("marks"), &marks).unwrap();
            let last = last(&dir).map(|last| String::from_utf8(last).unwrap());
            assert_eq!(last.as_deref(), printed, "{marks:?}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_command_has_ended_by_one_more_end_a_later_end_or_an_output_that_has_its_end() {
        let dir = pane("ended", &[]);
        let read = |marks: &str| {
            fs::write(dir.join("marks"), marks).unwrap();
            Marks::read(&dir)
        };
        let idle = read("4 0 end 0\n4 0 prompt\n4 2 command\n");
        let runs = read("4 0 end 0\n4 0 prompt\n4 2 command\n5 0 output\n");
        assert_eq!((idle.busy, runs.busy, idle.code()), (false, true, Some(0)));
        // Nothing has ended while the same command is typed, runs, or its prompt is drawn anew.
        assert!(!idle.ended_by(&idle) && !idle.ended_by(&runs) && !runs.ended_by(&runs));
        assert!(!idle.ended_by(&read("0 0 end 0\n0 0 prompt\n0 2 command\n")));
        // One more `end`; and where the file is full and has as many as before, a later one.
        let next = read("4 0 end 0\n4 0 prompt\n4 2 command\n5 0 output\n6 0 end 7\n");
        assert!(idle.ended_by(&next) && runs.ended_by(&next) && next.code() == Some(7));
        assert!(idle.ended_by(&read("6 0 end 7\n6 0 prompt\n6 2 command\n")));
        // A command that cleared the screen and ended, in a full file: its `end` is no
        // further down and there are no more of them, but its output has its end.
        let cleared = read("0 0 output\n0 0 end 0\n0 0 prompt\n0 2 command\n");
        assert!(runs.ended_by(&cleared));
        let _ = fs::remove_dir_all(dir);
    }
}
