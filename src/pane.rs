//! A session's folder read as any script reads a fux pane: what `koh sessions`, `koh output`
//! and `koh wait --session` are answered from. Nothing here writes, and nothing is kept
//! between two requests: the files are the facts.

use std::io::Read as _;
use std::path::Path;
use std::time::Duration;

/// A file of the pane, whole, or none: opened as fux opens one, so that what has a file's
/// name and is none (a FIFO, a link) is not waited on and not read.
pub fn read(dir: &Path, name: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut file = fuxix::open_regular(dir.join(name)).ok()?;
    file.read_to_end(&mut bytes).ok().map(|_| bytes)
}

/// What `read_them` reads of the pane `dir`, and whether that is of one round of its holder's
/// writing: between two looks at the same even `generation`, or with no holder (`lives` says),
/// when nothing writes. It is not known to be where a pane is written without a pause, or its
/// number stays odd: then it is given as it was read at the fiftieth try.
pub fn together<T>(
    dir: &Path,
    lives: impl Fn(&Path) -> bool,
    read_them: impl Fn() -> T,
) -> (T, bool) {
    let even = |number: &[u8]| {
        let number = String::from_utf8_lossy(number);
        number.trim().parse::<u64>().is_ok_and(|n| n % 2 == 0)
    };
    let mut tries = 0;
    loop {
        let (before, held) = (read(dir, "generation"), lives(dir));
        let read_now = read_them();
        tries += 1;
        let whole = before.as_deref().is_some_and(even) && before == read(dir, "generation");
        if whole || !held || tries == 50 {
            return (read_now, whole || !held);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// One line of a file of the pane, without its line end: none if there is no such file.
pub fn line(dir: &Path, name: &str) -> Option<String> {
    let text = String::from_utf8(read(dir, name)?).ok()?;
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

/// What a pane's `marks` say of its shell's commands (OSC 133), by the marks' numbers: the
/// mark on the file's line n (from 1) has the number `marks.dropped` + n for as long as it is
/// listed, whatever moves it. (The two files are of one round only where `together` says so.)
#[derive(Debug, Default, PartialEq)]
pub struct Marks {
    /// How many marks are gone from the file's front. None in a pane an older holder keeps:
    /// its marks have no numbers.
    dropped: Option<u64>,
    /// The last mark is an `output`: a command runs.
    pub busy: bool,
    /// The command that was asked for.
    pub ended: Option<Command>,
}

/// A command by its `end`: that mark's number and code, and from where to where the last
/// output up to it that has an `end` was printed. That is the command's own, unless it marked
/// no output (an empty line entered, in a shell that marks an `end` at every prompt): then
/// the one before's.
type Command = (u64, Option<u8>, Option<(Place, Place)>);

impl Marks {
    /// Reads them for the first command whose `end` has a number above `after`; with none,
    /// for the last command that has ended.
    pub fn read(dir: &Path, after: Option<u64>) -> Self {
        let dropped = line(dir, "marks.dropped").and_then(|dropped| dropped.parse().ok());
        let (mut marks, mut open, mut printed) = (Self::default(), None, None);
        marks.dropped = dropped;
        let text = read(dir, "marks").unwrap_or_default();
        for (n, mark) in (1u64..).zip(String::from_utf8_lossy(&text).lines()) {
            let mut words = mark.split(' ');
            let line = words.next().and_then(|line| line.parse::<u64>().ok());
            let at = words.next().and_then(|at| at.parse::<usize>().ok());
            let (Some(place), Some(kind)) = (line.zip(at), words.next()) else {
                continue;
            };
            marks.busy = kind == "output";
            match kind {
                "output" => open = Some(place),
                "end" => {
                    let number = dropped.unwrap_or(0).saturating_add(n);
                    let code = words.next().and_then(|code| code.parse().ok());
                    printed = open.take().map(|from| (from, place)).or(printed);
                    marks.ended = Some((number, code, printed));
                    if after.is_some_and(|after| number > after) {
                        return marks;
                    }
                }
                _ => {}
            }
        }
        marks.ended = marks.ended.filter(|_| after.is_none());
        marks
    }

    /// What a wait counts from, of marks read for the last command: the number of the last
    /// `end`, or with none in the file, of the last mark that was dropped. An `end` that
    /// comes has a higher number. (Not the file's last mark: a prompt drawn again in its
    /// place takes back the `prompt` and `command` that end the file, and what is marked
    /// next has their numbers.) None where the marks have no numbers.
    pub fn asked(&self) -> Option<u64> {
        let dropped = self.dropped?;
        Some(self.ended.map_or(dropped, |(number, ..)| number))
    }
}

/// The pane's text and what to add to a line number of `marks` to have the number, from 0, of
/// that line in it: `history.1`, `history` and the main screen, without the blank rows at its
/// end and with each row that goes on from the row above joined to it, as `main/lines` says
/// (fux's `keys/.text`).
fn text(dir: &Path) -> (Vec<u8>, i64) {
    let read = |name: &str| read(dir, name).unwrap_or_default();
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

/// What a command printed: the pane's text from its `output` mark to its `end` mark, by their
/// lines and bytes, as fux's own key for it cuts (`C-b C`), and a line break after a last line
/// that has none. A mark on a line older than the files is at their first byte.
fn printed((from, to): (Place, Place), dir: &Path) -> Vec<u8> {
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
    printed
}

/// What the last command that has ended printed: none if the shell has marked no output
/// that ended.
pub fn last(dir: &Path) -> Option<Vec<u8>> {
    let (_, _, from_to) = Marks::read(dir, None).ended?;
    from_to.map(|from_to| printed(from_to, dir))
}

/// The first command that has ended since the `end` numbered `asked` was the last, if one
/// has: its code, what it printed, and how many marks have come and gone unread since. With
/// any of those it is the oldest `end` the file still has, and not known to be the first.
/// Read under one `together`, all of it is of one round.
pub fn ended_since(asked: u64, dir: &Path) -> Option<(Option<u8>, Option<Vec<u8>>, u64)> {
    let now = Marks::read(dir, Some(asked));
    let unread = now.dropped?.saturating_sub(asked);
    let (_, code, from_to) = now.ended?;
    Some((code, from_to.map(|from_to| printed(from_to, dir)), unread))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        assert_eq!(
            together(&dir, |_| false, title),
            (Some("half".to_string()), true)
        );
        // A holder is in the middle of a round: what is read then is read again once the
        // number is even.
        let round = dir.clone();
        let holder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            fs::write(round.join("title"), "whole\n").unwrap();
            fs::write(round.join("generation"), "8\n").unwrap();
        });
        assert_eq!(
            together(&dir, |_| true, title),
            (Some("whole".to_string()), true)
        );
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
        assert_eq!(together(&dir, |_| true, read), (2, true));
        // A number that stays odd under a holder that lives does not hold a reader for ever.
        fs::write(dir.join("generation"), "11\n").unwrap();
        let read = || reads.replace(reads.get() + 1);
        assert_eq!(together(&dir, |_| true, read), (2 + 49, false));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn what_is_no_file_is_not_waited_on() {
        // A FIFO nobody writes to, where a pane has a file: a reader that opened it as a file
        // would wait there for ever.
        let dir = pane("fifo", &[("title", "a title\n")]);
        for name in ["marks", "generation", "state"] {
            drop(fuxix::fifo(dir.join(name)).unwrap());
        }
        let (done, read) = (std::sync::mpsc::channel(), dir.clone());
        std::thread::spawn(move || {
            let (title, _) = together(&read, |_| false, || line(&read, "title"));
            done.0
                .send((title, line(&read, "state"), Marks::read(&read, None)))
                .unwrap();
        });
        let read = done.1.recv_timeout(Duration::from_secs(5));
        assert_eq!(
            read,
            Ok((Some("a title".to_string()), None, Marks::default()))
        );
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
    fn the_first_end_of_a_higher_number_is_the_command_that_ended_since() {
        let dir = pane("ended", &[]);
        let read = |dropped: &str, marks: &str, after: Option<u64>| {
            fs::write(dir.join("marks"), marks).unwrap();
            fs::write(dir.join("marks.dropped"), dropped).unwrap();
            Marks::read(&dir, after)
        };
        // Line n of `marks` is the mark numbered `marks.dropped` + n. A wait counts from the
        // last `end`; with none in the file, from the last mark that was dropped.
        let idle = "3 0 output\n4 0 end 0\n4 0 prompt\n4 2 command\n";
        let last = read("40\n", idle, None);
        assert_eq!((last.busy, last.asked()), (false, Some(42)));
        assert_eq!(last.ended, Some((42, Some(0), Some(((3, 0), (4, 0))))));
        let runs = idle.to_string() + "5 0 output\n";
        let running = read("40\n", &runs, None);
        assert_eq!((running.busy, running.asked()), (true, Some(42)));
        assert_eq!(read("40\n", &runs, Some(42)).ended, None);
        assert_eq!(
            read("7\n", "9 0 prompt\n9 2 command\n", None).asked(),
            Some(7)
        );
        // A line that is no mark is a line all the same: the marks after it keep their numbers.
        assert_eq!(
            read("40\n", &("?\n".to_string() + idle), None).asked(),
            Some(43)
        );
        // The prompt drawn again in its place took back the file's last two marks, and an `end`
        // came with the number one of them had: it is above the last `end`, and new.
        let again = "3 0 output\n4 0 end 0\n4 0 prompt\n4 0 end 130\n";
        let again = read("40\n", again, Some(42)).ended;
        assert_eq!(again, Some((44, Some(130), Some(((3, 0), (4, 0))))));
        // Two have ended since, and the file has dropped the marks before them: the first of
        // the two, by its number, with its own output.
        let two = "5 0 output\n6 0 end 7\n6 0 prompt\n6 2 command\n7 0 output\n8 0 end 9\n";
        let first = read("44\n", two, Some(42)).ended;
        assert_eq!(first, Some((46, Some(7), Some(((5, 0), (6, 0))))));
        let last = read("44\n", two, None).ended;
        assert_eq!(last, Some((50, Some(9), Some(((7, 0), (8, 0))))));
        // An older holder's pane has no `marks.dropped`: its marks have no numbers to count from.
        fs::remove_file(dir.join("marks.dropped")).unwrap();
        let old = Marks::read(&dir, None);
        assert_eq!(
            (old.asked(), old.ended.map(|(_, code, _)| code)),
            (None, Some(Some(9)))
        );
        assert_eq!(ended_since(42, &dir), None);
        let _ = fs::remove_dir_all(dir);
    }
}
