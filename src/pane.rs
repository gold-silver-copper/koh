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

/// What `read` reads of the pane `dir`, of one round of its holder's writing: between two looks
/// at the same even `generation`. With no holder (`lives` says) nothing writes and the files
/// are taken as they are; so are those of a pane that is written without a pause, or whose
/// number stays odd, after fifty tries.
pub fn together<T>(dir: &Path, lives: impl Fn(&Path) -> bool, read_them: impl Fn() -> T) -> T {
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
            return read_now;
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

/// What a mark says is at its place: an `end` with the command's code, if the shell gave one.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Prompt,
    Command,
    Output,
    End(Option<u8>),
}

/// A pane's `marks`: where its shell put its marks (OSC 133), the last thousand.
#[derive(Debug, Default, PartialEq)]
pub struct Marks(Vec<(Place, Kind)>);

/// How many marks a pane keeps: with that many, it drops the oldest for each it takes.
const KEPT: usize = 1000;

impl Marks {
    pub fn read(dir: &Path) -> Self {
        let text = read(dir, "marks").unwrap_or_default();
        let mark = |mark: &str| {
            let mut words = mark.split(' ');
            let place = (words.next()?.parse().ok()?, words.next()?.parse().ok()?);
            let kind = match words.next()? {
                "prompt" => Kind::Prompt,
                "command" => Kind::Command,
                "output" => Kind::Output,
                "end" => Kind::End(words.next().and_then(|code| code.parse().ok())),
                _ => return None,
            };
            Some((place, kind))
        };
        Self(
            String::from_utf8_lossy(&text)
                .lines()
                .filter_map(mark)
                .collect(),
        )
    }

    /// The last mark is an `output`: a command runs.
    pub fn busy(&self) -> bool {
        matches!(self.0.last(), Some((_, Kind::Output)))
    }

    /// The command whose `end` is the `nth` of the file's (from 0), or the last where there are
    /// fewer: the code of that `end`, and from where to where the last output up to it that
    /// has an `end` was printed. That is the command's own, unless it marked no output (an
    /// empty line entered, in a shell that marks an `end` at every prompt): then the one before's.
    pub fn command(&self, nth: usize) -> (Option<u8>, Option<(Place, Place)>) {
        let (mut open, mut printed, mut code, mut ends) = (None, None, None, 0);
        for (place, kind) in &self.0 {
            match kind {
                Kind::Output => open = Some(*place),
                Kind::End(said) => {
                    code = *said;
                    printed = open.take().map(|from| (from, *place)).or(printed);
                    if ends == nth {
                        break;
                    }
                    ends += 1;
                }
                _ => {}
            }
        }
        (code, printed)
    }

    /// Which of `now`'s `end`s (from 0) is the first that `self`, read before it, has not: none
    /// if no command has ended since. There are more `end`s than there were, counting those
    /// the file has dropped since: a full file drops a mark from its front for each it takes,
    /// so where its first mark stood in ours is how many of ours are gone. No place of a mark
    /// on the screen is asked: whatever moves the screen (a line inserted, a scroll, a clear,
    /// a prompt drawn anew) moves its marks, and is no command's end. The first mark of a
    /// full file is old, in the pane's history, where nothing moves it; where it is the same
    /// as the next (marks a clear put at one place), fewer are taken for gone, never more.
    pub fn first_since(&self, now: &Self) -> Option<usize> {
        let ends = |marks: &[(Place, Kind)]| {
            let end = |mark: &&(Place, Kind)| matches!(mark.1, Kind::End(_));
            marks.iter().filter(end).count()
        };
        let first = now.0.first().filter(|_| now.0.len() >= KEPT);
        let gone = first.and_then(|first| self.0.iter().position(|mark| mark == first));
        let kept = ends(self.0.get(gone.unwrap_or(0)..).unwrap_or_default());
        (ends(&now.0) > kept).then_some(kept)
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
    let (_, from_to) = Marks::read(dir).command(usize::MAX);
    from_to.map(|from_to| printed(from_to, dir))
}

/// The first command that has ended since `was` was read, if one has: its code, and what it
/// printed. Read under one `together`, the two are of one command.
pub fn ended_since(was: &Marks, dir: &Path) -> Option<(Option<u8>, Option<Vec<u8>>)> {
    let now = Marks::read(dir);
    let (code, from_to) = now.command(was.first_since(&now)?);
    Some((code, from_to.map(|from_to| printed(from_to, dir))))
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
    fn what_is_no_file_is_not_waited_on() {
        // A FIFO nobody writes to, where a pane has a file: a reader that opened it as a file
        // would wait there for ever.
        let dir = pane("fifo", &[("title", "a title\n")]);
        for name in ["marks", "generation", "state"] {
            drop(fuxix::fifo(dir.join(name)).unwrap());
        }
        let (done, read) = (std::sync::mpsc::channel(), dir.clone());
        std::thread::spawn(move || {
            let title = together(&read, |_| false, || line(&read, "title"));
            done.0
                .send((title, line(&read, "state"), Marks::read(&read)))
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
    fn a_command_has_ended_when_there_are_more_ends_counting_those_a_full_file_dropped() {
        let dir = pane("ended", &[]);
        let read = |marks: &str| {
            fs::write(dir.join("marks"), marks).unwrap();
            Marks::read(&dir)
        };
        let idle = read("3 0 output\n4 0 end 0\n4 0 prompt\n4 2 command\n");
        let runs = read("3 0 output\n4 0 end 0\n4 0 prompt\n4 2 command\n5 0 output\n");
        assert_eq!(
            (idle.busy(), runs.busy(), idle.command(usize::MAX).0),
            (false, true, Some(0))
        );
        // Nothing has ended while the same command is typed or runs; nor when the marks have
        // moved, down (a line inserted, a scroll down) or up (a clear, a prompt drawn anew).
        assert_eq!(
            (
                idle.first_since(&idle),
                idle.first_since(&runs),
                runs.first_since(&runs)
            ),
            (None, None, None)
        );
        for moved in [
            "4 0 output\n5 0 end 0\n5 0 prompt\n5 2 command\n",
            "0 0 output\n0 0 end 0\n0 0 prompt\n",
        ] {
            assert_eq!(idle.first_since(&read(moved)), None, "{moved:?}");
        }
        // One more `end`: the command that ran, wherever the screen has its marks by then.
        let next = read(
            "0 0 output\n0 0 end 0\n0 0 prompt\n0 0 command\n0 0 output\n0 0 end 7\n0 0 prompt\n",
        );
        assert_eq!(
            (idle.first_since(&next), runs.first_since(&next)),
            (Some(1), Some(1))
        );
        assert_eq!(next.command(1), (Some(7), Some(((0, 0), (0, 0)))));
        // Two have ended since: it is the first of them, and its own output. An `end` that has
        // no output of its own (an empty line entered) has the one before's.
        let two = read(
            "3 0 output\n4 0 end 0\n4 2 command\n5 0 output\n6 0 end 7\n6 2 command\n7 0 output\n8 0 end 9\n8 0 end 9\n",
        );
        assert_eq!(idle.first_since(&two), Some(1));
        assert_eq!(two.command(1), (Some(7), Some(((5, 0), (6, 0)))));
        assert_eq!(
            (two.command(2), two.command(3)),
            (two.command(usize::MAX), two.command(usize::MAX))
        );
        assert_eq!(two.command(3), (Some(9), Some(((7, 0), (8, 0)))));
        // A full file: 250 commands of four marks, a line each. One more command, and its
        // four marks are in for the first four: as many `end`s as before, further down.
        let full = |from: usize, last: &str| {
            let command =
                |n: usize| format!("{n} 0 prompt\n{n} 2 command\n{n} 9 output\n{n} 9 end 0\n");
            (from..from + 250).map(command).collect::<String>() + last
        };
        let (was, now) = (read(&full(0, "")), read(&full(1, "")));
        assert_eq!(
            (was.0.len(), was.first_since(&was), was.first_since(&now)),
            (KEPT, None, Some(249))
        );
        // That file's marks on the screen moved (the last six commands' here, two lines down,
        // or all to one place), and nothing was dropped: nothing has ended.
        let moved = |to: fn(usize) -> usize| {
            let command =
                |n: usize| format!("{n} 0 prompt\n{n} 2 command\n{n} 9 output\n{n} 9 end 0\n");
            let place = |n: usize| if n >= 244 { to(n) } else { n };
            read(&(0..250).map(place).map(command).collect::<String>())
        };
        assert_eq!(
            (
                was.first_since(&moved(|n| n + 2)),
                was.first_since(&moved(|_| 244))
            ),
            (None, None)
        );
        // The limit that is left: the file's oldest marks are alike, three commands that a
        // clear put at one place. One command on, its first mark is as before and none is
        // taken for gone: the end is not seen. Once the front is past them it is, and it is
        // still the first command that ended since.
        let alike = "5 0 prompt\n5 0 command\n5 0 output\n5 0 end 0\n".repeat(3);
        let rest = |from: usize, to: usize| {
            let command = |n: usize| {
                format!(
                    "{n} 0 prompt\n{n} 2 command\n{n} 9 output\n{n} 9 end {}\n",
                    n % 200
                )
            };
            (from..to).map(command).collect::<String>()
        };
        let was = read(&(alike.clone() + &rest(6, 253)));
        let one = read(&(alike.split_once("end 0\n").unwrap().1.to_string() + &rest(6, 254)));
        let three = read(&rest(6, 256));
        assert_eq!(
            (was.0.len(), one.0.len(), three.0.len()),
            (KEPT, KEPT, KEPT)
        );
        assert_eq!(
            (was.first_since(&one), was.first_since(&three)),
            (None, Some(247))
        );
        assert_eq!(three.command(247).0, Some(53));
        // It took a prompt and a command, and dropped two: no `end` came, and none went.
        let was = read(&full(0, ""));
        let typed = full(0, "250 0 prompt\n250 2 command\n");
        let typed = read(typed.split_once("0 2 command\n").unwrap().1);
        assert_eq!((typed.0.len(), was.first_since(&typed)), (KEPT, None));
        let _ = fs::remove_dir_all(dir);
    }
}
