//! Shell marks for the shells `koh serve` starts.
//!
//! bash, zsh and fish are started so that they mark each command (OSC 133 `C` as its output
//! begins, `D;STATUS` as it ends, and `A` where the next prompt starts), after reading the user's
//! own startup files as they would. The client then tells the user's terminal where each remote command starts and ends, and how, with nothing set
//! up on the server (see ARCHITECTURE.md, "The shell's marks").
//!
//! This is fux's design (its `marks.rs`), for the shells koh starts as they are started: plainly,
//! the program alone with no argument, as `$SHELL` or a lone `--shell` is. Each is given a startup
//! file koh writes in a private directory of this server run ([`MarksDir`]), which reads the
//! user's own first: bash's `--rcfile` sources `~/.bashrc` and takes the marks from `PS0` and
//! `PROMPT_COMMAND`; zsh's `ZDOTDIR` shim puts the user's back and sources their `.zshenv`; fish's
//! `--init-command` only adds two event handlers. A shell given any argument is left as it is, as
//! is any other program.
//!
//! Each marked shell is given a nonce its marks carry, and its session's emulator counts only marks
//! that carry it (`fux_vt::Parser::require_mark_nonce`): a program the shell runs, `cat` of a file
//! or a shell of its own (ssh, a nested koh, fish 4's own marks), cannot end a command for it.

use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

/// bash, 4.4 or later (an older one, macOS's 3.2, is left unmarked): the user's own startup, then
/// the marks, set by `__koh_marks`, a function defined first. A function inherits no DEBUG or
/// RETURN trap (unless `set -T`), so a trap the user's startup set sees one command of koh's: its
/// call. With `set -T` it sees what the function runs too, but what it prints goes nowhere (the
/// function's output, and END's, go to /dev/null; END writes its marks to a copy of stderr), and
/// nothing of koh's reads it (no command substitution). The marks run no command of the shell's
/// own either, so the user's DEBUG, ERR and RETURN traps see nothing of them, and `$?` and
/// `PIPESTATUS` stay the command's, for the user's hooks too:
///
/// - `END`, first in `PROMPT_COMMAND` (its first element, an array's too, so that setting it anew
///   replaces the user's hooks, as without koh), so before the user's own hooks print: subshells,
///   which inherit no DEBUG trap, print `D;STATUS` and `A`, the test of an `if` (which sets off no
///   ERR trap) that then makes `PIPESTATUS` and `$?` again. The status, `PIPESTATUS` and the state
///   (`__koh_w`, a prompt shown and no command started since; `__koh_h`, the next history number
///   then) are kept in the arithmetic of a redirection of its own, as no subshell can keep them: a
///   line run with no start mark (one bash could not parse, or a comment: the history number
///   moved) gets one as it ends, `C;late`, which starts its output after the prompt's line, so
///   bash's complaint is its output. Its stderr is /dev/null, so that `set -x` traces none of it;
///   the marks go to fd 3, stderr's copy.
/// - `PS1` ends a command too, in case `PROMPT_COMMAND` is set anew while the shell runs (a `D`
///   that ends no command does nothing); its hooks then print before that end.
/// - `PS0` marks a command's output beginning.
///
/// A variable the user made readonly is left as it is, unmarked. Marks go to stderr, as the
/// prompt does; koh's PROMPT_COMMAND is not exported, so shells started from this one do not
/// inherit it.
const BASHRC: &str = r"if [ -r ~/.bashrc ]; then . ~/.bashrc; fi
";

/// A command's end, `{K}` keeping the command's `PIPESTATUS` and `{P}` making it again (see
/// [`BASHRC`]). No single quotes: the startup file quotes it with them.
const END: &str = r#"{ if ([ "$__koh_m" = 1 ] && printf "\033]133;C;late;nonce=%s\007" "$__koh_k" >&3; printf "\033]133;D;%s;nonce=%s\007\033]133;A;nonce=%s\007" "$__koh_s" "$__koh_k" "$__koh_k" >&3; exit $((__koh_c != 1))); then {P}; fi; } >/dev/null 3>&$((__koh_s = $?, {K}__koh_c = ${#PIPESTATUS[@]}, __koh_n = ${HISTCMD-0}, __koh_m = ${__koh_w-0} && __koh_n != ${__koh_h-0}, __koh_w = 1, __koh_h = __koh_n, 2)) 2>/dev/null"#;
/// The longest pipeline whose statuses `END` gives the user's hooks in `PIPESTATUS`; of a longer
/// one they see its status alone.
const PIPES: usize = 8;
/// What `PS1` starts with: a command's end, should `END` not have run.
const PS1_END: &str = r"\[\033]133;D;$?;nonce=${__koh_k-}\007\033]133;A;nonce=${__koh_k-}\007\]";
/// What `PS0` ends with: a command's start.
const PS0_START: &str = r"\033]133;C;nonce=${__koh_k-}\007${__koh_z[__koh_w = 0]-}";

/// `END`, the command's `PIPESTATUS` kept (`__koh_p`, its length `__koh_c`) and made again last,
/// for the user's hooks after: a pipeline of as many subshells, each exiting with a status, run
/// twice (`&&`: once if it fails, as a failure there would set off the ERR trap; again if not, so
/// that it is the last pipeline run).
fn end() -> String {
    let kept = (0..PIPES)
        .map(|i| format!("__koh_p[{i}] = ${{PIPESTATUS[{i}]-0}}, "))
        .collect::<Vec<_>>()
        .concat();
    let made = (1..=PIPES)
        .map(|n| {
            let pipe = (0..n)
                .map(|i| format!("(exit ${{__koh_p[{i}]}})"))
                .collect::<Vec<_>>()
                .join(" | ");
            let test = if n > 1 {
                format!("elif (exit $((__koh_c != {n}))); then ")
            } else {
                String::new()
            };
            format!("{test}{pipe} && {pipe}")
        })
        .collect::<Vec<_>>()
        .join("; ");
    let made = format!("{made}; else (exit \"$__koh_s\") && (:)");
    END.replace("{K}", &kept).replace("{P}", &made)
}

/// The bash startup file: koh's function, the user's `~/.bashrc`, then the marks.
fn bash_rc() -> String {
    format!(
        r#"# koh: OSC 133 shell marks, after your own startup. Off: `koh serve --no-shell-marks`.
__koh_marks() {{
  unset -f __koh_marks
  export -n __koh_k
  [ "${{BASH_VERSINFO[0]}}${{BASH_VERSINFO[1]}}" -ge 44 ] || return
  __koh_free() {{ case ${{!1@a}} in *r*) return 1 ;; esac; }}
  local __koh_end='{end}'
  if __koh_free PROMPT_COMMAND; then
    PROMPT_COMMAND="$__koh_end${{PROMPT_COMMAND:+$'\n'$PROMPT_COMMAND}}"
    export -n PROMPT_COMMAND
  fi
  if __koh_free PS0; then
    PS0="${{PS0-}}"'{PS0_START}'
    export -n PS0
  fi
  if __koh_free PS1; then PS1='{PS1_END}'"${{PS1-}}"; fi
  unset -f __koh_free
}} >/dev/null 2>&1
{BASHRC}__koh_marks
"#,
        end = end(),
    )
}

/// zsh: read first of all startup files, from the shim `ZDOTDIR`; it puts the user's `ZDOTDIR`
/// back, so the rest of their files are read from there as always, and sources their `.zshenv`.
const ZSHENV: &str = r#"# koh: OSC 133 shell marks, after your own startup. Off: `koh serve --no-shell-marks`.
if [[ -n "${__koh_zdotdir+x}" ]]; then ZDOTDIR=$__koh_zdotdir; unset __koh_zdotdir; else unset ZDOTDIR; fi
[[ -r "${ZDOTDIR:-$HOME}/.zshenv" ]] && source "${ZDOTDIR:-$HOME}/.zshenv"
if [[ -o interactive ]]; then
  typeset +x __koh_k
  __koh_preexec() { print -n "\e]133;C;nonce=${__koh_k-}\a" >&2 }
  __koh_precmd() { print -n "\e]133;D;$?;nonce=${__koh_k-}\a\e]133;A;nonce=${__koh_k-}\a" >&2 }
  preexec_functions=(__koh_preexec $preexec_functions)
  precmd_functions=(__koh_precmd $precmd_functions)
fi
"#;

/// fish: two event handlers, after its own startup.
const FISH: &str = "set -gu __koh_k $__koh_k; \
     function __koh_preexec --on-event fish_preexec; printf '\\e]133;C;nonce=%s\\a' $__koh_k >&2; end; \
     function __koh_postexec --on-event fish_postexec; printf '\\e]133;D;%s;nonce=%s\\a\\e]133;A;nonce=%s\\a' $status $__koh_k $__koh_k >&2; end";

/// How a shell is started so that it marks its commands.
#[derive(Debug)]
pub struct Marked {
    /// Its words.
    pub argv: Vec<String>,
    /// Variables to add, the nonce among them.
    pub env: Vec<(String, String)>,
    /// The nonce its marks carry.
    pub nonce: String,
}

/// The private directory of one server run that the shells' startup files are written in, made
/// on the first shell marked and removed when this drops (the server's end).
#[derive(Debug)]
pub struct MarksDir {
    dir: PathBuf,
}

impl MarksDir {
    /// One under `parent`, made later, named for this run.
    pub fn new(parent: &Path) -> std::io::Result<Self> {
        let run = getrandom::u64().map_err(std::io::Error::from)?;
        Ok(Self {
            dir: parent.join(format!("koh-shell-marks-{}-{run:016x}", std::process::id())),
        })
    }

    /// `argv` and the variables to start it with so that it marks its commands, if it is a
    /// shell koh knows started plainly; `None` leaves it as it is, as when its startup files
    /// cannot be written (said in the log).
    pub fn mark(&self, argv: &[String]) -> Option<Marked> {
        let [program] = argv else {
            return None;
        };
        let name = Path::new(program.trim_start_matches('-'))
            .file_name()?
            .to_str()?;
        let shell = match name {
            "bash" | "zsh" | "fish" => name,
            _ => return None,
        };
        let marked = self.marked(program, shell);
        if let Err(error) = &marked {
            tracing::warn!(%error, dir = %self.dir.display(), "the shell is started without marks");
        }
        marked.ok()
    }

    fn marked(&self, program: &str, shell: &str) -> std::io::Result<Marked> {
        let nonce = format!("{:016x}", getrandom::u64().map_err(std::io::Error::from)?);
        let mut argv = vec![program.to_owned()];
        let mut env = Vec::new();
        match shell {
            "bash" => {
                let rc = self.write(&self.dir, "bashrc", &bash_rc())?;
                argv.extend(["--rcfile".to_owned(), rc.to_string_lossy().into_owned()]);
            }
            "zsh" => {
                let shim = self.dir.join("zsh");
                self.write(&shim, ".zshenv", ZSHENV)?;
                env.push(("ZDOTDIR".to_owned(), shim.to_string_lossy().into_owned()));
                if let Some(theirs) = std::env::var_os("ZDOTDIR") {
                    env.push((
                        "__koh_zdotdir".to_owned(),
                        theirs.to_string_lossy().into_owned(),
                    ));
                }
            }
            _ => argv.extend(["--init-command".to_owned(), FISH.to_owned()]),
        }
        env.push(("__koh_k".to_owned(), nonce.clone()));
        Ok(Marked { argv, env, nonce })
    }

    /// Writes `text` to `dir/name` unless it holds it already (a shell starting reads a whole
    /// file): `dir`, this run's directory or one in it, made private if missing; its path.
    fn write(&self, dir: &Path, name: &str, text: &str) -> std::io::Result<PathBuf> {
        if let Some(parent) = self.dir.parent() {
            safe_parent(parent)?;
        }
        private_dir(&self.dir)?;
        if dir != self.dir {
            private_dir(dir)?;
        }
        let path = dir.join(name);
        if read_private(&path).ok().as_deref() == Some(text) {
            return Ok(path);
        }
        let part = dir.join(format!(
            ".{name}.{:016x}.part",
            getrandom::u64().map_err(std::io::Error::from)?
        ));
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&part)
            .and_then(|mut file| file.write_all(text.as_bytes()))
            .and_then(|()| std::fs::rename(&part, &path));
        if written.is_err() {
            let _ = std::fs::remove_file(&part);
        }
        written.map(|()| path)
    }
}

impl Drop for MarksDir {
    fn drop(&mut self) {
        // Only ever a directory this run made (`private_dir` refuses any other), and so ours.
        if std::fs::symlink_metadata(&self.dir).is_ok_and(|meta| meta.is_dir()) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// Refused unless no other user can move this run's directory out of `parent` and put another in
/// its place (a shell would run what that one holds): it is this user's or root's, and writable by
/// no one else, or sticky, as `/tmp` is.
fn safe_parent(parent: &Path) -> std::io::Result<()> {
    let meta = std::fs::metadata(parent)?;
    let owner = meta.uid() == fuxix::process::geteuid() || meta.uid() == 0;
    if !owner || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0) {
        return Err(std::io::Error::other(format!(
            "{} could be written by another user",
            parent.display()
        )));
    }
    Ok(())
}

/// Make `dir` (0700) if missing; refused unless it is then a directory of this user's that no one
/// else can enter, not a symlink: one planted in its place is never followed.
fn private_dir(dir: &Path) -> std::io::Result<()> {
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(error) if error.kind() != std::io::ErrorKind::AlreadyExists => return Err(error),
        _ => {}
    }
    let meta = std::fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != fuxix::process::geteuid() || meta.mode() & 0o077 != 0 {
        return Err(std::io::Error::other(format!(
            "{} is not a private directory of this user's",
            dir.display()
        )));
    }
    Ok(())
}

/// The text of the file at `path`, not followed if a symlink, if small.
fn read_private(path: &Path) -> std::io::Result<String> {
    let mut text = String::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(fuxix::file::NOFOLLOW)
        .open(path)?
        .take(1 << 16)
        .read_to_string(&mut text)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::MarksDir;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    /// The shells koh knows, started plainly, are marked, each with its own nonce; anything else,
    /// a shell given an argument included, is left alone; the directory goes with the run.
    #[test]
    fn only_plain_shells_are_marked() {
        let scratch = crate::test_runtime::scratch("marks");
        let marks = MarksDir::new(&scratch).unwrap();
        for shell in ["bash", "/bin/bash", "-bash", "zsh", "/usr/bin/fish"] {
            assert!(marks.mark(&words(shell)).is_some(), "{shell}");
        }
        for other in [
            "bash -l",
            "bash script.sh",
            "sh",
            "zsh -c ls",
            "vim",
            "fish -i",
        ] {
            assert!(marks.mark(&words(other)).is_none(), "{other}");
        }
        let (a, b) = (
            marks.mark(&words("bash")).unwrap(),
            marks.mark(&words("bash")).unwrap(),
        );
        assert_ne!(a.nonce, b.nonce);
        assert_eq!(a.argv.get(1).map(String::as_str), Some("--rcfile"));
        let rc = std::path::PathBuf::from(&a.argv[2]);
        assert!(std::fs::read_to_string(&rc)
            .unwrap()
            .contains(". ~/.bashrc"));
        assert!(a.env.contains(&("__koh_k".to_owned(), a.nonce.clone())));
        let dir = rc.parent().unwrap().to_owned();
        drop(marks);
        assert!(!dir.exists());
    }
}
