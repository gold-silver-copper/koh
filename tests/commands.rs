//! The real `koh` binary's commands besides a shell, against an in-process loopback server it
//! dials with `--direct`: `koh exec` (output apart, statuses, stdin, the hang-up), `koh cp` both
//! ways (trees whole, nothing half landed), and `koh sessions` beside `koh connect --new` and
//! `--session`.
#![forbid(clippy::disallowed_methods)]

#[expect(
    dead_code,
    reason = "no `koh serve` process here: the server runs in process"
)]
mod common;

use std::ffi::OsString;
use std::io::{BufRead as _, Write as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use common::{connected, endpoint_id, loopback_server, on_pty};
use koh_testkit::Scratch;

/// A loopback server hosting `sh` for one client, and that client's key.
struct Remote {
    id: String,
    port: u16,
    key: PathBuf,
    _server: tokio::task::JoinHandle<()>,
    _dir: Scratch,
}

impl Remote {
    async fn start(name: &str) -> anyhow::Result<Self> {
        let dir = koh_testkit::scratch!(name)?;
        let key = dir.join("client.key");
        let (id, port, server) = loopback_server(&endpoint_id(&key)?).await?;
        Ok(Self {
            id,
            port,
            key,
            _server: server,
            _dir: dir,
        })
    }

    /// The flags that dial this server as its client.
    fn dialing(&self) -> Vec<OsString> {
        vec![
            "--key-file".into(),
            self.key.clone().into_os_string(),
            "--direct".into(),
            format!("127.0.0.1:{}", self.port).into(),
        ]
    }

    /// `koh SUBCOMMAND`, dialing this server.
    fn koh(&self, subcommand: &str) -> anyhow::Result<Command> {
        let mut koh = koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())?;
        koh.arg(subcommand).args(self.dialing());
        Ok(koh)
    }

    /// `path` on this server, as `koh cp` takes it.
    fn at(&self, path: &Path) -> OsString {
        let mut at = format!("{}:", self.id).into_bytes();
        at.extend_from_slice(path.as_os_str().as_bytes());
        OsString::from_vec(at)
    }

    /// `koh exec` running `line`, `stdin` its input: what it printed and how it exited.
    fn exec(&self, line: &str, stdin: &[u8]) -> anyhow::Result<Output> {
        let mut child = self
            .koh("exec")?
            .arg(&self.id)
            .arg("--")
            .arg(line)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut input) = child.stdin.take() {
            input.write_all(stdin)?;
        }
        Ok(child.wait_with_output()?)
    }
}

#[test]
fn exec_runs_a_command_with_its_output_apart_and_exits_with_its_status() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("exec").await.expect("the server");
            let out = remote
                .exec("echo out; echo err >&2; exit 3", b"")
                .expect("exec");
            assert_eq!(
                (out.status.code(), &out.stdout[..], &out.stderr[..]),
                (Some(3), &b"out\n"[..], &b"err\n"[..]),
                "{out:?}"
            );
            // Killed by a signal: 128 plus it, as a shell says, and nothing else on stderr.
            let out = remote.exec("kill -9 $$", b"").expect("exec");
            assert_eq!((out.status.code(), &out.stderr[..]), (Some(137), &b""[..]));
            // Stdin goes through whole, and its end is the command's.
            let big = vec![b'x'; 3 << 20];
            let out = remote.exec("wc -c", &big).expect("exec");
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "3145728");
            let out = remote.exec("tr a-z A-Z", b"piped through\n").expect("exec");
            assert_eq!(out.stdout, b"PIPED THROUGH\n");
            // With no stdin at all, as from a script, it runs at once.
            let out = remote
                .koh("exec")
                .expect("koh")
                .args([&remote.id, "cat; echo done"])
                .stdin(Stdio::null())
                .output()
                .expect("exec");
            assert_eq!(
                (out.status.code(), &out.stdout[..]),
                (Some(0), &b"done\n"[..])
            );
        });
}

#[test]
fn a_command_whose_client_is_stopped_is_hung_up() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("exec-hangup").await.expect("the server");
            let mut child = remote
                .koh("exec")
                .expect("koh")
                .args([&remote.id, "echo $$; exec sleep 300"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("exec");
            let mut line = String::new();
            std::io::BufReader::new(child.stdout.take().expect("stdout"))
                .read_line(&mut line)
                .expect("the command's pid");
            let pid =
                fuxix::process::Pid::from_raw(line.trim().parse().expect("a pid")).expect("a pid");
            let client = fuxix::process::Pid::of(&child).expect("the client's pid");
            fuxix::process::kill(client, fuxix::process::Signal::Term).expect("stop the client");
            assert_eq!(child.wait().expect("the client exits").code(), Some(255));
            // Hung up, and reaped once the hang-up's grace is over.
            let mut gone = false;
            for _ in 0..50 {
                gone = !fuxix::process::exists(pid);
                if gone {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(gone, "the command outlived its client");
        });
}

/// One entry of a tree: its path in it, kind, mode and contents (a file's bytes, a symlink's
/// target).
type Entry = (PathBuf, char, u32, Vec<u8>);

/// What is in `dir`, recursively, sorted.
fn tree(dir: &Path) -> std::io::Result<Vec<Entry>> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<Entry>) -> std::io::Result<()> {
        for entry in std::fs::read_dir(at)? {
            let path = entry?.path();
            let rel = path
                .strip_prefix(root)
                .map_err(std::io::Error::other)?
                .to_path_buf();
            let meta = std::fs::symlink_metadata(&path)?;
            let mode = meta.mode() & 0o7777;
            if meta.is_symlink() {
                let target = std::fs::read_link(&path)?;
                out.push((rel, 'l', 0, target.into_os_string().into_vec()));
            } else if meta.is_dir() {
                out.push((rel, 'd', mode, Vec::new()));
                walk(root, &path, out)?;
            } else {
                out.push((rel, 'f', mode, std::fs::read(&path)?));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out)?;
    out.sort();
    Ok(out)
}

/// A tree with a mode, a name holding a newline and a byte no UTF-8 holds, a directory in it and
/// a symlink.
fn sample(at: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(at.join("sub dir"))?;
    // A byte that is no UTF-8 where the file system takes one; macOS's refuses it.
    let odd = std::ffi::OsStr::from_bytes(if cfg!(target_os = "macos") {
        b"line\nbreak \xc3\xa9"
    } else {
        b"line\nbreak \xff"
    });
    std::fs::write(at.join(odd), b"odd")?;
    std::fs::write(at.join("run me"), b"#!/bin/sh\n")?;
    std::fs::set_permissions(at.join("run me"), std::fs::Permissions::from_mode(0o751))?;
    std::fs::write(at.join("sub dir/inner"), vec![7; 200_000])?;
    std::os::unix::fs::symlink("run me", at.join("link"))
}

#[test]
fn cp_copies_a_tree_both_ways_whole_and_a_failed_copy_lands_nothing() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("cp").await.expect("the server");
            let dir = koh_testkit::scratch!("cp-trees").expect("a scratch directory");
            let from = dir.join("a tree");
            sample(&from).expect("the tree");
            let cp = |args: &[OsString]| {
                remote
                    .koh("cp")
                    .expect("koh")
                    .args(args)
                    .output()
                    .expect("cp")
            };
            // Here to there, into a directory; scp's flags taken as what it does anyway.
            let there = dir.join("there");
            std::fs::create_dir(&there).expect("a directory there");
            let out = cp(&["-rp".into(), from.clone().into(), remote.at(&there)]);
            assert!(out.status.success(), "{out:?}");
            let want = tree(&from).expect("the tree");
            assert_eq!(tree(&there.join("a tree")).expect("there"), want);
            // There to here, as a new name.
            let back = dir.join("back");
            let out = cp(&[remote.at(&there.join("a tree")), back.clone().into()]);
            assert!(out.status.success(), "{out:?}");
            assert_eq!(tree(&back).expect("back"), want);
            // `~` is the server user's home.
            let name = format!("koh-cp-{}", std::process::id());
            let mut home_path = b"~/".to_vec();
            home_path.extend_from_slice(name.as_bytes());
            let home_arg = remote.at(Path::new(std::ffi::OsStr::from_bytes(&home_path)));
            let out = cp(&[from.join("run me").into(), home_arg]);
            assert!(out.status.success(), "{out:?}");
            let landed = koh_testkit::home!().join(&name);
            let mode = std::fs::metadata(&landed).map(|m| m.mode() & 0o7777);
            let _ = std::fs::remove_file(&landed);
            assert_eq!(mode.ok(), Some(0o751));
            // A copy that fails partway lands nothing, either way: not the tree, nor anything
            // beside where it would have gone. (Root reads any file.)
            if fuxix::process::geteuid() != 0 {
                let bad = dir.join("bad");
                sample(&bad).expect("the tree");
                let locked = bad.join("sub dir/locked");
                std::fs::write(&locked, b"secret").expect("a file");
                std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
                    .expect("mode");
                let into = dir.join("into");
                std::fs::create_dir(&into).expect("a directory");
                for args in [
                    [bad.clone().into(), remote.at(&into)],
                    [remote.at(&bad), into.clone().into()],
                ] {
                    let out = cp(&args);
                    assert!(!out.status.success(), "{out:?}");
                    let said = String::from_utf8_lossy(&out.stderr);
                    assert!(said.contains("permission denied"), "{said}");
                    let left: Vec<_> = std::fs::read_dir(&into).expect("into").collect();
                    assert!(left.is_empty(), "{left:?}");
                }
            }
        });
}

#[test]
fn connect_picks_a_session_by_number_or_a_new_one_and_sessions_lists_them() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("sessions").await.expect("the server");
            let connect = |pick: &[&str]| {
                let mut argv = vec![env!("CARGO_BIN_EXE_koh").to_owned(), "connect".to_owned()];
                argv.extend(
                    remote
                        .dialing()
                        .into_iter()
                        .map(|a| a.to_string_lossy().into_owned()),
                );
                argv.push(remote.id.clone());
                argv.extend(pick.iter().map(|&a| a.to_owned()));
                argv
            };
            // Typed in the session it reaches, whose variable only it holds: what it answers says
            // which it is. Then left with the escape, detached.
            let session = |pick: &[&str], typed: &'static [u8], answer: &'static str| {
                let argv = connect(pick);
                async move {
                    let (mut client, seen, at) = connected(&argv, typed, answer).await?;
                    client.write(vec![0x1e, b'.'])?;
                    for _ in 0..100 {
                        if client.try_wait()?.is_some() {
                            return anyhow::Ok(());
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                    anyhow::bail!("the client did not leave: {}", seen.text_from(at))
                }
            };
            session(&[], b"X=one; echo set_${X}_$((6*7))\r", "set_one_42")
                .await
                .expect("the first session");
            session(&["--new"], b"X=two; echo set_${X}_$((6*7))\r", "set_two_42")
                .await
                .expect("a new session");
            let out = remote
                .koh("sessions")
                .expect("koh")
                .arg(&remote.id)
                .output()
                .expect("sessions");
            let listed = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = listed.lines().collect();
            assert_eq!(lines.len(), 2, "{listed}");
            for (line, n) in lines.iter().zip(["1 ", "2 "]) {
                assert!(
                    line.starts_with(n) && line.contains(" 80x24 running"),
                    "{listed}"
                );
            }
            session(
                &["--session", "1"],
                b"echo got_${X}_$((6*7))\r",
                "got_one_42",
            )
            .await
            .expect("session 1");
            // The latest attached, though the other started after it.
            session(&[], b"echo got_${X}_$((6*7))\r", "got_one_42")
                .await
                .expect("the latest");
            // On a terminal, as connect needs one: the refusal is the server's.
            let (_client, seen) = on_pty(&connect(&["--session", "9"])).expect("connect");
            seen.wait_for(0, "no such session", 20)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        });
}
