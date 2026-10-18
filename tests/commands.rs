//! The real `koh` binary's commands besides a shell, against an in-process loopback server it
//! dials with `--direct`: `koh exec` (argv as given, output apart, statuses, stdin, the hang-up),
//! jobs (`run`, `wait`, `logs`, `kill`, `jobs`), `koh cp` as a sync both ways, and `koh sessions`,
//! `wait --session` and `output` beside `koh connect --new` and `--session`.
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

    /// `koh SUBCOMMAND SERVER ARGS`: what it printed and how it exited.
    fn run(&self, subcommand: &str, args: &[&str]) -> anyhow::Result<Output> {
        Ok(self.koh(subcommand)?.arg(&self.id).args(args).output()?)
    }

    /// `koh exec --sh LINE`, `stdin` its input: what it printed and how it exited.
    fn exec(&self, line: &str, stdin: &[u8]) -> anyhow::Result<Output> {
        let mut child = self
            .koh("exec")?
            .arg(&self.id)
            .arg("--sh")
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
fn exec_passes_its_words_as_they_are_and_exits_with_the_commands_status() {
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
            // Words go as they are, no shell between: quotes, spaces and `$` reach the program.
            let out = remote
                .run(
                    "exec",
                    &["--", "printf", "[%s]\n", "a b", "it's", "$HOME", "x\"y"],
                )
                .expect("exec");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                "[a b]\n[it's]\n[$HOME]\n[x\"y]\n",
                "{out:?}"
            );
            // No such program: 127, and koh says so.
            let out = remote
                .run("exec", &["--", "no-such-program"])
                .expect("exec");
            assert_eq!(out.status.code(), Some(127), "{out:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("no-such-program"));
            // A directory to start in; one not there is said as that, 126: the command could
            // not start, not that there is no such program.
            let out = remote.run("exec", &["-C", "/", "--", "pwd"]).expect("exec");
            assert_eq!(out.stdout, b"/\n", "{out:?}");
            let out = remote
                .run("exec", &["-C", "/no/such/dir", "--", "pwd"])
                .expect("exec");
            let said = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(126), "{out:?}");
            assert!(said.contains("/no/such/dir: no such directory"), "{said}");
            // Killed by a signal: 128 plus it, as a shell says, and nothing else on stderr.
            let out = remote.exec("kill -9 $$", b"").expect("exec");
            assert_eq!((out.status.code(), &out.stderr[..]), (Some(137), &b""[..]));
            // Stdin goes through whole, and its end is the command's.
            let big = vec![b'x'; 3 << 20];
            let out = remote.exec("wc -c", &big).expect("exec");
            assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "3145728");
            // As JSON: the output kept and the status beside it.
            let out = remote
                .run("exec", &["--json", "--sh", "echo hi; echo no >&2; exit 2"])
                .expect("exec");
            let said: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(out.status.code(), Some(2));
            assert_eq!(said["status"], 2);
            assert_eq!(said["stdout"], "hi\n");
            assert_eq!(said["stderr"], "no\n");
            // With no stdin at all, as from a script, it runs at once.
            let out = remote
                .koh("exec")
                .expect("koh")
                .args([&remote.id, "--sh", "cat; echo done"])
                .stdin(Stdio::null())
                .output()
                .expect("exec");
            assert_eq!(
                (out.status.code(), &out.stdout[..]),
                (Some(0), &b"done\n"[..])
            );
        });
}

/// The command `koh exec` runs, hung up once its client goes, as `koh help exec` says: at once if
/// the client is stopped by a signal, within the 20 s idle timeout if it is killed where it stands.
#[test]
fn a_command_whose_client_is_stopped_or_killed_is_hung_up() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("exec-hangup").await.expect("the server");
            for (signal, within) in [
                (fuxix::process::Signal::Term, 5),
                (fuxix::process::Signal::Kill, 30),
            ] {
                let mut child = remote
                    .koh("exec")
                    .expect("koh")
                    .args([&remote.id, "--sh", "echo $$; exec sleep 300"])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("exec");
                let mut line = String::new();
                std::io::BufReader::new(child.stdout.take().expect("stdout"))
                    .read_line(&mut line)
                    .expect("the command's pid");
                let pid = fuxix::process::Pid::from_raw(line.trim().parse().expect("a pid"))
                    .expect("a pid");
                let client = fuxix::process::Pid::of(&child).expect("the client's pid");
                fuxix::process::kill(client, signal).expect("stop the client");
                let _ = child.wait();
                let mut gone = false;
                for _ in 0..within * 10 {
                    gone = !fuxix::process::exists(pid);
                    if gone {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                assert!(gone, "the command outlived its client ({signal:?})");
            }
        });
}

#[test]
fn a_job_outlives_its_client_and_is_waited_for_followed_and_killed() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let remote = Remote::start("jobs").await.expect("the server");
            let ok = |out: &Output| {
                assert!(out.status.success(), "{out:?}");
                String::from_utf8_lossy(&out.stdout).into_owned()
            };
            let started = remote
                .run(
                    "run",
                    &[
                        "--name",
                        "build",
                        "--sh",
                        "echo start; sleep 1; echo listening; sleep 1; echo err >&2; exit 4",
                    ],
                )
                .expect("run");
            assert_eq!(ok(&started), "build\n");
            // Its name is taken while it runs.
            let again = remote
                .run("run", &["--name", "build", "--", "true"])
                .expect("run");
            assert_eq!(again.status.code(), Some(1), "{again:?}");
            // The text comes before the end: the wait ends at it.
            let waited = remote
                .run("wait", &["build", "--text", "listening", "--json"])
                .expect("wait");
            assert_eq!(waited.status.code(), Some(0), "{waited:?}");
            // The end, with its status.
            let ended = remote.run("wait", &["build"]).expect("wait");
            assert_eq!(ended.status.code(), Some(4), "{ended:?}");
            let logs = remote.run("logs", &["build"]).expect("logs");
            assert_eq!(ok(&logs), "start\nlistening\nerr\n");
            let listed = remote.run("jobs", &["--json"]).expect("jobs");
            let jobs: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("json");
            assert_eq!(jobs[0]["name"], "build");
            assert_eq!(jobs[0]["status"], 4);
            // A job is one line in the list, its command's first line marked as cut; by name, its
            // command whole.
            let script = "echo one\necho two";
            ok(&remote
                .run("run", &["--name", "lines", "--sh", script])
                .expect("run"));
            let listed = ok(&remote.run("jobs", &[]).expect("jobs"));
            let line = listed
                .lines()
                .find(|l| l.starts_with("lines "))
                .expect("listed");
            assert!(line.ends_with(" echo one …"), "{listed}");
            assert_eq!(listed.lines().count(), 2, "{listed}");
            let one = ok(&remote.run("jobs", &["lines"]).expect("jobs"));
            assert!(one.ends_with("\n  echo one\n  echo two\n"), "{one}");
            // Unnamed, it takes the next number; killed, it ends by the signal.
            let sleeper = remote.run("run", &["--", "sleep", "300"]).expect("run");
            assert_eq!(ok(&sleeper), "1\n");
            ok(&remote.run("kill", &["1"]).expect("kill"));
            let killed = remote.run("wait", &["1", "--timeout", "10"]).expect("wait");
            assert_eq!(killed.status.code(), Some(128 + 15), "{killed:?}");
            // Followed: what it writes as it writes it, then its status.
            remote
                .run(
                    "run",
                    &["--name", "f", "--sh", "sleep 0.5; echo late; exit 6"],
                )
                .expect("run");
            let followed = remote.run("logs", &["f", "--follow"]).expect("logs");
            assert_eq!(
                (followed.status.code(), &followed.stdout[..]),
                (Some(6), &b"late\n"[..])
            );
            // A wait for a file, and one that gives up.
            let gave_up = remote
                .run("wait", &["--file", "never-made", "--timeout", "0.3"])
                .expect("wait");
            assert_eq!(gave_up.status.code(), Some(124), "{gave_up:?}");
            let no_job = remote.run("wait", &["nope"]).expect("wait");
            assert_ne!(no_job.status.code(), Some(0));
            assert!(String::from_utf8_lossy(&no_job.stderr).contains("no such job"));
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

/// The modification time of `path`.
fn mtime(path: &Path) -> (i64, i64) {
    std::fs::metadata(path).map_or((0, 0), |meta| (meta.mtime(), meta.mtime_nsec()))
}

#[test]
fn cp_brings_a_tree_into_line_both_ways_and_says_what_it_did() {
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
            // Here to there, into a directory made with its parents.
            let there = dir.join("there/deep");
            let mut into = remote.at(&there);
            into.push("/");
            let out = cp(&["-r".into(), from.clone().into(), into.clone()]);
            assert!(out.status.success(), "{out:?}");
            // It says where the tree landed: in the directory, as its own name.
            let said = String::from_utf8_lossy(&out.stdout);
            let landed = format!("{}a tree", into.to_string_lossy());
            assert!(
                said.starts_with(&format!("3 files, 200 KB → {landed} (")),
                "{said}"
            );
            let want = tree(&from).expect("the tree");
            assert_eq!(tree(&there.join("a tree")).expect("there"), want);
            // Named as the tree, which is there now, it would nest inside it (cp's rule): refused,
            // saying how to bring it into line, which `a tree/.` does.
            let same = remote.at(&there.join("a tree"));
            let out = cp(&["-r".into(), from.clone().into(), same.clone()]);
            assert_eq!(out.status.code(), Some(1), "{out:?}");
            let said = String::from_utf8_lossy(&out.stderr);
            assert!(said.contains("nested") && said.contains("DIR/."), "{said}");
            assert!(!there.join("a tree/a tree").exists());
            let out = cp(&[from.join(".").into(), same.clone()]);
            let said = String::from_utf8_lossy(&out.stdout);
            assert!(
                said.starts_with(&format!("0 files, 0 B → {}", same.to_string_lossy())),
                "{said}"
            );
            // Again: nothing changed, nothing sent.
            let out = cp(&[from.clone().into(), into.clone()]);
            assert!(
                String::from_utf8_lossy(&out.stdout).starts_with("0 files, 0 B"),
                "{out:?}"
            );
            // One file edited, dated before the copy landed (an editor's save, or `touch -d`):
            // sent, and it lands with its arrival time, newer than the copy before, so a build
            // there sees it changed (K1).
            let inner = there.join("a tree/sub dir/inner");
            let before = mtime(&inner);
            std::fs::write(from.join("sub dir/inner"), vec![8; 200_000]).expect("edit");
            let old = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000);
            std::fs::File::options()
                .write(true)
                .open(from.join("sub dir/inner"))
                .and_then(|f| f.set_modified(old))
                .expect("an old time");
            let out = cp(&["--json".into(), from.clone().into(), into.clone()]);
            let summary: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(
                (summary["replaced"].as_u64(), summary["unchanged"].as_u64()),
                (Some(1), Some(3)),
                "{summary}"
            );
            assert_eq!(summary["landed"].as_str(), Some(&*landed), "{summary}");
            assert!(mtime(&inner) > before, "the edit landed with an old time");
            // -p keeps the source's time.
            let out = cp(&["-p".into(), from.clone().into(), into.clone()]);
            assert!(out.status.success(), "{out:?}");
            assert_eq!(mtime(&inner).0, 1_000_000);
            // There to here, as a new name.
            let back = dir.join("back");
            let out = cp(&[remote.at(&there.join("a tree")), back.clone().into()]);
            assert!(out.status.success(), "{out:?}");
            assert_eq!(tree(&back).expect("back"), tree(&from).expect("the tree"));
            // --delete takes away what the source lacks, but what is excluded.
            std::fs::write(there.join("a tree/stray"), b"s").expect("a stray file");
            std::fs::write(there.join("a tree/kept.o"), b"o").expect("an excluded file");
            let out = cp(&[
                "--delete".into(),
                "--exclude".into(),
                "*.o".into(),
                from.clone().into(),
                into.clone(),
            ]);
            assert!(
                String::from_utf8_lossy(&out.stdout).contains("1 deleted"),
                "{out:?}"
            );
            assert!(!there.join("a tree/stray").exists());
            assert!(there.join("a tree/kept.o").exists());
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
            // A copy that fails partway says why, and leaves no file half written.
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
                    assert!(!into.join("bad/sub dir/locked").exists());
                }
            }
        });
}

/// An in-process loopback server for the client `client`, saved with the scope `scope`
/// (`cp=DIR`, `exec=DIR`), as `koh clients add` saves one.
async fn scoped_server(
    client: &str,
    scope: &str,
) -> anyhow::Result<(String, u16, tokio::task::JoinHandle<()>)> {
    let dir = koh_testkit::scratch!("scoped-server")?;
    let server_key = dir.join("server.key");
    let clients = dir.join("clients");
    std::fs::write(&clients, format!("agent {client} {scope}\n"))?;
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&clients, std::fs::Permissions::from_mode(0o600))?;
    }
    let config = koh::server::ServeConfig {
        saved_clients: Some(koh::names::Places::new(None, Some(server_key))?),
        command: vec!["bash".to_owned()],
        home: common::home(),
        ..koh::server::ServeConfig::default()
    };
    let (id, port, task) = common::serve_in_process(&config).await?;
    // The scratch directory lives as long as the server.
    let task = koh_testkit::spawn(async move {
        let _dir = dir;
        let _ = task.await;
    });
    Ok((id, port, task))
}

#[test]
fn a_scoped_key_copies_only_in_its_directory_and_runs_no_shell() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("scoped").expect("a scratch directory");
            let drop_dir = dir.join("drop");
            std::fs::create_dir_all(&drop_dir).expect("the scope");
            let key = dir.join("client.key");
            let id = endpoint_id(&key).expect("the client's id");
            let (server_id, port, _server) =
                scoped_server(&id, &format!("cp={}", drop_dir.display()))
                    .await
                    .expect("the server");
            let koh = |args: &[OsString]| {
                koh_testkit::command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
                    .expect("koh")
                    .args(args)
                    .args([
                        "--key-file".into(),
                        key.clone().into_os_string(),
                        "--direct".into(),
                        OsString::from(format!("127.0.0.1:{port}")),
                    ])
                    .output()
                    .expect("koh")
            };
            let file = dir.join("f");
            std::fs::write(&file, b"f").expect("a file");
            let at = |p: &str| OsString::from(format!("{server_id}:{p}"));
            let ok = koh(&["cp".into(), file.clone().into(), at("in/f")]);
            assert!(ok.status.success(), "{ok:?}");
            assert_eq!(std::fs::read(drop_dir.join("in/f")).expect("landed"), b"f");
            for outside in ["../f", "/etc/f", "~/f"] {
                let out = koh(&["cp".into(), file.clone().into(), at(outside)]);
                assert!(!out.status.success(), "{outside}: {out:?}");
            }
            // No command, no shell: refused for good (4).
            let out = koh(&[
                "exec".into(),
                server_id.clone().into(),
                "--".into(),
                "true".into(),
            ]);
            assert_eq!(out.status.code(), Some(255), "{out:?}");
            let out = koh(&["sessions".into(), server_id.clone().into()]);
            assert_eq!(out.status.code(), Some(4), "{out:?}");
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
                assert!(line.starts_with(n) && line.contains(" 80x24 "), "{listed}");
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
            // The last command's output, as the shell's marks place it; no command runs, so a
            // wait for its end ends at once, with the last one's status.
            let out = remote
                .run("output", &["--session", "1", "--last"])
                .expect("output");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                "got_one_42\n",
                "{out:?}"
            );
            let out = remote.run("wait", &["--session", "1"]).expect("wait");
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            let out = remote.run("sessions", &["--json"]).expect("sessions");
            let listed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
            assert_eq!(
                listed[0]["commands_finished"].as_u64().map(|n| n >= 2),
                Some(true),
                "{listed}"
            );
            // On a terminal, as connect needs one: the refusal is the server's.
            let (_client, seen) = on_pty(&connect(&["--session", "9"])).expect("connect");
            seen.wait_for(0, "no such session", 20)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        });
}
