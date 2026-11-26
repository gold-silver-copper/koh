//! End-to-end integration tests over real loopback iroh QUIC connections.
// (A test reads files of its own making.)
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering::SeqCst},
};

use iroh::endpoint::{RecvStream, SendStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use koh::Exit;
use koh::client::Client;
use koh::keys::{ClientEntry, Role, Route, Scope, load_or_create_key, save_clients};
use koh::proto::{
    Attach, Attached, MAX_CHUNK, MAX_CTRL, Request, VIEW_FRAME, ViewInput, ViewOutput, ViewSize,
    recv_msg, send_msg,
};
use koh::server::{ServeOptions, start_server};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("koh-e2e-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn boot_pair(
    tag: &str,
) -> (
    TempDir,
    koh::server::RunningServer,
    Client,
    iroh::SecretKey,
    PathBuf,
) {
    let tmp = TempDir::new(tag);
    let srv_cfg = tmp.0.join("srv_cfg");
    let cli_cfg = tmp.0.join("cli_cfg");
    fs::create_dir_all(&srv_cfg).unwrap();
    fs::create_dir_all(&cli_cfg).unwrap();

    let client_key = load_or_create_key(Role::Client, Some(&cli_cfg.join("client.key"))).unwrap();
    let state_dir = tmp.0.join("state");
    let srv = start_server(ServeOptions {
        key_file: Some(srv_cfg.join("server.key")),
        direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        allow: vec![client_key.public()],
        shell: Some("/bin/sh".into()),
        state_dir: Some(state_dir.clone()),
        disable_relay: true,
        quiet: true,
        ..ServeOptions::default()
    })
    .await
    .unwrap();
    let addr = srv.direct_addr.expect("server bound local udp");
    let client = Client::connect_direct(
        client_key.clone(),
        srv.endpoint_id,
        Some(Route::Direct(addr)),
        true,
    )
    .await
    .unwrap();
    (tmp, srv, client, client_key, state_dir)
}

#[tokio::test]
async fn raw_exec_binary_streams_stdin_eof_and_exit_code() {
    let (_tmp, srv, client, _, _) = boot_pair("exec").await;

    // Separate stdout/stderr, binary NUL byte preserved (no PTY mangling), exit code 42.
    let (code, out, err) = client
        .exec(
            vec!["printf 'out\\000line\\n'; printf 'errline\\n' >&2; exit 42".into()],
            Some("/tmp".into()),
            true,
            None,
            true,
        )
        .await
        .unwrap();
    assert_eq!(code, 42);
    assert_eq!(out, b"out\0line\n");
    assert_eq!(err, b"errline\n");

    // Stdin forwarding + clean EOF.
    let (code, out, err) = client
        .exec(
            vec!["cat".into()],
            Some("/tmp".into()),
            false,
            Some(b"hello stdin\n".to_vec()),
            true,
        )
        .await
        .unwrap();
    assert_eq!(code, 0);
    assert_eq!(out, b"hello stdin\n");
    assert!(err.is_empty());

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn headless_jobs_raw_logs_wait_text_timeout_and_kill() {
    let (tmp, srv, client, _, _) = boot_pair("jobs").await;

    // 200-char line must NOT be wrapped at 80 columns (raw append-only log, no PTY).
    let long_line = "X".repeat(200);
    let info = client
        .run_job(
            Some("long".into()),
            vec![format!("printf '{long_line}\\nREADY_TOKEN\\n'; exit 7")],
            Some(tmp.0.display().to_string()),
            true,
        )
        .await
        .unwrap();
    assert_eq!(info.name, "long");

    let wait_res = client
        .wait_job("long".into(), None, 200, Some(10))
        .await
        .unwrap();
    assert!(!wait_res.timed_out);
    assert_eq!(wait_res.exit, 7);
    assert!(wait_res.tail.contains(&long_line));

    let (raw_log, state, exit, _) = client.logs("long".into(), None, true, false).await.unwrap();
    assert_eq!(state, "exited 7");
    assert_eq!(exit, Some(7));
    assert!(String::from_utf8_lossy(&raw_log).contains(&long_line));

    // Wait for --text, timeout 124, and kill.
    let _ = client
        .run_job(
            Some("srv".into()),
            vec!["printf 'BOOTING\\n'; sleep 0.05; printf 'LISTENING\\n'; sleep 60".into()],
            Some(tmp.0.display().to_string()),
            true,
        )
        .await
        .unwrap();
    let matched = client
        .wait_job("srv".into(), Some("LISTENING".into()), 50, Some(5))
        .await
        .unwrap();
    assert!(!matched.timed_out && matched.exit == 0);

    let timed = client
        .wait_job("srv".into(), Some("NEVER_APPEARS".into()), 10, Some(1))
        .await
        .unwrap();
    assert!(timed.timed_out && timed.exit == 124);

    let jobs = client.jobs(None).await.unwrap();
    assert_eq!(jobs.len(), 2);

    let _ = client.kill_job("srv".into(), 9).await.unwrap();
    let killed = client
        .wait_job("srv".into(), None, 10, Some(5))
        .await
        .unwrap();
    assert!(!killed.timed_out && killed.exit != 0);

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_wait_with_a_limit_the_clock_cannot_say_has_no_limit() {
    let (tmp, srv, client, _, _) = boot_pair("wait-limit").await;
    let cwd = Some(tmp.0.display().to_string());
    let script = vec!["sleep 0.3; exit 3".to_string()];
    client
        .run_job(Some("brief".into()), script, cwd, true)
        .await
        .unwrap();
    // More seconds than the clock has: the job is waited for to its end, and the server serves on.
    let waited = client
        .wait_job("brief".into(), None, 10, Some(u64::MAX))
        .await
        .unwrap();
    assert!(!waited.timed_out && waited.exit == 3, "{waited:?}");
    assert_eq!(client.jobs(None).await.unwrap().len(), 1);

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_wait_and_a_followed_log_end_on_the_server_when_their_client_s_stream_does() {
    let (tmp, srv, client, _, _) = boot_pair("left").await;
    let cwd = Some(tmp.0.display().to_string());
    let script = vec!["sleep 60".to_string()];
    client
        .run_job(Some("long".into()), script, cwd, true)
        .await
        .unwrap();
    let name = || "long".to_string();
    let (wait, follow) = (
        Request::WaitJob {
            name: name(),
            text: Some("NEVER_APPEARS".into()),
            tail: 10,
            timeout_secs: None,
        },
        Request::Logs {
            name: name(),
            tail: None,
            all: false,
            follow: true,
        },
    );
    for request in [wait, follow] {
        // The client lets go of what it reads, on a connection that lives: the server lets go
        // of the request, which is seen here as its end of what the client sends being let go.
        let (send, recv) = client.request(&request).await.unwrap();
        drop(recv);
        let ended = tokio::time::timeout(Duration::from_secs(5), send.stopped()).await;
        assert!(ended.is_ok(), "still served after 5 s: {request:?}");
    }

    client.kill_job(name(), 9).await.unwrap();
    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn delta_cp_push_pull_exclude_delete_dry_run_and_preserve() {
    let (tmp, srv, client, _, _) = boot_pair("cp").await;
    let src = tmp.0.join("src");
    let dst = tmp.0.join("dst");
    let back = tmp.0.join("back");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::create_dir_all(src.join("target")).unwrap();
    fs::write(src.join("a.txt"), "alpha").unwrap();
    fs::write(src.join("sub/b.txt"), "beta").unwrap();
    fs::write(src.join("target/ignored.o"), "skipme").unwrap();

    // First push: excludes `target`.
    let s1 = client
        .cp_push(
            &src,
            dst.display().to_string(),
            vec!["target".into()],
            false,
            true,
            false,
        )
        .await
        .unwrap();
    assert_eq!(s1.added.len(), 2);
    assert!(!dst.join("target").exists());
    assert_eq!(fs::read_to_string(dst.join("sub/b.txt")).unwrap(), "beta");
    // -p preserved mtime.
    assert_eq!(
        fs::metadata(src.join("a.txt")).unwrap().mtime(),
        fs::metadata(dst.join("a.txt")).unwrap().mtime()
    );

    // Second push unchanged -> 0 bytes transferred!
    let s2 = client
        .cp_push(
            &src,
            dst.display().to_string(),
            vec!["target".into()],
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(s2.unchanged, 2);
    assert_eq!(s2.bytes_transferred, 0);

    // Dry-run with an extra remote file + --delete reports deletion without removing it.
    fs::write(dst.join("extra.txt"), "stale").unwrap();
    let dry = client
        .cp_push(
            &src,
            dst.display().to_string(),
            vec!["target".into()],
            true,
            false,
            true,
        )
        .await
        .unwrap();
    assert_eq!(dry.deleted, vec!["extra.txt".to_string()]);
    assert!(dst.join("extra.txt").exists());

    // Real --delete removes extra.txt.
    let del = client
        .cp_push(
            &src,
            dst.display().to_string(),
            vec!["target".into()],
            true,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(del.deleted, vec!["extra.txt".to_string()]);
    assert!(!dst.join("extra.txt").exists());

    // Pull back to `back`.
    let pull = client
        .cp_pull(
            dst.display().to_string(),
            &back,
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(pull.added.len(), 2);
    assert_eq!(fs::read_to_string(back.join("a.txt")).unwrap(), "alpha");

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn multi_source_cp_push_and_pull_files_and_dirs() {
    let (tmp, srv, client, _, _) = boot_pair("multicp").await;
    let src_root = tmp.0.join("src");
    let remote_dst = tmp.0.join("remote_dst");
    let local_out = tmp.0.join("local_out");
    fs::create_dir_all(src_root.join("d1")).unwrap();
    fs::create_dir_all(src_root.join("d2")).unwrap();
    fs::write(src_root.join("top.txt"), "top").unwrap();
    fs::write(src_root.join("d1/one.txt"), "one").unwrap();
    fs::write(src_root.join("d2/two.txt"), "two").unwrap();

    // Multi-source push: 1 file + 2 directories into one remote destination dir.
    let pushed = client
        .cp_push_many(
            &[
                src_root.join("top.txt"),
                src_root.join("d1"),
                src_root.join("d2"),
            ],
            &remote_dst.display().to_string(),
            &[],
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(pushed.added.len(), 3);
    assert_eq!(
        fs::read_to_string(remote_dst.join("top.txt")).unwrap(),
        "top"
    );
    assert_eq!(
        fs::read_to_string(remote_dst.join("d1/one.txt")).unwrap(),
        "one"
    );
    assert_eq!(
        fs::read_to_string(remote_dst.join("d2/two.txt")).unwrap(),
        "two"
    );

    // --delete with multiple sources is refused with Usage error (push AND pull).
    let del_err = client
        .cp_push_many(
            &[src_root.join("d1"), src_root.join("d2")],
            &remote_dst.display().to_string(),
            &[],
            true,
            false,
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(del_err.code, Exit::USAGE);

    let pull_del_err = client
        .cp_pull_many(
            &[
                remote_dst.join("d1").display().to_string(),
                remote_dst.join("d2").display().to_string(),
            ],
            &local_out,
            &[],
            true,
            false,
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(pull_del_err.code, Exit::USAGE);

    // Multi-source --dry-run reports additions without creating local_out.
    let dry_pull = client
        .cp_pull_many(
            &[
                remote_dst.join("top.txt").display().to_string(),
                remote_dst.join("d1").display().to_string(),
            ],
            &local_out,
            &[],
            false,
            false,
            true,
        )
        .await
        .unwrap();
    assert!(dry_pull.dry_run);
    assert_eq!(dry_pull.added.len(), 2);
    assert!(!local_out.exists());

    // Multi-source pull: 1 remote file + 2 remote dirs into one local dir.
    let pulled = client
        .cp_pull_many(
            &[
                remote_dst.join("top.txt").display().to_string(),
                remote_dst.join("d1").display().to_string(),
                remote_dst.join("d2").display().to_string(),
            ],
            &local_out,
            &[],
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(pulled.added.len(), 3);
    assert_eq!(
        fs::read_to_string(local_out.join("top.txt")).unwrap(),
        "top"
    );
    assert_eq!(
        fs::read_to_string(local_out.join("d1/one.txt")).unwrap(),
        "one"
    );
    assert_eq!(
        fs::read_to_string(local_out.join("d2/two.txt")).unwrap(),
        "two"
    );

    client.close().await;
    srv.shutdown().await;
}

/// `koh connect` as a person runs it, in a terminal of the test's own (a pty): what it drew there
/// and how it ended. It is killed when the test lets go of it, however the test ends.
struct InTerminal {
    koh: std::process::Child,
    tty: fs::File,
    drawn: Vec<u8>,
    /// Whether it says what it is when it is asked, as every terminal does (once: koh asks once).
    answers: bool,
}

impl Drop for InTerminal {
    fn drop(&mut self) {
        let _ = self.koh.kill();
        let _ = self.koh.wait();
    }
}

impl InTerminal {
    fn connect(config: &Path, runtime: &Path, args: &[&str]) -> Self {
        Self::connect_in(config, runtime, args, true)
    }

    /// In a terminal that is koh's controlling terminal (`its`), as a shell's is; or one that
    /// is only its standard input and output.
    fn connect_in(config: &Path, runtime: &Path, args: &[&str], its: bool) -> Self {
        Self::connect_on(Self::pty(), config, runtime, args, its)
    }

    /// A terminal of 80 by 24: its end here, and the end a program has.
    fn pty() -> (fs::File, fs::File) {
        let size = fuxix::Winsize {
            rows: 24,
            cols: 80,
            xpixel: 800,
            ypixel: 480,
        };
        fuxix::pty(size).unwrap()
    }

    /// `koh connect` on this terminal.
    fn connect_on(
        (tty, theirs): (fs::File, fs::File),
        config: &Path,
        runtime: &Path,
        args: &[&str],
        its: bool,
    ) -> Self {
        let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
        koh.env("KOH_CONFIG_DIR", config)
            .env("XDG_RUNTIME_DIR", runtime)
            .arg("connect")
            .args(args)
            .stdin(theirs.try_clone().unwrap())
            .stdout(theirs.try_clone().unwrap())
            .stderr(theirs);
        fuxix::new_session(&mut koh, its);
        Self {
            koh: koh.spawn().unwrap(),
            tty,
            drawn: Vec::new(),
            answers: true,
        }
    }

    /// Waits until `done` says so, reading meanwhile what koh draws (a terminal nobody reads
    /// holds its program up). Twenty seconds is the most any of it may take.
    fn until(&mut self, what: &str, mut done: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut some = [0u8; 4096];
            while let Ok(n @ 1..) = (&self.tty).read(&mut some) {
                self.drawn.extend_from_slice(&some[..n]);
            }
            if self.answers && self.drawn.windows(3).any(|asked| asked == b"\x1b[c") {
                self.answers = false;
                self.types(b"\x1b[?62c");
            }
            if done(self) {
                return;
            }
            let last = self.drawn.len().saturating_sub(400);
            let drawn = String::from_utf8_lossy(&self.drawn[last..]);
            assert!(
                Instant::now() < deadline,
                "{what}: not in 20 s. The last it drew: {drawn:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Types into the terminal, all of it: a pty takes only so much at once (a kilobyte on
    /// macOS), and the rest when koh has read.
    fn types(&mut self, keys: &[u8]) {
        let mut typed = 0;
        while typed < keys.len() {
            match (&self.tty).write(&keys[typed..]) {
                Ok(n) => typed += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("typing: {e}"),
            }
        }
    }

    /// The exit code koh ended with.
    fn ends(&mut self) -> Option<i32> {
        let mut code = None;
        let ended = |me: &mut Self| {
            code = me.koh.try_wait().unwrap().map(|status| status.code());
            code.is_some()
        };
        self.until("koh connect ends", ended);
        code.flatten()
    }
}

#[tokio::test]
async fn unauthorized_and_scoped_keys_enforce_exit_code_4() {
    let tmp = TempDir::new("auth");
    let srv_cfg = tmp.0.join("srv_cfg");
    let cli_cfg = tmp.0.join("cli_cfg");
    fs::create_dir_all(&srv_cfg).unwrap();
    fs::create_dir_all(&cli_cfg).unwrap();

    let allowed_dir = tmp.0.join("allowed");
    let outside_dir = tmp.0.join("outside");
    fs::create_dir_all(&allowed_dir).unwrap();
    fs::create_dir_all(&outside_dir).unwrap();

    let stranger_key =
        load_or_create_key(Role::Client, Some(&cli_cfg.join("stranger.key"))).unwrap();
    let cp_only_key = load_or_create_key(Role::Client, Some(&cli_cfg.join("cponly.key"))).unwrap();
    save_clients(
        Some(&srv_cfg.join("server.key")),
        &[ClientEntry {
            name: "cpbot".into(),
            id: cp_only_key.public(),
            scope: Scope::Cp(allowed_dir.clone()),
        }],
    )
    .unwrap();

    let srv = start_server(ServeOptions {
        key_file: Some(srv_cfg.join("server.key")),
        direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        allow: Vec::new(),
        shell: None,
        state_dir: Some(tmp.0.join("state")),
        disable_relay: true,
        quiet: true,
        ..ServeOptions::default()
    })
    .await
    .unwrap();
    let addr = srv.direct_addr.unwrap();

    // 1. Unknown key -> Exit::REFUSED (4).
    let stranger = Client::connect_direct(
        stranger_key,
        srv.endpoint_id,
        Some(Route::Direct(addr)),
        false,
    )
    .await
    .unwrap();
    let err = stranger.jobs(None).await.unwrap_err();
    assert_eq!(err.code, Exit::REFUSED, "expected exit 4, got {err:?}");
    stranger.close().await;

    // 2. cp-scoped key cannot exec (exit 4) and cannot cp outside allowed_dir (exit 4),
    //    but CAN cp inside allowed_dir!
    let cpbot = Client::connect_direct(
        cp_only_key,
        srv.endpoint_id,
        Some(Route::Direct(addr)),
        false,
    )
    .await
    .unwrap();
    let exec_err = cpbot
        .exec(
            vec!["true".into()],
            Some(allowed_dir.display().to_string()),
            false,
            None,
            true,
        )
        .await
        .unwrap_err();
    assert_eq!(exec_err.code, Exit::REFUSED);

    let local_file = tmp.0.join("payload.txt");
    fs::write(&local_file, "hi").unwrap();
    let escape_err = cpbot
        .cp_push(
            &local_file,
            outside_dir.display().to_string(),
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(escape_err.code, Exit::REFUSED);

    let ok = cpbot
        .cp_push(
            &local_file,
            allowed_dir.display().to_string(),
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(ok.added, vec!["payload.txt".to_string()]);
    assert_eq!(
        fs::read_to_string(allowed_dir.join("payload.txt")).unwrap(),
        "hi"
    );

    cpbot.close().await;
    srv.shutdown().await;
}

#[test]
fn cli_help_keys_and_peer_lists() {
    let tmp = TempDir::new("cli");
    let bin = env!("CARGO_BIN_EXE_koh");

    let help = Command::new(bin).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("koh connect"));

    let id_out = Command::new(bin)
        .env("KOH_CONFIG_DIR", &tmp.0)
        .arg("id")
        .output()
        .unwrap();
    assert!(id_out.status.success());
    let id = String::from_utf8(id_out.stdout).unwrap().trim().to_string();
    assert_eq!(id.len(), 64);

    assert!(
        Command::new(bin)
            .env("KOH_CONFIG_DIR", &tmp.0)
            .args(["servers", "add", "box", &id, "--direct", "127.0.0.1:4433"])
            .status()
            .unwrap()
            .success()
    );
    let list = Command::new(bin)
        .env("KOH_CONFIG_DIR", &tmp.0)
        .arg("servers")
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&list.stdout).contains("box "));

    // Usage error with --json emits structured JSON and exit code 2.
    let bad = Command::new(bin)
        .args(["unknown-cmd", "--json"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stdout).contains("\"kind\":\"usage\""));

    // Multi-source `cp --delete` MUST fail with usage (exit 2) BEFORE dialing any server.
    let del_multi = Command::new(bin)
        .env("KOH_CONFIG_DIR", &tmp.0)
        .args(["cp", "--delete", "a", "b", "nosuch:dst", "--json"])
        .output()
        .unwrap();
    assert_eq!(del_multi.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&del_multi.stdout).contains("\"kind\":\"usage\""));

    // Mixing remote sources with remote destination or mismatched servers fails with exit 2.
    let mixed = Command::new(bin)
        .args(["cp", "box:a", "box:b", "box:dst"])
        .output()
        .unwrap();
    assert_eq!(mixed.status.code(), Some(2));

    let diff_srv = Command::new(bin)
        .args(["cp", "box1:a", "box2:b", "."])
        .output()
        .unwrap();
    assert_eq!(diff_srv.status.code(), Some(2));
}

/// A server with one `--cp DIR` key, and that key's client.
async fn boot_scoped(
    tag: &str,
) -> (
    TempDir,
    koh::server::RunningServer,
    Client,
    PathBuf,
    PathBuf,
) {
    let tmp = TempDir::new(tag);
    let srv_cfg = tmp.0.join("srv_cfg");
    let cli_cfg = tmp.0.join("cli_cfg");
    let allowed = tmp.0.join("allowed");
    let outside = tmp.0.join("outside");
    for dir in [&srv_cfg, &cli_cfg, &allowed, &outside] {
        fs::create_dir_all(dir).unwrap();
    }
    let key = load_or_create_key(Role::Client, Some(&cli_cfg.join("client.key"))).unwrap();
    save_clients(
        Some(&srv_cfg.join("server.key")),
        &[ClientEntry {
            name: "cpbot".into(),
            id: key.public(),
            scope: Scope::Cp(allowed.clone()),
        }],
    )
    .unwrap();
    let srv = start_server(ServeOptions {
        key_file: Some(srv_cfg.join("server.key")),
        direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        allow: Vec::new(),
        shell: None,
        state_dir: Some(tmp.0.join("state")),
        disable_relay: true,
        quiet: true,
        ..ServeOptions::default()
    })
    .await
    .unwrap();
    let addr = srv.direct_addr.unwrap();
    let client = Client::connect_direct(key, srv.endpoint_id, Some(Route::Direct(addr)), false)
        .await
        .unwrap();
    (tmp, srv, client, allowed, outside)
}

#[tokio::test]
async fn a_scoped_copy_is_held_by_the_text_of_its_path_and_a_symlink_leads_where_it_leads() {
    use std::os::unix::fs::symlink;
    let (tmp, srv, client, allowed, outside) = boot_scoped("symlink").await;
    let push = |src: PathBuf, dst: PathBuf, delete: bool| {
        let (client, dst) = (&client, dst.display().to_string());
        async move {
            client
                .cp_push(&src, dst, Vec::new(), delete, false, false)
                .await
        }
    };

    // A path that says by its text that it is beneath DIR is taken, and the file system says
    // where it is: a symlink on the way is followed, in the path the client names and in the
    // tree that lands.
    symlink(&outside, allowed.join("link")).unwrap();
    let through = tmp.0.join("through");
    fs::create_dir_all(through.join("link")).unwrap();
    fs::write(through.join("link/x"), "through the tree").unwrap();
    push(through, allowed.clone(), false).await.unwrap();
    assert_eq!(
        fs::read_to_string(outside.join("x")).unwrap(),
        "through the tree"
    );
    let file = tmp.0.join("y");
    fs::write(&file, "through the path").unwrap();
    push(file, allowed.join("link"), false).await.unwrap();
    assert_eq!(
        fs::read_to_string(outside.join("y")).unwrap(),
        "through the path"
    );

    // `--delete` goes by what a tree that is read holds, and a symlink is not read: it stays,
    // and so does what is beyond it.
    let empty = tmp.0.join("empty");
    fs::create_dir_all(&empty).unwrap();
    push(empty, allowed.clone(), true).await.unwrap();
    assert!(allowed.join("link").is_symlink());
    assert_eq!(names_in(&outside), ["x", "y"]);

    // A file lands under a name of its own and is then renamed: a symlink where it lands is
    // replaced by it, and the file the symlink led to is as it was. That file has the same
    // bytes here, and the copy must not find the file "unchanged" for that: what is where a
    // file lands is the symlink, and a symlink is not the file.
    fs::write(outside.join("target"), "same").unwrap();
    symlink(outside.join("target"), allowed.join("final")).unwrap();
    let onto = tmp.0.join("onto");
    fs::create_dir_all(&onto).unwrap();
    fs::write(onto.join("final"), "same").unwrap();
    let done = push(onto, allowed.clone(), false).await.unwrap();
    assert_eq!(done.unchanged, 0, "compared with the file beyond DIR/final");
    assert!(!allowed.join("final").is_symlink());
    assert_eq!(fs::read_to_string(allowed.join("final")).unwrap(), "same");
    assert_eq!(fs::read_to_string(outside.join("target")).unwrap(), "same");

    // A tree with directories lands, and no temporary file is left beside what landed.
    let nested = tmp.0.join("nested");
    fs::create_dir_all(nested.join("a/b")).unwrap();
    fs::write(nested.join("a/b/c.txt"), "deep").unwrap();
    let landed = push(nested, allowed.join("sub/tree"), false).await.unwrap();
    assert_eq!(landed.added, vec!["a/b/c.txt".to_string()]);
    assert_eq!(names_in(&allowed.join("sub/tree/a/b")), ["c.txt"]);

    // Reading is the same: a symlink in a tree is not sent, as a file or as a directory, and a
    // path that names a file through one reaches that file.
    fs::write(outside.join("secret"), "secret").unwrap();
    symlink(&outside, allowed.join("sub/tree/out")).unwrap();
    symlink(outside.join("secret"), allowed.join("sub/tree/a/s")).unwrap();
    let pull = |src: PathBuf, to: &str| {
        let (client, to) = (&client, tmp.0.join(to));
        async move {
            let src = src.display().to_string();
            let done = client
                .cp_pull(src, &to, Vec::new(), false, false, false)
                .await;
            (done.unwrap(), to)
        }
    };
    let (whole, to) = pull(allowed.join("sub/tree"), "whole").await;
    assert_eq!(whole.added, vec!["a/b/c.txt".to_string()]);
    assert_eq!(names_in(&to), ["a"]);
    assert_eq!(names_in(&to.join("a")), ["b"]);
    // The client's own destination is as its file system has it too: a symlink there is
    // followed.
    let (local, beyond) = (tmp.0.join("local"), tmp.0.join("beyond"));
    fs::create_dir_all(&local).unwrap();
    fs::create_dir_all(&beyond).unwrap();
    symlink(&beyond, local.join("a")).unwrap();
    pull(allowed.join("sub/tree"), "local").await;
    assert_eq!(fs::read_to_string(beyond.join("b/c.txt")).unwrap(), "deep");
    let (named, to) = pull(allowed.join("sub/tree/out/secret"), "named").await;
    assert_eq!(named.added, vec!["secret".to_string()]);
    assert_eq!(fs::read_to_string(to.join("secret")).unwrap(), "secret");

    // The text is what holds: a path that does not begin with DIR is refused, though a symlink
    // would have led it there.
    symlink(&allowed, outside.join("in")).unwrap();
    let file = tmp.0.join("z");
    fs::write(&file, "z").unwrap();
    let err = push(file, outside.join("in"), false).await.unwrap_err();
    assert_eq!(err.code, Exit::REFUSED, "{err:?}");
    assert!(!allowed.join("z").exists());

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn cp_receiver_bounds_the_manifest_and_takes_only_the_files_it_asked_for() {
    use koh::proto::{SyncEntry, SyncMsg};
    let (tmp, srv, client, _, _) = boot_pair("cp-bounds").await;
    let dst = tmp.0.join("dst");
    let entry = |path: String| SyncEntry {
        path,
        size: 1,
        mtime_secs: 0,
        mode: 0o644,
        hash: [0; 32],
        is_dir: false,
    };
    let push = |dry_run| Request::CpPush {
        dst: dst.display().to_string(),
        excludes: Vec::new(),
        delete: false,
        preserve_mtime: false,
        dry_run,
    };

    // One file more than a tree may hold.
    let (mut send, mut recv) = client.request(&push(true)).await.unwrap();
    let many = (0..=100_000).map(|n| entry(format!("f{n}"))).collect();
    send_msg(&mut send, &SyncMsg::Manifest(many), MAX_CTRL * 8)
        .await
        .unwrap();
    let answer: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
    assert!(
        matches!(&answer, SyncMsg::Failed(why) if why.code == 4),
        "{answer:?}"
    );

    // A file the receiver did not ask for.
    let (mut send, mut recv) = client.request(&push(false)).await.unwrap();
    let manifest = SyncMsg::Manifest(vec![entry("asked".into())]);
    send_msg(&mut send, &manifest, MAX_CTRL).await.unwrap();
    let need: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
    assert!(matches!(&need, SyncMsg::Need(n) if n == &["asked".to_string()]));
    let start = SyncMsg::FileStart {
        path: "unasked".into(),
        size: 1,
        mtime_secs: 0,
        mode: 0o644,
    };
    send_msg(&mut send, &start, MAX_CTRL).await.unwrap();
    let _ = send_msg(&mut send, &SyncMsg::FileChunk(vec![b'!']), MAX_CHUNK).await;
    let _ = send_msg(&mut send, &SyncMsg::FileEnd, MAX_CTRL).await;
    let answer: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
    assert!(
        matches!(&answer, SyncMsg::Failed(why) if why.code == 4),
        "{answer:?}"
    );
    assert!(!dst.join("unasked").exists());

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_second_server_on_one_key_is_refused_until_the_first_stops() {
    let tmp = TempDir::new("serve-lock");
    let key = tmp.0.join("cfg/server.key");
    fs::create_dir_all(tmp.0.join("cfg")).unwrap();
    let serve = || {
        start_server(ServeOptions {
            key_file: Some(key.clone()),
            direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            allow: Vec::new(),
            shell: None,
            state_dir: Some(tmp.0.join("state")),
            disable_relay: true,
            quiet: true,
            ..ServeOptions::default()
        })
    };
    let first = serve().await.expect("the first server starts");
    let refused = serve().await.err().expect("a second server on the key");
    assert_eq!(refused.code, Exit::BUSY, "{refused:?}");
    assert!(refused.message.contains("server.key"), "{refused:?}");

    // The first stopped: the key is free, and what marks it held is a lock, not a file's being
    // there (a server that was killed leaves the file, and nothing to clean up).
    first.shutdown().await;
    assert!(tmp.0.join("cfg/server.key.serving").exists());
    let again = serve().await.expect("a server once the first stopped");
    again.shutdown().await;
}

/// A server that allows `allow`, with its other options from `more`.
async fn boot_server(
    tmp: &TempDir,
    allow: Vec<iroh::EndpointId>,
    more: ServeOptions,
) -> (koh::server::RunningServer, Option<Route>) {
    fs::create_dir_all(tmp.0.join("srv_cfg")).unwrap();
    let srv = start_server(ServeOptions {
        key_file: Some(tmp.0.join("srv_cfg/server.key")),
        direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        allow,
        shell: Some("/bin/sh".into()),
        state_dir: Some(tmp.0.join("state")),
        disable_relay: true,
        quiet: true,
        ..more
    })
    .await
    .unwrap();
    let route = Some(Route::Direct(srv.direct_addr.unwrap()));
    (srv, route)
}

fn new_key(tmp: &TempDir, name: &str) -> iroh::SecretKey {
    fs::create_dir_all(tmp.0.join("cli_cfg")).unwrap();
    load_or_create_key(Role::Client, Some(&tmp.0.join("cli_cfg").join(name))).unwrap()
}

#[tokio::test]
async fn connections_are_capped_before_auth_and_a_place_comes_back_when_one_ends() {
    let tmp = TempDir::new("max-conn");
    let (friend, stranger) = (new_key(&tmp, "friend.key"), new_key(&tmp, "stranger.key"));
    let more = ServeOptions {
        max_connections: 2,
        proof_timeout: Duration::from_secs(60),
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    let dial = |key: &iroh::SecretKey| {
        Client::connect_direct(key.clone(), srv.endpoint_id, route.clone(), false)
    };

    // Two peers the server does not know, which prove nothing, hold both places.
    let (first, second) = (
        dial(&stranger).await.unwrap(),
        dial(&stranger).await.unwrap(),
    );
    let third = dial(&friend).await.unwrap();
    let busy = third.jobs(None).await.unwrap_err();
    assert_eq!(busy.code, Exit::BUSY, "{busy:?}");
    third.close().await;

    // One of them goes: its place is the next client's.
    first.close().await;
    let served = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let next = dial(&friend).await.unwrap();
            let listed = next.jobs(None).await;
            next.close().await;
            match listed {
                Ok(list) => break list,
                Err(busy) => assert_eq!(busy.code, Exit::BUSY, "{busy:?}"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a place came back within 5 s");
    assert!(served.is_empty());

    second.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_connection_that_proves_no_allowed_key_in_time_is_closed() {
    let tmp = TempDir::new("proof-deadline");
    let (friend, stranger) = (new_key(&tmp, "friend.key"), new_key(&tmp, "stranger.key"));
    let more = ServeOptions {
        proof_timeout: Duration::from_secs(1),
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    let dial = |key: &iroh::SecretKey| {
        Client::connect_direct(key.clone(), srv.endpoint_id, route.clone(), true)
    };

    let silent = dial(&stranger).await.unwrap();
    let known = dial(&friend).await.unwrap();
    known.jobs(None).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), silent.connection().closed())
        .await
        .expect("the silent connection was closed within 5 s");
    let refused = koh::proto::CloseCode::Refused as u64;
    assert!(
        matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == refused),
        "{closed:?}"
    );
    // One that proved its key in time stays, past the deadline (it came a moment after the other).
    tokio::time::sleep(Duration::from_millis(300)).await;
    known.jobs(None).await.unwrap();

    known.close().await;
    silent.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn the_server_takes_no_stream_but_a_request() {
    let (_tmp, srv, client, _, _) = boot_pair("no-uni").await;
    // Nothing reads a unidirectional stream, so a peer is given none to fill.
    let conn = client.connection();
    let opened = tokio::time::timeout(Duration::from_millis(300), conn.open_uni()).await;
    assert!(opened.is_err(), "a unidirectional stream was opened");
    client.jobs(None).await.unwrap();
    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_command_that_fails_gives_its_place_back_at_once() {
    let tmp = TempDir::new("close-on-error");
    let cfg = tmp.0.join("cli_cfg");
    let friend = new_key(&tmp, "client.key");
    let more = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let (srv, _) = boot_server(&tmp, vec![friend.public()], more).await;
    let (id, addr) = (srv.endpoint_id.to_string(), srv.direct_addr.unwrap());
    let koh = move |args: &'static [&'static str]| {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_koh"));
        command
            .env("KOH_CONFIG_DIR", &cfg)
            .arg(args[0])
            .arg(&id)
            .args(&args[1..])
            .args(["--direct", &addr.to_string()]);
        async move { command.output().await.unwrap() }
    };

    // No such job: the command fails after it connected. The server has one place, and the
    // next command must find it free, not wait out the first one's connection.
    let failed = koh(&["jobs", "no-such-job"]).await;
    assert_eq!(failed.status.code(), Some(127), "{failed:?}");
    let next = koh(&["jobs"]).await;
    assert_eq!(next.status.code(), Some(0), "{next:?}");

    srv.shutdown().await;
}

#[tokio::test]
async fn a_connection_s_place_comes_back_when_its_requests_have_ended_or_five_seconds_after_it() {
    let tmp = TempDir::new("place-requests");
    let friend = new_key(&tmp, "friend.key");
    let more = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    let dial = || Client::connect_direct(friend.clone(), srv.endpoint_id, route.clone(), false);
    // A command, which hanging up does not end, of a client that then leaves. (It says when
    // it is that: a client that left before, on a slow machine, hung up a shell that had not
    // yet read its first word.)
    let left = |script: &str| {
        let exec = Request::Exec {
            argv: vec![format!("trap '' HUP; : > deaf; {script}")],
            cwd: Some(tmp.0.display().to_string()),
            shell: true,
        };
        let deaf = tmp.0.join("deaf");
        async move {
            let client = dial().await.unwrap();
            let streams = client.request(&exec).await.unwrap();
            until("the command is deaf to a hangup", || deaf.exists());
            fs::remove_file(&deaf).unwrap();
            (client, streams)
        }
    };
    // The next client is served: asked again for as long as the server is busy.
    let served = || async {
        let serving = async {
            loop {
                let listed = match dial().await {
                    Ok(next) => {
                        let listed = next.jobs(None).await;
                        next.close().await;
                        listed
                    }
                    Err(busy) => Err(busy),
                };
                match listed {
                    Ok(_) => break,
                    Err(busy) => assert_eq!(busy.code, Exit::BUSY, "{busy:?}"),
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let served = tokio::time::timeout(Duration::from_secs(20), serving).await;
        served.expect("the place came back within 20 s");
    };

    // The command goes on for a second after its client left: the place is the connection's
    // until then, and the next client's only once the command has ended.
    let (client, streams) = left("sleep 1; : > ended").await;
    drop(streams);
    client.close().await;
    served().await;
    assert!(tmp.0.join("ended").exists(), "served beside the command");

    // A command that goes on writing to a client that left is read no further, and so ends:
    // it does not hold the place for the five seconds a command that does not end has.
    let (client, streams) = left("sleep 0.2; head -c 2097152 /dev/zero").await;
    drop(streams);
    client.close().await;
    let cut_off = tokio::time::timeout(Duration::from_secs(3), served()).await;
    cut_off.expect("the place of a command that only writes came back within 3 s");

    // A command that does not end is let go of five seconds after its connection: the place
    // is not its to keep.
    let (client, streams) = left("echo $$ > pid; exec sleep 600").await;
    until("the command runs", || tmp.0.join("pid").is_file());
    drop(streams);
    client.close().await;
    let left_at = Instant::now();
    served().await;
    let after = left_at.elapsed();
    assert!(after >= Duration::from_secs(4), "after {after:?}");
    signal(
        fs::read_to_string(tmp.0.join("pid")).unwrap().trim(),
        "-KILL",
    );

    srv.shutdown().await;
}

#[test]
fn a_fifo_where_the_list_of_clients_is_holds_no_server() {
    let tmp = TempDir::new("fifo-list");
    // A FIFO nobody writes to, where the server reads who is allowed at every request: it is
    // read as a list of nobody, and whoever reads it is not kept waiting for a writer.
    drop(fuxix::fifo(tmp.0.join("clients")).unwrap());
    let key = tmp.0.join("server.key");
    let (tell, told) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tell.send(koh::keys::load_clients(Some(&key), |_, _| {}).map(|list| list.len()))
    });
    let read = told.recv_timeout(Duration::from_secs(5));
    assert!(matches!(read, Ok(Ok(0))), "{read:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn a_tree_that_takes_long_to_hash_holds_up_nothing_else_the_server_serves() {
    use koh::proto::{SyncEntry, SyncMsg};
    let (tmp, srv, client, _, _) = boot_pair("cp-beside").await;
    // As much of nothing as takes about half a second to hash here (8 MiB to 2 GiB): long to
    // hash, and nothing to make.
    let began = Instant::now();
    blake3::hash(&vec![0u8; 8 << 20]);
    let eighth = began.elapsed().as_micros().max(1) as u64;
    let (size, tree) = (
        (8u64 << 20) * (500_000 / eighth).clamp(1, 256),
        tmp.0.join("tree"),
    );
    fs::create_dir_all(&tree).unwrap();
    let big = fs::File::create(tree.join("big")).unwrap();
    big.set_len(size).unwrap();
    // The server is in this process, and one thread serves all its requests: what else that
    // thread serves stands in for another client's link. It wakes every two milliseconds.
    let woken = Arc::new(AtomicUsize::new(0));
    let wakes = woken.clone();
    let beside = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(2)).await;
            wakes.fetch_add(1, SeqCst);
        }
    });
    // It went on waking while the server hashed: for a quarter of that time at the least.
    // (Held up, it wakes a few times in all: the hashing is nearly all the time there is.)
    let went_on = |what: &str, began: Instant, woke: usize| {
        let took = began.elapsed();
        let awake = Duration::from_millis(2) * (woken.load(SeqCst) - woke) as u32;
        assert!(awake >= took / 4, "{what}: awake for {awake:?} of {took:?}");
    };

    // A pull: the server hashes the tree before it sends its list. (Nothing is made here.)
    let (began, woke) = (Instant::now(), woken.load(SeqCst));
    let (from, to) = (tree.display().to_string(), tmp.0.join("back"));
    let pulled = client.cp_pull(from.clone(), &to, vec![], false, false, true);
    assert_eq!(pulled.await.unwrap().added, ["big"]);
    went_on("a pull", began, woke);

    // A push of a file as long as the one that is there: the server hashes its own to compare.
    let push = Request::CpPush {
        dst: from,
        excludes: Vec::new(),
        delete: false,
        preserve_mtime: false,
        dry_run: true,
    };
    let (mut send, mut recv) = client.request(&push).await.unwrap();
    let entry = SyncEntry {
        path: "big".into(),
        size,
        mtime_secs: 0,
        mode: 0o644,
        hash: [0; 32],
        is_dir: false,
    };
    let (began, woke) = (Instant::now(), woken.load(SeqCst));
    let list = SyncMsg::Manifest(vec![entry]);
    send_msg(&mut send, &list, MAX_CTRL).await.unwrap();
    let need: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
    assert!(matches!(need, SyncMsg::Need(..)), "{need:?}");
    went_on("a push", began, woke);

    beside.abort();
    client.close().await;
    srv.shutdown().await;
}

/// `dirs` directories, one inside the other, with a file `f` in the innermost: its path beneath `root`.
fn deep(root: &std::path::Path, dirs: usize) -> PathBuf {
    let inner = (0..dirs).fold(root.to_path_buf(), |at, _| at.join("d"));
    fs::create_dir_all(&inner).unwrap();
    fs::write(inner.join("f"), "deep").unwrap();
    inner.join("f")
}

#[tokio::test]
async fn a_tree_is_copied_to_128_directories_deep_on_both_ends_and_no_deeper() {
    let (tmp, srv, client, _, _) = boot_pair("depth").await;
    let dst = tmp.0.join("dst");
    let push = |src: &[PathBuf], delete: bool| {
        let (client, dst, src) = (&client, dst.display().to_string(), src.to_vec());
        async move {
            client
                .cp_push_many(&src, &dst, &[], delete, false, false)
                .await
        }
    };
    // A file 128 directories beneath its tree is copied: that is the bound, on both ends.
    let fits = tmp.0.join("fits");
    let file = deep(&fits, 128);
    let landed = push(std::slice::from_ref(&fits), false).await.unwrap();
    assert_eq!(landed.added.len(), 1);
    let there = dst.join(file.strip_prefix(&fits).unwrap());
    assert_eq!(fs::read_to_string(there).unwrap(), "deep");

    // One more is too deep. The end that reads it says so plainly (exit 1: nothing was refused,
    // its own tree is too deep), before it sends anything.
    let over = tmp.0.join("over");
    deep(&over, 129);
    let err = push(&[over], false).await.unwrap_err();
    assert_eq!(err.code, Exit::FAILED, "{err:?}");
    assert!(
        err.message.contains("more than 128 directories deep"),
        "{err:?}"
    );

    // Sent beside another tree, a tree's own name is one of the 128.
    let (keep, one, two) = (tmp.0.join("keep"), tmp.0.join("one"), tmp.0.join("two"));
    fs::create_dir_all(&keep).unwrap();
    fs::write(keep.join("keep"), "new").unwrap();
    deep(&one, 127);
    deep(&two, 128);
    assert_eq!(
        push(&[keep.clone(), one], false).await.unwrap().added.len(),
        2
    );
    let err = push(&[keep.clone(), two], false).await.unwrap_err();
    assert!(
        err.message.contains("more than 128 directories deep"),
        "{err:?}"
    );

    // With --delete the receiving end reads its own tree too, by the same bound, before it
    // removes anything: a destination that is too deep stops the copy, and nothing has gone.
    let pruned = tmp.0.join("pruned");
    deep(&pruned, 129);
    fs::write(pruned.join("zzz"), "stays").unwrap();
    let err = client
        .cp_push(
            &keep,
            pruned.display().to_string(),
            Vec::new(),
            true,
            false,
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, Exit::FAILED, "{err:?}");
    assert!(
        err.message.contains("more than 128 directories deep"),
        "{err:?}"
    );
    assert_eq!(fs::read_to_string(pruned.join("zzz")).unwrap(), "stays");

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_cap_out_of_range_is_a_usage_error_not_a_panic() {
    let tmp = TempDir::new("cap-range");
    for (max_connections, max_sessions, flag) in [
        (usize::MAX, 64, "--max-connections"),
        (0, 64, "--max-connections"),
        (64, 65_536, "--max-sessions"),
        (64, 0, "--max-sessions"),
    ] {
        let more = ServeOptions {
            key_file: Some(tmp.0.join("srv_cfg/server.key")),
            direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            max_connections,
            max_sessions,
            quiet: true,
            disable_relay: true,
            ..ServeOptions::default()
        };
        let err = start_server(more).await.err().expect("a refusal");
        assert_eq!(err.code, Exit::USAGE, "{err:?}");
        assert!(
            err.message.contains(flag) && err.message.contains("1 to 65535"),
            "{err:?}"
        );
    }
    // (Nothing was started for them: not even the key.)
    assert!(!tmp.0.join("srv_cfg").exists());

    let koh = |flag: &'static str, value: &'static str| {
        let out = Command::new(env!("CARGO_BIN_EXE_koh"))
            .env("KOH_CONFIG_DIR", tmp.0.join("cli"))
            .args(["serve", "--no-relay", flag, value])
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    for (flag, value) in [
        ("--max-connections", "18446744073709551615"),
        ("--max-sessions", "70000"),
        ("--max-connections", "0"),
        ("--max-sessions", "many"),
    ] {
        let (code, said) = koh(flag, value);
        assert_eq!(code, Some(2), "{flag} {value}: {said}");
        assert!(said.contains(flag) && said.contains("1 to 65535"), "{said}");
    }
}

#[tokio::test]
async fn a_handshake_that_never_finishes_gives_its_place_back_at_the_deadline() {
    let tmp = TempDir::new("handshake");
    let friend = new_key(&tmp, "friend.key");
    let more = ServeOptions {
        max_connections: 1,
        proof_timeout: Duration::from_secs(2),
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    let server = srv.direct_addr.unwrap();

    // A peer whose packets reach the server and to whom nothing comes back: a socket that passes
    // on what it is sent and never reads the answers. Its handshake begins and cannot end, and it
    // sends its first packet again and again, which keeps the transport from giving it up.
    let front = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let back = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let front_addr = front.local_addr().unwrap();
    let (passed, mut passed_on) = tokio::sync::watch::channel(0u32);
    let forward = tokio::spawn(async move {
        let mut packet = vec![0u8; 65_536];
        while let Ok((len, _)) = front.recv_from(&mut packet).await {
            let _ = back.send_to(&packet[..len], server).await;
            passed.send_modify(|count| *count += 1);
        }
    });
    let stalled = tokio::spawn(Client::connect_direct(
        friend.clone(),
        srv.endpoint_id,
        Some(Route::Direct(front_addr)),
        false,
    ));
    tokio::time::timeout(
        Duration::from_secs(5),
        passed_on.wait_for(|count| *count > 0),
    )
    .await
    .expect("the stalled peer sent a packet within 5 s")
    .unwrap();

    // It has the server's one place: a client that comes now is told the server is busy.
    let dial = || Client::connect_direct(friend.clone(), srv.endpoint_id, route.clone(), false);
    let early = dial().await.unwrap();
    let busy = early.jobs(None).await.unwrap_err();
    assert_eq!(busy.code, Exit::BUSY, "{busy:?}");
    early.close().await;

    // The deadline is counted from when the server took that up, handshake and all: two seconds on, the
    // place is the next client's, though the stalled peer is still sending.
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let next = dial().await.unwrap();
            let listed = next.jobs(None).await;
            next.close().await;
            if listed.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the place came back within 8 s");
    assert!(!stalled.is_finished(), "the stalled peer gave up by itself");

    stalled.abort();
    forward.abort();
    srv.shutdown().await;
}

#[tokio::test]
async fn a_client_refused_at_the_door_is_told_the_server_is_busy_too() {
    let tmp = TempDir::new("refused-busy");
    let friend = new_key(&tmp, "friend.key");
    let more = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    let dial = || Client::connect_direct(friend.clone(), srv.endpoint_id, route.clone(), false);

    // One client has the place. A second is let connect to be told so, and has not asked yet: it
    // holds the one place there is for that. A third is refused before it has connected at all,
    // and that is the server being busy as much as the second's answer is: exit 75, not 3.
    let first = dial().await.unwrap();
    first.jobs(None).await.unwrap();
    let second = dial().await.unwrap();
    let third = dial().await.err().expect("a refusal");
    assert_eq!(third.code, Exit::BUSY, "{third:?}");
    assert!(third.message.contains("server busy"), "{third:?}");
    let told = second.jobs(None).await.unwrap_err();
    assert_eq!(told.code, Exit::BUSY, "{told:?}");

    second.close().await;
    first.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_server_that_is_dropped_stops_taking_connections_as_it_lets_go_of_its_key() {
    let tmp = TempDir::new("drop-lock");
    let friend = new_key(&tmp, "friend.key");
    let (first, route) = boot_server(&tmp, vec![friend.public()], ServeOptions::default()).await;
    let id = first.endpoint_id;
    let dial = |route: Option<Route>| Client::connect_direct(friend.clone(), id, route, false);
    let client = dial(route.clone()).await.unwrap();
    client.jobs(None).await.unwrap();
    client.close().await;

    // Dropped, not shut down: the key is free for another server only once this one takes no
    // more connections. So when a second server on the key has started, the first one's address
    // serves nobody.
    drop(first);
    let second = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match boot_server_on(&tmp, vec![friend.public()]).await {
                Ok(server) => break server,
                Err(busy) => assert_eq!(busy.code, Exit::BUSY, "{busy:?}"),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the key was free within 5 s");
    let old = tokio::time::timeout(Duration::from_secs(1), async {
        let client = dial(route).await?;
        client.jobs(None).await
    })
    .await;
    assert!(
        !matches!(old, Ok(Ok(_))),
        "the dropped server served a client"
    );

    second.shutdown().await;
}

/// A server on the key `boot_server` uses, or why it could not start.
async fn boot_server_on(
    tmp: &TempDir,
    allow: Vec<iroh::EndpointId>,
) -> koh::Result<koh::server::RunningServer> {
    start_server(ServeOptions {
        key_file: Some(tmp.0.join("srv_cfg/server.key")),
        direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        allow,
        state_dir: Some(tmp.0.join("state2")),
        disable_relay: true,
        quiet: true,
        ..ServeOptions::default()
    })
    .await
}

#[tokio::test]
async fn a_file_that_cannot_be_read_is_replaced_when_its_size_says_it_differs() {
    use std::os::unix::fs::PermissionsExt as _;
    let (tmp, srv, client, _, _) = boot_pair("unreadable").await;
    let (src, dst) = (tmp.0.join("src"), tmp.0.join("dst"));
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    fs::write(src.join("f"), "the new contents").unwrap();
    fs::write(dst.join("f"), "old").unwrap();
    fs::set_permissions(dst.join("f"), fs::Permissions::from_mode(0o000)).unwrap();

    // The file there is of another size, so it differs, and nobody needs to read it to know:
    // it is replaced, as a file in a directory one may write to can be.
    let done = client
        .cp_push(
            &src,
            dst.display().to_string(),
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(done.updated, vec!["f".to_string()]);
    assert_eq!(
        fs::read_to_string(dst.join("f")).unwrap(),
        "the new contents"
    );

    client.close().await;
    srv.shutdown().await;
}

/// The names in `dir`, in order.
fn names_in(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn a_hostile_sender_lands_nothing_and_leaves_no_temporary_file() {
    use koh::proto::{SyncEntry, SyncMsg};
    let (tmp, srv, client, _, _) = boot_pair("hostile-sender").await;
    let dst = tmp.0.join("dst");
    fs::create_dir_all(&dst).unwrap();
    fs::write(dst.join("there"), "before").unwrap();
    let entry = |path: &str, size: u64| SyncEntry {
        path: path.to_string(),
        size,
        mtime_secs: 0,
        mode: 0o644,
        hash: [0; 32],
        is_dir: false,
    };
    let push = |delete| Request::CpPush {
        dst: dst.display().to_string(),
        excludes: Vec::new(),
        delete,
        preserve_mtime: false,
        dry_run: false,
    };
    let refused = |answer: &SyncMsg| matches!(answer, SyncMsg::Failed(why) if why.code == 4);

    // A path that is not plain names beneath the tree, in the manifest or at a file's start,
    // with --delete or without: refused, and the destination is as it was (--delete has removed
    // nothing: every path is looked at before anything goes).
    for path in ["../x", "/x", "a//b", "a/./b", "a/../x", "", "a/"] {
        for delete in [false, true] {
            let (mut send, mut recv) = client.request(&push(delete)).await.unwrap();
            let manifest = SyncMsg::Manifest(vec![entry("ok", 1), entry(path, 1)]);
            send_msg(&mut send, &manifest, MAX_CTRL).await.unwrap();
            let answer: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
            assert!(refused(&answer), "manifest {path:?} {delete}: {answer:?}");

            let (mut send, mut recv) = client.request(&push(delete)).await.unwrap();
            let manifest = SyncMsg::Manifest(vec![entry("there", 9)]);
            send_msg(&mut send, &manifest, MAX_CTRL).await.unwrap();
            let need: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
            assert!(matches!(&need, SyncMsg::Need(asked) if asked == &["there".to_string()]));
            let start = SyncMsg::FileStart {
                path: path.to_string(),
                size: 1,
                mtime_secs: 0,
                mode: 0o644,
            };
            send_msg(&mut send, &start, MAX_CTRL).await.unwrap();
            let answer: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
            assert!(refused(&answer), "start {path:?} {delete}: {answer:?}");
            assert_eq!(names_in(&dst), ["there"], "{path:?} {delete}");
            assert_eq!(names_in(&tmp.0).iter().filter(|n| *n == "x").count(), 0);
        }
    }
    assert_eq!(fs::read_to_string(dst.join("there")).unwrap(), "before");

    // A file that is longer or shorter than its sender said: the copy fails, the file that was
    // there is as it was, and nothing is left beside it.
    for sent in [&b"too long"[..], b"sh"] {
        let (mut send, mut recv) = client.request(&push(false)).await.unwrap();
        let manifest = SyncMsg::Manifest(vec![entry("there", 4)]);
        send_msg(&mut send, &manifest, MAX_CTRL).await.unwrap();
        let _need: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
        let start = SyncMsg::FileStart {
            path: "there".to_string(),
            size: 4,
            mtime_secs: 0,
            mode: 0o644,
        };
        send_msg(&mut send, &start, MAX_CTRL).await.unwrap();
        let _ = send_msg(&mut send, &SyncMsg::FileChunk(sent.to_vec()), MAX_CHUNK).await;
        let _ = send_msg(&mut send, &SyncMsg::FileEnd, MAX_CTRL).await;
        let answer: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
        assert!(
            matches!(&answer, SyncMsg::Failed(why) if why.code == 1 && why.message.contains("size mismatch")),
            "{answer:?}"
        );
        assert_eq!(names_in(&dst), ["there"]);
        assert_eq!(fs::read_to_string(dst.join("there")).unwrap(), "before");
    }

    // A copy cut off in the middle of a file: while it runs, the bytes are in a file of another
    // name beside where they land; once the sender is gone, that file is too.
    let (mut send, mut recv) = client.request(&push(false)).await.unwrap();
    let manifest = SyncMsg::Manifest(vec![entry("there", 1 << 20)]);
    send_msg(&mut send, &manifest, MAX_CTRL).await.unwrap();
    let _need: SyncMsg = recv_msg(&mut recv, MAX_CTRL * 4).await.unwrap();
    let start = SyncMsg::FileStart {
        path: "there".to_string(),
        size: 1 << 20,
        mtime_secs: 0,
        mode: 0o644,
    };
    send_msg(&mut send, &start, MAX_CTRL).await.unwrap();
    let part = SyncMsg::FileChunk(vec![7; 4096]);
    send_msg(&mut send, &part, MAX_CHUNK).await.unwrap();
    let partial = |dst: &std::path::Path| names_in(dst).iter().any(|n| n.starts_with(".koh-"));
    let until = |want: bool, dst: PathBuf| async move {
        tokio::time::timeout(Duration::from_secs(5), async {
            while partial(&dst) != want {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
    };
    until(true, dst.clone())
        .await
        .expect("its bytes were being written within 5 s");
    drop((send, recv));
    client.close().await;
    until(false, dst.clone())
        .await
        .expect("the temporary file was gone within 5 s");
    assert_eq!(names_in(&dst), ["there"]);
    assert_eq!(fs::read_to_string(dst.join("there")).unwrap(), "before");

    srv.shutdown().await;
}

#[tokio::test]
async fn a_file_that_has_a_staging_name_is_not_written_over() {
    let (tmp, srv, client, _, _) = boot_pair("staging-name").await;
    let (src, dst) = (tmp.0.join("src"), tmp.0.join("dst"));
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    // A file is written as `.koh-PID-N.tmp` beside where it lands, N counted up by the process
    // that writes it (here this one). Three of every four such names are files of someone
    // else's: wherever the count stands, eight files in a row meet some of them, and a free
    // name is never more than four tries away.
    let pid = std::process::id();
    let theirs: Vec<PathBuf> = (0..4096u32)
        .filter(|n| n % 4 != 3)
        .map(|n| dst.join(format!(".koh-{pid:x}-{n:x}.tmp")))
        .collect();
    for path in &theirs {
        fs::write(path, "theirs").unwrap();
    }
    for n in 0..8 {
        fs::write(src.join(format!("f{n}")), "sent").unwrap();
    }
    let done = client
        .cp_push(
            &src,
            dst.display().to_string(),
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(done.added.len(), 8);
    assert_eq!(fs::read_to_string(dst.join("f7")).unwrap(), "sent");
    let kept = |path: &PathBuf| fs::read_to_string(path).is_ok_and(|text| text == "theirs");
    assert_eq!(theirs.iter().filter(|path| !kept(path)).count(), 0);

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn an_exec_scoped_key_runs_and_copies_beneath_its_directory_and_nothing_else() {
    use std::os::unix::fs::symlink;
    let tmp = TempDir::new("exec-scope");
    let (allowed, outside) = (tmp.0.join("allowed"), tmp.0.join("outside"));
    fs::create_dir_all(allowed.join("sub")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, allowed.join("out")).unwrap();
    let key = new_key(&tmp, "exec.key");
    fs::create_dir_all(tmp.0.join("srv_cfg")).unwrap();
    save_clients(
        Some(&tmp.0.join("srv_cfg/server.key")),
        &[ClientEntry {
            name: "runner".into(),
            id: key.public(),
            scope: Scope::Exec(allowed.clone()),
        }],
    )
    .unwrap();
    let (srv, route) = boot_server(&tmp, Vec::new(), ServeOptions::default()).await;
    let client = Client::connect_direct(key, srv.endpoint_id, route, false)
        .await
        .unwrap();
    let at = |dir: &std::path::Path| Some(dir.display().to_string());
    let pwd = |dir: PathBuf| {
        let client = &client;
        async move {
            client
                .exec(vec!["pwd".into()], at(&dir), false, None, true)
                .await
        }
    };

    // A command starts in its directory, or in one beneath it, and is any command: this is no
    // sandbox, and the command reaches what the server's user can.
    let (code, out, _) = pwd(allowed.join("sub")).await.unwrap();
    assert_eq!(code, 0);
    assert!(
        String::from_utf8_lossy(&out)
            .trim_end()
            .ends_with("/allowed/sub")
    );
    let reach = format!("cat {}", outside.join("secret").display());
    fs::write(outside.join("secret"), "reached").unwrap();
    let (_, out, _) = client
        .exec(vec![reach], at(&allowed), true, None, true)
        .await
        .unwrap();
    assert_eq!(out, b"reached");

    // It does not start elsewhere, and elsewhere is told by the text of the path: a directory
    // that is beneath its own by name and somewhere else in fact (a symlink out of it) is
    // beneath its own.
    for dir in [outside.clone(), tmp.0.clone(), allowed.join("sub/../..")] {
        let err = pwd(dir.clone()).await.unwrap_err();
        assert_eq!(err.code, Exit::REFUSED, "{}: {err:?}", dir.display());
    }
    let (code, out, _) = pwd(allowed.join("out")).await.unwrap();
    assert_eq!(code, 0);
    assert!(
        String::from_utf8_lossy(&out)
            .trim_end()
            .ends_with("/outside")
    );
    let job = client
        .run_job(Some("j".into()), vec!["true".into()], at(&allowed), false)
        .await
        .unwrap();
    assert_eq!(job.name, "j");
    let nowhere = client
        .run_job(None, vec!["true".into()], at(&outside), false)
        .await;
    assert_eq!(nowhere.unwrap_err().code, Exit::REFUSED);

    // It copies beneath its directory as a `--cp` key does.
    let file = tmp.0.join("payload");
    fs::write(&file, "copied").unwrap();
    let push = |dst: PathBuf| {
        let (client, file) = (&client, file.clone());
        async move {
            let dst = dst.display().to_string();
            client
                .cp_push(&file, dst, Vec::new(), false, false, false)
                .await
        }
    };
    push(allowed.join("sub")).await.unwrap();
    assert_eq!(
        fs::read_to_string(allowed.join("sub/payload")).unwrap(),
        "copied"
    );
    let err = push(outside.clone()).await.unwrap_err();
    assert_eq!(err.code, Exit::REFUSED, "{err:?}");
    assert!(!outside.join("payload").exists());

    // And it asks for nothing else: no look at jobs, its own among them. (Nor a session:
    // `the_three_commands_are_a_full_keys`.)
    assert_eq!(client.jobs(None).await.unwrap_err().code, Exit::REFUSED);
    let waited = client.wait_job("j".into(), None, 10, Some(1)).await;
    assert_eq!(waited.unwrap_err().code, Exit::REFUSED);

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_proof_deadline_too_far_off_for_the_clock_is_no_deadline_and_no_panic() {
    // (`ServeOptions` is public: `Duration::MAX` added to the clock's time panicked in the task
    // that takes connections, at the first peer to come, and no other was taken after it.)
    let tmp = TempDir::new("proof-never");
    let friend = new_key(&tmp, "friend.key");
    let more = ServeOptions {
        proof_timeout: Duration::MAX,
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    for nth in 0..2 {
        let dial = Client::connect_direct(friend.clone(), srv.endpoint_id, route.clone(), false);
        let client = tokio::time::timeout(Duration::from_secs(5), dial)
            .await
            .unwrap_or_else(|_| panic!("connection {nth} was not taken within 5 s"))
            .unwrap();
        client.jobs(None).await.unwrap();
        client.close().await;
    }
    srv.shutdown().await;
}

#[tokio::test]
async fn a_scoped_copy_reaches_a_tree_however_far_beneath_its_directory() {
    // The 128 directories are a bound on a path within a tree, as it goes over the wire. The way
    // from a `--cp DIR` key's directory to the tree is not such a path: it may be any length.
    let (tmp, srv, client, allowed, _) = boot_scoped("deep-root").await;
    let root = deep(&allowed, 130).parent().unwrap().to_path_buf();
    let src = tmp.0.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("f"), "pushed").unwrap();
    client
        .cp_push(
            &src,
            root.display().to_string(),
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(fs::read_to_string(root.join("f")).unwrap(), "pushed");
    let back = tmp.0.join("back");
    client
        .cp_pull(
            root.display().to_string(),
            &back,
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap();
    assert_eq!(fs::read_to_string(back.join("f")).unwrap(), "pushed");

    // Each name on that way is still one plain name: none of them may lead back out.
    let out = format!("{}/d/../../outside", allowed.display());
    let err = client
        .cp_push(&src, out, Vec::new(), false, false, false)
        .await
        .unwrap_err();
    assert_eq!(err.code, Exit::REFUSED, "{err:?}");

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_destination_that_cannot_be_read_through_is_pruned_of_nothing() {
    // 144 directories, one in the next, each of a 40-character name: the path of the innermost
    // is longer than a path may be (and a tree that deep is too deep to copy). `--delete` must
    // find that out, or fail in the trying, before it removes anything: an entry it cannot look
    // at is not an entry that is not there.
    let (tmp, srv, client, _, _) = boot_pair("delete-unreadable").await;
    let (src, dst) = (tmp.0.join("src"), tmp.0.join("dst"));
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&dst).unwrap();
    fs::write(dst.join("stays"), "stays").unwrap();
    // (No path can name them all, so they are made as nine chains of 16, which a path can
    // name, and each chain is then moved to the bottom of the one before it.)
    let name = "d".repeat(40);
    let chain = |nth: usize| dst.join(format!("chain{nth}"));
    let bottom = |nth: usize| (0..16).fold(chain(nth), |at, _| at.join(&name));
    for nth in 0..9 {
        fs::create_dir_all(bottom(nth)).unwrap();
    }
    for nth in (1..9).rev() {
        fs::rename(chain(nth).join(&name), bottom(nth - 1).join(&name)).unwrap();
        fs::remove_dir(chain(nth)).unwrap();
    }

    let pushed = client
        .cp_push(
            &src,
            dst.display().to_string(),
            Vec::new(),
            true,
            false,
            false,
        )
        .await;
    assert_eq!(pushed.map(|_| ()).unwrap_err().code, Exit::FAILED);
    assert_eq!(fs::read_to_string(dst.join("stays")).unwrap(), "stays");

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn a_destination_that_cannot_be_one_is_not_reported_as_copied_to() {
    let (tmp, srv, client, allowed, _) = boot_scoped("bad-destination").await;
    let src = tmp.0.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("f"), "sent").unwrap();
    fs::write(allowed.join("file"), "a file").unwrap();
    let push = |dst: String, dry_run: bool| {
        let (client, src) = (&client, src.clone());
        async move {
            client
                .cp_push(&src, dst, Vec::new(), false, false, dry_run)
                .await
        }
    };
    std::os::unix::fs::symlink(allowed.join("nowhere"), allowed.join("dangling")).unwrap();
    for dry_run in [true, false] {
        // A file is no directory to copy into, and a dry run says so as the copy would. Nor is
        // a symlink that leads nowhere: something is there, and it is not a directory.
        for name in ["file", "dangling"] {
            let err = push(allowed.join(name).display().to_string(), dry_run).await;
            assert_eq!(
                err.unwrap_err().code,
                Exit::FAILED,
                "{name}, dry: {dry_run}"
            );
        }
        // A name with a NUL in it names nothing: by its text it is not a path beneath DIR.
        let err = push(format!("{}/bad\0name", allowed.display()), dry_run).await;
        assert_eq!(err.unwrap_err().code, Exit::REFUSED, "dry run: {dry_run}");
    }
    assert_eq!(fs::read_to_string(allowed.join("file")).unwrap(), "a file");
    assert_eq!(names_in(&allowed), ["dangling", "file"]);

    client.close().await;
    srv.shutdown().await;
}

/// `koh serve` as a process of its own, and processes it started: all ended when this is dropped.
struct Served {
    server: std::process::Child,
    started: Vec<u32>,
    // (Kept open: the server goes on writing to it.)
    said: std::io::BufReader<std::process::ChildStderr>,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
        for pid in &self.started {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    }
}

impl Served {
    /// A server that allows `client`, with `path` for its PATH, a runtime directory or none,
    /// and a temporary directory of its own.
    fn start(
        tmp: &TempDir,
        path: &std::path::Path,
        client: iroh::EndpointId,
        runtime: bool,
    ) -> Self {
        let mut serve = Command::new(env!("CARGO_BIN_EXE_koh"));
        serve
            .args(["serve", "--direct", "127.0.0.1:0", "--no-relay", "--allow"])
            .arg(client.to_string())
            .env("PATH", path)
            .env("KOH_CONFIG_DIR", tmp.0.join("served_cfg"))
            .env("TMPDIR", &tmp.0)
            .env_remove("XDG_RUNTIME_DIR")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        if runtime {
            serve.env("XDG_RUNTIME_DIR", tmp.0.join("run"));
        }
        let mut server = serve.spawn().unwrap();
        let said = std::io::BufReader::new(server.stderr.take().unwrap());
        Self {
            server,
            started: Vec::new(),
            said,
        }
    }

    /// What follows `label` on a line the server says as it starts; `Err` with all it said if
    /// it ended without saying it.
    fn says(&mut self, label: &str) -> Result<String, String> {
        use std::io::BufRead as _;
        let mut all = String::new();
        loop {
            let mut line = String::new();
            if self.said.read_line(&mut line).unwrap() == 0 {
                return Err(all);
            }
            if let Some(rest) = line.strip_prefix(label) {
                return Ok(rest.trim().to_string());
            }
            all.push_str(&line);
        }
    }
}

#[tokio::test]
async fn koh_serve_needs_kill_keeps_its_state_under_its_user_and_says_when_a_job_was_not_signalled()
{
    let tmp = TempDir::new("kill-helper");
    let key = new_key(&tmp, "client.key");
    let bin = tmp.0.join("bin");
    fs::create_dir_all(&bin).unwrap();

    // With no kill(1) to run, a server could end no job and hang up no command: it says so as
    // it starts, and does not start.
    let mut none = Served::start(&tmp, &bin, key.public(), true);
    let said = none.says("listening:").unwrap_err();
    assert!(said.contains("kill"), "{said}");
    assert_eq!(none.server.wait().unwrap().code(), Some(1));

    // With no runtime directory, its state is in the temporary directory under the number of
    // the user who runs it (here, the owner of what this test made).
    let all = std::env::var_os("PATH").unwrap();
    let mut plain = Served::start(&tmp, std::path::Path::new(&all), key.public(), false);
    let (mine, state) = (
        fs::metadata(&tmp.0).unwrap().uid(),
        fs::canonicalize(&tmp.0).unwrap(),
    );
    assert_eq!(
        plain.says("sessions dir:").unwrap(),
        format!("{}/koh-{mine}/fux/koh-sessions", state.display())
    );
    drop(plain);

    // A kill(1) that takes two seconds and then fails. (Asked whether a process or a group
    // is there, `kill -0`, it is the real one.)
    let fake = |then: &str| {
        format!("#!/bin/sh\n[ \"$1\" = -0 ] && exec /bin/kill \"$@\"\n{then}exit 42\n")
    };
    script(&bin.join("kill"), &fake("/bin/sleep 2\n"));
    let mut served = Served::start(&tmp, &bin, key.public(), true);
    let id: iroh::EndpointId = served.says("koh server id:").unwrap().parse().unwrap();
    let addr: SocketAddr = served.says("listening:").unwrap().parse().unwrap();
    let client = Client::connect_direct(key, id, Some(Route::Direct(addr)), false)
        .await
        .unwrap();
    let sleep = vec!["/bin/sleep".to_string(), "300".into()];
    let job = client
        .run_job(Some("j".into()), sleep, None, false)
        .await
        .unwrap();
    served.started.push(job.pid);

    // While it runs, the server answers others: nothing waits for kill(1) but who asked for it.
    let others = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let asked = std::time::Instant::now();
        let jobs = client.jobs(None).await.unwrap();
        (jobs, asked.elapsed())
    };
    let (killed, (jobs, waited)) = tokio::join!(client.kill_job("j".into(), 15), others);
    assert!(waited < Duration::from_secs(1), "{waited:?}");
    assert_eq!(jobs[0].state, "running");
    // And a job that was not signalled is not reported as signalled.
    let err = killed.unwrap_err();
    assert_eq!(err.code, Exit::FAILED, "{err:?}");
    assert!(err.message.contains("kill"), "{err:?}");

    // A job whose first process has ended and left another behind in its group: the job says
    // it has ended, and the group is what `koh kill` is for. Not signalled, it is not reported
    // as signalled; once it has gone, there is nothing to signal and nothing to report.
    script(&bin.join("kill"), &fake(""));
    let left = tmp.0.join("left.pid");
    let line = format!("/bin/sleep 300 & echo $! > {}", left.display());
    client
        .run_job(Some("o".into()), vec![line], None, true)
        .await
        .unwrap();
    let ended = client.wait_job("o".into(), None, 10, Some(10)).await;
    assert!(!ended.unwrap().timed_out);
    let pid = fs::read_to_string(&left).unwrap().trim().to_string();
    served.started.push(pid.parse().unwrap());
    let there = |pid: &str| {
        let mut asked = Command::new("kill");
        asked.args(["-0", pid]).stderr(std::process::Stdio::null());
        asked.status().unwrap().success()
    };
    assert!(there(&pid));
    let err = client.kill_job("o".into(), 15).await.unwrap_err();
    assert_eq!(err.code, Exit::FAILED, "{err:?}");
    assert!(there(&pid));
    assert!(Command::new("kill").arg(&pid).status().unwrap().success());
    for _ in 0..500 {
        if !there(&pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(client.kill_job("o".into(), 15).await.unwrap().name, "o");

    client.close().await;
}

#[test]
fn a_key_that_is_a_symlink_is_read_as_the_file_it_leads_to() {
    // (koh has no anti-symlink mechanics. The one this replaced was a number written by hand
    // for each system, and the wrong one on arm64 Linux, where it refused nothing.)
    let tmp = TempDir::new("key-link");
    let (real, link) = (tmp.0.join("real.key"), tmp.0.join("link.key"));
    let made = load_or_create_key(Role::Client, Some(&real)).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let read = load_or_create_key(Role::Client, Some(&link)).unwrap();
    assert_eq!(read.public(), made.public());
}

#[tokio::test]
async fn koh_serve_does_not_take_its_user_from_an_id_that_failed() {
    // With no runtime directory the server asks id(1) whose state it keeps. An id(1) that says
    // a number and then that it failed has told nothing: the server says so and does not start.
    let tmp = TempDir::new("id-failed");
    let key = new_key(&tmp, "client.key");
    let bin = tmp.0.join("bin");
    fs::create_dir_all(&bin).unwrap();
    script(&bin.join("id"), "#!/bin/sh\necho 42424\nexit 42\n");
    let mut path = bin.into_os_string();
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap());
    let mut served = Served::start(&tmp, std::path::Path::new(&path), key.public(), false);
    let said = served.says("sessions dir:").unwrap_err();
    assert!(said.contains("id -u"), "{said}");
    assert_eq!(served.server.wait().unwrap().code(), Some(1));
    assert!(!tmp.0.join("koh-42424").exists());
}

/// `koh` run with `args` and a runtime directory: how it ended, and what it said on its
/// standard output and its standard error.
fn koh(runtime: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
    koh.env("XDG_RUNTIME_DIR", runtime).args(args);
    let said = koh.stdin(std::process::Stdio::null()).output().unwrap();
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).trim_end().to_string();
    (said.status.code(), text(&said.stdout), text(&said.stderr))
}

/// Writes a script that is then run. A shell of its own writes it: written by the test itself,
/// the file is open for writing in whatever another test starts at that moment, until that
/// runs its own program, and a script that is open for writing is not run ("Text file busy").
fn script(path: &Path, text: &str) {
    let writes = "printf %s \"$1\" > \"$0\" && chmod 755 \"$0\"";
    let mut shell = Command::new("sh");
    let written = shell.args(["-c", writes]).arg(path).arg(text).status();
    assert!(written.unwrap().success(), "{}", path.display());
}

/// What `ps` says of a process under one of its headings.
fn ps(pid: &str, what: &str) -> String {
    let said = Command::new("ps").args(["-o", what, "-p", pid]).output();
    String::from_utf8_lossy(&said.unwrap().stdout)
        .trim()
        .to_string()
}

/// The holder a pane's `status` names.
fn holder_of(pane: &Path) -> String {
    let status = fs::read_to_string(pane.join("status")).unwrap();
    status
        .lines()
        .next()
        .unwrap()
        .strip_prefix("holder ")
        .unwrap()
        .to_string()
}

#[test]
fn koh_fux_is_fux_and_a_holder_has_no_runtime() {
    let tmp = TempDir::new("koh-fux");
    let run = fs::canonicalize(&tmp.0).unwrap().join("run");
    // `koh fux …` is fux's command line: its default session, by fux's rule.
    let (code, dir, _) = koh(&run, &["fux", "dir"]);
    assert_eq!(
        (code, dir.as_str()),
        (Some(0), run.join("fux").to_str().unwrap())
    );
    // A pane it starts is held by this same file, under the word `hold`: no `fux` is looked for.
    let named = run.join("ws/p");
    let (code, pane, said) = koh(
        &run,
        &["fux", "start", named.to_str().unwrap(), "--", "sleep", "30"],
    );
    assert_eq!(
        (code, pane.as_str()),
        (Some(0), named.to_str().unwrap()),
        "{said}"
    );
    let holder = holder_of(&named);
    let args = ps(&holder, "args=");
    let words: Vec<&str> = args.split_whitespace().collect();
    assert_eq!(words[..2], [env!("CARGO_BIN_EXE_koh"), "hold"], "{args}");
    assert_eq!(words[words.len() - 2..], ["sleep", "30"], "{args}");
    // The holder is fux's code and nothing of koh's: the thread it began with and the one fux
    // waits for the program on. A runtime would be a thread for each core.
    if cfg!(target_os = "linux") {
        let threads = fs::read_dir(format!("/proc/{holder}/task"))
            .unwrap()
            .count();
        assert_eq!(threads, 2);
    }
    // `koh fux wait` waits for the holder's end and says what became of the program.
    fs::write(named.join("ctl"), "kill\n").unwrap();
    let (code, state, said) = koh(&run, &["fux", "wait", &pane]);
    assert_eq!(code, Some(0), "{said}");
    assert!(state.ends_with("state killed 1"), "{state}");
    // A word fux does not know is fux's to refuse.
    let (code, _, said) = koh(&run, &["fux", "nothing"]);
    assert_eq!(code, Some(1));
    assert!(said.starts_with("fux: usage:"), "{said}");
}

#[tokio::test]
async fn a_message_with_more_after_it_is_no_message() {
    let (_tmp, srv, client, key, _) = boot_pair("more-after").await;
    // A request as it is sent, and one byte more inside its frame.
    let conn = client.connection();
    let (mut send, mut recv) = koh::net::open_authed_stream(&conn, &key).await.unwrap();
    let mut body = postcard::to_allocvec(&Request::Jobs { name: None }).unwrap();
    body.push(0);
    send.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .unwrap();
    send.write_all(&body).await.unwrap();
    // The server reads no request in it, and answers none: it closes the connection.
    let answer = recv_msg::<koh::proto::Reply>(&mut recv, MAX_CTRL).await;
    assert!(answer.is_err(), "{answer:?}");
    client.close().await;
    srv.shutdown().await;
}

// ---- sessions: a real `koh serve`, real `koh connect` ---------------------------

/// Waits, twenty seconds at most, until `done` says so.
fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < deadline, "not in 20 s: {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn signal(pid: &str, signal: &str) {
    let _ = Command::new("kill").args([signal, pid]).status();
}

fn screen(dir: &Path) -> String {
    fs::read_to_string(dir.join("shown/screen")).unwrap_or_default()
}

/// A real `koh serve`, its sessions in the test's folder, and two keys it allows: a client's
/// (`cli_cfg`) and the relay's (`tap_cfg`). The holders it started are ended with it.
struct Host {
    tmp: TempDir,
    served: Option<Served>,
    port: u16,
    extra: Vec<String>,
    id: String,
    sessions: PathBuf,
}

impl Drop for Host {
    fn drop(&mut self) {
        // The holders of the sessions that live are ended: each keeps its folder locked. (A
        // pane a test wrote by hand names a holder that is none, or is some other process.)
        for pane in fs::read_dir(&self.sessions).into_iter().flatten().flatten() {
            let folder = fuxix::open(pane.path(), false).map(|folder| folder.try_lock_shared());
            if matches!(folder, Ok(Err(fs::TryLockError::WouldBlock))) {
                signal(&holder_of(&pane.path()), "-KILL");
            }
        }
    }
}

impl Host {
    fn start(tag: &str, extra: &[&str]) -> Self {
        let tmp = TempDir::new(tag);
        for dir in ["cli_cfg", "tap_cfg", "home", "crun"] {
            fs::create_dir_all(tmp.0.join(dir)).unwrap();
        }
        let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut host = Self {
            tmp,
            served: None,
            port: free.local_addr().unwrap().port(),
            extra: extra.iter().map(|arg| arg.to_string()).collect(),
            id: String::new(),
            sessions: PathBuf::new(),
        };
        drop(free);
        host.serve();
        host
    }

    fn key(&self, who: &str) -> iroh::SecretKey {
        load_or_create_key(Role::Client, Some(&self.tmp.0.join(who).join("client.key"))).unwrap()
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Starts the server: the first time, and anew after `stop`, on the same port and state.
    fn serve(&mut self) {
        let mut serve = Command::new(env!("CARGO_BIN_EXE_koh"));
        serve.args([
            "serve",
            "--no-relay",
            "--shell",
            "/bin/sh",
            "--direct",
            &self.addr(),
        ]);
        for who in ["cli_cfg", "tap_cfg"] {
            serve.args(["--allow", &self.key(who).public().to_string()]);
        }
        serve
            .args(&self.extra)
            .env("KOH_CONFIG_DIR", self.tmp.0.join("srv_cfg"))
            .env("XDG_RUNTIME_DIR", self.tmp.0.join("run"))
            .env("HOME", self.tmp.0.join("home"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let mut server = serve.spawn().unwrap();
        let said = std::io::BufReader::new(server.stderr.take().unwrap());
        let mut served = Served {
            server,
            started: Vec::new(),
            said,
        };
        self.id = served.says("koh server id:").unwrap();
        self.sessions = PathBuf::from(served.says("sessions dir:").unwrap());
        self.served = Some(served);
    }

    /// Stops the server as Ctrl-C does, and waits until it is gone.
    fn stop(&mut self) {
        self.stop_by("-INT");
    }

    fn stop_by(&mut self, how: &str) {
        let mut served = self.served.take().unwrap();
        signal(&served.server.id().to_string(), how);
        served.server.wait().unwrap();
    }

    fn pane(&self, name: &str) -> PathBuf {
        self.sessions.join(name)
    }

    fn attach(&self, asks: &[&str], program: &[String]) -> InTerminal {
        let addr = self.addr();
        let mut args = vec![self.id.as_str(), "--direct", &addr];
        args.extend_from_slice(asks);
        if !program.is_empty() {
            args.push("--");
            args.extend(program.iter().map(String::as_str));
        }
        InTerminal::connect(&self.tmp.0.join("cli_cfg"), &self.tmp.0.join("crun"), &args)
    }

    /// A `koh` of the client's, with its key and a runtime directory of its own.
    fn koh(&self, args: &[&str]) -> Command {
        let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
        koh.args(args)
            .env("KOH_CONFIG_DIR", self.tmp.0.join("cli_cfg"))
            .env("XDG_RUNTIME_DIR", self.tmp.0.join("crun"))
            .env("HOME", self.tmp.0.join("home"))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null());
        koh
    }

    /// The client, in this process: for a test that speaks a session's messages itself.
    async fn client(&self) -> Client {
        let server = koh::keys::parse_endpoint_id(&self.id).unwrap();
        let route = Some(Route::Direct(self.addr().parse().unwrap()));
        Client::connect_direct(self.key("cli_cfg"), server, route, true)
            .await
            .unwrap()
    }
}

#[test]
fn koh_connect_in_a_terminal_has_its_keys_and_ends_when_the_program_does() {
    let host = Host::start("connect-tty", &[]);
    let (config, runtime) = (host.tmp.0.join("cli_cfg"), host.tmp.0.join("crun"));
    let (id, addr, pane) = (host.id.clone(), host.addr(), host.pane("1"));
    let program = "stty -icanon -echo; echo READY; od -An -tx1 -N2; head -c 1 >/dev/null; exit 7";
    let shown = |tty: &mut InTerminal| tty.drawn.windows(5).any(|drawn| drawn == b"READY");

    // The detach key, Ctrl-] and a dot: koh leaves with 0, and the session runs on.
    let started = ["--direct", &addr, &id, "--", "/bin/sh", "-c", program];
    let mut first = InTerminal::connect(&config, &runtime, &started);
    first.until("the terminal shows READY", shown);
    first.types(b"\x1d.");
    assert_eq!(first.ends(), Some(0));
    assert_eq!(fs::read_to_string(pane.join("state")).unwrap(), "running\n");

    // koh's key typed twice is the key's own byte, typed to the program; and C-b is no key of
    // koh's: it is the session's as it is typed.
    let again = ["--direct", &addr, &id, "--session", "1"];
    let mut second = InTerminal::connect(&config, &runtime, &again);
    second.until("the terminal shows READY", shown);
    second.types(b"\x1d\x1d\x02");
    let typed = |_: &mut InTerminal| {
        screen(&pane).split_whitespace().collect::<Vec<_>>() == ["READY", "1d", "02"]
    };
    second.until("the program reads the two bytes", typed);

    // The terminal's size is the session's, also when it changes.
    let size = fuxix::Winsize {
        rows: 30,
        cols: 100,
        xpixel: 1000,
        ypixel: 600,
    };
    fuxix::set_winsize(&second.tty, size).unwrap();
    let resized = |_: &mut InTerminal| fs::read_to_string(pane.join("size")).unwrap() == "100 30\n";
    second.until("the session takes the terminal's size", resized);

    // The program's end is the end of `koh connect`, with the program's status: nobody has to
    // type the detach key at a session that is over.
    second.types(b"x");
    assert_eq!(second.ends(), Some(7));

    // No local session files were created.
    assert_eq!(names_in(&runtime), [""; 0]);
}

#[test]
fn viewer_reconnects_after_serve_restarts() {
    let mut host = Host::start("view-restart", &[]);
    let mut tty = host.attach(&["--session", "s"], &[]);
    let pane = host.pane("s");
    tty.types(b"echo shell-$((20+22))\n");
    tty.until("shell echo", |tty| {
        tty.drawn.windows(8).any(|s| s == b"shell-42")
    });
    let holder = holder_of(&pane);
    host.stop();
    tty.until("link down", |tty| {
        tty.drawn.windows(7).any(|s| s == b"no link")
    });
    tty.types(b"echo back-$((6*7))\n");
    host.serve();
    tty.until("held input after reconnect", |tty| {
        tty.drawn.windows(7).any(|s| s == b"back-42")
    });
    assert_eq!(holder_of(&pane), holder);
    // Told to end as a service is (`systemctl restart`), the server closes as it does on
    // Ctrl-C: its clients hear of it at once, and not after the eight seconds of silence.
    let drawn = tty.drawn.len();
    host.stop_by("-TERM");
    let told = Instant::now();
    tty.until("link down again", |tty| {
        tty.drawn[drawn..].windows(7).any(|s| s == b"no link")
    });
    assert!(
        told.elapsed() < Duration::from_secs(4),
        "{:?}",
        told.elapsed()
    );
    host.serve();
    tty.types(b"exit 7\n");
    assert_eq!(tty.ends(), Some(7));
}

#[test]
fn one_session_draws_to_two_terminals_and_survives_hangup() {
    let host = Host::start("view-two", &[]);
    let mut a = host.attach(&["--session", "s"], &[]);
    let has = |tty: &mut InTerminal, what: &[u8]| tty.drawn.windows(what.len()).any(|s| s == what);
    a.types(b"printf '\\033[?1049h'; echo fullscreen-$((6*7))\n");
    a.until("alternate screen", |tty| has(tty, b"fullscreen-42"));
    assert_eq!(
        fs::read_link(host.pane("s").join("shown")).unwrap(),
        Path::new("alt")
    );
    // A second terminal comes to the session: it is shown the screen as it is now. (This one is
    // a terminal that draws what it is sent, a pane of fux's: a viewer sends the cells that
    // changed, and a line of text is not one run of bytes.)
    let b = InPane::connect(&host, "second", &[], &["--session", "s"]);
    let shows = |what: &str| b.says("shown/screen").contains(what);
    until("the second terminal shows the current screen", || {
        shows("fullscreen-42")
    });
    // The first is closed: its koh ends, and the second goes on, through a flood, to the
    // session's end.
    drop(std::mem::replace(
        &mut a.tty,
        fs::File::open("/dev/null").unwrap(),
    ));
    until("closed terminal exits", || {
        a.koh.try_wait().unwrap().is_some()
    });
    b.types(b"printf '\\033[?1049l'; seq 1 300000; echo flood-$((6*7))\n");
    until("the flood's end is drawn", || {
        shows("300000") && shows("flood-42")
    });
    assert_eq!(
        fs::read_link(host.pane("s").join("shown")).unwrap(),
        Path::new("main")
    );
    b.types(b"exit 9\n");
    assert_eq!(b.ends(), "exited 9");
}

/// An attach as a test asks it: of the session `name`, or of a new one running `program`.
fn asks(name: Option<&str>, program: &[String]) -> Attach {
    Attach {
        name: name.map(String::from),
        new: name.is_none(),
        size: ViewSize {
            cols: 80,
            rows: 24,
            ..ViewSize::default()
        },
        argv: program.to_vec(),
        cwd: None,
        run: None,
        client: 7,
        term: "xterm-256color".into(),
        keyboard: 0,
        colours: String::new(),
    }
}

/// An attach by the client in this process: the stream, and what the server said of the session.
async fn attach(client: &Client, asks: Attach) -> koh::Result<(SendStream, RecvStream, Attached)> {
    let (send, mut recv) = client.request(&Request::Attach(asks)).await?;
    let attached = recv_msg(&mut recv, MAX_CTRL).await?;
    Ok((send, recv, attached))
}

/// Reads a session's stream to its end: what its viewer drew, and its last word if it had one.
async fn drawn(from: &mut RecvStream) -> (Vec<u8>, Option<i32>) {
    let mut all = Vec::new();
    loop {
        match koh::proto::recv_msg_opt::<ViewOutput>(from, VIEW_FRAME).await {
            Ok(Some(ViewOutput::Bytes(bytes))) => all.extend(bytes),
            Ok(Some(ViewOutput::Exit(code))) => return (all, Some(code)),
            _ => return (all, None),
        }
    }
}

/// The viewers of a server's sessions that run now: the folders they have in koh's fux session.
fn viewers(host: &Host) -> Vec<String> {
    let all = names_in(host.sessions.parent().unwrap());
    let viewers = all.into_iter().filter(|name| name.starts_with(".view."));
    viewers.collect()
}

/// A program for a session that takes what is typed as it is typed, into the file `out`: it
/// says READY once its terminal is raw, and then reads.
fn reads_into(out: &Path) -> Vec<String> {
    let script = "stty raw -echo; echo READY; exec cat > \"$0\"";
    ["sh", "-c", script, out.to_str().unwrap()]
        .map(String::from)
        .to_vec()
}

/// `koh connect` in a terminal that answers what it is asked: a pane of fux's, in a session of
/// the test's own, whose program `koh connect` is. The pane is the terminal, and its files say
/// what a terminal would show: `screen`, `modes`, `cursor`, and which screen (`shown`).
struct InPane(PathBuf);

impl Drop for InPane {
    fn drop(&mut self) {
        signal(&holder_of(&self.0), "-KILL");
    }
}

impl InPane {
    /// A terminal `tag` of the colours and the keyboard's flags its session's files say, and
    /// `koh connect` to the host in it.
    fn connect(host: &Host, tag: &str, like: &[(&str, &str)], asks: &[&str]) -> Self {
        let root = host.tmp.0.join(tag);
        let pane = root.join("fux/main/terminal");
        fs::create_dir_all(root.join("fux")).unwrap();
        for (name, text) in like {
            fs::write(root.join("fux").join(name), text).unwrap();
        }
        let mut start = host.koh(&["fux", "start", pane.to_str().unwrap(), "--"]);
        start.args([env!("CARGO_BIN_EXE_koh"), "connect", &host.id]);
        start.args(["--direct", &host.addr()]).args(asks);
        start.env("XDG_RUNTIME_DIR", &root).env("COLUMNS", "80");
        let started = start.env("LINES", "24").output().unwrap();
        assert!(started.status.success(), "{started:?}");
        InPane(pane)
    }

    fn says(&self, what: &str) -> String {
        fs::read_to_string(self.0.join(what)).unwrap_or_default()
    }

    /// Whether the terminal is as a program finds one: the main screen, nothing asked of it
    /// (no mouse, no pastes marked), the cursor shown.
    fn is_put_back(&self) -> bool {
        let main =
            fs::read_link(self.0.join("shown")).is_ok_and(|shown| shown == Path::new("main"));
        main && self.says("modes").trim().is_empty() && self.says("cursor").contains("shown")
    }

    fn types(&self, keys: &[u8]) {
        let mut typed = fuxix::open(self.0.join("in"), true).unwrap();
        typed.write_all(keys).unwrap();
    }

    /// `koh connect`'s process number, and how it ended once it has (`state`).
    fn pid(&self) -> String {
        let status = self.says("status");
        let pid = status.lines().find_map(|line| line.strip_prefix("pid "));
        pid.unwrap().to_string()
    }

    fn ends(&self) -> String {
        until("koh connect ends", || {
            self.says("state").trim() != "running"
        });
        self.says("state").trim().to_string()
    }
}

#[tokio::test]
async fn a_scoped_key_cannot_attach() {
    let (tmp, srv, client, allowed, _) = boot_scoped("scoped-attach").await;
    // A `--cp` key, and then the same key as an `--exec` key: neither has sessions.
    for exec in [false, true] {
        if exec {
            let scope = Scope::Exec(allowed.clone());
            let entry = ClientEntry {
                name: "bot".into(),
                id: load_or_create_key(Role::Client, Some(&tmp.0.join("cli_cfg/client.key")))
                    .unwrap()
                    .public(),
                scope,
            };
            save_clients(Some(&tmp.0.join("srv_cfg/server.key")), &[entry]).unwrap();
        }
        let err = attach(&client, asks(None, &[])).await.unwrap_err();
        assert_eq!(err.code, Exit::REFUSED, "{err:?}");
    }
    // Refused before anything is made.
    assert_eq!(names_in(&tmp.0.join("state/fux/koh-sessions")), [""; 0]);
    client.close().await;
    srv.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_is_a_pane_kept_by_koh_hold_and_shown_by_a_viewer_on_the_server() {
    let host = Host::start("pane", &[]);
    let client = host.client().await;
    let sleeps = ["sleep".to_string(), "30".into()];
    let (send, mut from, attached) = attach(&client, asks(None, &sleeps)).await.unwrap();
    // The session is a folder in koh's own fux session, beneath its state, which it printed;
    // its run is the one its holder wrote there.
    let state = fs::canonicalize(host.tmp.0.join("run/koh")).unwrap();
    assert_eq!(host.sessions, state.join("fux/koh-sessions"));
    assert_eq!(
        (names_in(&host.sessions), attached.name.as_str()),
        (vec!["1".to_string()], "1")
    );
    let (pane, server) = (host.pane("1"), host.served.as_ref().unwrap().server.id());
    assert_eq!(fux::run_of(&pane), Some(attached.run));
    // Its holder is this binary under the word `hold`, with the lock on the folder: fux's proof
    // that it lives. It is no child of `koh serve`, and lives on when that is stopped.
    let holder = holder_of(&pane);
    let words = |pid: &str| {
        let args = ps(pid, "args=");
        let words = args.split_whitespace().take(2).map(String::from);
        words.collect::<Vec<_>>()
    };
    assert_eq!(words(&holder), [env!("CARGO_BIN_EXE_koh"), "hold"]);
    assert_ne!(ps(&holder, "ppid="), server.to_string());
    let locked = || fs::File::open(&pane).unwrap().try_lock_shared().is_err();
    assert!(locked());
    // Its viewer is this binary too, a child of `koh serve`, with a folder of its own in the
    // session; what it draws is what the stream carries.
    until("the viewer is there", || viewers(&host).len() == 1);
    let viewer = viewers(&host)[0].trim_start_matches(".view.").to_string();
    assert_eq!(words(&viewer), [env!("CARGO_BIN_EXE_koh"), "view-session"]);
    assert_eq!(ps(&viewer, "ppid="), server.to_string());
    let first: ViewOutput = recv_msg(&mut from, VIEW_FRAME).await.unwrap();
    assert!(
        matches!(first, ViewOutput::Bytes(bytes) if bytes.starts_with(b"\x1b]8;;\x1b\\\x1b[22;2t\x1b[?1049h"))
    );
    // The client leaves: the viewer does, and its folder; the session runs on. Nothing of the
    // session was ever the client's to keep.
    drop((send, from));
    client.close().await;
    until("the viewer is gone", || {
        viewers(&host).is_empty() && ps(&viewer, "pid=").is_empty()
    });
    assert!(locked() && fs::read_to_string(pane.join("state")).unwrap() == "running\n");
    assert_eq!(names_in(&host.tmp.0.join("crun")), [""; 0]);
    assert_eq!(names_in(&state), ["fux", "jobs"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_are_capped_and_the_oldest_ended_one_makes_room() {
    let host = Host::start("capped", &["--max-sessions", "2"]);
    let client = host.client().await;
    let run = |who: u64, program: &[&str]| {
        let program: Vec<String> = program.iter().map(|word| word.to_string()).collect();
        let asks = Attach {
            client: who,
            ..asks(None, &program)
        };
        attach(&client, asks)
    };
    // Two sessions: one that runs, and one that has ended.
    let _first = run(1, &["sleep", "30"]).await.unwrap();
    let (_send, mut from, _) = run(2, &["sh", "-c", "exit 0"]).await.unwrap();
    assert_eq!(drawn(&mut from).await.1, Some(0));
    assert_eq!(names_in(&host.sessions), ["1", "2"]);
    // A third takes the place of the one that ended, once it has started.
    let _third = run(3, &["sleep", "30"]).await.unwrap();
    until("the third runs, and the ended one is gone", || {
        names_in(&host.sessions) == ["1", "3"]
    });
    // With both running there is no room: the client is told the server is busy, and nothing starts.
    let err = run(4, &["sleep", "30"]).await.unwrap_err();
    assert!(
        err.code == Exit::BUSY && err.message.contains("--max-sessions"),
        "{err:?}"
    );
    assert_eq!(names_in(&host.sessions), ["1", "3"]);
    client.close().await;
}

/// How `ps` has a process: nothing once it is gone and was waited for (a `Z` while it is not).
fn in_ps(pid: &str) -> String {
    let said = Command::new("ps").args(["-o", "stat=", "-p", pid]).output();
    String::from_utf8_lossy(&said.unwrap().stdout)
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_ends_with_its_stream_and_its_viewer_is_gone_before_its_folder() {
    let host = Host::start("ends", &[]);
    let client = host.client().await;
    let soon = |what: &str, mut done: Box<dyn FnMut() -> bool>| {
        let deadline = Instant::now() + Duration::from_secs(4);
        while !done() {
            assert!(Instant::now() < deadline, "not in 4 s: {what}");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    // A client that stops reading its stream and keeps its connection, under a program that
    // draws nothing more and with megabytes typed that the program does not read: the server
    // waits on neither end for it. The attach ends, and its viewer goes.
    let deaf = ["sh", "-c", "stty -echo; echo READY; exec sleep 300"].map(String::from);
    let (mut send, mut from, attached) = attach(&client, asks(None, &deaf)).await.unwrap();
    until("the program is ready", || {
        screen(&host.pane(&attached.name)).contains("READY")
    });
    let pasted = ViewInput::Bytes(vec![b'p'; 8 << 10]);
    let paste = async {
        loop {
            send_msg(&mut send, &pasted, VIEW_FRAME).await.unwrap();
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(2), paste).await;
    assert_eq!(viewers(&host).len(), 1);
    from.stop(0u32.into()).unwrap();
    let there = host.sessions.parent().unwrap().to_path_buf();
    let gone = move || {
        !names_in(&there)
            .iter()
            .any(|name| name.starts_with(".view."))
    };
    soon(
        "the viewer of a stream that was stopped is gone",
        Box::new(gone),
    );
    // A viewer that does not leave in its second (stopped, here) is killed and waited for
    // before the attach is over: no dead process is left for some later moment, and its
    // folder went after it, not under it.
    client.close().await;
    let mut tty = host.attach(&["--session", "z"], &[]);
    tty.until("the viewer is there", |_| viewers(&host).len() == 1);
    let viewer = viewers(&host)[0].trim_start_matches(".view.").to_string();
    signal(&viewer, "-STOP");
    tty.types(b"\x1d.");
    assert_eq!(tty.ends(), Some(0));
    let (pid, there) = (
        viewer.clone(),
        host.sessions.parent().unwrap().to_path_buf(),
    );
    let reaped = move || in_ps(&pid).is_empty() && !there.join(format!(".view.{viewer}")).exists();
    soon(
        "the stopped viewer is killed, waited for, and its folder gone",
        Box::new(reaped),
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_attach_ends_the_clients_older_stream_first_and_is_to_the_run_it_names() {
    let host = Host::start("older", &[]);
    let client = host.client().await;
    let out = host.tmp.0.join("out");
    let (mut older, mut old, attached) = attach(&client, asks(None, &reads_into(&out)))
        .await
        .unwrap();
    let pane = host.pane(&attached.name);
    until("the program is ready", || screen(&pane).contains("READY"));
    until("the older stream's viewer is there", || {
        viewers(&host).len() == 1
    });
    let viewer = viewers(&host);
    let typed = |keys: &[u8]| ViewInput::Bytes(keys.to_vec());
    send_msg(&mut older, &typed(b"aaaa"), VIEW_FRAME)
        .await
        .unwrap();
    // (Typed, and not on its way: what a stream has not typed when it is ended may be lost.)
    until("the program has read the older stream's bytes", || {
        fs::read(&out).unwrap_or_default() == b"aaaa"
    });
    // The same client attaches anew to the run. Once it is answered the older stream's viewer
    // has left, and its stream has ended without a last word: it was cut, not ended.
    let again = Attach {
        run: Some(attached.run),
        ..asks(Some(&attached.name), &[])
    };
    let (mut newer, _from, _) = attach(&client, again.clone()).await.unwrap();
    assert!(
        viewers(&host).iter().all(|now| !viewer.contains(now)),
        "{:?}",
        viewers(&host)
    );
    assert_eq!(drawn(&mut old).await.1, None);
    send_msg(&mut newer, &typed(b"bbbb"), VIEW_FRAME)
        .await
        .unwrap();
    until("the program has read both", || {
        fs::read(&out).unwrap_or_default() == b"aaaabbbb"
    });
    // Asked for a run the name has not, a client is answered with none: nothing is typed into
    // a session that only has the name. And one that names no session names no run.
    let other = Attach {
        run: Some(attached.run ^ 1),
        ..again.clone()
    };
    let session = host.sessions.parent().unwrap();
    let told = || fs::read_to_string(session.join("keyboard")).unwrap();
    let before = told();
    let other = Attach {
        keyboard: 9,
        ..other
    };
    let err = attach(&client, other).await.unwrap_err();
    assert_eq!(err.code, Exit::NOT_FOUND, "{err:?}");
    assert!(
        err.message.contains("another run has the session's name 1"),
        "{err:?}"
    );
    assert_eq!((before.as_str(), told().as_str()), ("0\n", "0\n"));
    let nameless = Attach {
        name: None,
        ..again
    };
    assert_eq!(
        attach(&client, nameless).await.unwrap_err().code,
        Exit::USAGE
    );
    assert_eq!(names_in(&host.sessions), ["1"]);
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_says_what_no_client_says_is_refused_or_loses_its_stream() {
    let host = Host::start("says", &[]);
    let client = host.client().await;
    let session = host.sessions.parent().unwrap().to_path_buf();
    let sleeps = ["sleep".to_string(), "100".into()];
    // What a client says of its terminal is a name and three colours: anything else is refused
    // before a session is started or a file written.
    let not_said: [fn(&mut Attach); 7] = [
        |asks| asks.term = "xterm\n256".into(),
        |asks| asks.term = "x".repeat(65),
        |asks| asks.colours = "layout #000000\n".into(),
        |asks| asks.colours = "background #1c1c1c\n../../told #000000\n".into(),
        |asks| asks.colours = "background #1c1c1c\n".repeat(4),
        |asks| asks.colours = "cursor #000000\n".repeat(4),
        |asks| asks.colours = "cursor #000000\r\n".into(),
    ];
    for not_said in not_said {
        let mut asks = asks(None, &sleeps);
        not_said(&mut asks);
        let err = attach(&client, asks.clone()).await.unwrap_err();
        assert_eq!(err.code, Exit::USAGE, "{asks:?}");
    }
    // And an attach that is refused for another reason changes nothing: what it says of its
    // terminal is written once it will be shown a session, and not before. A run of no
    // session, a name there is no session of; and a program that cannot be started leaves no
    // session's name behind, with a name or without one.
    let told = Attach {
        keyboard: 9,
        colours: "foreground #aabbcc\n".into(),
        ..asks(None, &sleeps)
    };
    let refused = [
        (Some(1), None, &sleeps[..], Exit::USAGE),
        (Some(1), Some("nosuch"), &sleeps[..], Exit::NOT_FOUND),
    ];
    for (run, name, program, code) in refused {
        let asks = Attach {
            run,
            name: name.map(String::from),
            new: false,
            argv: program.to_vec(),
            ..told.clone()
        };
        let err = attach(&client, asks.clone()).await.unwrap_err();
        assert_eq!(err.code, code, "{asks:?}: {err:?}");
    }
    assert_eq!(
        (names_in(&session), names_in(&host.sessions)),
        (vec!["koh-sessions".to_string()], vec![])
    );
    let none = ["/no/such/koh-test-program".to_string()];
    for name in [Some("dead"), None] {
        let asks = Attach {
            name: name.map(String::from),
            argv: none.to_vec(),
            ..told.clone()
        };
        let err = attach(&client, asks).await.unwrap_err();
        assert_eq!(err.code, Exit::CANNOT_START, "{err:?}");
        assert_eq!(names_in(&host.sessions), [""; 0], "{err:?}");
    }
    // What it may say is written where the session's programs are answered from.
    let said = Attach {
        keyboard: 5,
        colours: "foreground #d0d0d0\nbackground #1c1c1c\n".into(),
        ..asks(None, &sleeps)
    };
    let (mut send, mut from, _) = attach(&client, said.clone()).await.unwrap();
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "5\n");
    assert_eq!(
        fs::read_to_string(session.join("colours")).unwrap(),
        said.colours
    );
    // On the stream a client types and tells its terminal's size, a message of 16 KiB at most:
    // one that is longer ends the stream, with nothing of it typed.
    let size = ViewSize {
        cols: 100,
        rows: 30,
        ..ViewSize::default()
    };
    send_msg(&mut send, &ViewInput::Resize(size), VIEW_FRAME)
        .await
        .unwrap();
    until("the session takes the size", || {
        fs::read_to_string(host.pane("1").join("size")).unwrap_or_default() == "100 30\n"
    });
    let long = ViewInput::Bytes(vec![b'x'; VIEW_FRAME + 1]);
    send_msg(&mut send, &long, MAX_CHUNK).await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(10), drawn(&mut from)).await;
    assert_eq!(ended.expect("the stream lived on").1, None);
    until("its viewer is gone", || viewers(&host).is_empty());
    assert_eq!(names_in(&host.tmp.0.join("run/koh")), ["fux", "jobs"]);
    client.close().await;
}

#[test]
fn the_exit_code_is_the_programs_and_not_zero_without_one() {
    let host = Host::start("code", &[]);
    let run = |asks: &[&str], program: &[&str]| {
        let program: Vec<String> = program.iter().map(|word| word.to_string()).collect();
        host.attach(asks, &program).ends()
    };
    // The program's status; of one a signal ended, 128 and the signal.
    assert_eq!(run(&["--new"], &["sh", "-c", "exit 7"]), Some(7));
    assert_eq!(run(&["--new"], &["sh", "-c", "kill -9 $$"]), Some(137));
    // An ended session stays, and a later client is shown the same and ends the same.
    assert_eq!(run(&["--session", "1"], &[]), Some(7));
    assert_eq!(run(&["--session", "2"], &[]), Some(137));
    // A holder that was killed left `state` at `running`, with no lock: that is no 0.
    let mut shown = host.attach(&["--new"], &sh("echo SHOWN; exec sleep 30"));
    shown.until("the session is shown", |tty| {
        tty.drawn.windows(5).any(|drawn| drawn == b"SHOWN")
    });
    signal(&holder_of(&host.pane("3")), "-KILL");
    assert_eq!(shown.ends(), Some(1));
    assert_eq!(run(&["--session", "3"], &[]), Some(1));
    assert_eq!(names_in(&host.sessions), ["1", "2", "3"]);
    assert_eq!(viewers(&host), [""; 0]);
}

#[test]
fn koh_connect_asks_its_terminal_what_it_is_like_and_puts_it_back_however_it_ends() {
    let host = Host::start("terminal", &[]);
    let session = host.sessions.parent().unwrap().to_path_buf();
    // A program that takes the alternate screen, the mouse and pastes marked, and hides the cursor.
    let modes = r"printf '\033[?1049h\033[?1002h\033[?1006h\033[?2004h\033[?25l\033[5;5HMODES-%s' ON; exec sleep 600";
    let like = [
        ("colours", "foreground #d0d0d0\nbackground #1c1c1c\n"),
        ("keyboard", "5\n"),
    ];
    let on = |terminal: &InPane| {
        until("the terminal shows the program, its modes on", || {
            terminal.says("shown/screen").contains("MODES-ON")
                && terminal.says("modes").contains("mouse")
        });
        assert!(!terminal.is_put_back());
    };
    // A terminal that says its colours and takes the keyboard's flags 1 and 4: asked before
    // anything was dialled, and its answers are in the server's session, where the programs of
    // its panes are answered from. Nothing of the answers was typed into the session.
    let asks = ["--session", "s", "--", "sh", "-c", modes];
    let first = InPane::connect(&host, "t1", &like, &asks);
    on(&first);
    assert_eq!(
        fs::read_to_string(session.join("colours")).unwrap(),
        like[0].1
    );
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "5\n");
    // Told to end, it puts the terminal back before it goes, and the session runs on.
    signal(&first.pid(), "-TERM");
    assert_eq!(first.ends(), "exited 0");
    until("the terminal is put back", || first.is_put_back());
    // One that knows neither: no colours are told (the file is as it was), the plain keyboard.
    // Hung up, as by a terminal that is closed, it ends the same way; and so when its user leaves.
    let second = InPane::connect(&host, "t2", &[], &["--session", "s"]);
    on(&second);
    assert_eq!(
        fs::read_to_string(session.join("colours")).unwrap(),
        like[0].1
    );
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "0\n");
    signal(&second.pid(), "-HUP");
    assert_eq!(second.ends(), "exited 0");
    until("the terminal is put back", || second.is_put_back());
    let third = InPane::connect(&host, "t3", &[], &["--session", "s"]);
    on(&third);
    third.types(b"\x1d.");
    assert_eq!(third.ends(), "exited 0");
    until("the terminal is put back", || third.is_put_back());
    // The session's program was typed nothing, by any of the three, and no viewer is left.
    assert_eq!(screen(&host.pane("s")).trim(), "MODES-ON");
    until("the viewers are gone", || viewers(&host).is_empty());
}

/// A program for a session that asks its terminal for its background and, having set the
/// keyboard's first flag, which flags are in force; and then writes all it reads into `out`.
fn asks_and_reads_into(out: &Path) -> Vec<String> {
    let script = r#"stty raw -echo; printf '\033]11;?\033\\\033[>1u\033[?u'; exec cat > "$0""#;
    ["sh", "-c", script, out.to_str().unwrap()]
        .map(String::from)
        .to_vec()
}

#[test]
fn a_sessions_program_is_told_the_terminals_colours_and_has_its_keys_in_the_form_it_asked_for() {
    let host = Host::start("told", &[]);
    let read =
        |out: &Path| String::from_utf8_lossy(&fs::read(out).unwrap_or_default()).into_owned();
    let with = |tag: &str, like: &[(&str, &str)]| {
        let out = host.tmp.0.join(format!("{tag}.out"));
        let program = asks_and_reads_into(&out);
        let mut asks = vec!["--session", tag, "--"];
        asks.extend(program.iter().map(String::as_str));
        (InPane::connect(&host, tag, like, &asks), out)
    };
    // In a terminal that tells no colours and does not know the kitty keyboard protocol, the
    // program is told that no flag is in force, and no colour; Escape, typed, is the one byte.
    let (plain, out) = with("plain", &[]);
    until("the program is told of no flags", || {
        read(&out) == "\x1b[?0u"
    });
    plain.types(b"\x1b");
    until("Escape is typed in its old form", || {
        read(&out) == "\x1b[?0u\x1b"
    });
    // In one that says its colours and takes the keyboard's flags, the program is told the
    // background and that its flag is in force; and Escape, which such a terminal sends in the
    // protocol's form once the flag is set there, reaches the program in that form.
    let like = [
        ("colours", "foreground #d0d0d0\nbackground #1c1c1c\n"),
        ("keyboard", "5\n"),
    ];
    let (kitty, out) = with("kitty", &like);
    let told = "\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\\x1b[?1u";
    until("the program is told the background and its flag", || {
        read(&out) == told
    });
    until("the flag is set in the client's terminal", || {
        kitty.says("modes").contains("keys1")
    });
    kitty.types(b"\x1b[27u");
    until("Escape is typed in the protocol's form", || {
        read(&out) == format!("{told}\x1b[27u")
    });
    assert_eq!(read(&host.tmp.0.join("plain.out")), "\x1b[?0u\x1b");
    // koh's key leaves in that form too, and the terminal is as it was.
    kitty.types(b"\x1b[93;5u.");
    assert_eq!(kitty.ends(), "exited 0");
    until("the terminal is put back", || {
        kitty.is_put_back() && !kitty.says("modes").contains("keys")
    });
    assert_eq!(read(&out), format!("{told}\x1b[27u"));
}

#[test]
fn a_terminal_that_answers_nothing_is_asked_once_and_one_that_answers_in_pieces_is_heard() {
    let mut host = Host::start("late", &[]);
    let session = host.sessions.parent().unwrap().to_path_buf();
    let out = host.tmp.0.join("out");
    let has = |tty: &mut InTerminal, what: &[u8]| tty.drawn.windows(what.len()).any(|s| s == what);
    let asked = |tty: &InTerminal| tty.drawn.windows(3).filter(|s| s == b"\x1b[c").count();
    // A terminal that answers nothing: koh waits a second for it, and goes on with the plain
    // keyboard and no colours.
    let began = Instant::now();
    let mut tty = host.attach(&["--session", "s"], &reads_into(&out));
    tty.answers = false;
    tty.until("the program is ready", |tty| has(tty, b"READY"));
    assert!(
        began.elapsed() >= Duration::from_secs(1),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "0\n");
    assert!(!session.join("colours").exists());
    // What it sends after the wait was typed, whatever its form: koh looks for no answer in
    // it, and drops none of it. (An answer that comes late is typed into the session so, once.)
    let late = b"\x1b[?5u\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\\x1b[?62;4c\x1b]1hello\x07x";
    tty.types(late);
    until("what has an answer's form is typed, to the byte", || {
        fs::read(&out).unwrap_or_default() == late
    });
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "0\n");
    assert!(!session.join("colours").exists());
    // The server goes and comes back: koh dials again and attaches again, and asks its
    // terminal nothing again. (So a terminal that answers nothing costs its second once.)
    host.stop();
    tty.until("link down", |tty| has(tty, b"no link"));
    let (down, drawn) = (Instant::now(), tty.drawn.len());
    host.serve();
    tty.until("the session is shown again", |tty| {
        tty.drawn[drawn..].windows(8).any(|s| s == b"\x1b[?1049h")
    });
    println!("shown again {:?} after the link went", down.elapsed());
    assert_eq!(asked(&tty), 1);
    tty.types(b"y");
    until("typed on return", || {
        fs::read(&out).unwrap_or_default() == [&late[..], b"y"].concat()
    });
    // A terminal that answers in pieces, within the wait: its flags, a colour cut in two, and
    // what it is, cut in two, with a key right after it. The answers are heard, and the key
    // is the session's first.
    let out = host.tmp.0.join("out.pieces");
    let mut slow = host.attach(&["--session", "p"], &reads_into(&out));
    slow.answers = false;
    slow.until("it is asked", |tty| has(tty, b"\x1b[c"));
    for piece in [
        &b"\x1b[?5u\x1b]11;rgb:12"[..],
        b"34/abcd/00ff\x1b\\\x1b[?6",
        b"2;4cz",
    ] {
        slow.types(piece);
        std::thread::sleep(Duration::from_millis(150));
    }
    slow.until("the program is ready", |tty| has(tty, b"READY"));
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "5\n");
    assert_eq!(
        fs::read_to_string(session.join("colours")).unwrap(),
        "background #12ab00\n"
    );
    until("the key after its answers is typed", || {
        fs::read(&out).unwrap_or_default() == b"z"
    });
}

#[test]
fn what_was_typed_before_the_key_that_leaves_is_typed() {
    let host = Host::start("before", &[]);
    // What is typed right before `Ctrl-] .`, in one write with it (a paste and the key, a
    // fast hand): koh leaves, and the session has it, all of it and in its order. One byte;
    // and more than a pty holds at once, so that the last of it waits on the server for the
    // viewer to read what is before it, while the client is leaving.
    let lines: Vec<u8> = (0..5000)
        .flat_map(|n| format!("{n:07}\n").into_bytes())
        .collect();
    for (name, typed) in [("one", &b"q"[..]), ("many", &lines[..])] {
        let out = host.tmp.0.join(name);
        let mut tty = host.attach(&["--session", name], &reads_into(&out));
        tty.until("the program is ready", |tty| {
            tty.drawn.windows(5).any(|drawn| drawn == b"READY")
        });
        tty.types(&[typed, b"\x1d."].concat());
        let typing = Instant::now();
        assert_eq!(tty.ends(), Some(0));
        let left = typing.elapsed();
        let has = || fs::read(&out).unwrap_or_default();
        let deadline = Instant::now() + Duration::from_secs(10);
        while has() != typed {
            let (read, whole) = (has().len(), typed.len());
            let said = format!(
                "{name}: the program read {read} of {whole} bytes; koh left after {left:?}"
            );
            assert!(Instant::now() < deadline, "{said}");
            std::thread::sleep(Duration::from_millis(20));
        }
        until("the viewer is gone", || viewers(&host).is_empty());
    }
}

#[test]
fn a_session_that_ends_with_typing_unread_ends_for_its_client_at_once() {
    let host = Host::start("unread", &[]);
    // A program that reads nothing and ends after a second, with megabytes typed meanwhile:
    // more than its pane takes, so that the viewer's own terminal holds what the viewer has
    // not read. The viewer has left when the server looks for that, and nothing waits a
    // second for a viewer that is gone to read it: the client has the program's status then.
    let ends = ["sh", "-c", "stty -echo; echo READY; sleep 1; exit 42"].map(String::from);
    let mut tty = host.attach(&["--session", "s"], &ends);
    tty.until("the program is ready", |tty| {
        tty.drawn.windows(5).any(|drawn| drawn == b"READY")
    });
    let (ready, burst) = (Instant::now(), vec![b'x'; 64 << 10]);
    let state = || fs::read_to_string(host.pane("s").join("state")).unwrap_or_default();
    let mut over = None;
    let ended = loop {
        // (As much as the terminal takes, and nothing once koh is gone; what koh draws is read.)
        let _ = (&tty.tty).write(&burst);
        let mut drawn = [0; 4096];
        while let Ok(n @ 1..) = (&tty.tty).read(&mut drawn) {
            tty.drawn.extend_from_slice(&drawn[..n]);
        }
        if over.is_none() && state().trim() != "running" {
            over = Some(Instant::now());
        }
        match tty.koh.try_wait().unwrap() {
            Some(ended) => break ended.code(),
            None => assert!(ready.elapsed() < Duration::from_secs(10), "still there"),
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(ended, Some(42));
    // From the program's end to koh's, well under the second that was waited; and koh never
    // said that there was no link: there was one, and the session's last word on it.
    let after = over.map(|over| over.elapsed());
    assert!(
        after.is_some_and(|after| after < Duration::from_millis(800)),
        "{after:?} after the program ended; {:?} in all",
        ready.elapsed()
    );
    assert!(!tty.drawn.windows(7).any(|said| said == b"no link"));
}

// (On Linux alone: on CI's macOS the test itself did not end, twice, and where it waits there
// is not known. What it holds is in code that is the same on both.)
#[cfg(target_os = "linux")]
#[test]
fn koh_connect_started_on_a_terminal_that_takes_nothing_ends_when_it_is_told_to() {
    let host = Host::start("stalled-first", &[]);
    let (config, runtime) = (host.tmp.0.join("cli_cfg"), host.tmp.0.join("crun"));
    // A terminal that takes nothing from before koh starts (another program has filled it,
    // and nobody reads): koh cannot ask it what it is like, and waits for nothing to do so.
    // Told to end, it ends, each of the three ways.
    for (how, code) in [("-TERM", 0), ("-HUP", 0), ("-INT", 130)] {
        let (tty, theirs) = InTerminal::pty();
        let mut fills = Command::new("sh");
        fills
            .args(["-c", "stty raw <&1; exec head -c 4194304 /dev/zero"])
            .stdout(theirs.try_clone().unwrap());
        let mut fills = fills.spawn().unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let name = how.trim_start_matches('-');
        let asks = [&host.id, "--direct", &host.addr(), "--session", name];
        let mut koh = InTerminal::connect_on((tty, theirs), &config, &runtime, &asks, true);
        // (koh has dialled and has its terminal by now: the session is there.)
        until("the session is started", || {
            host.pane(name).join("run").exists()
        });
        std::thread::sleep(Duration::from_millis(500));
        let told = Instant::now();
        signal(&koh.koh.id().to_string(), how);
        let ended = loop {
            match koh.koh.try_wait().unwrap() {
                Some(ended) => break ended.code(),
                None => assert!(
                    told.elapsed() < Duration::from_secs(2),
                    "{how}: still there"
                ),
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(ended, Some(code), "{how}");
        // (The terminal goes first: on macOS a program that leaves a terminal it has written
        // to is not gone until what it wrote is read, or the terminal's other end is closed.)
        drop(koh);
        let _ = (fills.kill(), fills.wait());
    }
}

#[test]
fn koh_connect_ends_when_it_is_told_to_though_its_terminal_takes_nothing() {
    let host = Host::start("stalled", &[]);
    // A terminal that takes nothing more (one behind a path that is stuck), under a program
    // that goes on printing: koh's writing to it waits, and so would putting it back. Told to
    // end, koh ends all the same, each of the three ways, and soon.
    for (how, code) in [("-TERM", 0), ("-HUP", 0), ("-INT", 130)] {
        // (Every cell of another colour than the one before it: a screen of it is many bytes.)
        let draws = r"while :; do printf '\033[31mfl\033[32moo\033[33md-\033[34mof\033[35m-l\033[36min\033[37mes'; done";
        let flood = ["sh", "-c", draws].map(String::from);
        let mut tty = host.attach(&["--session", how.trim_start_matches('-')], &flood);
        tty.until("the flood is drawn", |tty| {
            tty.drawn.windows(2).any(|drawn| drawn == b"es")
        });
        // (Not read from here on: what koh writes fills the terminal, and waits.)
        std::thread::sleep(Duration::from_secs(3));
        let told = Instant::now();
        signal(&tty.koh.id().to_string(), how);
        let ended = loop {
            match tty.koh.try_wait().unwrap() {
                Some(ended) => break ended.code(),
                None => assert!(
                    told.elapsed() < Duration::from_secs(2),
                    "{how}: still there"
                ),
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(ended, Some(code), "{how}");
    }
}

#[test]
fn a_terminal_that_is_closed_ends_koh_and_a_server_that_was_killed_leaves_no_viewer() {
    let mut host = Host::start("hangup", &[]);
    // `koh connect` on a pty that is no controlling terminal of its own, which is then closed:
    // it ends, its viewer on the server with it, and nothing was made on the client.
    let (config, runtime) = (host.tmp.0.join("cli_cfg"), host.tmp.0.join("crun"));
    let asks = ["--direct", &host.addr(), &host.id, "--session", "s"];
    let mut connect = InTerminal::connect_in(&config, &runtime, &asks, false);
    connect.until("the terminal shows the session", |tty| {
        tty.drawn.windows(8).any(|drawn| drawn == b"\x1b[?1049h") && viewers(&host).len() == 1
    });
    drop(std::mem::replace(
        &mut connect.tty,
        fs::File::open("/dev/null").unwrap(),
    ));
    assert_eq!(connect.ends(), Some(0));
    until("its viewer is gone", || viewers(&host).is_empty());
    assert_eq!(names_in(&runtime), [""; 0]);
    // The server is killed outright while a client is attached: the viewer reads the end of
    // its terminal and leaves by itself. One that was killed with it left its folder: the
    // server that starts next removes it, and the client is shown the session again.
    let mut connect = host.attach(&["--session", "s"], &[]);
    connect.until("the session is shown", |_| viewers(&host).len() == 1);
    let viewer = viewers(&host)[0].trim_start_matches(".view.").to_string();
    // (The server is stopped first: it removes the folder of a viewer it sees end.)
    let server = host.served.as_ref().unwrap().server.id().to_string();
    for (pid, how) in [(&server, "-STOP"), (&viewer, "-KILL"), (&server, "-KILL")] {
        signal(pid, how);
    }
    connect.until("koh says there is no link", |tty| {
        tty.drawn.windows(7).any(|drawn| drawn == b"no link")
    });
    assert_eq!(viewers(&host).len(), 1);
    host.served = None;
    host.serve();
    connect.types(b"echo back-$((6*7))\n");
    connect.until("the session is shown again", |tty| {
        tty.drawn.windows(7).any(|drawn| drawn == b"back-42")
    });
    assert!(viewers(&host).len() == 1 && !viewers(&host).contains(&format!(".view.{viewer}")));
    assert_eq!(
        fs::read_to_string(host.pane("s").join("state")).unwrap(),
        "running\n"
    );
}

// ---- the three commands: `koh sessions`, `koh output`, `koh wait --session` ---------------------

/// A shell for a session that marks its prompts and its commands as fux reads them (OSC 133):
/// bash, as Linux and macOS have it (3.2 there, which has no `PS0`). Its prompt says how the
/// command before it ended (`D;$?`), where the prompt begins (`A`) and where what is typed does
/// (`B`); a `DEBUG` trap says where a command's output begins (`C`), once for each simple
/// command, so a test types one at a time.
fn marking_shell(host: &Host) -> Vec<String> {
    let rc = host.tmp.0.join("marks.bashrc");
    let prompt = r"PS1='\[\e]133;D;$?\a\e]133;A\a\]$ \[\e]133;B\a\]'";
    let output = r#"trap 'printf "\033]133;C\007"' DEBUG"#;
    fs::write(&rc, format!("{prompt}\n{output}\n")).unwrap();
    [
        "bash",
        "--noprofile",
        "--rcfile",
        rc.to_str().unwrap(),
        "-i",
    ]
    .map(String::from)
    .to_vec()
}

fn sh(script: &str) -> Vec<String> {
    ["sh", "-c", script].map(String::from).to_vec()
}

impl Host {
    /// One of the client's `koh` commands about this server, run to its end: how it ended,
    /// what it printed and what it said.
    fn asked(&self, command: &str, args: &[&str]) -> (Option<i32>, String, String) {
        let mut koh = self.koh(&[command, &self.id, "--direct", &self.addr()]);
        koh.args(args)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let said = koh.output().unwrap();
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        (said.status.code(), text(&said.stdout), text(&said.stderr))
    }

    /// `koh wait` for the session `s` of this server, started, with whatever else it is told.
    fn waits(&self, more: &[&str]) -> Waits {
        let mut koh = self.koh(&["wait", &self.id, "--direct", &self.addr()]);
        koh.args(["--session", "s"])
            .args(more)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        Waits(koh.spawn().unwrap())
    }

    fn session(&self, name: &str, program: &[String], ready: &str) -> PathBuf {
        let mut tty = self.attach(&["--session", name], program);
        let pane = self.pane(name);
        tty.until(ready, |_| screen(&pane).contains(ready));
        tty.types(b"\x1d.");
        assert_eq!(tty.ends(), Some(0));
        pane
    }
}

/// A `koh wait` that runs. It is killed if the test lets go of it before it has ended.
struct Waits(std::process::Child);

impl Drop for Waits {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Waits {
    fn ended(&mut self) -> bool {
        self.0.try_wait().unwrap().is_some()
    }

    /// Once it has ended: its exit code, what it printed and what it said.
    fn said(&mut self) -> (Option<i32>, String, String) {
        let (code, mut printed, mut said) =
            (self.0.wait().unwrap().code(), String::new(), String::new());
        let _ = self.0.stdout.take().unwrap().read_to_string(&mut printed);
        let _ = self.0.stderr.take().unwrap().read_to_string(&mut said);
        (code, printed, said)
    }
}

#[test]
fn sessions_lists_what_the_folders_say() {
    let host = Host::start("list", &[]);
    // Three sessions: one that lives, with a shell that marks its commands and a client; one
    // whose program has ended; one whose holder was killed, so that nothing says how it ended.
    let mut live = host.attach(&["--session", "live"], &marking_shell(&host));
    let pane = host.pane("live");
    until("the shell has its prompt", || screen(&pane).contains('$'));
    let mut done = host.attach(&["--session", "done"], &sh("exit 7"));
    assert_eq!(done.ends(), Some(7));
    let mut dead = host.attach(&["--session", "dead"], &marking_shell(&host));
    let killed = host.pane("dead");
    until("the third has its prompt", || screen(&killed).contains('$'));
    fs::write(killed.join("in"), "sleep 30\n").unwrap();
    let marks = || fs::read_to_string(killed.join("marks")).unwrap_or_default();
    until("its command runs", || marks().ends_with(" output\n"));
    signal(&holder_of(&killed), "-KILL");
    assert_eq!(dead.ends(), Some(1));
    assert_eq!(
        fs::read_to_string(host.pane("dead").join("state")).unwrap(),
        "running\n"
    );
    let list = || -> Vec<serde_json::Value> {
        let (code, list, said) = host.asked("sessions", &["--json"]);
        assert_eq!(code, Some(0), "{said}");
        serde_json::from_str(&list).unwrap()
    };
    let of = |name: &str, what: &str| {
        let list = list();
        let session = list.iter().find(|session| session["name"] == name);
        session.unwrap_or_else(|| panic!("no {name} in {list:?}"))[what].clone()
    };
    // Each by its name, the oldest first; where it is, its size and whether a client has it.
    let names: Vec<_> = list().iter().map(|s| s["name"].clone()).collect();
    assert_eq!(names, ["live", "done", "dead"]);
    assert_eq!(of("live", "pane_dir"), pane.to_str().unwrap());
    assert_eq!(
        (of("live", "cols"), of("live", "rows")),
        (80.into(), 24.into())
    );
    assert_eq!(
        (of("live", "attached"), of("done", "attached")),
        (true.into(), false.into())
    );
    // What became of each program is what `state` says; but only a session whose holder lives
    // runs: of the one that was killed nothing says how it ended.
    let states = ["live", "done", "dead"].map(|name| of(name, "state"));
    assert_eq!(states, ["running", "exited 7", "ended"]);
    // At a prompt no command runs: the last mark is where what is typed begins. One runs from
    // where its output begins (the last mark is `output`) to its end, which has its code.
    assert_eq!(of("live", "running_command"), false);
    let gate = host.tmp.0.join("gate");
    let waits = format!(
        "sh -c 'until [ -e {} ]; do sleep 0.1; done; exit 5'\n",
        gate.display()
    );
    fs::write(pane.join("in"), waits).unwrap();
    until("the command runs", || of("live", "running_command") == true);
    assert!(
        fs::read_to_string(pane.join("marks"))
            .unwrap()
            .ends_with(" output\n")
    );
    fs::write(&gate, "").unwrap();
    until("the command has ended", || {
        of("live", "running_command") == false
    });
    assert_eq!(of("live", "last_exit"), 5);
    // A session whose holder is gone runs no command, whatever its marks say: the last mark
    // of the one that was killed is still the `output` of the command it ran.
    assert_eq!(
        (of("done", "running_command"), of("dead", "running_command")),
        (false.into(), false.into())
    );
    // The client leaves: the session is not attached. As a line for a person to read.
    signal(&live.koh.id().to_string(), "-TERM");
    assert_eq!(live.ends(), Some(0));
    until("the session has no client", || {
        of("live", "attached") == false
    });
    let (code, lines, said) = host.asked("sessions", &[]);
    assert_eq!(code, Some(0), "{said}");
    let lines: Vec<&str> = lines.lines().collect();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(
        lines[0].starts_with("live\tdetached\trunning\tidle\texit=5\t80x24\t"),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with("done\tdetached\texited 7\tidle\texit=-\t80x24\t"),
        "{lines:?}"
    );
}

#[test]
fn output_last_is_the_last_commands_output_across_history() {
    let host = Host::start("last", &[]);
    let pane = host.session("1", &marking_shell(&host), "$");
    // A pane of ten rows, forty wide; and so much output that `history` has become `history.1`.
    fs::write(pane.join("ctl"), "resize 40 10\n").unwrap();
    until("the pane takes the size", || {
        fs::read_to_string(pane.join("size")).unwrap() == "40 10\n"
    });
    fs::write(pane.join("in"), "seq 1 800000\n").unwrap();
    until(
        "history has become history.1, and the command has ended",
        || {
            let marks = fs::read_to_string(pane.join("marks")).unwrap_or_default();
            pane.join("history.1").is_file() && marks.ends_with(" command\n")
        },
    );
    // That command's output began in `history.1`: all of it is there, in pieces.
    let (code, flood, said) = host.asked("output", &["--session", "1", "--last"]);
    let numbers: String = (1..=800_000).map(|n| format!("{n}\n")).collect();
    assert_eq!((code, flood.len()), (Some(0), numbers.len()), "{said}");
    assert!(flood == numbers);
    // A command that prints 26 lines, one of them wider than the pane: 19 of them are in
    // `history` by its end, and the wide one is three rows of the screen.
    let lines: Vec<String> = (1..=26)
        .map(|n| match n {
            24 => "wide-".repeat(20),
            n => format!("line-{n}"),
        })
        .collect();
    fs::write(
        pane.join("in"),
        format!("printf '%s\\n' {}\n", lines.join(" ")),
    )
    .unwrap();
    let printed = lines.join("\n") + "\n";
    let deadline = Instant::now() + Duration::from_secs(20);
    let last = loop {
        let last = host.asked("output", &["--session", "1", "--last"]);
        if last.0 != Some(0) || last.1 == printed || Instant::now() > deadline {
            break last;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // What it printed, each line whole, from where its output began to where it ended: not
    // the command, not the prompt after it.
    assert_eq!(
        (last.0, last.1.as_str()),
        (Some(0), printed.as_str()),
        "{}",
        last.2
    );
    let rows = screen(&pane);
    assert!(
        rows.contains(&format!("{}\n", "wide-".repeat(8))),
        "{rows:?}"
    );
    let history = fs::read_to_string(pane.join("history")).unwrap();
    assert!(history.ends_with("line-19\n") && rows.contains("line-20\n"));
    // Without `--last` it is the screen that is shown; `--json` has it as one value.
    let (code, shown, said) = host.asked("output", &["--session", "1"]);
    assert_eq!((code, shown.as_str()), (Some(0), rows.as_str()), "{said}");
    let (code, json, said) = host.asked("output", &["--session", "1", "--last", "--json"]);
    assert_eq!(code, Some(0), "{said}");
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        json,
        serde_json::json!({ "session": "1", "output": printed })
    );
    // A name that is no session's is not found.
    let (code, _, said) = host.asked("output", &["--session", "none"]);
    assert_eq!(code, Some(127), "{said}");
    assert!(said.contains("no session none"), "{said}");
    // Nor is a name that is none a path: the folder above the sessions is no session, also
    // where it looks like a pane.
    let above = host.sessions.parent().unwrap();
    fs::create_dir_all(above.join("shown")).unwrap();
    fs::write(above.join("status"), "holder 1\n").unwrap();
    fs::write(above.join("run"), format!("{:032x}\n", 1)).unwrap();
    fs::write(above.join("shown/screen"), "not a session's\n").unwrap();
    let (code, shown, said) = host.asked("output", &["--session", ".."]);
    assert_eq!((code, shown.as_str()), (Some(127), ""), "{said}");
}

#[test]
fn wait_session_returns_the_commands_code_or_124() {
    let host = Host::start("wait", &[]);
    let pane = host.session("s", &marking_shell(&host), "$");
    // No command ends: when the time given is over it is 124, with the screen as it is.
    let began = Instant::now();
    let (code, waited, said) = host.asked("wait", &["--session", "s", "--timeout", "1", "--json"]);
    assert_eq!(code, Some(124), "{said}");
    assert!(began.elapsed() >= Duration::from_secs(1));
    let waited: serde_json::Value = serde_json::from_str(&waited).unwrap();
    assert_eq!(
        (&waited["timed_out"], &waited["exit"]),
        (&true.into(), &124.into())
    );
    assert_eq!(waited["tail"], screen(&pane));
    // A wait returns when one more command has ended than when it was asked, with that
    // command's code and what it printed. (When the server takes the request the test cannot
    // see: it types one command after the other until the wait has returned. Each prints a
    // line of its own and ends with 42.)
    let mut wait = host.waits(&["--timeout", "30"]);
    let mut typed = 0;
    until("koh wait returns", || {
        typed += 1;
        let command = format!("sh -c 'echo waited-{typed}; exit 42'\n");
        fs::write(pane.join("in"), command).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        wait.ended()
    });
    let (code, printed, said) = wait.said();
    assert_eq!(code, Some(42), "{said}");
    let line = printed
        .strip_prefix("waited-")
        .and_then(|n| n.strip_suffix('\n'));
    assert!(
        line.is_some_and(|n| n.parse::<u32>().is_ok_and(|n| n <= typed)),
        "{printed:?}"
    );
    // A pane with no `marks.dropped` is kept by a holder of before there was one, whose marks
    // have no numbers: a wait for it is refused, with what to do.
    fs::remove_file(pane.join("marks.dropped")).unwrap();
    let (code, _, said) = host.asked("wait", &["--session", "s", "--timeout", "1"]);
    assert_eq!(code, Some(1), "{said}");
    assert!(
        said.contains("marks.dropped") && said.contains("End that session"),
        "{said}"
    );
}

#[test]
fn wait_session_ends_when_the_session_does() {
    let host = Host::start("wait-end", &[]);
    let pane = host.session(
        "s",
        &sh("echo ready; read line; echo bye-$line; exit 3"),
        "ready",
    );
    // A wait with no time given, of a program that marks nothing: it waits while that runs.
    let mut wait = host.waits(&[]);
    std::thread::sleep(Duration::from_millis(700));
    assert!(!wait.ended());
    // The program ends: the wait ends with its status and its last screen.
    fs::write(pane.join("in"), "now\n").unwrap();
    until("koh wait ends", || wait.ended());
    let (code, shown, said) = wait.said();
    assert_eq!(code, Some(3), "{said}");
    assert!(
        shown.contains("bye-now") && said.contains("exited 3"),
        "{shown:?} {said}"
    );
    // Asked of a session that has ended, it says the same at once.
    let (code, shown, said) = host.asked("wait", &["--session", "s"]);
    assert_eq!(code, Some(3), "{said}");
    assert!(shown.contains("bye-now"), "{shown:?}");
    // Of one whose holder was killed nothing says how it ended: that is 1, not 0.
    let dead = host.session("dead", &sh("echo ready; sleep 30"), "ready");
    signal(&holder_of(&dead), "-KILL");
    until("the holder is gone", || {
        fs::File::open(&dead).unwrap().try_lock_shared().is_ok()
    });
    let (code, _, said) = host.asked("wait", &["--session", "dead"]);
    assert_eq!(code, Some(1), "{said}");
    // And a name that is no session's is not found.
    let (code, _, said) = host.asked("wait", &["--session", "none"]);
    assert_eq!(code, Some(127), "{said}");
}

#[test]
fn the_three_commands_are_a_full_keys() {
    let host = Host::start("full-key", &[]);
    host.session("s", &sh("echo ready; sleep 30"), "ready");
    // A key with a scope, of either kind, beside the full key: it lists no session, reads
    // none and waits for none, and is told so.
    let bot = host.tmp.0.join("bot_cfg");
    fs::create_dir_all(&bot).unwrap();
    let id = load_or_create_key(Role::Client, Some(&bot.join("client.key")))
        .unwrap()
        .public();
    let dir = host.tmp.0.join("home");
    for scope in [Scope::Cp(dir.clone()), Scope::Exec(dir.clone())] {
        let entry = ClientEntry {
            name: "bot".into(),
            id,
            scope,
        };
        save_clients(Some(&host.tmp.0.join("srv_cfg/server.key")), &[entry]).unwrap();
        let mut terminal = InTerminal::connect(
            &bot,
            &host.tmp.0.join("crun"),
            &[&host.id, "--direct", &host.addr(), "--session", "s"],
        );
        assert_eq!(terminal.ends(), Some(4), "scoped key attached");
        let asks: [&[&str]; 4] = [
            &["sessions"],
            &["output", "--session", "s"],
            &["output", "--session", "s", "--last"],
            &["wait", "--session", "s", "--timeout", "1"],
        ];
        for asks in asks {
            let mut koh = host.koh(&[asks[0], &host.id, "--direct", &host.addr()]);
            koh.args(&asks[1..]).env("KOH_CONFIG_DIR", &bot);
            let said = koh.stderr(std::process::Stdio::piped()).output().unwrap();
            let why = String::from_utf8_lossy(&said.stderr);
            assert_eq!(said.status.code(), Some(4), "{asks:?}: {why}");
            assert!(why.contains("scope"), "{asks:?}: {why}");
        }
    }
    // The full key is answered.
    let (code, list, said) = host.asked("sessions", &[]);
    assert_eq!(code, Some(0), "{said}");
    assert!(list.starts_with("s\tdetached\trunning\t"), "{list:?}");
}

#[test]
fn the_recipes_of_help_agents_read_what_the_commands_read() {
    let host = Host::start("recipes", &[]);
    let pane = host.session("s", &marking_shell(&host), "$");
    // The script is the end of what `koh help-agents` prints, from its first line on; the help
    // itself has none of it.
    let (_, help, _) = koh(&host.tmp.0, &["help-agents"]);
    let script = host.tmp.0.join("sessions.sh");
    fs::write(&script, &help[help.find("#!/bin/sh").unwrap()..]).unwrap();
    assert!(!koh(&host.tmp.0, &["--help"]).1.contains("#!/bin/sh"));
    let recipe = |args: &[&str]| {
        let mut sh = Command::new("sh");
        let said = sh.arg(&script).args(args).output().unwrap();
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        (said.status.code(), text(&said.stdout), text(&said.stderr))
    };
    // Run on the server, where the folders are, it lists, shows and waits as the commands do.
    let (dir, pane_dir) = (host.sessions.to_str().unwrap(), pane.to_str().unwrap());
    fs::write(pane.join("in"), "sh -c 'echo from-the-recipe; exit 9'\n").unwrap();
    until("the command has ended", || {
        host.asked("sessions", &[]).1.contains("\texit=9\t")
    });
    let (code, list, said) = recipe(&["list", dir]);
    assert_eq!(
        (code, list.as_str()),
        (Some(0), "s\talive\trunning\t80x24\tidle\t9\t\n"),
        "{said}"
    );
    let (code, last, said) = recipe(&["last", pane_dir]);
    assert_eq!(
        (code, last.as_str()),
        (Some(0), "from-the-recipe\n"),
        "{said}"
    );
    assert_eq!(last, host.asked("output", &["--session", "s", "--last"]).1);
    let (code, shown, said) = recipe(&["wait", pane_dir, "1"]);
    assert_eq!((code, shown), (Some(124), screen(&pane)), "{said}");
    assert_eq!(recipe(&["screen", pane_dir]).1, screen(&pane));
    // The session ends: the recipe's wait ends with the program's status.
    fs::write(pane.join("in"), "exit 3\n").unwrap();
    assert_eq!(recipe(&["wait", pane_dir, "20"]).0, Some(3));
    assert_eq!(
        recipe(&["list", dir]).1,
        "s\tended\texited 3\t80x24\tidle\t9\t\n"
    );
    // Its wait has the command's rule: marks that only moved end nothing (a line inserted
    // above the prompt), and of two commands that ended the code is the first's.
    let steps = ["ran one 7", MOVES[0], "ran two 9; ran three 5"];
    let moving = host.session("m", &marks_by_steps(&steps), "$");
    let step = |done: u32| {
        fs::write(moving.join("in"), "\n").unwrap();
        let title = format!("done-{done}\n");
        until(&title, || {
            fs::read_to_string(moving.join("title")).is_ok_and(|said| said == title)
        });
    };
    step(1);
    let mut wait = Command::new("sh");
    wait.arg(&script)
        .args(["wait", moving.to_str().unwrap(), "30"]);
    let mut wait = Waits(
        wait.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap(),
    );
    std::thread::sleep(Duration::from_millis(500));
    step(2);
    std::thread::sleep(Duration::from_millis(500));
    assert!(!wait.ended(), "{:?}", wait.said());
    step(3);
    until("the recipe's wait ends", || wait.ended());
    assert_eq!(wait.said().0, Some(9));
    // And its list has a pane that has only begun: a `status`, and nothing else yet.
    fs::create_dir(host.sessions.join("bare")).unwrap();
    fs::write(host.sessions.join("bare/status"), "holder 1\n").unwrap();
    let (code, list, said) = recipe(&["list", dir]);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        list.starts_with("bare\tended\t\t0x0\tidle\t-\t\n"),
        "{list:?} {said}"
    );
}

/// A program for a session that marks as a shell does (OSC 133), by itself: a prompt, and then,
/// each time a line is entered, the next of `steps` (sh, with `prompt` and `ran TEXT CODE` for a
/// command that printed and ended); after each the pane's title says how many are done.
fn marks_by_steps(steps: &[&str]) -> Vec<String> {
    let script = r#"stty -echo
m() { printf '\033]133;%s\007' "$1"; }
prompt() { m A; printf '$ '; m B; }
ran() { printf '\r\n'; m C; printf '%s\r\n' "$1"; m "D;$2"; prompt; }
n=0; prompt; printf '\033]2;done-0\007'
for step in "$@"; do read line; eval "$step"; n=$((n + 1)); printf '\033]2;done-%s\007' "$n"; done
read line"#;
    let mut program = sh(script);
    program.push("sh".into());
    program.extend(steps.iter().map(|step| step.to_string()));
    program
}

/// The four ways a screen moves its marks without a command's end: a line inserted above the
/// prompt, a scroll down, a clear with the prompt drawn anew, the prompt drawn again in its place.
const MOVES: [&str; 4] = [
    r"printf '\0337\033[1;1H\033[L\0338\033[B'",
    r"printf '\033[T\033[B'",
    r"printf '\033[H\033[2J'; prompt",
    r"printf '\r'; prompt",
];

/// A wait asked of the server by the client in this process: the stream, once the server has
/// taken the request.
async fn waits(client: &Client, session: &str) -> RecvStream {
    let asked = Request::WaitSession {
        session: session.into(),
        timeout_secs: Some(8),
    };
    client.request(&asked).await.unwrap().1
}

/// What a wait was answered: its exit code and its text.
async fn waited(wait: RecvStream) -> (i32, String) {
    let (exit, text, _) = told(wait).await;
    (exit, text)
}

/// The same, and the word it was answered with.
async fn told(mut wait: RecvStream) -> (i32, String, String) {
    let ended: koh::proto::WaitResult = recv_msg(&mut wait, MAX_CTRL).await.unwrap();
    let text = koh::proto::recv_pieces(&mut wait).await.unwrap();
    (ended.exit, String::from_utf8(text).unwrap(), ended.detail)
}

/// Whether a wait has said nothing for four looks of the server's.
async fn silent(wait: &mut RecvStream) -> bool {
    let look = Duration::from_millis(400);
    tokio::time::timeout(look, wait.read(&mut [0; 1]))
        .await
        .is_err()
}

/// A session of `marks_by_steps`, and how many of its steps are done.
struct Stepped(PathBuf, u32);

impl Stepped {
    fn start(host: &Host, steps: &[&str]) -> Self {
        Self(host.session("s", &marks_by_steps(steps), "$"), 0)
    }

    /// Has the next step done, and gives the pane's `marks` after it.
    fn step(&mut self) -> String {
        self.1 += 1;
        stepped(&self.0, self.1)
    }
}

/// Has a session of `marks_by_steps` do its next step, the `done`th, and gives the pane's
/// `marks` once its title says so: the two as one round of the holder's left them, read
/// between two looks at the same even `generation`. (A round writes `title` before `marks`:
/// read one after the other and no more, the marks may be those of the round before, which
/// under load is one from the middle of the step.)
fn stepped(pane: &Path, done: u32) -> String {
    fs::write(pane.join("in"), "\n").unwrap();
    let title = format!("done-{done}\n");
    let read = |name: &str| fs::read_to_string(pane.join(name)).unwrap_or_default();
    let mut marks = String::new();
    until(&title, || {
        let number = read("generation");
        let even = number.trim().parse::<u64>().is_ok_and(|n| n % 2 == 0);
        let said = read("title");
        marks = read("marks");
        even && said == title && read("generation") == number
    });
    marks
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_is_not_ended_by_marks_that_only_moved() {
    let host = Host::start("moved", &[]);
    let fill = "i=0; while [ $i -lt 260 ]; do ran fill 0; i=$((i + 1)); done";
    let cleared = r"printf '\r\n'; m C; printf '\033[H\033[2Jfour\r\n'; m 'D;4'; prompt";
    let mut steps = vec!["ran one 7"];
    steps.extend(MOVES);
    steps.extend(["ran two 9", fill]);
    steps.extend(MOVES);
    steps.push(cleared);
    let pane = host.session("s", &marks_by_steps(&steps), "$");
    let mut done = 0;
    let mut step = || {
        done += 1;
        stepped(&pane, done)
    };
    let client = host.client().await;
    // A command has ended with 7; a wait is asked at the prompt after it. The marks are few, and
    // all on the screen.
    let before = step();
    let mut wait = waits(&client, "s").await;
    // Whatever moves the screen moves its marks, and is no command's end: the wait says nothing.
    for moved in [
        "a line inserted",
        "a scroll down",
        "a clear",
        "the prompt again",
    ] {
        let marks = step();
        let said = tokio::time::timeout(Duration::from_millis(400), wait.read(&mut [0; 1])).await;
        assert!(
            said.is_err(),
            "after {moved} the wait ended: {before:?} became {marks:?}"
        );
    }
    // A command's end is one.
    step();
    assert_eq!(waited(wait).await, (9, "two\n".to_string()));
    // The same in a pane whose `marks` is full: it keeps a thousand, and drops one for each it takes.
    let full = step();
    assert_eq!(full.lines().count(), 1000);
    let mut wait = waits(&client, "s").await;
    for moved in [
        "a line inserted",
        "a scroll down",
        "a clear",
        "the prompt again",
    ] {
        let marks = step();
        let said = tokio::time::timeout(Duration::from_millis(400), wait.read(&mut [0; 1])).await;
        assert!(
            said.is_err(),
            "full, after {moved} the wait ended: {marks:?}"
        );
    }
    // There a command that clears the screen and ends no further down than the last has ended too.
    let marks = step();
    assert_eq!(marks.lines().count(), 1000);
    assert_eq!(waited(wait).await, (4, "four\n".to_string()));
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_gives_the_first_command_that_ended_since_it_was_asked() {
    let host = Host::start("first", &[]);
    // Two commands end before the wait looks again: one typed while the other ran.
    let pane = host.session(
        "s",
        &marks_by_steps(&["ran one 7", "ran two 0; ran three 5"]),
        "$",
    );
    let step = |done: u32| {
        fs::write(pane.join("in"), "\n").unwrap();
        let title = format!("done-{done}\n");
        until(&title, || {
            fs::read_to_string(pane.join("title")).is_ok_and(|said| said == title)
        });
    };
    step(1);
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    step(2);
    // It is the first of them that the wait was for: its code, and what it printed.
    assert_eq!(waited(wait).await, (0, "two\n".to_string()));
    client.close().await;
}

#[tokio::test]
async fn a_list_of_sessions_longer_than_one_message_is_whole() {
    let (_tmp, srv, client, _, state) = boot_pair("many").await;
    // As many ended panes as `--max-sessions` may keep, each with a title as long as fux
    // writes one: more than a message holds.
    let sessions = state.join("fux/koh-sessions");
    for n in 1..=4500 {
        let pane = sessions.join(n.to_string());
        fs::create_dir(&pane).unwrap();
        fs::write(pane.join("status"), "holder 1\npid 1\n").unwrap();
        fs::write(pane.join("run"), format!("{n:032x}\n")).unwrap();
        fs::write(pane.join("title"), "t".repeat(256) + "\n").unwrap();
    }
    let list = client.sessions().await.unwrap();
    assert_eq!(list.len(), 4500);
    assert!(
        list.iter()
            .all(|session| session.title.len() == 256 && session.state == "ended")
    );
    client.close().await;
    srv.shutdown().await;
}

#[test]
fn a_wait_for_a_job_and_a_session_at_once_is_a_usage_error() {
    let tmp = TempDir::new("wait-usage");
    // A wait is for a job or for a session; what is a job's alone is not said of a session.
    for more in [&["build"][..], &["--text", "done"], &["--tail", "5"]] {
        let mut args = vec!["wait", "nowhere", "--session", "s"];
        args.extend(more);
        let (code, _, said) = koh(&tmp.0, &args);
        assert_eq!(code, Some(2), "{more:?}: {said}");
        assert!(
            said.contains("a job's") && said.contains("--session"),
            "{more:?}: {said}"
        );
    }
}

// The sequences of the second round of reviews, each against fux's holder: what a full `marks`
// could not say, and its count of the marks it dropped does.

/// So many times `body`, as one step of a session's program.
fn times(n: u32, body: &str) -> String {
    format!("i=0; while [ $i -lt {n} ]; do {body}; i=$((i + 1)); done")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_sees_a_commands_end_in_a_shell_that_clears_at_every_command() {
    let host = Host::start("clears", &[]);
    // `clear; echo hi N`, 255 times, in a pane of 80 by 24: the file is full, and every mark
    // of it but the last few is at one place. Then a command that ends with 4, and 16 more.
    let clears = times(
        255,
        r"printf '\r\n'; m C; printf '\033[H\033[2Jhi %s\r\n' $i; m 'D;0'; prompt",
    );
    let more = times(16, "ran more $((i + 10))");
    let mut session = Stepped::start(&host, &[&clears, "ran four 4", &more, "ran fresh 3"]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    session.step();
    session.step();
    assert_eq!(waited(wait).await, (4, "four\n".to_string()));
    // And a wait asked afresh after those.
    let wait = waits(&client, "s").await;
    session.step();
    assert_eq!(waited(wait).await, (3, "fresh\n".to_string()));
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_screen_that_moves_ends_nothing_where_every_mark_is_on_it() {
    let host = Host::start("on-screen", &[]);
    // `clear` 255 times and `true`: a full file whose first mark is still on the screen. A
    // command begins, scrolls the screen down, and ends with 5 only later.
    let clears = times(
        255,
        r"printf '\r\n'; m C; printf '\033[H\033[2J'; m 'D;0'; prompt",
    );
    let begun = r"printf '\r\n'; m C; printf '\033[1T'";
    let steps = [
        &clears,
        r"printf '\r\n'; m C; m 'D;0'; prompt",
        begun,
        "m 'D;5'; prompt",
    ];
    let mut session = Stepped::start(&host, &steps);
    session.step();
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let mut wait = waits(&client, "s").await;
    let scrolled = session.step();
    assert!(
        silent(&mut wait).await,
        "the wait ended at a scroll down: {scrolled:?}"
    );
    session.step();
    assert_eq!(waited(wait).await.0, 5);
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_line_inserted_ends_nothing_where_a_shell_clears_at_each_prompt() {
    let host = Host::start("inserted", &[]);
    // 260 commands, each at a prompt drawn on a cleared screen: a full file on three rows.
    let cleared = r"printf '\033[H\033[2J'; prompt; printf '\r\n'; m C; printf 'x\r\n'; m 'D;7'";
    let fill = times(260, cleared) + "; prompt";
    let mut session = Stepped::start(&host, &[&fill, MOVES[0], "ran after 3"]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let mut wait = waits(&client, "s").await;
    let inserted = session.step();
    assert!(
        silent(&mut wait).await,
        "the wait ended at a line inserted: {inserted:?}"
    );
    session.step();
    assert_eq!(waited(wait).await, (3, "after\n".to_string()));
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn more_marks_than_a_pane_keeps_between_two_looks_are_said_and_not_guessed() {
    let host = Host::start("burst", &[]);
    // One command has ended; then the marks of 300, in one write: more than the file keeps.
    let one = r#"s="$s\r\n\033]133;C\007burst-$i\r\n\033]133;D;$((i % 100))\007\033]133;A\007\$ \033]133;B\007""#;
    let burst = format!(r#"s=; {}; printf "$s""#, times(300, one));
    let mut session = Stepped::start(&host, &["ran one 7", &burst]);
    session.step();
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    // The server looks ten times a second, and the holder writes the burst in as many rounds
    // as it reads it in. So that all of it is between two looks, the server stands still
    // from the look the wait was asked with until the pane has the whole burst: a look in the
    // middle would find the first command, or the oldest of that moment.
    let server = host.served.as_ref().unwrap().server.id().to_string();
    let state = || {
        let ps = Command::new("ps")
            .args(["-o", "state=", "-p", &server])
            .output();
        String::from_utf8_lossy(&ps.unwrap().stdout).into_owned()
    };
    signal(&server, "-STOP");
    until("the server is stopped", || state().contains('T'));
    let marks = session.step();
    signal(&server, "-CONT");
    assert_eq!(marks.lines().count(), 1000);
    let (code, text, said) = told(wait).await;
    // The first that ended is not there any more. The wait gives the oldest that is, and says
    // that it is not known to be the first.
    let kept = marks.lines().filter(|mark| mark.contains(" end")).count();
    let oldest = 300 - kept;
    assert!(said.contains("marks came and went unread"), "{said}");
    assert_eq!(
        (code, text),
        ((oldest % 100) as i32, format!("burst-{oldest}\n")),
        "{said}"
    );
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_end_is_the_first_where_the_files_oldest_marks_are_alike() {
    let host = Host::start("alike", &[]);
    // Three commands and a clear, which puts their marks at one place; 247 more, and the file
    // is full with those alike at its front. Then an empty line entered, whose `end` has the
    // code of the command before, and a command that ends with 22: the first is the first.
    let quiet = r"printf '\r\n'; m C; m 'D;0'; prompt";
    let fill = format!(
        "{quiet}; {quiet}; {quiet}; printf '\\r\\n'; m C; printf '\\033[H\\033[2J'; m 'D;0'; prompt; {}",
        times(247, "ran fill 1")
    );
    let entered = r"printf '\r\n'; m 'D;1'; prompt; ran second 22";
    let mut session = Stepped::start(&host, &[&fill, entered]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    session.step();
    assert_eq!(waited(wait).await, (1, "fill\n".to_string()));
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_end_is_seen_where_a_prompt_drawn_again_left_a_full_file_short() {
    let host = Host::start("short", &[]);
    // A full file. A command ends with 77; a prompt with no `end` (Ctrl-C); a clear and the
    // prompt anew, which takes two marks back: 998 lines, and six were dropped.
    let after = r"ran hello 77; printf '^C\r\n'; prompt; printf '\033[H\033[2J'; prompt";
    let mut session = Stepped::start(&host, &[&times(260, "ran fill 0"), after]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    assert_eq!(session.step().lines().count(), 998);
    // (What it printed went with the clear, unless the wait looked before that.)
    assert_eq!(waited(wait).await.0, 77);
    client.close().await;
}

#[tokio::test]
async fn each_client_dials_from_its_own_key_and_proves_the_client_key() {
    let tmp = TempDir::new("ephemeral-dial");
    let key = new_key(&tmp, "client.key");
    let (srv, route) = boot_server(&tmp, vec![key.public()], ServeOptions::default()).await;
    let dial = || Client::connect_direct(key.clone(), srv.endpoint_id, route.clone(), false);

    let (a, b) = (dial().await.unwrap(), dial().await.unwrap());
    assert!(srv.endpoint.remote_info(key.public()).await.is_none());
    let (r1, r2) = tokio::join!(a.jobs(None), b.jobs(None));
    assert!(r1.unwrap().is_empty() && r2.unwrap().is_empty());
    a.close().await;
    b.close().await;

    let cfg = koh::net::transport_config(false);
    let (e1, _, _) = koh::net::connect_server(srv.endpoint_id, route.clone(), cfg.clone())
        .await
        .unwrap();
    let (e2, _, _) = koh::net::connect_server(srv.endpoint_id, route, cfg)
        .await
        .unwrap();
    assert_ne!(e1.id(), key.public());
    assert_ne!(e2.id(), key.public());
    assert_ne!(e1.id(), e2.id());
    assert!(srv.endpoint.remote_info(e1.id()).await.is_some());
    assert!(srv.endpoint.remote_info(e2.id()).await.is_some());
    e1.close().await;
    e2.close().await;
    srv.shutdown().await;
}

#[test]
fn clients_file_scopes_fail_closed_and_preserve_spaces() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    let tmp = TempDir::new("clients-parse");
    let (key, file) = (tmp.0.join("server.key"), tmp.0.join("clients"));
    let k = iroh::SecretKey::from_bytes(&[1; 32]).public();
    let cp = |p: &str| Scope::Cp(p.into());
    let ex = |p: &str| Scope::Exec(p.into());
    let rows = [
        ("# comment".into(), None),
        (String::new(), None),
        (format!("full {k}"), Some(("full", Scope::Full))),
        (format!("ws {k}   "), Some(("ws", Scope::Full))),
        (format!("cp {k} cp=/srv"), Some(("cp", cp("/srv")))),
        (format!("sp {k}\tcp=/a  b "), Some(("sp", cp("/a  b ")))),
        (format!("ex {k} exec=~/a b"), Some(("ex", ex("~/a b")))),
        (format!("h {k} cp=/a # n"), Some(("h", cp("/a # n")))),
        (format!("cr {k} cp=/c d\r"), Some(("cr", cp("/c d")))),
        (format!("t1 {k} copy=/srv"), None),
        (format!("t2 {k} cp:/srv"), None),
        (format!("t3 {k} cp"), None),
        (format!("t4 {k} cp="), None),
        (format!("t5 {k} exec="), None),
        (format!("t6 {k} --cp /srv\x1b[2K"), None),
        ("bad_id notakey cp=/srv".into(), None),
        ("lone_word".into(), None),
    ];
    let text: Vec<_> = rows.iter().map(|(l, _)| l.as_str()).collect();
    fs::write(&file, format!("{}\n", text.join("\n"))).unwrap();

    let mut skipped = Vec::new();
    let entries =
        koh::keys::load_clients(Some(&key), |n, l| skipped.push((n, l.to_string()))).unwrap();
    let want: Vec<_> = rows.iter().filter_map(|(_, w)| w.clone()).collect();
    let got: Vec<_> = entries
        .iter()
        .map(|e| (e.name.as_str(), e.scope.clone()))
        .collect();
    assert_eq!(got, want);
    let skipped_want: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, (l, w))| w.is_none() && !l.is_empty() && !l.starts_with('#'))
        .map(|(i, (l, _))| (i + 1, l.clone()))
        .collect();
    assert_eq!(skipped, skipped_want);

    let cli = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_koh"));
        c.arg("clients").arg("--key-file").arg(&key).args(args);
        c
    };
    let out = cli(&[]).output().unwrap();
    assert!(out.status.success());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    for (name, _) in &want {
        assert!(stdout.contains(&format!("{name} ")), "{stdout}");
    }
    assert_eq!(stderr.lines().count(), skipped_want.len(), "{stderr}");
    for (n, line) in &skipped_want {
        let expected =
            format!("koh: clients:{n}: ignored, not NAME ID [cp=DIR|exec=DIR]: {line:?}");
        assert!(stderr.contains(&expected), "missing {expected} in {stderr}");
    }

    let injected = format!("/a\nevil {k}");
    for flag in ["--cp", "--exec"] {
        for bad in [b"".as_slice(), injected.as_bytes(), b"/a\rb", b"/a\xffb"] {
            let res = cli(&["add", "bad", &k.to_string(), flag])
                .arg(OsStr::from_bytes(bad))
                .output()
                .unwrap();
            assert_eq!(res.status.code(), Some(2), "{flag} {bad:?}");
        }
    }
    let bad_json = Command::new(env!("CARGO_BIN_EXE_koh"))
        .arg("servers")
        .arg(OsStr::from_bytes(b"\xff"))
        .arg("--json")
        .output()
        .unwrap();
    assert_eq!(bad_json.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_json.stdout).contains("\"kind\":\"usage\""));
    assert!(bad_json.stderr.is_empty());
    // Trailing CRs on the last line without LF are line endings, not DIR, and survive a rename.
    fs::write(&file, format!("lead {k}\nlast {k} cp=/x\r\r")).unwrap();
    assert_eq!(
        koh::keys::load_clients(Some(&key), |_, _| {}).unwrap()[1].scope,
        cp("/x")
    );
    assert!(
        cli(&["rename", "lead", "renamed"])
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        koh::keys::load_clients(Some(&key), |_, _| {}).unwrap()[1].scope,
        cp("/x")
    );

    // Hand-written bare CR in another line does not block `koh clients rm`.
    fs::write(&file, format!("raw {k} cp=/a\rb\nother {k}\n")).unwrap();
    assert!(cli(&["rm", "other"]).status().unwrap().success());
}

#[tokio::test]
async fn server_refuses_bad_clients_line_and_enforces_spaced_scope_dir() {
    let tmp = TempDir::new("clients-enforce");
    let (dir_a, dir_ab) = (tmp.0.join("a"), tmp.0.join("a b"));
    for d in [&tmp.0.join("srv_cfg"), &dir_a, &dir_ab] {
        fs::create_dir_all(d).unwrap();
    }
    let srv_key = tmp.0.join("srv_cfg/server.key");
    let valid = new_key(&tmp, "v.key");
    let typo = new_key(&tmp, "t.key");
    let cp_key = new_key(&tmp, "c.key");
    let mut add = Command::new(env!("CARGO_BIN_EXE_koh"));
    add.args(["clients", "--key-file"]).arg(&srv_key);
    add.args(["add", "cpbot", &cp_key.public().to_string(), "--cp"])
        .arg(&dir_ab);
    assert!(add.status().unwrap().success());
    let mut text = fs::read_to_string(tmp.0.join("srv_cfg/clients")).unwrap();
    text.push_str(&format!(
        "typo {} copy=/srv\nvalid {}\n",
        typo.public(),
        valid.public()
    ));
    fs::write(tmp.0.join("srv_cfg/clients"), text).unwrap();

    let (srv, route) = boot_server(&tmp, Vec::new(), ServeOptions::default()).await;
    let dial = |k| Client::connect_direct(k, srv.endpoint_id, route.clone(), false);
    let t = dial(typo).await.unwrap();
    let v = dial(valid).await.unwrap();
    let c = dial(cp_key).await.unwrap();
    assert_eq!(t.jobs(None).await.unwrap_err().code, Exit::REFUSED);
    assert!(v.jobs(None).await.unwrap().is_empty());
    let f = tmp.0.join("f.txt");
    fs::write(&f, "hi").unwrap();
    let push = |d: &Path| c.cp_push(&f, d.display().to_string(), vec![], false, false, false);
    assert_eq!(push(&dir_a).await.unwrap_err().code, Exit::REFUSED);
    assert_eq!(push(&dir_ab).await.unwrap().added, vec!["f.txt"]);
    for cl in [t, v, c] {
        cl.close().await;
    }
    srv.shutdown().await;
}

fn wait_child(child: &mut std::process::Child, secs: u64, what: &str) -> std::process::ExitStatus {
    let until = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} timed out after {secs}s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn box_sh(host: &Host, script: &str) {
    let addr = host.addr();
    let add = ["servers", "add", "box", &host.id, "--direct", &addr];
    assert!(host.koh(&add).status().unwrap().success());
    let bin = Path::new(env!("CARGO_BIN_EXE_koh")).parent().unwrap();
    let mut paths = vec![bin.to_path_buf()];
    if let Some(old) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&old));
    }
    let mut child = Command::new("/bin/sh")
        .args(["-ec", script])
        .current_dir(&host.tmp.0)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("KOH_CONFIG_DIR", host.tmp.0.join("cli_cfg"))
        .env("XDG_RUNTIME_DIR", host.tmp.0.join("crun"))
        .env("XDG_CONFIG_HOME", host.tmp.0.join("xdg_cfg"))
        .env("HOME", host.tmp.0.join("home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out_r = child.stdout.take().unwrap();
    let mut err_r = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_r.read_to_end(&mut b);
        b
    });
    let err_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_r.read_to_end(&mut b);
        b
    });
    let status = wait_child(&mut child, 30, "box_sh");
    let (stdout, stderr) = (out_t.join().unwrap(), err_t.join().unwrap());
    assert!(
        status.success(),
        "status={status:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
}

#[test]
fn exec_exits_when_remote_command_ends_even_with_open_stdin() {
    let host = Host::start("exec-open-stdin", &[]);
    let addr = host.addr();
    let run_open = |args: &[&str]| {
        let mut child = host
            .koh(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let _hold = child.stdin.take().unwrap();
        let mut out = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        });
        let st = wait_child(&mut child, 5, "koh with open stdin");
        (st.code(), reader.join().unwrap())
    };
    let (rc, out) = run_open(&[
        "exec",
        &host.id,
        "--direct",
        &addr,
        "--",
        "/bin/sh",
        "-c",
        "printf 'hi\\n'; exit 7",
    ]);
    assert_eq!((rc, out.as_slice()), (Some(7), b"hi\n".as_slice()));
    let awk = "BEGIN { for (i = 0; i < 4096; i++) printf \"0123456789abcdef0123456789abcdef\\n\" }";
    let (rc, out) = run_open(&["exec", &host.id, "--direct", &addr, "--", "awk", awk]);
    assert_eq!(rc, Some(0));
    assert_eq!(out, b"0123456789abcdef0123456789abcdef\n".repeat(4096));
    let (rc, out) = run_open(&[
        "rsh",
        "--direct",
        &addr,
        &host.id,
        "printf 'rsh-hi\\n'; exit 11",
    ]);
    assert_eq!((rc, out.as_slice()), (Some(11), b"rsh-hi\n".as_slice()));

    // At the lowest open-fd limit where `koh exec` can bind, both stdout and stderr arrive
    // without needing spare descriptors to duplicate them.
    box_sh(
        &host,
        "found=0
         for n in 10 11 12 13 14 15 16 18 20 24 32; do
           set +e
           (ulimit -n \"$n\" 2>/dev/null && exec koh exec box -- /bin/sh -c 'printf O; printf E >&2') >o 2>e
           rc=$?
           set -e
           if [ \"$rc\" = 0 ]; then
             found=1
             [ \"$(cat o)\" = O ]
             [ \"$(cat e)\" = E ]
             break
           fi
         done
         [ \"$found\" = 1 ]",
    );
}

#[test]
fn exec_and_rsh_handle_nonblocking_socketpair() {
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    let host = Host::start("nonblock-sock", &[]);
    let addr = host.addr();

    // Non-blocking stdin: send second line only after first has been echoed; wait for child first.
    let (mut peer, sock) = UnixStream::pair().unwrap();
    sock.set_nonblocking(true).unwrap();
    let mut peer_r = peer.try_clone().unwrap();
    let mut child = host
        .koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "cat; exit 37",
        ])
        .stdin(OwnedFd::from(sock.try_clone().unwrap()))
        .stdout(OwnedFd::from(sock))
        .spawn()
        .unwrap();
    let (echoed_tx, echoed_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let mut notified = false;
        while let Ok(n @ 1..) = peer_r.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
            if !notified && got.starts_with(b"hello\n") {
                notified = true;
                let _ = echoed_tx.send(());
            }
        }
        got
    });
    peer.write_all(b"hello\n").unwrap();
    echoed_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first line was not echoed");
    peer.write_all(b"world\n").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        wait_child(&mut child, 10, "nonblock stdin").code(),
        Some(37)
    );
    assert_eq!(reader.join().unwrap(), b"hello\nworld\n");

    // Non-blocking stdout: 1.5 MiB (exceeds default Unix socket buffers) with a delayed
    // small-buffer reader arrives whole.
    let (mut peer, sock) = UnixStream::pair().unwrap();
    sock.set_nonblocking(true).unwrap();
    let cmd = "awk 'BEGIN { for (i = 0; i < 15000; i++) printf \"%099d\\n\", i }'; exit 19";
    let mut child = host
        .koh(&["rsh", "--direct", &addr, &host.id, cmd])
        .stdin(OwnedFd::from(sock.try_clone().unwrap()))
        .stdout(OwnedFd::from(sock))
        .spawn()
        .unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    let reader = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(400));
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n @ 1..) = peer.read(&mut buf) {
            out.extend_from_slice(&buf[..n]);
        }
        out
    });
    let st = wait_child(&mut child, 15, "nonblock stdout");
    let out = reader.join().unwrap();
    assert_eq!(st.code(), Some(19));
    let expected: Vec<u8> = (0..15000)
        .flat_map(|i| format!("{i:099}\n").into_bytes())
        .collect();
    assert_eq!(out.len(), expected.len());
    assert_eq!(out, expected);
}

#[test]
fn rsh_options_rsync_and_git() {
    let host = Host::start("rsh-e2e", &[]);
    let direct_cmd = format!(
        "koh rsh --direct {} {} printf ok >o
         [ \"$(cat o)\" = ok ]
         koh servers add -box {} --direct {}
         koh rsh -- -box printf ok >o
         [ \"$(cat o)\" = ok ]",
        host.addr(),
        host.id,
        host.id,
        host.addr(),
    );
    box_sh(
        &host,
        &format!(
            "set +e; koh rsh box 'printf out; printf err >&2; exit 9' >o 2>e; rc=$?; set -e
             [ \"$rc\" = 9 ]
             [ \"$(cat o)\" = out ]
             [ \"$(cat e)\" = err ]
             printf 'in\\n' | koh rsh box cat >o
             [ \"$(cat o)\" = in ]
             koh rsh -- box printf %s --json >o
             [ \"$(cat o)\" = --json ]
             {direct_cmd}
             for f in -G -o -l -p --json; do
               set +e; koh rsh \"$f\" box --json >o 2>e; rc=$?; set -e
               [ \"$rc\" = 2 ]
               [ ! -s o ]
               grep -Fq -- \"$f\" e
               grep -Fq 'rsh does not support' e
             done
             set +e; koh rsh nosuchhostxyz printf %s --json >o 2>e; rc=$?; set -e
             [ \"$rc\" = 2 ]
             [ ! -s o ]
             [ -s e ]
             set +e; koh rsh box >o 2>e; rc=$?; set -e
             [ \"$rc\" = 2 ]
             [ ! -s o ]
             grep -Fq usage e"
        ),
    );

    let (src, dst) = (host.tmp.0.join("src"), host.tmp.0.join("home/dst"));
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::create_dir_all(src.join("target")).unwrap();
    fs::create_dir_all(dst.join("target")).unwrap();
    let big: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
    fs::write(src.join("big.bin"), &big).unwrap();
    fs::write(src.join("sub/with space.txt"), b"spaced\n").unwrap();
    std::os::unix::fs::symlink("sub/with space.txt", src.join("link_s")).unwrap();
    fs::write(src.join("target/ignored.txt"), b"skip").unwrap();
    fs::write(dst.join("stray.txt"), b"bye").unwrap();
    fs::write(dst.join("target/keep.txt"), b"stay").unwrap();

    box_sh(
        &host,
        "tar -C src -cf - . | koh rsh box 'mkdir -p tardst && tar -C tardst -xf -'",
    );
    let tar_f = host.tmp.0.join("home/tardst/sub/with space.txt");
    assert_eq!(fs::read(tar_f).unwrap(), b"spaced\n");

    if Command::new("rsync").arg("--version").output().is_err() {
        eprintln!("skipping rsync in rsh_options_rsync_and_git: rsync not installed");
    } else {
        let sync = "rsync -a --delete --exclude target -e 'koh rsh' src/ box:dst/";
        box_sh(&host, sync);
        assert_eq!(fs::read(dst.join("big.bin")).unwrap(), big);
        assert_eq!(
            fs::read(dst.join("sub/with space.txt")).unwrap(),
            b"spaced\n"
        );
        let link = fs::read_link(dst.join("link_s")).unwrap();
        assert_eq!(link, Path::new("sub/with space.txt"));
        assert!(!dst.join("stray.txt").exists() && !dst.join("target/ignored.txt").exists());
        assert_eq!(fs::read(dst.join("target/keep.txt")).unwrap(), b"stay");

        let inos = || {
            (
                fs::metadata(dst.join("big.bin")).unwrap().ino(),
                fs::metadata(dst.join("sub/with space.txt")).unwrap().ino(),
            )
        };
        let before = inos();
        box_sh(&host, sync);
        assert_eq!(inos(), before, "second rsync rewrote unchanged files");

        box_sh(&host, "rsync -a -e 'koh rsh' box:dst/ pulled/");
        assert_eq!(fs::read(host.tmp.0.join("pulled/big.bin")).unwrap(), big);
        let p_sp = host.tmp.0.join("pulled/sub/with space.txt");
        assert_eq!(fs::read(p_sp).unwrap(), b"spaced\n");
        let p_lk = fs::read_link(host.tmp.0.join("pulled/link_s")).unwrap();
        assert_eq!(p_lk, Path::new("sub/with space.txt"));
    }

    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping git in rsh_options_rsync_and_git: git not installed");
    } else {
        box_sh(
            &host,
            "koh rsh box git init -q --bare demo.git
             mkdir work
             cd work
             git init -q
             printf 'from-git\\n' > hello.txt
             git add hello.txt
             git commit -qm init
             GIT_SSH_COMMAND='koh rsh' git push box:demo.git HEAD:refs/heads/main
             cd ..
             GIT_SSH_COMMAND='koh rsh' git clone -b main box:demo.git cloned",
        );
        let cloned = host.tmp.0.join("cloned/hello.txt");
        assert_eq!(fs::read(cloned).unwrap(), b"from-git\n");
    }
}

#[test]
fn cp_delete_requires_one_directory_push_and_pull() {
    let host = Host::start("cp-delete-dir", &[]);
    box_sh(
        &host,
        "mkdir -p ld ldst home/rd home/rdst
         printf f > f; ln -s f lf; ln -s ld ld_link; printf ok > ld/ok
         printf rf > home/rf; ln -s rf home/rlf; ln -s rd home/rd_link; printf rok > home/rd/rok
         printf h > home/keep_home; printf k > home/rdst/keep; printf k > ldst/keep
         refuse() {
           set +e; koh cp --delete \"$1\" \"$2\" >o 2>e; rc=$?; set -e
           [ \"$rc\" = 2 ]
           grep -Fq directory e
           grep -Fq deleted e
         }
         refuse f box:rdst/; refuse f box:; refuse lf box:rdst/
         refuse box:rf ldst; refuse box:rlf ldst
         set +e; koh cp --delete ld ld box:rdst/ >o 2>e; rc=$?; set -e
         [ \"$rc\" = 2 ]
         grep -Fq 'single source' e
         for pair in 'missing box:rdst/' 'box:missing ldst'; do
           set +e; koh cp --delete $pair >o 2>e; rc=$?; set -e
           [ \"$rc\" = 1 ]
         done
         [ -f home/rdst/keep ]
         [ -f ldst/keep ]
         [ -f home/keep_home ]
         for s in ld ld/ ld/. ld_link; do
           printf s > home/rdst/stray
           koh cp -r --delete \"$s\" box:rdst/ >/dev/null
           [ -f home/rdst/ok ]
           [ ! -e home/rdst/stray ]
         done
         for s in box:rd box:rd/ box:rd/. box:rd_link; do
           printf s > ldst/stray
           koh cp -r --delete \"$s\" ldst >/dev/null
           [ -f ldst/rok ]
           [ ! -e ldst/stray ]
         done",
    );
}

#[test]
fn failed_run_preserves_existing_job_and_leaves_no_orphan() {
    let host = Host::start("run-keep-job", &[]);
    box_sh(
        &host,
        "set +e; koh run box --name fresh -- /no/such/bin; rc=$?; set -e
         [ \"$rc\" = 127 ]
         [ ! -e run/koh/jobs/fresh ]
         koh run box --name keep -- /bin/sh -c 'printf \"kept\\n\"' >/dev/null
         koh wait box keep --timeout 10 >/dev/null
         set +e
         koh run box --name keep -- /no/such/bin; rc1=$?
         koh run box -C /no/such/dir --name keep -- true; rc2=$?
         set -e
         [ \"$rc1\" = 127 ]
         [ \"$rc2\" = 126 ]
         koh logs box keep --all >o
         [ \"$(cat o)\" = kept ]
         koh jobs box keep >o
         grep -Fq 'keep	exited 0' o
         koh run box --name keep -- /bin/sh -c 'printf \"new\\n\"' >/dev/null
         koh wait box keep --timeout 10 >/dev/null
         koh logs box keep --all >o
         [ \"$(cat o)\" = new ]",
    );
}
