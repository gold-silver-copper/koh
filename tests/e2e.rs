//! End-to-end integration tests over real loopback iroh QUIC connections.

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use koh::Exit;
use koh::client::Client;
use koh::keys::{ClientEntry, Role, Route, Scope, load_or_create_key, save_clients};
use koh::proto::{MAX_CHUNK, MAX_CTRL, Request, recv_msg, send_msg};
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
}

impl Drop for InTerminal {
    fn drop(&mut self) {
        let _ = self.koh.kill();
        let _ = self.koh.wait();
    }
}

impl InTerminal {
    fn connect(config: &Path, runtime: &Path, args: &[&str]) -> Self {
        let size = fuxix::Winsize {
            rows: 24,
            cols: 80,
            xpixel: 800,
            ypixel: 480,
        };
        let (tty, theirs) = fuxix::pty(size).unwrap();
        let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
        koh.env("KOH_CONFIG_DIR", config)
            .env("XDG_RUNTIME_DIR", runtime)
            .arg("connect")
            .args(args)
            .stdin(theirs.try_clone().unwrap())
            .stdout(theirs.try_clone().unwrap())
            .stderr(theirs);
        fuxix::new_session(&mut koh, true);
        Self {
            koh: koh.spawn().unwrap(),
            tty,
            drawn: Vec::new(),
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

    fn types(&mut self, keys: &[u8]) {
        (&self.tty).write_all(keys).unwrap();
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
    assert!(String::from_utf8_lossy(&help.stdout).contains("koh mount"));

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
    // `a_scoped_key_cannot_attach`.)
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
    use std::os::unix::fs::PermissionsExt as _;
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
    fs::write(bin.join("kill"), fake("/bin/sleep 2\n")).unwrap();
    fs::set_permissions(bin.join("kill"), fs::Permissions::from_mode(0o755)).unwrap();
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
    fs::write(bin.join("kill"), fake("")).unwrap();
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
    use std::os::unix::fs::PermissionsExt as _;
    // With no runtime directory the server asks id(1) whose state it keeps. An id(1) that says
    // a number and then that it failed has told nothing: the server says so and does not start.
    let tmp = TempDir::new("id-failed");
    let key = new_key(&tmp, "client.key");
    let bin = tmp.0.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("id"), "#!/bin/sh\necho 42424\nexit 42\n").unwrap();
    fs::set_permissions(bin.join("id"), fs::Permissions::from_mode(0o755)).unwrap();
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

// ---- sessions: a real `koh serve`, real `koh mount` and `koh connect` ---------------------------

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

/// What a pane's folder holds that a mirror of it holds too: all but `generation` (a mirror's is
/// the last round's that changed it), the two names that are not carried and names with a dot
/// first. A file by its length and its hash, a link by where it leads.
fn held(dir: &Path) -> std::collections::BTreeMap<String, String> {
    let (mut held, mut folders) = (std::collections::BTreeMap::new(), vec![String::new()]);
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(dir.join(&folder))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = entry.file_name().to_string_lossy().into_owned();
            let own = ["generation", "status", "command"].contains(&name.as_str());
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if name.starts_with('.') || (folder.is_empty() && own) {
                continue;
            }
            let (path, name) = (entry.path(), format!("{folder}{name}"));
            let what = if kind.is_symlink() {
                format!("to {}", fs::read_link(&path).unwrap_or_default().display())
            } else if kind.is_dir() {
                folders.push(format!("{name}/"));
                "a folder".to_string()
            } else if kind.is_file() {
                let bytes = fs::read(&path).unwrap_or_default();
                format!("{} bytes {}", bytes.len(), blake3::hash(&bytes).to_hex())
            } else {
                "a FIFO".to_string()
            };
            held.insert(name, what);
        }
    }
    held
}

/// Waits until a mirror is its pane: the same names, each the same thing, and an even number.
fn agrees(pane: &Path, mirror: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let (theirs, ours) = (held(pane), held(mirror));
        let number = fs::read_to_string(mirror.join("generation")).unwrap_or_default();
        let even = number
            .trim()
            .parse::<u64>()
            .is_ok_and(|number| number % 2 == 0);
        if theirs == ours && even && !ours.is_empty() {
            return;
        }
        let differ = |(name, what): (&String, &String)| ours.get(name) != Some(what);
        let differ: Vec<&String> = theirs
            .iter()
            .filter(|at| differ(*at))
            .map(|at| at.0)
            .collect();
        let over: Vec<&String> = ours
            .keys()
            .filter(|name| !theirs.contains_key(*name))
            .collect();
        assert!(
            Instant::now() < deadline,
            "the mirror is not the pane: {differ:?} differ, {over:?} are left over, generation {number:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The screen a pane's folder, or a mirror, shows.
fn screen(dir: &Path) -> String {
    fs::read_to_string(dir.join("shown/screen")).unwrap_or_default()
}

/// A program for a session that takes what is typed as it is typed, into the file `out`: it
/// says READY once its terminal is raw, waits so many seconds, and then reads.
fn reads_into(out: &Path, wait: u32) -> Vec<String> {
    let script = format!("stty raw -echo; echo READY; sleep {wait}; exec cat > \"$0\"");
    vec!["sh".into(), "-c".into(), script, out.display().to_string()]
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
        for pane in fs::read_dir(&self.sessions).into_iter().flatten().flatten() {
            if pane.path().join("status").is_file() {
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
        let mut served = self.served.take().unwrap();
        signal(&served.server.id().to_string(), "-INT");
        served.server.wait().unwrap();
    }

    fn pane(&self, name: &str) -> PathBuf {
        self.sessions.join(name)
    }

    /// `koh mount` of this server (or of a relay to it), with `asks` for which session and
    /// `program` for a new one: its mirror is `AT/ws/m` in the test's folder, so `AT` is where
    /// a viewer there would say what its terminal is like.
    fn mount(&self, at: &str, via: Option<&Tap>, asks: &[&str], program: &[String]) -> Mount {
        let root = self.tmp.0.join(at);
        fs::create_dir_all(root.join("ws")).unwrap();
        let (dir, said) = (root.join("ws/m"), root.join("said"));
        let (id, addr) = match via {
            Some(tap) => (tap.id.clone(), tap.addr.clone()),
            None => (self.id.clone(), self.addr()),
        };
        let mut koh = self.koh(&["mount", &id, "--direct", &addr]);
        koh.args(asks).arg(&dir);
        if !program.is_empty() {
            koh.arg("--").args(program);
        }
        koh.stderr(fs::File::create(&said).unwrap());
        let koh = koh.spawn().unwrap();
        Mount { koh, dir, said }
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

/// A `koh mount` and its mirror. It is killed when the test lets go of it: its session lives on.
struct Mount {
    koh: std::process::Child,
    dir: PathBuf,
    said: PathBuf,
}

impl Drop for Mount {
    fn drop(&mut self) {
        let _ = self.koh.kill();
        let _ = self.koh.wait();
    }
}

impl Mount {
    /// What it said on its standard error so far.
    fn said(&self) -> String {
        fs::read_to_string(&self.said).unwrap_or_default()
    }

    fn says(&self, line: &str, times: usize) {
        until(&format!("koh mount says {line:?} {times} times"), || {
            self.said().matches(line).count() >= times
        });
    }

    fn shows(&self, text: &str) {
        until(
            &format!("the mirror shows {text:?}: {}", self.said()),
            || screen(&self.dir).contains(text),
        );
    }

    /// Writes to the mirror's `in`, as a viewer of it would type.
    fn types(&self, bytes: &[u8]) {
        let mut keys = fs::OpenOptions::new()
            .write(true)
            .open(self.dir.join("in"))
            .unwrap();
        keys.write_all(bytes).unwrap();
    }

    /// The exit code it ended with.
    fn ends(&mut self) -> Option<i32> {
        until("koh mount ends", || self.koh.try_wait().unwrap().is_some());
        self.koh.wait().unwrap().code()
    }
}

use iroh::endpoint::{Connection, RecvStream, SendStream};
use koh::net::{bind_server, connect_server, open_authed_stream, verify_client};
use koh::proto::{Attach, Attached, FromMirror, KeyProof, MAX_PROOF, Reply, Run, ToMirror};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};

/// A relay of the test's own between a client and the server: each stream of the client is a
/// stream of the relay's on the server, byte for byte, until the test cuts it. It is the
/// link, and where a test breaks it: after so many bytes, at once, or for a while.
struct Tap {
    id: String,
    addr: String,
    wire: Arc<Wire>,
}

struct Wire {
    /// How many more of the client's bytes pass before its stream is cut.
    left: AtomicUsize,
    /// While set there is no link: a stream is cut as soon as it comes.
    down: AtomicBool,
    cut: tokio::sync::Notify,
    cuts: AtomicUsize,
    /// Tells the streams that are open to take no more of the client's bytes.
    deaf: tokio::sync::Notify,
    /// Tells them to say no more to the client, and to carry what it sends a moment longer.
    half: tokio::sync::Notify,
    client: Mutex<Option<Connection>>,
}

impl Wire {
    fn new() -> Arc<Wire> {
        Arc::new(Wire {
            left: AtomicUsize::new(usize::MAX),
            down: AtomicBool::new(false),
            cut: tokio::sync::Notify::new(),
            cuts: AtomicUsize::new(0),
            deaf: tokio::sync::Notify::new(),
            half: tokio::sync::Notify::new(),
            client: Mutex::new(None),
        })
    }
}

impl Tap {
    async fn start(host: &Host) -> Self {
        let dir = host.tmp.0.join("tap_cfg");
        let secret = load_or_create_key(Role::Server, Some(&dir.join("server.key"))).unwrap();
        let id = secret.public().to_string();
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let endpoint = bind_server(secret, Some(local), true).await.unwrap();
        let addr = endpoint
            .bound_sockets()
            .into_iter()
            .next()
            .unwrap()
            .to_string();
        let key = host.key("tap_cfg");
        let server = koh::keys::parse_endpoint_id(&host.id).unwrap();
        let route = Some(Route::Direct(host.addr().parse().unwrap()));
        let (kept, _, upstream) = connect_server(key.clone(), server, route, true)
            .await
            .unwrap();
        let wire = Wire::new();
        let relayed = wire.clone();
        tokio::spawn(async move {
            let _kept = kept;
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                *relayed.client.lock().unwrap() = Some(conn.clone());
                let (wire, upstream, key) = (relayed.clone(), upstream.clone(), key.clone());
                tokio::spawn(async move {
                    while let Ok((send, recv)) = conn.accept_bi().await {
                        let (wire, upstream, key) = (wire.clone(), upstream.clone(), key.clone());
                        tokio::spawn(relay(wire, upstream, key, send, recv));
                    }
                });
            }
        });
        Self { id, addr, wire }
    }

    /// The stream that carries the client's next `bytes` bytes is cut after them.
    fn cut_after(&self, bytes: usize) {
        self.wire.left.store(bytes, SeqCst);
    }

    /// No link (every stream is cut, and each new one as it comes), or a link again.
    fn down(&self, down: bool) {
        self.wire.down.store(down, SeqCst);
        if down {
            self.wire.cut.notify_waiters();
        }
    }

    /// The stream that is open takes no more of what the client sends: the client's next
    /// message is one its stream does not take.
    fn deafen(&self) {
        self.wire.deaf.notify_waiters();
    }

    /// The client hears no more of its stream, at once, while what it has sent and sends for
    /// a moment yet still reaches the server: a link that breaks one way first.
    fn half(&self) {
        self.wire.half.notify_waiters();
    }

    /// Closes the client's connection: its next stream needs a new one.
    fn close(&self) {
        if let Some(conn) = self.wire.client.lock().unwrap().take() {
            conn.close(0u32.into(), b"cut");
        }
    }
}

/// One stream of a client through the relay.
async fn relay(
    wire: Arc<Wire>,
    upstream: Connection,
    key: iroh::SecretKey,
    mut down: SendStream,
    mut from: RecvStream,
) {
    let carried = async {
        if wire.down.load(SeqCst) {
            return false;
        }
        // (The client's proof is for the relay, which asks the server in its own name.)
        let Ok(_proof) = recv_msg::<KeyProof>(&mut from, MAX_PROOF).await else {
            return false;
        };
        let Ok((mut up, mut back)) = open_authed_stream(&upstream, &key).await else {
            return false;
        };
        let to_client = async {
            let mut some = vec![0u8; 64 << 10];
            while let Ok(Some(n)) = back.read(&mut some).await {
                if down.write_all(&some[..n]).await.is_err() {
                    return false;
                }
            }
            down.finish().is_ok()
        };
        let to_server = async {
            let mut some = vec![0u8; 4096];
            loop {
                let read = tokio::select! {
                    read = from.read(&mut some) => read,
                    () = wire.deaf.notified() => {
                        let _ = from.stop(0u32.into());
                        return std::future::pending().await;
                    }
                };
                let Ok(Some(n)) = read else { return };
                let left = wire.left.load(SeqCst);
                let pass = n.min(left);
                if up.write_all(&some[..pass]).await.is_err() {
                    return;
                }
                if left != usize::MAX {
                    wire.left.store(left - pass, SeqCst);
                }
                if left <= n {
                    wire.left.store(usize::MAX, SeqCst);
                    wire.cuts.fetch_add(1, SeqCst);
                    return;
                }
            }
        };
        let (whole, half) = {
            tokio::pin!(to_server);
            tokio::select! {
                whole = to_client => (whole, false),
                () = &mut to_server => (false, false),
                () = wire.cut.notified() => (false, false),
                () = wire.half.notified() => {
                    let _ = down.reset(0u32.into());
                    let _ = tokio::time::timeout(Duration::from_millis(50), &mut to_server).await;
                    (false, true)
                }
            }
        };
        // (Broken one way first, the server is left to read what the client had sent.)
        if half {
            let _ = up.finish();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = up.reset(0u32.into());
        let _ = back.stop(0u32.into());
        whole
    };
    // (A stream the server ended is ended, with all it said; any other is cut.)
    if !carried.await {
        let _ = down.reset(0u32.into());
    }
    let _ = from.stop(0u32.into());
}

/// An attach as a test asks it: of the session `name`, or of a new one running `program`.
fn asks(name: Option<&str>, program: &[String]) -> Attach {
    Attach {
        format: fux::FORMAT,
        name: name.map(String::from),
        new: name.is_none(),
        cols: 80,
        rows: 24,
        argv: program.to_vec(),
        cwd: None,
        run: None,
        client: 7,
    }
}

/// An attach by the client in this process: the stream, and what the server said of the session.
async fn attach(client: &Client, asks: Attach) -> koh::Result<(SendStream, RecvStream, Attached)> {
    let (send, mut recv) = client.request(&Request::Attach(asks)).await?;
    let attached = recv_msg(&mut recv, MAX_CTRL).await?;
    Ok((send, recv, attached))
}

async fn tell(send: &mut SendStream, message: FromMirror) {
    send_msg(send, &message, MAX_CHUNK).await.unwrap();
}

fn typed(bytes: &[u8]) -> FromMirror {
    FromMirror::Write {
        name: "in".into(),
        bytes: bytes.to_vec(),
    }
}

#[test]
fn a_session_is_a_fux_pane_kept_by_koh_hold() {
    let host = Host::start("pane", &[]);
    let mut mount = host.mount("a", None, &["--new"], &["sleep".into(), "30".into()]);
    until("the mirror has a round", || {
        mount.dir.join("generation").is_file()
    });
    // The session is a folder in koh's own fux session, beneath its state, which it printed.
    let state = fs::canonicalize(host.tmp.0.join("run/koh")).unwrap();
    assert_eq!(host.sessions, state.join("fux/koh-sessions"));
    assert_eq!(names_in(&host.sessions), ["1"]);
    assert!(!state.join("sessions").exists());
    // Its holder is this binary under the word `hold`, with the lock on the folder: fux's proof
    // that it lives. It is no child of `koh serve`, and lives on when that is stopped.
    let (pane, server) = (host.pane("1"), host.served.as_ref().unwrap().server.id());
    let holder = holder_of(&pane);
    let args = ps(&holder, "args=");
    assert_eq!(
        args.split_whitespace().take(2).collect::<Vec<_>>(),
        [env!("CARGO_BIN_EXE_koh"), "hold"]
    );
    assert_ne!(ps(&holder, "ppid="), server.to_string());
    let locked = || fs::File::open(&pane).unwrap().try_lock_shared().is_err();
    assert!(locked());
    assert_eq!(fs::read_to_string(pane.join("state")).unwrap(), "running\n");
    // Nothing of the session is the client's to keep: the mirror goes with the mount.
    signal(&mount.koh.id().to_string(), "-TERM");
    assert_eq!(mount.ends(), Some(0));
    assert!(!mount.dir.exists() && locked());
}

#[test]
fn the_mirror_is_the_pane() {
    let host = Host::start("mirror", &[]);
    // (Where a viewer would say what its terminal is like there is a FIFO nobody writes to:
    // koh reads a file there when one changes, and waits at nothing else.)
    fs::create_dir_all(host.tmp.0.join("a")).unwrap();
    drop(fuxix::fifo(host.tmp.0.join("a/colours")).unwrap());
    let mut mount = host.mount("a", None, &[], &[]);
    let pane = host.pane("1");
    agrees(&pane, &mount.dir);
    // A mirror has the pane's FIFOs and never its `status` or `command`.
    let fifo =
        |name: &str| fs::symlink_metadata(mount.dir.join(name)).is_ok_and(|file| !file.is_file());
    assert!(fifo("in") && fifo("ctl"));
    assert!(pane.join("status").is_file() && pane.join("command").is_file());
    assert!(!mount.dir.join("status").exists() && !mount.dir.join("command").exists());
    // A shell; output that scrolls into history. (Each is waited for by what the program
    // printed, which the command as it was typed does not have.)
    mount.types(b"echo typed-$((6 * 7)); seq 1 3000\n");
    let history = || fs::read_to_string(mount.dir.join("history")).unwrap_or_default();
    until("the mirror's history has what scrolled", || {
        history().contains("typed-42\n") && history().contains("\n2900\n")
    });
    agrees(&pane, &mount.dir);
    // What a program puts on the clipboard, and a picture it draws, are files of the pane: the
    // mirror has them.
    mount.types(b"printf '\\033]52;c;aGVsbG8=\\007\\033Pq#0;2;100;0;0#0~~~~~~-~~~~~~\\033\\\\'\n");
    until("the mirror has the clipboard and the picture", || {
        let listed = fs::read_to_string(mount.dir.join("main/pictures")).unwrap_or_default();
        fs::read(mount.dir.join("clipboard")).is_ok_and(|bytes| bytes == b"hello")
            && listed.starts_with("pic-1.sixel ")
            && mount.dir.join("pic-1.sixel").is_file()
    });
    agrees(&pane, &mount.dir);
    // The alternate screen comes, `shown` turns to it; and goes again.
    mount.types(b"printf '\\033[?1049hALTERNATE'\n");
    let shown = || fs::read_link(mount.dir.join("shown")).unwrap_or_default();
    until("the mirror shows the alternate screen", || {
        shown() == Path::new("alt") && screen(&mount.dir).contains("ALTERNATE")
    });
    agrees(&pane, &mount.dir);
    mount.types(b"printf '\\033[?1049l'; echo back\n");
    until("the mirror shows the main screen again", || {
        shown() == Path::new("main") && !mount.dir.join("alt").exists()
    });
    agrees(&pane, &mount.dir);
    // A size asked through the mirror's `ctl` is the pane's.
    fs::write(mount.dir.join("ctl"), "resize 100 30\n").unwrap();
    until("the pane takes the size", || {
        fs::read_to_string(pane.join("size")).unwrap() == "100 30\n"
    });
    agrees(&pane, &mount.dir);
    // The program's end is the mount's, with its status; the mirror goes, the session's folder stays.
    mount.types(b"exit 7\n");
    assert_eq!(mount.ends(), Some(7));
    assert!(!mount.dir.exists());
    assert_eq!(
        fs::read_to_string(pane.join("state")).unwrap(),
        "exited 7\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_cut_and_back_leaves_the_mirror_the_pane() {
    let host = Host::start("cut", &[]);
    let tap = Tap::start(&host).await;
    let mount = host.mount("a", Some(&tap), &[], &[]);
    let pane = host.pane("1");
    agrees(&pane, &mount.dir);
    let write = |line: &str| fs::write(pane.join("in"), line).unwrap();
    // The stream is cut, the connection stands: the pane changes while there is no link, and
    // the mirror is as its last round left it. On return it is the pane again.
    tap.down(true);
    mount.says("no link", 1);
    // (Of what is written to the mirror's `ctl` meanwhile, the last size asked for is asked
    // on return; a line that hangs the program up is dropped, and koh says so.)
    fs::write(mount.dir.join("ctl"), "resize 90 20\nkill\nresize 100 30\n").unwrap();
    mount.says("a line written to ctl was dropped", 1);
    let before = held(&mount.dir);
    write("echo while-away; seq 1 2000\n");
    until("the pane has changed", || screen(&pane).contains("2000"));
    assert_eq!(held(&mount.dir), before);
    tap.down(false);
    mount.says("the link is back", 1);
    mount.shows("2000");
    until("the pane takes the size asked for while away", || {
        fs::read_to_string(pane.join("size")).unwrap() == "100 30\n"
    });
    agrees(&pane, &mount.dir);
    assert_eq!(fs::read_to_string(pane.join("state")).unwrap(), "running\n");
    // The connection is closed: the next attach is on a new one.
    tap.close();
    mount.says("no link", 2);
    write("echo after-the-connection\n");
    mount.says("the link is back", 2);
    mount.shows("after-the-connection");
    agrees(&pane, &mount.dir);
    assert_eq!(names_in(&host.sessions), ["1"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_is_typed_without_a_link_is_typed_on_return() {
    let host = Host::start("typed-away", &[]);
    let tap = Tap::start(&host).await;
    let out = host.tmp.0.join("out");
    let mount = host.mount("a", Some(&tap), &["--new"], &reads_into(&out, 0));
    mount.shows("READY");
    let mut all = Vec::new();
    let arrived = |all: &[u8]| {
        until("the program has read what was typed", || {
            fs::read(&out).unwrap_or_default().len() >= all.len()
        })
    };
    for away in 0..10u32 {
        tap.down(true);
        mount.says("no link", away as usize + 1);
        let some: Vec<u8> = (0..18)
            .flat_map(|n| format!("{:07}\n", away * 18 + n).into_bytes())
            .collect();
        mount.types(&some);
        all.extend(some);
        tap.down(false);
        mount.says("the link is back", away as usize + 1);
        // (Read by the program before the link is cut again: what is on its way when a link
        // dies may be lost, and that is not what this asks.)
        arrived(&all);
    }
    // And a message the stream does not take is kept for the next link: the link is found
    // broken by it, and what was typed is typed on the next.
    for deaf in 0..5u32 {
        tap.deafen();
        std::thread::sleep(Duration::from_millis(500));
        let some = format!("{:07}\n", 180 + deaf).into_bytes();
        mount.types(&some);
        all.extend(some);
        mount.says("the link is back", 11 + deaf as usize);
        arrived(&all);
    }
    // All of it, once, in order.
    assert_eq!(all.len(), 1480);
    until("the program has read what was typed", || {
        fs::read(&out).unwrap().len() >= all.len()
    });
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        String::from_utf8_lossy(&fs::read(&out).unwrap()),
        String::from_utf8_lossy(&all)
    );
}

/// The fewest stretches that, left out of `typed`, leave `read`; none if no leaving out does.
fn stretches_left_out(read: &[u8], typed: &[u8]) -> Option<usize> {
    const NONE: usize = usize::MAX / 2;
    // (`at[j]`: the fewest, for what was read so far with its last byte the typed byte `j`.)
    let mut at = vec![NONE; typed.len()];
    for (i, byte) in read.iter().enumerate() {
        let (mut next, mut before) = (vec![NONE; typed.len()], NONE);
        for j in 0..typed.len() {
            if typed[j] == *byte {
                let on = if j > 0 { at[j - 1] } else { NONE };
                next[j] = if i == 0 {
                    usize::from(j > 0)
                } else {
                    on.min(before + 1)
                };
            }
            if j > 0 {
                before = before.min(at[j - 1]);
            }
        }
        at = next;
    }
    let ends = |(j, fewest): (usize, &usize)| fewest + usize::from(j + 1 < typed.len());
    let fewest = at.iter().enumerate().map(ends).min().unwrap_or(0);
    (fewest < NONE).then_some(fewest)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_bytes_never_arrive_twice_or_out_of_order() {
    let host = Host::start("typed-cut", &[]);
    let tap = Tap::start(&host).await;
    let out = host.tmp.0.join("out");
    let mount = host.mount("a", Some(&tap), &["--new"], &reads_into(&out, 0));
    mount.shows("READY");
    // Numbered lines are typed without a pause, while ten links in turn are cut some bytes into
    // what the client sends on them: in the middle of a message, with more on its way.
    let (dir, typing) = (mount.dir.clone(), Arc::new(AtomicBool::new(true)));
    let goes_on = typing.clone();
    let typist = std::thread::spawn(move || {
        let mut keys = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("in"))
            .unwrap();
        let mut all = Vec::new();
        for n in 0.. {
            if !goes_on.load(SeqCst) {
                break;
            }
            let line = format!("{n:07}\n");
            keys.write_all(line.as_bytes()).unwrap();
            all.extend(line.into_bytes());
            std::thread::sleep(Duration::from_millis(3));
        }
        all
    });
    for cut in 0..10usize {
        tap.cut_after(40 + cut * 86);
        until("the link is cut", || tap.wire.cuts.load(SeqCst) > cut);
        mount.says("the link is back", cut + 1);
    }
    std::thread::sleep(Duration::from_millis(200));
    typing.store(false, SeqCst);
    let all = typist.join().unwrap();
    // What was typed after the last link came back arrives whole, so the end is the same.
    let tail = &all[all.len() - 64..];
    until("the program has read to the end", || {
        fs::read(&out).unwrap().ends_with(tail)
    });
    let read = fs::read(&out).unwrap();
    // What arrived is what was typed with stretches left out: nothing twice, nothing out of
    // its order. A stretch for each link that ended, at the most.
    let left_out = stretches_left_out(&read, &all);
    assert!(
        left_out.is_some_and(|stretches| stretches <= 10),
        "{left_out:?} stretches"
    );
    assert!(read.len() <= all.len());
    println!(
        "typed {} bytes, {} arrived, {left_out:?} stretches left out",
        all.len(),
        read.len()
    );
}

#[test]
fn a_paste_larger_than_the_pipe_waits_and_is_not_cut() {
    let host = Host::start("paste", &[]);
    let out = host.tmp.0.join("out");
    let mount = host.mount("a", None, &["--new"], &reads_into(&out, 3));
    mount.shows("READY");
    // Three megabytes written to the mirror's `in` while the program reads nothing: more than
    // every pipe and queue on the way holds, so the writer is made to wait.
    let paste: Vec<u8> = (0..300_000u32)
        .flat_map(|n| format!("{n:09}\n").into_bytes())
        .collect();
    let (dir, pasted, done) = (
        mount.dir.clone(),
        paste.clone(),
        Arc::new(AtomicBool::new(false)),
    );
    let wrote = done.clone();
    let writer = std::thread::spawn(move || {
        let mut keys = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("in"))
            .unwrap();
        keys.write_all(&pasted).unwrap();
        wrote.store(true, SeqCst);
    });
    std::thread::sleep(Duration::from_secs(1));
    assert!(!done.load(SeqCst), "the writer was not made to wait");
    // All of it reaches the program, in order: nothing was dropped to make room. (A terminal
    // takes typed bytes slowly on some systems: two minutes, and it must keep coming.)
    let (began, mut read) = (Instant::now(), 0);
    while read < paste.len() {
        std::thread::sleep(Duration::from_millis(50));
        read = fs::metadata(&out).map_or(0, |out| out.len() as usize);
        let of = paste.len();
        assert!(
            began.elapsed() < Duration::from_secs(120),
            "the program read {read} of {of} bytes in two minutes; koh said: {}",
            mount.said()
        );
    }
    writer.join().unwrap();
    assert!(fs::read(&out).unwrap() == paste);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_attach_ends_the_clients_older_stream_first() {
    let host = Host::start("older", &[]);
    let client = host.client().await;
    let out = host.tmp.0.join("out");
    // The older stream brings two megabytes the program does not read yet: the FIFO takes some
    // of them, and the rest wait on the server and on their way to it.
    let (mut older, _from, attached) = attach(&client, asks(None, &reads_into(&out, 3)))
        .await
        .unwrap();
    let pane = host.pane(&attached.name);
    until("the program is ready", || screen(&pane).contains("READY"));
    tell(&mut older, FromMirror::Has(Vec::new())).await;
    let paste = tokio::spawn(async move {
        for _ in 0..128 {
            let piece = typed(&[b'a'; 16 << 10]);
            if send_msg(&mut older, &piece, MAX_CHUNK).await.is_err() {
                break;
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    // The same client attaches anew to the run. Once it is answered, nothing of the older
    // stream's is written: what the newer brings is not typed before the rest of that paste.
    let again = Attach {
        run: Some(attached.run),
        ..asks(Some(&attached.name), &[])
    };
    let (mut newer, _from, _) = attach(&client, again).await.unwrap();
    tell(&mut newer, FromMirror::Has(Vec::new())).await;
    tell(&mut newer, typed(b"bbbb")).await;
    until("the program has read the newer stream's bytes", || {
        fs::read(&out).unwrap_or_default().ends_with(b"bbbb")
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let read = fs::read(&out).unwrap();
    let pasted = read.iter().take_while(|byte| **byte == b'a').count();
    assert_eq!(
        read[pasted..],
        *b"bbbb",
        "{} bytes after the paste",
        read.len() - pasted
    );
    assert!(
        (1..2 << 20).contains(&pasted),
        "{pasted} of the paste arrived"
    );
    paste.abort();
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn typed_bytes_go_to_the_run_that_was_checked() {
    let host = Host::start("run", &[]);
    let tap = Tap::start(&host).await;
    let outs = ["o1", "o2", "o3", "o4"].map(|name| host.tmp.0.join(name));
    // The name is given to another run, by hand: one started beside it takes its place in one
    // step, and the folder that had the name is removed (which ends its holder).
    let anew = |name: &str, out: &Path| {
        let (pane, beside, old) = (host.pane(name), host.pane("beside"), host.pane("old"));
        let holder = holder_of(&pane);
        let mut start = vec!["fux".to_string(), "start".into()];
        start.extend([beside.display().to_string(), "--".into()]);
        start.extend(reads_into(out, 0));
        let start: Vec<&str> = start.iter().map(String::as_str).collect();
        let (code, _, said) = koh(&host.tmp.0.join("run"), &start);
        assert_eq!(code, Some(0), "{said}");
        until("the new run is ready", || screen(&beside).contains("READY"));
        fs::rename(&pane, &old).unwrap();
        fs::rename(&beside, &pane).unwrap();
        assert_ne!(holder_of(&pane), holder);
        move || _ = fs::remove_dir_all(&old).or_else(|_| fs::remove_dir_all(&old))
    };
    // While the client is away: what it typed meanwhile is typed nowhere, and it ends.
    let mut away = host.mount(
        "a",
        Some(&tap),
        &["--session", "s"],
        &reads_into(&outs[0], 0),
    );
    away.shows("READY");
    tap.down(true);
    away.says("no link", 1);
    away.types(b"typed while away\n");
    anew("s", &outs[1])();
    tap.down(false);
    assert_eq!(away.ends(), Some(127));
    let said = away.said();
    assert!(
        said.contains("another run has the session's name s"),
        "{said}"
    );
    assert!(said.contains("17 typed bytes were not sent"), "{said}");
    // (That is the server's word as well as the client's: asked for a run the name has not,
    // by a client that would take any answer, it answers none.)
    let client = host.client().await;
    let asks = Attach {
        run: Some(RUNS[0]),
        ..asks(Some("s"), &[])
    };
    let err = attach(&client, asks).await.unwrap_err();
    assert_eq!(err.code, Exit::NOT_FOUND, "{err:?}");
    assert!(
        err.message.contains("another run has the session's name s"),
        "{err:?}"
    );
    client.close().await;
    // While the stream lives: what is typed then goes into the FIFOs of the run that was
    // checked, and the client is told that its session ended.
    let mut live = host.mount("b", None, &["--session", "t"], &reads_into(&outs[2], 0));
    live.shows("READY");
    let remove = anew("t", &outs[3]);
    let _ = fs::OpenOptions::new()
        .write(true)
        .open(live.dir.join("in"))
        .map(|mut keys| keys.write_all(b"typed at once\n"));
    assert_eq!(live.ends(), Some(1));
    remove();
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(fs::read(&outs[1]).unwrap(), b"");
    assert_eq!(fs::read(&outs[3]).unwrap(), b"");
}

#[test]
fn a_client_that_attached_as_status_was_written_is_not_told_it_ended() {
    let host = Host::start("status", &[]);
    let mut mount = host.mount("a", None, &[], &[]);
    let pane = host.pane("1");
    agrees(&pane, &mount.dir);
    // fux writes `status` twice at a start: another file of another time, with the same holder
    // in its first line. The run is the same, and the client follows it on.
    let status = fs::read_to_string(pane.join("status")).unwrap();
    for _ in 0..3 {
        std::thread::sleep(Duration::from_millis(300));
        fux::replace(
            pane.join("status"),
            format!("{status}command sh\n").as_bytes(),
        )
        .unwrap();
    }
    mount.types(b"echo still-$((40 + 2))\n");
    mount.shows("still-42");
    assert_eq!(mount.koh.try_wait().unwrap(), None, "{}", mount.said());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_holder_killed_as_it_wrote_is_shown_and_ended() {
    let host = Host::start("killed", &[]);
    let client = host.client().await;
    let flood = ["sh", "-c", "while :; do seq 1 100000; done"].map(String::from);
    let (mut send, mut from, attached) = attach(&client, asks(None, &flood)).await.unwrap();
    let pane = host.pane(&attached.name);
    let mut second = host.mount("a", None, &["--session", &attached.name], &[]);
    // A mirror of the test's own, kept after the session's end.
    let kept = host.tmp.0.join("kept");
    let mut mirror = koh::carry::Mirror::make(&kept).unwrap();
    tell(&mut send, FromMirror::Has(mirror.has().unwrap())).await;
    let (holder, wrote) = (holder_of(&pane), pane.clone());
    let killer = tokio::task::spawn_blocking(move || {
        // In the middle of a round: its number is odd then. The holder is stopped when it is
        // seen odd, and killed if it stopped so.
        std::thread::sleep(Duration::from_millis(700));
        let odd = || {
            let number = fs::read_to_string(wrote.join("generation")).unwrap_or_default();
            number
                .trim()
                .parse::<u64>()
                .is_ok_and(|number| number % 2 == 1)
        };
        for _ in 0..200_000 {
            if odd() {
                signal(&holder, "-STOP");
                if odd() {
                    break;
                }
                signal(&holder, "-CONT");
            }
        }
        signal(&holder, "-KILL");
    });
    let mut rounds = 0;
    let carried = async {
        loop {
            let message: ToMirror = recv_msg(&mut from, MAX_CHUNK).await.unwrap();
            rounds += usize::from(message == ToMirror::Done);
            if mirror.take(message, Instant::now()).unwrap() {
                break;
            }
        }
    };
    let ended = tokio::time::timeout(Duration::from_secs(20), carried).await;
    assert!(
        ended.is_ok(),
        "the client was not told that the session ended"
    );
    killer.await.unwrap();
    // The last round is the folder as the holder left it, under an even number; then `Ended`.
    let left: u64 = fs::read_to_string(pane.join("generation"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let ours: u64 = fs::read_to_string(kept.join("generation"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert_eq!((left % 2, ours), (1, left + 1), "after {rounds} rounds");
    assert_eq!(held(&kept), held(&pane));
    assert_eq!(fs::read_to_string(kept.join("state")).unwrap(), "running\n");
    // A client is not told that all is well: nothing says how the program ended.
    assert_eq!(second.ends(), Some(1));
    assert!(
        second
            .said()
            .contains("the session ended without saying how"),
        "{}",
        second.said()
    );
    client.close().await;
}

#[test]
fn the_exit_code_is_the_programs_and_not_zero_without_one() {
    let host = Host::start("code", &[]);
    let run = |asks: &[&str], program: &[&str]| {
        let program: Vec<String> = program.iter().map(|word| word.to_string()).collect();
        host.mount("a", None, asks, &program).ends()
    };
    // The program's status; of one a signal ended, 128 and the signal.
    assert_eq!(run(&["--new"], &["sh", "-c", "exit 7"]), Some(7));
    assert_eq!(run(&["--new"], &["sh", "-c", "kill -9 $$"]), Some(137));
    // An ended session stays, and a later client is shown the same and ends the same.
    assert_eq!(run(&["--session", "1"], &[]), Some(7));
    assert_eq!(run(&["--session", "2"], &[]), Some(137));
    // A holder that was killed left `state` at `running`, with no lock: that is no 0.
    let mut mount = host.mount("b", None, &["--new"], &["sleep".into(), "30".into()]);
    until("the mirror has a round", || {
        mount.dir.join("generation").is_file()
    });
    signal(&holder_of(&host.pane("3")), "-KILL");
    assert_eq!(mount.ends(), Some(1));
    assert_eq!(run(&["--session", "3"], &[]), Some(1));
    assert_eq!(names_in(&host.sessions), ["1", "2", "3"]);
}

#[test]
fn koh_serve_started_anew_keeps_the_session() {
    let mut host = Host::start("anew", &[]);
    let mount = host.mount("a", None, &[], &[]);
    let pane = host.pane("1");
    agrees(&pane, &mount.dir);
    let holder = holder_of(&pane);
    // The server is stopped: the session lives, with nobody to carry it.
    host.stop();
    mount.says("no link", 1);
    fs::write(pane.join("in"), "echo while-stopped\n").unwrap();
    until("the session runs on", || {
        screen(&pane).contains("while-stopped")
    });
    // Started anew, it has the same key (no holder kept its lock) and the same sessions: the
    // client attaches to the run it had, by its name.
    host.serve();
    mount.says("the link is back", 1);
    mount.shows("while-stopped");
    mount.types(b"echo after-$((1 + 1))\n");
    mount.shows("after-2");
    agrees(&pane, &mount.dir);
    assert_eq!(
        (holder_of(&pane), names_in(&host.sessions)),
        (holder, vec!["1".to_string()])
    );
}

#[test]
fn two_clients_see_one_session() {
    let host = Host::start("two", &[]);
    let first = host.mount("a", None, &[], &[]);
    let pane = host.pane("1");
    agrees(&pane, &first.dir);
    // With no session named, a second client is given the newest that lives: the same one.
    let second = host.mount("b", None, &[], &[]);
    agrees(&pane, &second.dir);
    // What either types, both see.
    first.types(b"echo from-the-first\n");
    second.shows("from-the-first");
    second.types(b"echo from-the-second\n");
    first.shows("from-the-second");
    agrees(&pane, &first.dir);
    agrees(&pane, &second.dir);
    assert_eq!(names_in(&host.sessions), ["1"]);
}

#[test]
fn two_clients_tell_their_terminals_at_once() {
    let host = Host::start("told", &[]);
    let mounts = [
        host.mount("a", None, &[], &[]),
        host.mount("b", None, &[], &[]),
    ];
    agrees(&host.pane("1"), &mounts[1].dir);
    // Each client's viewer writes what its terminal is like into its own fux session; koh's
    // fux session on the server has what the last of them said, whole.
    let session = host.sessions.parent().unwrap().to_path_buf();
    let says = |who: &str, turn: u32| format!("foreground #{turn:06x}\n# {who}\n");
    for turn in 0..20 {
        for (who, name) in [
            ("a", "colours"),
            ("b", "colours"),
            ("a", "keyboard"),
            ("b", "keyboard"),
        ] {
            fux::replace(host.tmp.0.join(who).join(name), says(who, turn).as_bytes()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(60));
    }
    for name in ["colours", "keyboard"] {
        let last = [says("a", 19), says("b", 19)];
        until(&format!("the server has the last {name}"), || {
            fs::read_to_string(session.join(name)).is_ok_and(|told| last.contains(&told))
        });
    }
    // Neither failed, and nothing is left of the writing.
    assert_eq!(names_in(&session), ["colours", "keyboard", "koh-sessions"]);
    for mount in mounts {
        assert!(mount.said().lines().count() == 1, "{}", mount.said());
    }
}

#[tokio::test]
async fn a_client_of_another_format_starts_nothing() {
    let host = Host::start("format", &[]);
    let client = host.client().await;
    for (format, older) in [(fux::FORMAT + 1, "server"), (fux::FORMAT - 1, "client")] {
        let asks = Attach {
            format,
            ..asks(None, &["sleep".into(), "30".into()])
        };
        let err = attach(&client, asks).await.unwrap_err();
        assert_eq!(err.code, Exit::FAILED);
        assert!(
            err.message
                .contains(&format!("the {older}'s koh is the older one")),
            "{err:?}"
        );
    }
    // No folder, and no program.
    assert_eq!(names_in(&host.sessions), [""; 0]);
    client.close().await;
}

#[test]
fn a_mirror_is_made_by_koh_and_no_folder_that_is_there_is_taken() {
    let host = Host::start("made", &[]);
    // A folder that is there is not taken, cleared or written into; and nothing is started.
    let there = host.tmp.0.join("a/ws/m");
    fs::create_dir_all(&there).unwrap();
    fs::write(there.join("mine"), "kept").unwrap();
    let mut refused = host.mount("a", None, &[], &[]);
    assert_eq!(refused.ends(), Some(1));
    assert!(
        refused.said().contains("takes none that is there"),
        "{}",
        refused.said()
    );
    assert_eq!(names_in(&there), ["mine"]);
    assert_eq!(names_in(&host.sessions), [""; 0]);
    // With no place named, the mirror is in a fux session of koh's own on the client, under
    // the server's name and the session's: nothing is put into the user's fux session.
    let mounts = host.tmp.0.join("crun/koh/fux/koh-mounts");
    let mut koh = host.koh(&["mount", &host.id, "--direct", &host.addr()]);
    let mut mount = Mount {
        koh: koh.stderr(std::process::Stdio::null()).spawn().unwrap(),
        dir: mounts.join(format!("{}.1", &host.id[..62])),
        said: PathBuf::new(),
    };
    until("the mirror is in koh's own folder", || {
        mount.dir.join("generation").is_file()
    });
    assert_eq!(fs::metadata(&mount.dir).unwrap().mode() & 0o777, 0o700);
    assert!(!host.tmp.0.join("crun/fux").exists() && !host.tmp.0.join("home/.cache").exists());
    // Stopped, the mount removes its mirror.
    signal(&mount.koh.id().to_string(), "-TERM");
    assert_eq!(mount.ends(), Some(0));
    assert_eq!(names_in(&mounts), [""; 0]);
    // With no runtime directory, or an empty one, koh's own place is in the cache directory.
    let mounts = host.tmp.0.join("home/.cache/koh/fux/koh-mounts");
    for runtime in [Some(""), None] {
        let mut koh = host.koh(&["mount", &host.id, "--direct", &host.addr()]);
        match runtime {
            Some(runtime) => koh.env("XDG_RUNTIME_DIR", runtime),
            None => koh.env_remove("XDG_RUNTIME_DIR"),
        };
        let mut mount = Mount {
            koh: koh.stderr(std::process::Stdio::null()).spawn().unwrap(),
            dir: mounts.join(format!("{}.1", &host.id[..62])),
            said: PathBuf::new(),
        };
        until("the mirror is in the cache directory", || {
            mount.dir.join("generation").is_file()
        });
        signal(&mount.koh.id().to_string(), "-TERM");
        assert_eq!(mount.ends(), Some(0));
        assert_eq!(names_in(&mounts), [""; 0]);
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

#[test]
fn sessions_are_capped_and_the_oldest_ended_one_makes_room() {
    let host = Host::start("capped", &["--max-sessions", "2"]);
    let run = |at: &str, program: &[&str]| {
        let program: Vec<String> = program.iter().map(|word| word.to_string()).collect();
        host.mount(at, None, &["--new"], &program)
    };
    // Two sessions: one that runs, and one that has ended.
    let first = run("a", &["sleep", "30"]);
    until("the first runs", || first.dir.join("generation").is_file());
    assert_eq!(run("b", &["sh", "-c", "exit 0"]).ends(), Some(0));
    assert_eq!(names_in(&host.sessions), ["1", "2"]);
    // A third takes the place of the one that ended, once it has started.
    let third = run("c", &["sleep", "30"]);
    until("the third runs, and the ended one is gone", || {
        names_in(&host.sessions) == ["1", "3"]
    });
    until("the third is mirrored", || {
        third.dir.join("generation").is_file()
    });
    // With both running there is no room: the client is told the server is busy, and nothing starts.
    let mut fourth = run("d", &["sleep", "30"]);
    assert_eq!(fourth.ends(), Some(75));
    assert!(
        fourth.said().contains("--max-sessions"),
        "{}",
        fourth.said()
    );
    assert_eq!(names_in(&host.sessions), ["1", "3"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_message_ends_the_client_and_a_broken_link_does_not() {
    let host = Host::start("refused", &[]);
    // A server of the test's own, which the client dials: it may send anything.
    let secret =
        load_or_create_key(Role::Server, Some(&host.tmp.0.join("tap_cfg/server.key"))).unwrap();
    let id = secret.public().to_string();
    let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let endpoint = bind_server(secret, Some(local), true).await.unwrap();
    let addr = endpoint
        .bound_sockets()
        .into_iter()
        .next()
        .unwrap()
        .to_string();
    let hostile = Tap {
        id,
        addr,
        wire: Wire::new(),
    };
    let mut mount = host.mount("a", Some(&hostile), &[], &[]);
    let conn = endpoint.accept().await.unwrap().await.unwrap();
    let run = Run {
        device: 1,
        folder: 2,
        holder: 3,
    };
    let mut asked = Vec::new();
    for link in 0..2 {
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        verify_client(&conn, &mut recv).await.unwrap();
        let Request::Attach(asks) = recv_msg(&mut recv, MAX_CTRL).await.unwrap() else {
            panic!("no attach")
        };
        asked.push(asks.run);
        send_msg(&mut send, &Reply::Ok, MAX_CTRL).await.unwrap();
        let attached = Attached {
            name: "1".into(),
            run,
        };
        send_msg(&mut send, &attached, MAX_CTRL).await.unwrap();
        let FromMirror::Has(has) = recv_msg(&mut recv, MAX_CHUNK).await.unwrap() else {
            panic!("no list")
        };
        let put = |name: &str| ToMirror::Put {
            name: name.into(),
            more: false,
            bytes: b"a screen\n".to_vec(),
        };
        let round = match link {
            // A whole round, and then the stream breaks: the client keeps its mirror and attaches anew.
            0 => vec![
                ToMirror::Round(2),
                ToMirror::Folder("main".into()),
                put("main/screen"),
                ToMirror::Done,
            ],
            // A round no server may send: a name that climbs out of the mirror.
            _ => {
                assert_eq!(
                    has.iter().map(|had| had.name.as_str()).collect::<Vec<_>>(),
                    ["main", "main/screen"]
                );
                vec![ToMirror::Round(4), put("../escaped"), ToMirror::Done]
            }
        };
        for message in round {
            send_msg(&mut send, &message, MAX_CHUNK).await.unwrap();
        }
        if link == 0 {
            until("the mirror has the round", || {
                mount.dir.join("main/screen").is_file()
            });
            let _ = send.reset(0u32.into());
        } else {
            // (The stream is kept until the client has read it.)
            assert_eq!(mount.ends(), Some(1));
        }
    }
    assert_eq!(asked, [None, Some(run)]);
    let said = mount.said();
    assert!(
        said.contains("the server sent what a mirror does not take"),
        "{said}"
    );
    // Nothing was changed by it, in the mirror or outside it; and the mount took its mirror with it.
    assert_eq!(names_in(&host.tmp.0.join("a")), ["said", "ws"]);
    assert_eq!(names_in(&host.tmp.0.join("a/ws")), [""; 0]);

    // A session's name is the server's to say, and a mirror with no place named is put under
    // it: a name that is a path, past a folder that is there, makes no folder anywhere.
    let mounts = host.tmp.0.join("crun/koh/fux/koh-mounts");
    fs::create_dir_all(mounts.join(format!("{}.1", &hostile.id[..48]))).unwrap();
    let mut koh = host.koh(&["mount", &hostile.id, "--direct", &hostile.addr]);
    let said = host.tmp.0.join("said");
    let mut climbing = Mount {
        koh: koh
            .stderr(fs::File::create(&said).unwrap())
            .spawn()
            .unwrap(),
        dir: mounts.clone(),
        said,
    };
    let conn = endpoint.accept().await.unwrap().await.unwrap();
    let (mut send, mut recv) = conn.accept_bi().await.unwrap();
    verify_client(&conn, &mut recv).await.unwrap();
    let _: Request = recv_msg(&mut recv, MAX_CTRL).await.unwrap();
    send_msg(&mut send, &Reply::Ok, MAX_CTRL).await.unwrap();
    let attached = Attached {
        name: "1/../../escaped".into(),
        run,
    };
    send_msg(&mut send, &attached, MAX_CTRL).await.unwrap();
    assert_eq!(climbing.ends(), Some(1));
    assert!(
        climbing.said().contains("a session's name that is none"),
        "{}",
        climbing.said()
    );
    assert_eq!(names_in(&host.tmp.0.join("crun/koh/fux")), ["koh-mounts"]);
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

    // Each of koh's two prefix keys typed twice is the key's own byte, typed to the program.
    let again = ["--direct", &addr, &id, "--session", "1"];
    let mut second = InTerminal::connect(&config, &runtime, &again);
    second.until("the terminal shows READY", shown);
    second.types(b"\x1d\x1d\x02\x02");
    let typed = |_: &mut InTerminal| {
        screen(&pane).split_whitespace().collect::<Vec<_>>() == ["READY", "1d", "02"]
    };
    second.until("the program reads the two bytes", typed);

    // The terminal's size is the session's, also when it changes: the viewer asks koh's
    // mirror to take it, as it asks any pane, and koh carries that to the session.
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

    // What koh made for its viewer, and its mirror, are gone with it.
    assert_eq!(names_in(&runtime), [""; 0]);
}

// ---- what the reviews of the switch asked for ---------------------------------------------------

/// The last `n` bytes of a file.
fn tail(path: &Path, n: u64) -> Vec<u8> {
    use std::io::{Seek as _, SeekFrom};
    let Ok(mut file) = fs::File::open(path) else {
        return Vec::new();
    };
    let len = file.metadata().map_or(0, |file| file.len());
    let _ = file.seek(SeekFrom::Start(len.saturating_sub(n)));
    let mut end = Vec::new();
    let _ = file.read_to_end(&mut end);
    end
}

/// What was read of numbered lines of 16 bytes that were typed (line N at byte 16 N): how
/// many stretches of them are left out, or where a byte came twice or out of its order.
fn stretches(read: &[u8], typed: &[u8]) -> Result<usize, String> {
    let (mut at, mut i, mut left_out) = (0, 0, 0);
    while i < read.len() {
        // Where what was read from here on is in what was typed: by the first whole line in it.
        let rest = &read[i..];
        let before = rest
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(rest.len(), |end| end + 1);
        let place = match rest
            .get(before..before + 15)
            .map(|line| String::from_utf8_lossy(line).parse::<usize>())
        {
            Some(Ok(line)) => (line * 16)
                .checked_sub(before)
                .ok_or(format!("byte {i}: before the first line"))?,
            // (The last bytes, with no whole line among them: they are the end of what was typed.)
            _ => typed
                .len()
                .checked_sub(rest.len())
                .ok_or(format!("byte {i}: more than was typed"))?,
        };
        if place < at {
            return Err(format!(
                "byte {i} of what was read was typed at {place}: before {at}, which was read already"
            ));
        }
        left_out += usize::from(place > at);
        let same = rest
            .iter()
            .zip(&typed[place..])
            .take_while(|(read, typed)| read == typed)
            .count();
        if same == 0 {
            return Err(format!(
                "byte {i} of what was read is not what was typed at {place}"
            ));
        }
        (i, at) = (i + same, place + same);
    }
    Ok(left_out)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paste_through_links_that_break_is_never_typed_twice() {
    let host = Host::start("twice", &[]);
    let tap = Tap::start(&host).await;
    let out = host.tmp.0.join("out");
    let mount = host.mount("a", Some(&tap), &["--new"], &reads_into(&out, 0));
    mount.shows("READY");
    // Numbered lines are pasted as fast as they are taken, while forty links in turn break:
    // the client hears no more, and the server still takes what the client had sent.
    let (pasting, ended) = (
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicBool::new(false)),
    );
    let (dir, goes_on, ends) = (mount.dir.clone(), pasting.clone(), ended.clone());
    let typist = std::thread::spawn(move || {
        let mut keys = fs::OpenOptions::new()
            .write(true)
            .open(dir.join("in"))
            .unwrap();
        let (mut all, mut line) = (Vec::new(), 0u64);
        while !ends.load(SeqCst) {
            if !goes_on.load(SeqCst) {
                std::thread::sleep(Duration::from_millis(2));
                continue;
            }
            let block: Vec<u8> = (line..line + 256)
                .flat_map(|n| format!("{n:015}\n").into_bytes())
                .collect();
            keys.write_all(&block).unwrap();
            all.extend(block);
            line += 256;
        }
        all
    });
    for broken in 0..40 {
        std::thread::sleep(Duration::from_millis(40));
        tap.half();
        pasting.store(false, SeqCst);
        mount.says("the link is back", broken + 1);
        pasting.store(true, SeqCst);
    }
    std::thread::sleep(Duration::from_millis(100));
    ended.store(true, SeqCst);
    let all = typist.join().unwrap();
    let end = &all[all.len() - 64..];
    until("the program has read to the paste's end", || {
        tail(&out, 64) == end
    });
    // A byte may be missing; none is there twice, and the order holds.
    let read = fs::read(&out).unwrap();
    let left_out = stretches(&read, &all);
    println!(
        "pasted {} bytes, {} arrived: {left_out:?}",
        all.len(),
        read.len()
    );
    assert!(
        left_out.as_ref().is_ok_and(|stretches| *stretches <= 40),
        "{left_out:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_ends_with_its_client() {
    // (What `koh serve` holds is counted in /proc.)
    if !cfg!(target_os = "linux") {
        return;
    }
    let host = Host::start("ends", &[]);
    let server = host.served.as_ref().unwrap().server.id();
    let holds = || {
        let count = |what: &str| {
            fs::read_dir(format!("/proc/{server}/{what}"))
                .unwrap()
                .count()
        };
        (count("fd"), count("task"))
    };
    let client = host.client().await;
    // One client comes and goes: what the server holds then is what it holds with none.
    let comes_and_goes = async |number: u64| {
        let asks = Attach {
            client: number,
            ..asks(Some("quiet"), &reads_into(&host.tmp.0.join("out"), 100))
        };
        let (mut send, mut from, _) = attach(&client, asks).await.unwrap();
        tell(&mut send, FromMirror::Has(Vec::new())).await;
        while recv_msg::<ToMirror>(&mut from, MAX_CHUNK).await.unwrap() != ToMirror::Done {}
    };
    comes_and_goes(0).await;
    let mut rest = holds();
    until("the server is at rest", || {
        std::thread::sleep(Duration::from_millis(500));
        std::mem::replace(&mut rest, holds()) == holds()
    });
    // A client that leaves in the middle of a paste the program does not read: its stream's
    // end is seen though typed bytes wait, and nothing of it is kept.
    for left in 0..3 {
        let mut mount = host.mount(&format!("m{left}"), None, &["--session", "quiet"], &[]);
        mount.shows("READY");
        let keys = mount.dir.join("in");
        let paste = std::thread::spawn(move || {
            let mut keys = fs::OpenOptions::new().write(true).open(keys).unwrap();
            let _ = keys.write_all(&vec![b'x'; 4 << 20]);
        });
        std::thread::sleep(Duration::from_secs(1));
        signal(&mount.koh.id().to_string(), "-TERM");
        assert_eq!(mount.ends(), Some(0));
        drop(mount);
        paste.join().unwrap();
    }
    until(
        &format!("the server holds {rest:?} again, not {:?}", holds()),
        || holds().0 <= rest.0 && holds().1 <= rest.1,
    );
    // And after a hundred clients that came and went.
    for number in 1..=100 {
        comes_and_goes(number).await;
    }
    until(
        &format!("the server holds {rest:?} again, not {:?}", holds()),
        || holds().0 <= rest.0 && holds().1 <= rest.1,
    );
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_that_ends_as_a_clients_list_is_read_is_shown_to_its_end() {
    let host = Host::start("listed", &[]);
    let client = host.client().await;
    let program = [
        "sh",
        "-c",
        "echo READY; read go; echo THE-LAST-WORD; exit 7",
    ]
    .map(String::from);
    let (mut send, mut from, attached) = attach(&client, asks(None, &program)).await.unwrap();
    let pane = host.pane(&attached.name);
    until("the program is ready", || screen(&pane).contains("READY"));
    // A list that takes the server a while to read (a file of 8 MB it has, under a hash it
    // has not), and the program's end while it reads.
    fs::write(pane.join("large"), vec![b'.'; 8 << 20]).unwrap();
    let had = koh::proto::Had {
        name: "large".into(),
        kind: koh::proto::Kind::File,
        len: 8 << 20,
        hash: [0; 32],
    };
    tell(&mut send, FromMirror::Has(vec![had])).await;
    tokio::time::sleep(Duration::from_millis(5)).await;
    fs::write(pane.join("in"), "go\n").unwrap();
    // The client is given the last round before it is told of the end: the last screen, and
    // how the program ended.
    let kept = host.tmp.0.join("kept");
    let mut mirror = koh::carry::Mirror::make(&kept).unwrap();
    let _ = mirror.has().unwrap();
    let carried = async {
        while !mirror
            .take(
                recv_msg(&mut from, MAX_CHUNK).await.unwrap(),
                Instant::now(),
            )
            .unwrap()
        {}
    };
    tokio::time::timeout(Duration::from_secs(60), carried)
        .await
        .unwrap();
    assert_eq!(
        fs::read_to_string(kept.join("state")).unwrap_or_default(),
        "exited 7\n"
    );
    assert!(screen(&kept).contains("THE-LAST-WORD"));
    client.close().await;
}

#[test]
fn a_terminal_that_is_closed_ends_koh_and_what_it_made() {
    let host = Host::start("hangup", &[]);
    // `koh mount`, hung up as a closed terminal hangs it up: it ends as if stopped, and its
    // mirror goes, so the next mount of that session is not refused by what koh itself left.
    let mounts = host.tmp.0.join("crun/koh/fux/koh-mounts");
    for _ in 0..2 {
        let mut koh = host.koh(&[
            "mount",
            &host.id,
            "--direct",
            &host.addr(),
            "--session",
            "s",
        ]);
        let mut mount = Mount {
            koh: koh.stderr(std::process::Stdio::null()).spawn().unwrap(),
            dir: mounts.join(format!("{}.s", &host.id[..62])),
            said: PathBuf::new(),
        };
        until("the mirror is there", || {
            mount.dir.join("generation").is_file()
        });
        signal(&mount.koh.id().to_string(), "-HUP");
        assert_eq!(mount.ends(), Some(0));
        assert_eq!(names_in(&mounts), [""; 0]);
    }
    // `koh connect`, its terminal closed: it ends, and its private folder goes with it.
    let (config, runtime) = (host.tmp.0.join("cli_cfg"), host.tmp.0.join("crun2"));
    fs::create_dir_all(&runtime).unwrap();
    let asks = ["--direct", &host.addr(), &host.id, "--session", "s"];
    let mut connect = InTerminal::connect(&config, &runtime, &asks);
    connect.until("the terminal shows the session", |tty| {
        !tty.drawn.is_empty() && names_in(&runtime).len() == 1
    });
    std::thread::sleep(Duration::from_millis(300));
    drop(std::mem::replace(
        &mut connect.tty,
        fs::File::open("/dev/null").unwrap(),
    ));
    assert_eq!(connect.ends(), Some(0));
    assert_eq!(names_in(&runtime), [""; 0]);
    assert_eq!(
        fs::read_to_string(host.pane("s").join("state")).unwrap(),
        "running\n"
    );
}

/// A server of the test's own, which a client dials: it may answer anything.
struct Hostile {
    endpoint: iroh::Endpoint,
    at: Tap,
}

impl Hostile {
    async fn start(host: &Host) -> Self {
        let key = host.tmp.0.join("tap_cfg/server.key");
        let secret = load_or_create_key(Role::Server, Some(&key)).unwrap();
        let id = secret.public().to_string();
        let local = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let endpoint = bind_server(secret, Some(local), true).await.unwrap();
        let addr = endpoint
            .bound_sockets()
            .into_iter()
            .next()
            .unwrap()
            .to_string();
        let at = Tap {
            id,
            addr,
            wire: Wire::new(),
        };
        Self { endpoint, at }
    }

    /// The next attach on a connection, answered `Ok`: its stream, and what it asked.
    async fn asked(conn: &Connection) -> (SendStream, RecvStream, Attach) {
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        verify_client(conn, &mut recv).await.unwrap();
        let Request::Attach(asks) = recv_msg(&mut recv, MAX_CTRL).await.unwrap() else {
            panic!("no attach")
        };
        send_msg(&mut send, &Reply::Ok, MAX_CTRL).await.unwrap();
        (send, recv, asks)
    }
}

const RUNS: [Run; 2] = [
    Run {
        device: 1,
        folder: 2,
        holder: 3,
    },
    Run {
        device: 1,
        folder: 2,
        holder: 4,
    },
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reconnect_answered_with_another_run_types_nothing() {
    let host = Host::start("answered", &[]);
    let hostile = Hostile::start(&host).await;
    let mut mount = host.mount("a", Some(&hostile.at), &[], &[]);
    let conn = hostile.endpoint.accept().await.unwrap().await.unwrap();
    // A first link, with a round that gives the mirror its `in`; then it breaks.
    let (mut send, mut recv, _) = Hostile::asked(&conn).await;
    let attached = |run| Attached {
        name: "1".into(),
        run,
    };
    send_msg(&mut send, &attached(RUNS[0]), MAX_CTRL)
        .await
        .unwrap();
    let _: FromMirror = recv_msg(&mut recv, MAX_CHUNK).await.unwrap();
    for message in [
        ToMirror::Round(2),
        ToMirror::Fifo("in".into()),
        ToMirror::Done,
    ] {
        send_msg(&mut send, &message, MAX_CHUNK).await.unwrap();
    }
    until("the mirror has its FIFO", || mount.dir.join("in").exists());
    let _ = send.reset(0u32.into());
    mount.says("no link", 1);
    mount.types(b"typed for the run that was\n");
    // The client asks for the run it had, and is answered with another: it says so and ends,
    // and what it held is typed nowhere.
    let (mut send, mut recv, asks) = Hostile::asked(&conn).await;
    assert_eq!(asks.run, Some(RUNS[0]));
    send_msg(&mut send, &attached(RUNS[1]), MAX_CTRL)
        .await
        .unwrap();
    assert_eq!(mount.ends(), Some(127));
    let said = mount.said();
    assert!(
        said.contains("another run has the session's name"),
        "{said}"
    );
    assert!(said.contains("27 typed bytes were not sent"), "{said}");
    let mut sent = Vec::new();
    while let Ok(Some(message)) = koh::proto::recv_msg_opt::<FromMirror>(&mut recv, MAX_CHUNK).await
    {
        sent.push(message);
    }
    assert!(
        !sent
            .iter()
            .any(|message| matches!(message, FromMirror::Write { .. })),
        "{sent:?}"
    );

    // An answer that is no answer (more than the name and the run a session has) is a
    // refusal too: the client ends, and does not ask again.
    let mut mount = host.mount("b", Some(&hostile.at), &[], &[]);
    let conn = hostile.endpoint.accept().await.unwrap().await.unwrap();
    let (mut send, _recv, _) = Hostile::asked(&conn).await;
    send_msg(&mut send, &(attached(RUNS[0]), 7u8), MAX_CTRL)
        .await
        .unwrap();
    assert_eq!(mount.ends(), Some(1));
    assert!(
        mount
            .said()
            .contains("the server sent what a mirror does not take"),
        "{}",
        mount.said()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_open_round_that_stands_still_is_a_broken_link() {
    let host = Host::start("still", &[]);
    let hostile = Hostile::start(&host).await;
    let mount = host.mount("a", Some(&hostile.at), &[], &[]);
    let conn = hostile.endpoint.accept().await.unwrap().await.unwrap();
    // A round is begun, and nothing follows it: no message, and no end of the stream.
    let (mut send, mut recv, _) = Hostile::asked(&conn).await;
    let attached = Attached {
        name: "1".into(),
        run: RUNS[0],
    };
    send_msg(&mut send, &attached, MAX_CTRL).await.unwrap();
    let _: FromMirror = recv_msg(&mut recv, MAX_CHUNK).await.unwrap();
    for message in [ToMirror::Round(2), ToMirror::Folder("main".into())] {
        send_msg(&mut send, &message, MAX_CHUNK).await.unwrap();
    }
    let began = Instant::now();
    // After thirty seconds the client throws the round away and attaches anew, to the run it had.
    let again = tokio::time::timeout(Duration::from_secs(50), Hostile::asked(&conn)).await;
    let (_send, _recv, asks) = again.expect("the client did not come again");
    assert!(
        began.elapsed() >= Duration::from_secs(29),
        "after {:?}",
        began.elapsed()
    );
    assert_eq!(asks.run, Some(RUNS[0]));
    // (Nothing of the round was done to the mirror, and nothing of it is left beside it.)
    assert_eq!(names_in(&mount.dir), [".koh"]);
    assert_eq!(names_in(&mount.dir.join(".koh")), [""; 0]);
}

#[test]
fn an_ended_session_with_a_client_is_not_removed_and_a_start_that_fails_removes_none() {
    let host = Host::start("kept", &["--max-sessions", "1"]);
    let run = |at: &str, asks: &[&str], program: &[&str]| {
        let program: Vec<String> = program.iter().map(|word| word.to_string()).collect();
        host.mount(at, None, asks, &program)
    };
    // One session, which has ended, with megabytes of text.
    assert_eq!(
        run("a", &["--new"], &["sh", "-c", "seq 1 400000"]).ends(),
        Some(0)
    );
    // A session that cannot start takes the place of none: the ended one is still there.
    let mut fails = run("b", &["--new"], &["/no/such/program"]);
    assert_eq!(fails.ends(), Some(126));
    assert!(
        fails.said().contains("no session was started"),
        "{}",
        fails.said()
    );
    until(
        "the folder of the start that failed is all that came",
        || names_in(&host.sessions).len() == 2,
    );
    assert!(host.pane("1").join("state").is_file());
    fs::remove_dir_all(host.pane("2")).unwrap();
    // A client is given the ended session and does not read what it is sent: its stream lives.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (client, stream) = runtime.block_on(async {
        let client = host.client().await;
        let (mut send, from, _) = attach(&client, asks(Some("1"), &[])).await.unwrap();
        tell(&mut send, FromMirror::Has(Vec::new())).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        (client, (send, from))
    });
    // While it does, the session does not go to make room: the server is busy.
    let mut third = run("c", &["--new"], &["sleep", "30"]);
    assert_eq!(third.ends(), Some(75));
    assert_eq!(names_in(&host.sessions), ["1"]);
    // Once the client has left it goes for a new one.
    drop(stream);
    runtime.block_on(client.close());
    let fourth = run("d", &["--new"], &["sleep", "30"]);
    until("the ended session made room", || {
        names_in(&host.sessions) == ["2"]
    });
    until("the new one is mirrored", || {
        fourth.dir.join("generation").is_file()
    });
}

#[test]
fn a_default_mirror_has_a_name_fux_shows_and_fuxs_own_names_are_no_sessions() {
    let host = Host::start("names", &[]);
    let mounts = host.tmp.0.join("crun/koh/fux/koh-mounts");
    // A session's name may be all of the 64 characters a name has: with no place named, its
    // mirror still has a pane's kind of name, cut to fit.
    for len in [3, 62, 63, 64] {
        let name = "n".repeat(len);
        let mut koh = host.koh(&[
            "mount",
            &host.id,
            "--direct",
            &host.addr(),
            "--session",
            &name,
        ]);
        let mut mount = Mount {
            koh: koh
                .args(["--", "sleep", "100"])
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
            dir: mounts.clone(),
            said: PathBuf::new(),
        };
        let mirrors = || fs::read_dir(&mounts).map_or(0, |mirrors| mirrors.count());
        until("the mirror is there", || mirrors() == 1);
        let mirror = names_in(&mounts).remove(0);
        assert!(
            mirror.len() <= 64 && !mirror.starts_with('.') && mirror.ends_with(&name),
            "{mirror}"
        );
        assert_eq!(mirror.len() == len, len > 62, "{mirror}");
        signal(&mount.koh.id().to_string(), "-TERM");
        assert_eq!(mount.ends(), Some(0));
    }
    // The names fux keeps for itself are refused as any other that is no name, before a
    // session is started for them.
    for name in ["layout", "-", "keyboard", "colours", ".hidden", "a/b"] {
        let mut mount = host.mount("r", None, &["--session", name], &[]);
        assert_eq!(mount.ends(), Some(2), "{name}");
    }
    assert_eq!(names_in(&host.sessions).len(), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_says_what_no_client_says_loses_its_stream() {
    let host = Host::start("says", &[]);
    let client = host.client().await;
    let session = host.sessions.parent().unwrap().to_path_buf();
    let sleeps = ["sleep".to_string(), "100".into()];
    let told = |name: &str| FromMirror::Told {
        name: name.into(),
        bytes: b"told\n".to_vec(),
    };
    let not_said = [
        // A second list: the first is what the server's record of the mirror is made of.
        FromMirror::Has(Vec::new()),
        // What a terminal is like, under any name but the two that are that.
        told("layout"),
        told("../../told"),
        told("koh-sessions/1/command"),
        // Typed bytes for anything but the two FIFOs.
        FromMirror::Write {
            name: "command".into(),
            bytes: b"typed\n".to_vec(),
        },
    ];
    for (number, message) in not_said.into_iter().enumerate() {
        let asks = Attach {
            client: number as u64,
            ..asks(Some("1"), &sleeps)
        };
        let (mut send, mut from, _) = attach(&client, asks).await.unwrap();
        tell(&mut send, FromMirror::Has(Vec::new())).await;
        tell(&mut send, told("keyboard")).await;
        tell(&mut send, message.clone()).await;
        // The stream ends: what follows is read by nobody.
        let ended = async {
            while let Ok(Some(_)) = koh::proto::recv_msg_opt::<ToMirror>(&mut from, MAX_CHUNK).await
            {
            }
        };
        let ended = tokio::time::timeout(Duration::from_secs(10), ended).await;
        assert!(ended.is_ok(), "the stream lived on after {message:?}");
    }
    // Nothing was written but what a client may say, where it may say it.
    assert_eq!(names_in(&session), ["keyboard", "koh-sessions"]);
    assert_eq!(
        fs::read_to_string(session.join("keyboard")).unwrap(),
        "told\n"
    );
    assert_eq!(names_in(&host.tmp.0.join("run/koh")), ["fux", "jobs"]);
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn koh_connect_told_to_end_before_its_first_round_ends_and_leaves_nothing() {
    let host = Host::start("early", &[]);
    let hostile = Hostile::start(&host).await;
    let (config, runtime) = (host.tmp.0.join("cli_cfg"), host.tmp.0.join("crun2"));
    fs::create_dir_all(&runtime).unwrap();
    // A server that answers the attach and never sends a whole round: `koh connect` waits
    // for its first round, with no viewer yet. Interrupted, terminated or hung up then, it
    // ends as it does later, and its private folder goes.
    for told in ["-HUP", "-INT", "-TERM"] {
        let asks = ["--direct", &hostile.at.addr, &hostile.at.id];
        let mut connect = InTerminal::connect(&config, &runtime, &asks);
        let conn = hostile.endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, mut recv, _) = Hostile::asked(&conn).await;
        let attached = Attached {
            name: "1".into(),
            run: RUNS[0],
        };
        send_msg(&mut send, &attached, MAX_CTRL).await.unwrap();
        let _: FromMirror = recv_msg(&mut recv, MAX_CHUNK).await.unwrap();
        send_msg(&mut send, &ToMirror::Round(2), MAX_CHUNK)
            .await
            .unwrap();
        assert_eq!(names_in(&runtime).len(), 1);
        tokio::time::sleep(Duration::from_millis(300)).await;
        signal(&connect.koh.id().to_string(), told);
        let began = Instant::now();
        assert_eq!(connect.ends(), Some(0), "{told}");
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "{told}: after {:?}",
            began.elapsed()
        );
        assert_eq!(names_in(&runtime), [""; 0], "{told}");
    }
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

    /// A session of that name running `program`, with nobody attached once this returns: its
    /// folder, when its screen shows `ready`.
    fn session(&self, name: &str, program: &[String], ready: &str) -> PathBuf {
        let mut mount = self.mount(name, None, &["--session", name], program);
        let pane = self.pane(name);
        until(&format!("the session {name} shows {ready:?}"), || {
            screen(&pane).contains(ready)
        });
        signal(&mount.koh.id().to_string(), "-TERM");
        assert_eq!(mount.ends(), Some(0), "{}", mount.said());
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
    let mut live = host.mount("a", None, &["--session", "live"], &marking_shell(&host));
    let pane = host.pane("live");
    until("the shell has its prompt", || screen(&pane).contains('$'));
    let mut done = host.mount("b", None, &["--session", "done"], &sh("exit 7"));
    assert_eq!(done.ends(), Some(7));
    let mut dead = host.mount("c", None, &["--session", "dead"], &marking_shell(&host));
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
        timeout_secs: Some(60),
    };
    client.request(&asked).await.unwrap().1
}

/// What a wait was answered: its exit code and its text.
async fn waited(mut wait: RecvStream) -> (i32, String) {
    let ended: koh::proto::WaitResult = recv_msg(&mut wait, MAX_CTRL).await.unwrap();
    let text = koh::proto::recv_pieces(&mut wait).await.unwrap();
    (ended.exit, String::from_utf8(text).unwrap())
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
        fs::write(pane.join("in"), "\n").unwrap();
        let title = format!("done-{done}\n");
        until(&title, || {
            fs::read_to_string(pane.join("title")).is_ok_and(|said| said == title)
        });
        fs::read_to_string(pane.join("marks")).unwrap()
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
