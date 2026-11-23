//! End-to-end integration tests over real loopback iroh QUIC connections.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use koh::Exit;
use koh::client::Client;
use koh::keys::{ClientEntry, Role, Route, Scope, load_or_create_key, save_clients};
use koh::proto::{
    ClientEvent, MAX_CHUNK, MAX_CTRL, MAX_FRAME, Request, ScreenFrame, recv_msg, send_msg,
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

    // Wait for --file.
    let marker = tmp.0.join("ready.flag");
    let marker_bg = marker.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _ = fs::write(&marker_bg, "ok");
    });
    let wf = client
        .wait_file(marker.display().to_string(), Some(5))
        .await
        .unwrap();
    assert!(!wf.timed_out && wf.exit == 0);

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
async fn fux_backed_session_pane_folder_osc133_marks_and_local_mount() {
    let (tmp, srv, client, _, state_dir) = boot_pair("session").await;

    // Attach to a new interactive session running a script that emits OSC 133 marks.
    let (mut send, mut recv) = client
        .request(&Request::Attach {
            session: None,
            new: true,
            cols: 80,
            rows: 10,
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "stty -echo; \
                 printf '\\033]133;A\\007$ \\033]133;B\\007cmd1\\033]133;C\\007\\r\\nFIRST_OUT\\r\\n\\033]133;D;7\\007'; \
                 read line; \
                 printf '\\033]133;A\\007$ \\033]133;B\\007cmd2\\033]133;C\\007\\r\\nSECOND_OUT_%s\\r\\n\\033]133;D;42\\007' \"$line\"; \
                 sleep 30"
                    .into(),
            ],
            cwd: Some(tmp.0.display().to_string()),
        })
        .await
        .unwrap();

    // Wait for first output frame pushed over QUIC (zero polling!).
    let sid = loop {
        let frame: ScreenFrame = recv_msg(&mut recv, MAX_FRAME).await.unwrap();
        if frame.screen.contains("FIRST_OUT") && frame.marks.contains("end 7") {
            break frame.session_id;
        }
    };

    // Verify genuine frozen v1 `fux` pane folder exists on the server!
    let pane_dir = state_dir.join("sessions").join(format!("s{sid}"));
    assert!(pane_dir.join("shown/screen").is_file());
    assert!(pane_dir.join("shown/screen.styled").is_file());
    assert!(pane_dir.join("shown/lines").is_file());
    assert!(pane_dir.join("marks").is_file());
    assert!(
        fs::read_to_string(pane_dir.join("shown/screen"))
            .unwrap()
            .contains("FIRST_OUT")
    );

    // Verify `koh sessions` reads OSC 133 state & last exit code.
    let sessions = client.sessions().await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].last_exit, Some(7));
    assert!(!sessions[0].running_command);

    // Verify `koh output --session N --last` slices via OSC 133 marks.
    let last_out = client.output(sid, true).await.unwrap();
    assert!(last_out.contains("FIRST_OUT"), "got: {last_out:?}");

    // Verify `koh wait --session N` wakes on next OSC 133 MarkKind::End and returns exit 42!
    let wait_task = tokio::spawn({
        let (srv_id, addr) = (srv.endpoint_id, srv.direct_addr.unwrap());
        let ckey =
            load_or_create_key(Role::Client, Some(&tmp.0.join("cli_cfg/client.key"))).unwrap();
        async move {
            let c2 = Client::connect_direct(ckey, srv_id, Some(Route::Direct(addr)), true)
                .await
                .unwrap();
            let res = c2.wait_session(sid, Some(5)).await.unwrap();
            c2.close().await;
            res
        }
    });
    tokio::time::sleep(Duration::from_millis(60)).await;
    send_msg(
        &mut send,
        &ClientEvent::Input(b"HELLO\n".to_vec()),
        MAX_CHUNK,
    )
    .await
    .unwrap();

    let waited = wait_task.await.unwrap();
    assert!(!waited.timed_out);
    assert_eq!(waited.exit, 42);
    assert!(
        waited.tail.contains("SECOND_OUT_HELLO"),
        "tail={:?}",
        waited.tail
    );

    let _ = send_msg(&mut send, &ClientEvent::Detach, MAX_CTRL).await;
    drop(send);
    drop(recv);

    // Verify local `fux` pane mirroring (`mount_local_pane`) writes valid v1 pane files + FIFOs.
    let local_mirror = tmp.0.join("local_fux_pane");
    let mirror_dir = local_mirror.clone();
    let (srv_id, addr) = (srv.endpoint_id, srv.direct_addr.unwrap());
    let ckey = load_or_create_key(Role::Client, Some(&tmp.0.join("cli_cfg/client.key"))).unwrap();
    let mount_task = tokio::spawn(async move {
        let c3 = Client::connect_direct(ckey, srv_id, Some(Route::Direct(addr)), true)
            .await
            .unwrap();
        let _ = c3.mount_local_pane(Some(sid), &mirror_dir, 80, 10).await;
        c3.close().await;
    });
    for _ in 0..80 {
        if local_mirror.join("shown/screen").is_file()
            && fs::read_to_string(local_mirror.join("shown/screen"))
                .unwrap_or_default()
                .contains("SECOND_OUT_HELLO")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        fs::read_to_string(local_mirror.join("shown/screen"))
            .unwrap()
            .contains("SECOND_OUT_HELLO")
    );
    assert!(local_mirror.join("in").exists() && local_mirror.join("ctl").exists());
    // Writing `kill` to local `ctl` detaches the mirror cleanly.
    fs::write(local_mirror.join("ctl"), "kill\n").unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(3), mount_task).await;

    client.close().await;
    srv.shutdown().await;
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
    let err = stranger.sessions().await.unwrap_err();
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
}
