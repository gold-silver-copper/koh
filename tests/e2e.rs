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
    ClientEvent, MAX_CHUNK, MAX_CTRL, MAX_FRAME, PictureKind, Request, ScreenFrame, ServerEvent,
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
    let (tmp, srv, client, client_key, state_dir) = boot_pair("session").await;

    // Attach to a new interactive session running a script that emits OSC 133 marks.
    let (mut send, mut recv) = client
        .request(&Request::Attach {
            session: None,
            new: true,
            cols: 80,
            rows: 10,
            cell_w: 10,
            cell_h: 20,
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "stty -echo; \
                 printf '\\033]133;A\\007$ \\033]133;B\\007cmd1\\033]133;C\\007\\r\\nFIRST_OUT\\r\\n\\033]133;D;7\\007'; \
                 read line; \
                 printf '\\033]133;A\\007$ \\033]133;B\\007cmd2\\033]133;C\\007\\r\\nSECOND_OUT_%s\\r\\n\\033]133;D;42\\007' \"$line\"; \
                 read line2; \
                 printf 'AFTER_RECONNECT_%s\\r\\n' \"$line2\"; \
                 sleep 30"
                    .into(),
            ],
            cwd: Some(tmp.0.display().to_string()),
        })
        .await
        .unwrap();

    // Wait for first output frame pushed over QUIC (zero polling!).
    let mut current = ScreenFrame::default();
    let sid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match recv_msg::<ServerEvent>(&mut recv, MAX_FRAME).await.unwrap() {
                ServerEvent::Full(frame) => current = frame,
                ServerEvent::Delta(delta) => {
                    let _ = current.apply_delta(delta);
                }
                ServerEvent::Picture(_) => {}
            }
            if current.screen.contains("FIRST_OUT") && current.marks.contains("end 7") {
                break current.session_id;
            }
        }
    })
    .await
    .expect("timed out waiting for FIRST_OUT and OSC 133 end 7");

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
        let ckey = client_key.clone();
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

    // Verify local `fux` pane mirroring (`mount_local_pane`) writes valid v1 pane files + FIFOs
    // AND automatically reconnects to the exact same session after a sudden QUIC link drop!
    let local_mirror = tmp.0.join("local_fux_pane");
    let mirror_dir = local_mirror.clone();
    let (srv_id, addr) = (srv.endpoint_id, srv.direct_addr.unwrap());
    let mut c3 = Client::connect_direct(client_key, srv_id, Some(Route::Direct(addr)), true)
        .await
        .unwrap();
    let conn_handle = c3.connection();
    let mount_task = tokio::spawn(async move {
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

    // Simulate a sudden network drop (close the mounted client's QUIC connection)
    // and write to `in` immediately — verifying BOTH FIFO input buffering during reconnect
    // AND automatic redial/reattach to the exact same remote session!
    conn_handle.close(0u32.into(), b"simulated-wifi-drop");
    fs::write(local_mirror.join("in"), "SURVIVED\n").unwrap();
    for _ in 0..160 {
        if fs::read_to_string(local_mirror.join("shown/screen"))
            .unwrap_or_default()
            .contains("AFTER_RECONNECT_SURVIVED")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        fs::read_to_string(local_mirror.join("shown/screen"))
            .unwrap()
            .contains("AFTER_RECONNECT_SURVIVED"),
        "expected mirrored pane to auto-reconnect and receive post-drop output"
    );

    assert!(local_mirror.join("in").exists() && local_mirror.join("ctl").exists());
    // Writing `kill` to local `ctl` detaches the mirror cleanly.
    fs::write(local_mirror.join("ctl"), "kill\n").unwrap();
    tokio::time::timeout(Duration::from_secs(3), mount_task)
        .await
        .expect("mount_task did not detach within 3s")
        .expect("mount_task panicked");

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

#[tokio::test]
async fn session_forwards_clipboard_links_colours_bell_deltas_and_kitty_pictures() {
    let (tmp, srv, client, client_key, state_dir) = boot_pair("rich-session").await;

    // Tiny valid 1x1 red PNG encoded by fux-vt itself, base64-encoded for Kitty graphics APC!
    let tiny_png = fux_vt::png::encode_rgba(1, 1, &[255, 0, 0, 255], 4096).unwrap();
    let png_b64 = fux_vt::base64_encode(&tiny_png);

    let script = format!(
        "stty raw -echo; \
         printf 'READY\\r\\n'; \
         head -c 1 >/dev/null; \
         printf '\\033]10;?\\033\\\\'; \
         ans=$(dd bs=64 count=1 2>/dev/null | tr -cd '[:print:]'); \
         printf 'COL=%s\\r\\n' \"$ans\"; \
         printf '\\033]12;#445566\\007'; \
         printf '\\033]52;c;aGVsbG8gY2xpcA==\\007'; \
         printf '\\033]8;;https://koh.sh\\007click\\033]8;;\\007\\r\\n'; \
         printf '\\033]9;build done\\007'; \
         printf '\\033_Ga=T,f=100,t=d,q=2;{png_b64}\\033\\\\\\r\\n'; \
         head -c 1 >/dev/null; \
         printf 'ONE_LINE_EDIT\\r\\n'; \
         head -c 1 >/dev/null; \
         printf '\\033_Ga=d,d=A,q=2\\033\\\\DELETED_PIC\\r\\n'; \
         sleep 30"
    );

    let (mut send, mut recv) = client
        .request(&Request::Attach {
            session: None,
            new: true,
            cols: 80,
            rows: 12,
            cell_w: 12,
            cell_h: 24,
            argv: vec!["/bin/sh".into(), "-c".into(), script],
            cwd: Some(tmp.0.display().to_string()),
        })
        .await
        .unwrap();

    // Forward host colours right after attach.
    send_msg(
        &mut send,
        &ClientEvent::Colours("foreground #aabbcc\nbackground #112233\n".into()),
        MAX_CTRL,
    )
    .await
    .unwrap();

    let mut frame = ScreenFrame::default();
    let sid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match recv_msg::<ServerEvent>(&mut recv, MAX_FRAME).await.unwrap() {
                ServerEvent::Full(f) => frame = f,
                ServerEvent::Delta(d) => {
                    let _ = frame.apply_delta(d);
                }
                ServerEvent::Picture(_) => {}
            }
            if frame.screen.contains("READY") {
                break frame.session_id;
            }
        }
    })
    .await
    .expect("timed out waiting for READY frame");

    // Give Colours event a moment to apply before triggering OSC 10;? query in step 1.
    tokio::time::sleep(Duration::from_millis(40)).await;
    send_msg(&mut send, &ClientEvent::Input(b"1".to_vec()), MAX_CHUNK)
        .await
        .unwrap();

    let mut pic_blobs = 0usize;
    let mut saw_clip = false;
    let mut saw_notice = false;
    let mut saw_link = false;
    let mut saw_pic_ref = false;
    let mut saw_colour = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !(saw_clip && saw_notice && saw_link && saw_pic_ref && saw_colour) {
            match recv_msg::<ServerEvent>(&mut recv, MAX_FRAME).await.unwrap() {
                ServerEvent::Picture(blob) => {
                    assert_eq!(blob.kind, PictureKind::Png);
                    assert_eq!(blob.bytes, tiny_png);
                    pic_blobs += 1;
                }
                ServerEvent::Full(f) => frame = f,
                ServerEvent::Delta(d) => {
                    let _ = frame.apply_delta(d);
                }
            }
            if frame.screen.contains("rgb:aaaa/bbbb/cccc") {
                saw_colour = true;
            }
            if frame.clipboard.as_deref() == Some(b"hello clip") {
                saw_clip = true;
            }
            if frame.notice.as_deref() == Some("build done") {
                saw_notice = true;
            }
            if frame.links.contains("https://koh.sh") {
                saw_link = true;
            }
            if frame.pictures.contains("pic-1.png") {
                saw_pic_ref = true;
            }
        }
    })
    .await
    .expect("timed out waiting for clipboard/notice/link/picture/colour events");
    assert_eq!(pic_blobs, 1, "picture payload must be sent once per ID");

    // Verify frozen v1 server pane folder also recorded clipboard, notice, links, cursor colour, and pic-1.png.
    let pane_dir = state_dir.join("sessions").join(format!("s{sid}"));
    assert_eq!(fs::read(pane_dir.join("clipboard")).unwrap(), b"hello clip");
    assert!(
        fs::read_to_string(pane_dir.join("cursor"))
            .unwrap()
            .contains("#445566"),
        "expected OSC 12 cursor colour as 5th word in v1 cursor file"
    );
    assert!(
        fs::read_to_string(pane_dir.join("notice"))
            .unwrap()
            .contains("build done")
    );
    assert!(
        fs::read_to_string(pane_dir.join("shown/links"))
            .unwrap()
            .contains("https://koh.sh")
    );
    assert!(pane_dir.join("pic-1.png").is_file());

    // Step 2: small 1-line edit MUST arrive as a compact Delta (NOT re-sending pic-1.png!).
    send_msg(&mut send, &ClientEvent::Input(b"2".to_vec()), MAX_CHUNK)
        .await
        .unwrap();
    let mut got_small_delta = false;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match recv_msg::<ServerEvent>(&mut recv, MAX_FRAME).await.unwrap() {
                ServerEvent::Picture(_) => panic!("picture must not be re-sent for unchanged ID"),
                ServerEvent::Delta(d) => {
                    if d.changed_rows.len() <= 2 {
                        got_small_delta = true;
                    }
                    let _ = frame.apply_delta(d);
                }
                ServerEvent::Full(f) => frame = f,
            }
            if frame.screen.contains("ONE_LINE_EDIT") {
                break;
            }
        }
    })
    .await
    .expect("timed out waiting for ONE_LINE_EDIT delta");
    assert!(got_small_delta, "expected compact row-level FrameDelta");

    // Mount the same session locally and verify pic-1.png + pictures mirror into local pane folder,
    // and that deleting the picture removes pic-1.png on BOTH server and local mirror!
    let local_mirror = tmp.0.join("mirror_pics");
    let addr = srv.direct_addr.unwrap();
    let mut mclient =
        Client::connect_direct(client_key, srv.endpoint_id, Some(Route::Direct(addr)), true)
            .await
            .unwrap();
    let mdir = local_mirror.clone();
    let mtask = tokio::spawn(async move {
        let r = mclient.mount_local_pane(Some(sid), &mdir, 80, 12).await;
        mclient.close().await;
        r
    });
    for _ in 0..80 {
        if local_mirror.join("pic-1.png").is_file()
            && fs::read_to_string(local_mirror.join("shown/pictures"))
                .unwrap_or_default()
                .contains("pic-1.png")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(local_mirror.join("pic-1.png").is_file());
    assert!(
        fs::read_to_string(local_mirror.join("status"))
            .unwrap()
            .starts_with("pid ")
    );
    assert!(
        fs::read_to_string(local_mirror.join("cursor"))
            .unwrap()
            .contains("#445566")
    );

    // Step 3: delete the Kitty image and verify cleanup on both server and mirror.
    send_msg(&mut send, &ClientEvent::Input(b"3".to_vec()), MAX_CHUNK)
        .await
        .unwrap();
    for _ in 0..80 {
        if !local_mirror.join("pic-1.png").exists()
            && fs::read_to_string(local_mirror.join("shown/screen"))
                .unwrap_or_default()
                .contains("DELETED_PIC")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(!local_mirror.join("pic-1.png").exists());
    assert!(!pane_dir.join("pic-1.png").exists());

    fs::write(local_mirror.join("ctl"), "kill\n").unwrap();
    tokio::time::timeout(Duration::from_secs(3), mtask)
        .await
        .expect("mount mirror task did not detach within 3s")
        .expect("mount mirror task panicked")
        .expect("mount mirror returned error");
    let _ = send_msg(&mut send, &ClientEvent::Detach, MAX_CTRL).await;
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
async fn scoped_cp_never_writes_reads_or_deletes_through_a_symlink() {
    use std::os::unix::fs::symlink;
    let (tmp, srv, client, allowed, outside) = boot_scoped("symlink").await;
    let push = |src: PathBuf, delete: bool| {
        let (client, dst) = (&client, allowed.display().to_string());
        async move {
            client
                .cp_push(&src, dst, Vec::new(), delete, false, false)
                .await
        }
    };

    // A directory on the way that is a symlink out of DIR: refused, nothing written beyond it.
    symlink(&outside, allowed.join("link")).unwrap();
    let through = tmp.0.join("through");
    fs::create_dir_all(through.join("link")).unwrap();
    fs::write(through.join("link/x"), "escaped").unwrap();
    let err = push(through.clone(), false).await.unwrap_err();
    assert_eq!(err.code, Exit::REFUSED, "{err:?}");
    assert!(!outside.join("x").exists(), "wrote through DIR/link");

    // `--delete` removes nothing beyond it either.
    fs::write(outside.join("victim"), "keep").unwrap();
    let _ = push(through, true).await;
    let empty = tmp.0.join("empty");
    fs::create_dir_all(&empty).unwrap();
    push(empty, true).await.unwrap();
    assert_eq!(fs::read_to_string(outside.join("victim")).unwrap(), "keep");
    fs::remove_file(allowed.join("link")).unwrap();

    // A symlink where the file lands is replaced, never read or written through: the same bytes
    // are beyond it, and the copy must not find the file "unchanged" by hashing them.
    fs::write(outside.join("target"), "same").unwrap();
    symlink(outside.join("target"), allowed.join("final")).unwrap();
    let onto = tmp.0.join("onto");
    fs::create_dir_all(&onto).unwrap();
    fs::write(onto.join("final"), "same").unwrap();
    let done = push(onto, false).await.unwrap();
    assert_eq!(done.unchanged, 0, "hashed the file beyond DIR/final");
    assert!(
        fs::symlink_metadata(allowed.join("final"))
            .unwrap()
            .is_file()
    );
    assert_eq!(fs::read_to_string(outside.join("target")).unwrap(), "same");

    // A symlink planted at the name the file's bytes used to be written under first.
    symlink(outside.join("planted"), allowed.join(".x.koh-tmp")).unwrap();
    let file = tmp.0.join("x");
    fs::write(&file, "payload").unwrap();
    push(file, false).await.unwrap();
    assert!(!outside.join("planted").exists(), "wrote through the temp");
    assert!(fs::symlink_metadata(allowed.join("x")).unwrap().is_file());
    assert_eq!(fs::read_to_string(allowed.join("x")).unwrap(), "payload");

    // A tree with directories still lands, and no temporary file is left beside what landed.
    let nested = tmp.0.join("nested");
    fs::create_dir_all(nested.join("a/b")).unwrap();
    fs::write(nested.join("a/b/c.txt"), "deep").unwrap();
    let dst = allowed.join("sub/tree").display().to_string();
    let landed = client
        .cp_push(&nested, dst, Vec::new(), false, false, false)
        .await
        .unwrap();
    assert_eq!(landed.added, vec!["a/b/c.txt".to_string()]);
    assert_eq!(
        fs::read_to_string(allowed.join("sub/tree/a/b/c.txt")).unwrap(),
        "deep"
    );
    let beside: Vec<_> = fs::read_dir(allowed.join("sub/tree/a/b"))
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(beside, vec![std::ffi::OsString::from("c.txt")]);

    // Reading is held to DIR the same way: a file beyond a symlink is refused when named, and
    // not sent as part of the tree the symlink is in.
    fs::write(outside.join("secret"), "secret").unwrap();
    symlink(&outside, allowed.join("sub/tree/out")).unwrap();
    let pull = |src: PathBuf, to: &str| {
        let (client, to) = (&client, tmp.0.join(to));
        async move {
            let src = src.display().to_string();
            let done = client
                .cp_pull(src, &to, Vec::new(), false, false, false)
                .await;
            (done, to)
        }
    };
    let (named, to) = pull(allowed.join("sub/tree/out/secret"), "named").await;
    assert_eq!(named.unwrap_err().code, Exit::REFUSED);
    assert!(!to.join("secret").exists());
    let (whole, to) = pull(allowed.join("sub/tree"), "whole").await;
    assert_eq!(whole.unwrap().added, vec!["a/b/c.txt".to_string()]);
    assert!(!to.join("out").exists());
    let (one, to) = pull(allowed.join("sub/tree/a/b/c.txt"), "one").await;
    assert_eq!(one.unwrap().added, vec!["c.txt".to_string()]);
    assert_eq!(fs::read_to_string(to.join("c.txt")).unwrap(), "deep");

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn cp_pull_never_writes_through_a_symlink_in_the_local_destination() {
    let (tmp, srv, client, _, _) = boot_pair("pull-symlink").await;
    let tree = tmp.0.join("tree");
    fs::create_dir_all(tree.join("link")).unwrap();
    fs::write(tree.join("link/x"), "escaped").unwrap();
    let (back, outside) = (tmp.0.join("back"), tmp.0.join("outside"));
    fs::create_dir_all(&back).unwrap();
    fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, back.join("link")).unwrap();

    let err = client
        .cp_pull(
            tree.display().to_string(),
            &back,
            Vec::new(),
            false,
            false,
            false,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, Exit::REFUSED, "{err:?}");
    assert!(!outside.join("x").exists(), "wrote through back/link");

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
    let busy = third.sessions().await.unwrap_err();
    assert_eq!(busy.code, Exit::BUSY, "{busy:?}");
    third.close().await;

    // One of them goes: its place is the next client's.
    first.close().await;
    let served = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let next = dial(&friend).await.unwrap();
            let listed = next.sessions().await;
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
        proof_timeout: Duration::from_millis(300),
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    let dial = |key: &iroh::SecretKey| {
        Client::connect_direct(key.clone(), srv.endpoint_id, route.clone(), true)
    };

    let silent = dial(&stranger).await.unwrap();
    let known = dial(&friend).await.unwrap();
    known.sessions().await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), silent.connection().closed())
        .await
        .expect("the silent connection was closed within 5 s");
    let refused = koh::proto::CloseCode::Refused as u64;
    assert!(
        matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == refused),
        "{closed:?}"
    );
    // One that proved its key in time stays, past the deadline.
    tokio::time::sleep(Duration::from_millis(400)).await;
    known.sessions().await.unwrap();

    known.close().await;
    silent.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn sessions_are_capped_and_an_ended_one_makes_room() {
    let tmp = TempDir::new("max-sess");
    let friend = new_key(&tmp, "friend.key");
    let more = ServeOptions {
        max_sessions: 2,
        ..ServeOptions::default()
    };
    let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
    let client = Client::connect_direct(friend, srv.endpoint_id, route, true)
        .await
        .unwrap();
    let attach = |line: &str| Request::Attach {
        session: None,
        new: true,
        cols: 80,
        rows: 10,
        cell_w: 10,
        cell_h: 20,
        argv: vec!["/bin/sh".into(), "-c".into(), line.into()],
        cwd: Some(tmp.0.display().to_string()),
    };

    let (mut ends, _ends_recv) = client.request(&attach("read line")).await.unwrap();
    let _stays = client.request(&attach("sleep 30")).await.unwrap();
    let busy = client.request(&attach("sleep 30")).await.unwrap_err();
    assert_eq!(busy.code, Exit::BUSY, "{busy:?}");
    assert_eq!(client.sessions().await.unwrap().len(), 2);

    // The first one's program ends and its client detaches: the server forgets it for a new one.
    send_msg(&mut ends, &ClientEvent::Input(b"go\n".to_vec()), MAX_CHUNK)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let list = client.sessions().await.unwrap();
            if list.iter().any(|s| s.state != "running" && !s.attached) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the first session ended and was left within 5 s");
    let _third = client.request(&attach("sleep 30")).await.unwrap();
    let list = client.sessions().await.unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|s| s.state == "running"), "{list:?}");

    client.close().await;
    srv.shutdown().await;
}

#[tokio::test]
async fn the_server_takes_no_stream_but_a_request() {
    let (_tmp, srv, client, _, _) = boot_pair("no-uni").await;
    // Nothing reads a unidirectional stream, so a peer is given none to fill.
    let conn = client.connection();
    let opened = tokio::time::timeout(Duration::from_millis(300), conn.open_uni()).await;
    assert!(opened.is_err(), "a unidirectional stream was opened");
    client.sessions().await.unwrap();
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
