//! Tier 1b: drive the **real `koh` binary** (`koh connect …`) attached to an allocated PTY.
//!
//! This is the standard way to test a terminal program headlessly: open a pseudo-terminal,
//! launch the client on the slave (so `isatty()` is true and raw mode runs for
//! real), and drive the master side by writing scripted keystrokes and reading back the
//! rendered frames. The server is an in-process loopback endpoint; the client connects with
//! `--direct`, so the whole thing is hermetic — no relay, no second machine, no real TTY.
//!
//! Unlike the mock-terminal e2e, this exercises the actual binary: argument parsing, raw-mode
//! lifecycle, the renderer, and stdin passthrough — the real terminal path.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![expect(
    clippy::string_slice,
    reason = "integration test code; panics are assertion failures"
)]

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh_core::server::run_session;
use koh_core::transport_iroh::{bind_endpoint_local, format_endpoint_id, generate_secret_key};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_client_binary_renders_over_pty() {
    // --- in-process loopback server with a real shell ---
    let server_ep = bind_endpoint_local(generate_secret_key().expect("OS randomness"), true)
        .await
        .expect("bind server");
    let server_id = format_endpoint_id(&server_ep.id());
    let server_port = server_ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
        .expect("server v4 port");

    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server_ep.accept().await {
            if let Ok(conn) = incoming.await {
                // The real client binary awaits an admission ack after connect; mirror the server
                // side so its accept_bi() completes, like `koh serve`.
                if koh_core::transport_iroh::admission::admit(&conn)
                    .await
                    .is_ok()
                {
                    let _ = run_session(conn, &["sh".to_owned()], 0).await;
                }
            }
        }
    });

    // --- launch the real client binary attached to a PTY slave ---
    let key_path = std::env::temp_dir().join(format!("koh-pty-test-{}.key", std::process::id()));
    let _ = std::fs::remove_file(&key_path);

    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_koh"));
    cmd.arg("connect");
    cmd.arg(&server_id);
    cmd.arg("--direct");
    cmd.arg(format!("127.0.0.1:{server_port}"));
    cmd.arg("--key-file");
    cmd.arg(&key_path);
    cmd.env("TERM", "xterm-256color");
    // The client creates its identity key on first run, without a prompt.

    let mut child = pair.slave.spawn_command(cmd).expect("spawn client binary");
    drop(pair.slave);

    // Read everything the client renders into a shared buffer.
    let mut reader = pair.master.try_clone_reader().expect("clone reader");
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let buf_reader = buf.clone();
    std::thread::spawn(move || {
        let mut tmp = [0u8; 8192];
        loop {
            match reader.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => buf_reader.lock().unwrap().extend_from_slice(&tmp[..n]),
            }
        }
    });
    let mut writer = pair.master.take_writer().expect("take writer");

    // Give the binary time to connect over loopback iroh and do the initial screen sync.
    tokio::time::sleep(Duration::from_millis(2000)).await;

    // Type a command with a distinctive marker; it round-trips to `sh` and back as a frame.
    writer
        .write_all(b"echo koh_pty_marker\r")
        .expect("write keystrokes");
    writer.flush().expect("flush keystrokes");

    let contains_marker = |b: &Arc<Mutex<Vec<u8>>>| {
        String::from_utf8_lossy(&b.lock().unwrap()).contains("koh_pty_marker")
    };

    let mut seen = false;
    for _ in 0..150 {
        if contains_marker(&buf) {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Disconnect via the escape sequence (Ctrl-^ then '.'), then ensure teardown.
    let _ = writer.write_all(&[0x1e, b'.']);
    let _ = writer.flush();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = child.kill();
    server_task.abort();
    let _ = std::fs::remove_file(&key_path);

    let rendered = String::from_utf8_lossy(&buf.lock().unwrap()).to_string();
    assert!(
        seen,
        "real client binary never rendered the marker over the PTY; captured:\n{}",
        // keep the failure message bounded
        &rendered[rendered.len().saturating_sub(2000)..]
    );
}

/// Everything the PTY master has produced so far, read on a background thread.
fn capture(mut reader: Box<dyn Read + Send>) -> Arc<Mutex<Vec<u8>>> {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = buf.clone();
    std::thread::spawn(move || {
        let mut tmp = [0u8; 8192];
        while let Ok(n) = reader.read(&mut tmp) {
            match (tmp.get(..n), sink.lock()) {
                (Some(chunk), Ok(mut all)) if !chunk.is_empty() => all.extend_from_slice(chunk),
                _ => break,
            }
        }
    });
    buf
}

/// The captured text from byte `from` on.
fn text_from(buf: &Arc<Mutex<Vec<u8>>>, from: usize) -> String {
    buf.lock().map_or_else(
        |_| String::new(),
        |all| String::from_utf8_lossy(all.get(from..).unwrap_or_default()).into_owned(),
    )
}

/// Wait up to `secs` for `needle` after byte `from`: the byte after the match, or what was captured.
async fn wait_for(
    buf: &Arc<Mutex<Vec<u8>>>,
    from: usize,
    needle: &str,
    secs: u64,
) -> Result<usize, String> {
    for _ in 0..secs.saturating_mul(10) {
        if let Some(at) = text_from(buf, from).find(needle) {
            return Ok(from.saturating_add(at).saturating_add(needle.len()));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(format!(
        "never saw {needle:?}; captured:\n{}",
        text_from(buf, 0)
    ))
}

/// `Ctrl-^ Ctrl-Z` stops the client with SIGTSTP, as a terminal's suspend key would: the job
/// control shell that ran it sees a job stopped by SIGTSTP (`$?` is 128 + SIGTSTP; SIGSTOP would
/// make the shell report "Stopped (signal)"), and `fg` resumes the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_z_suspends_the_client_with_sigtstp_and_fg_resumes_it() {
    let server_ep = bind_endpoint_local(generate_secret_key().expect("OS randomness"), true)
        .await
        .expect("bind server");
    let server_id = format_endpoint_id(&server_ep.id());
    let server_port = server_ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
        .expect("server v4 port");
    let server_task = tokio::spawn(async move {
        if let Some(incoming) = server_ep.accept().await {
            if let Ok(conn) = incoming.await {
                if koh_core::transport_iroh::admission::admit(&conn)
                    .await
                    .is_ok()
                {
                    let _ = run_session(conn, &["sh".to_owned()], 0).await;
                }
            }
        }
    });
    let key_path =
        std::env::temp_dir().join(format!("koh-suspend-test-{}.key", std::process::id()));
    let _ = std::fs::remove_file(&key_path);

    // An interactive bash with job control, as a user's login shell would be.
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");
    let mut cmd = CommandBuilder::new("bash");
    cmd.args(["--norc", "--noprofile", "-i"]);
    cmd.env("TERM", "xterm-256color");
    cmd.env("PS1", "job$ ");
    let mut bash = pair.slave.spawn_command(cmd).expect("spawn bash");
    drop(pair.slave);
    let buf = capture(pair.master.try_clone_reader().expect("clone reader"));
    let mut writer = pair.master.take_writer().expect("take writer");
    let mut type_ = |bytes: &[u8]| {
        writer.write_all(bytes).expect("type");
        writer.flush().expect("flush");
    };

    let mut at = wait_for(&buf, 0, "job$ ", 10)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    type_(
        format!(
            "'{}' connect {server_id} --direct 127.0.0.1:{server_port} --key-file '{}'\r",
            env!("CARGO_BIN_EXE_koh"),
            key_path.display()
        )
        .as_bytes(),
    );
    // Only the remote shell turns `$((6*7))` into 42, so this proves the session is up.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    type_(b"echo ready_$((6*7))\r");
    at = wait_for(&buf, at, "ready_42", 20)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    type_(&[0x1e, 0x1a]);
    at = wait_for(&buf, at, "job$ ", 10)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    type_(b"echo status=$?\r");
    let expected = format!("status={}", 128 + fuxix::process::Signal::Tstp.raw());
    at = wait_for(&buf, at, &expected, 10)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    type_(b"fg\r");
    tokio::time::sleep(Duration::from_millis(1000)).await;
    type_(b"echo back_$((6*7))\r");
    at = wait_for(&buf, at, "back_42", 20)
        .await
        .unwrap_or_else(|e| panic!("{e}"));

    type_(&[0x1e, b'.']);
    wait_for(&buf, at, "job$ ", 10)
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    type_(b"exit\r");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = bash.kill();
    server_task.abort();
    let _ = std::fs::remove_file(&key_path);
}
