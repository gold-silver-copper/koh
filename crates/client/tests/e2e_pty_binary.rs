//! Tier 1b: drive the **real `rmosh-client` binary** attached to an allocated PTY.
//!
//! This is the standard way to test a terminal program headlessly: open a pseudo-terminal,
//! launch the client on the slave (so `isatty()` is true and raw mode + termina run for
//! real), and drive the master side by writing scripted keystrokes and reading back the
//! rendered frames. The server is an in-process loopback endpoint; the client connects with
//! `--direct`, so the whole thing is hermetic — no relay, no second machine, no real TTY.
//!
//! Unlike the mock-terminal e2e, this exercises the actual binary: argument parsing, raw-mode
//! lifecycle, the termina renderer, and stdin passthrough — the real terminal path.

// Integration test: a failed unwrap/expect/assert IS the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::unwrap_in_result,
    reason = "integration test code; panics are assertion failures"
)]

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use rmosh_server::run_session;
use rmosh_transport_iroh::{bind_endpoint_local, format_endpoint_id, generate_secret_key};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_client_binary_renders_over_pty() {
    // --- in-process loopback server with a real shell ---
    let server_ep = bind_endpoint_local(generate_secret_key(), true)
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
                // The client *binary* runs the passphrase handshake after connect; mirror the
                // server side (no passphrase) so its accept_bi() completes, like the real server.
                if rmosh_transport_iroh::auth::handshake_server(&conn, None)
                    .await
                    .is_ok()
                {
                    let _ = run_session(conn, Some("sh".into()), 0).await;
                }
            }
        }
    });

    // --- launch the real client binary attached to a PTY slave ---
    let key_path = std::env::temp_dir().join(format!("rmosh-pty-test-{}.key", std::process::id()));
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

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_rmosh-client"));
    cmd.arg(&server_id);
    cmd.arg("--direct");
    cmd.arg(format!("127.0.0.1:{server_port}"));
    cmd.arg("--predict");
    cmd.arg("never");
    cmd.arg("--key-file");
    cmd.arg(&key_path);
    cmd.env("TERM", "xterm-256color");

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
        .write_all(b"echo rmosh_pty_marker\r")
        .expect("write keystrokes");
    writer.flush().ok();

    let contains_marker = |b: &Arc<Mutex<Vec<u8>>>| {
        String::from_utf8_lossy(&b.lock().unwrap()).contains("rmosh_pty_marker")
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
