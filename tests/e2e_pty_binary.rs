//! Tier 1b: drive the **real `koh` binary** (`koh connect …`) attached to an allocated PTY.
//!
//! This is the standard way to test a terminal program headlessly: open a pseudo-terminal,
//! launch the client on the slave (so `isatty()` is true and raw mode runs for
//! real), and drive the master side by writing scripted keystrokes and reading back the
//! rendered frames. Every program here starts through `koh __launch`, as `koh serve`'s do. The server is an in-process loopback endpoint; the client connects with
//! `--direct`, so the whole thing is hermetic — no relay, no second machine, no real TTY.
//!
//! Unlike the mock-terminal e2e, this exercises the actual binary: argument parsing, raw-mode
//! lifecycle, the renderer, and stdin passthrough — the real terminal path.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use koh::pty::{Launcher, Pty};
use koh::server::run_session;
use koh::transport_iroh::{bind_endpoint_local, format_endpoint_id, generate_secret_key};

/// The `koh` binary, as the launcher every program here starts through.
fn launcher() -> Launcher {
    Launcher::new(env!("CARGO_BIN_EXE_koh"))
}

/// A loopback server hosting `sh` for one connection: its id and IPv4 port, and its task.
async fn loopback_server() -> anyhow::Result<(String, u16, tokio::task::JoinHandle<()>)> {
    let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
    let server_id = format_endpoint_id(&server_ep.id());
    let server_port = server_ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
        .ok_or_else(|| anyhow::anyhow!("no IPv4 socket"))?;
    let task = tokio::spawn(async move {
        if let Some(incoming) = server_ep.accept().await {
            if let Ok(conn) = incoming.await {
                // The real client binary awaits an admission ack after connect; mirror the server
                // side so its accept_bi() completes, like `koh serve`.
                if koh::transport_iroh::admission::admit(&conn).await.is_ok() {
                    let _ = run_session(conn, &["sh".to_owned()], 0, launcher()).await;
                }
            }
        }
    });
    Ok((server_id, server_port, task))
}

/// Everything `output` delivers, gathered by a background task.
fn capture(mut output: tokio::sync::mpsc::Receiver<Vec<u8>>) -> Arc<Mutex<Vec<u8>>> {
    let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let sink = buf.clone();
    tokio::spawn(async move {
        while let Some(chunk) = output.recv().await {
            let Ok(mut all) = sink.lock() else { break };
            all.extend_from_slice(&chunk);
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

#[test]
fn real_client_binary_renders_over_pty() {
    runtime().expect("tokio runtime").block_on(async {
        let (server_id, server_port, server_task) = loopback_server().await.expect("server");
        let key_path =
            std::env::temp_dir().join(format!("koh-pty-test-{}.key", std::process::id()));
        let _ = std::fs::remove_file(&key_path);

        // The client creates its identity key on first run, without a prompt.
        let (mut client, output) = Pty::spawn(
            24,
            80,
            &[
                env!("CARGO_BIN_EXE_koh").to_owned(),
                "connect".to_owned(),
                server_id,
                "--direct".to_owned(),
                format!("127.0.0.1:{server_port}"),
                "--key-file".to_owned(),
                key_path.display().to_string(),
            ],
            "xterm-256color",
            &launcher(),
        )
        .expect("spawn client binary");
        let buf = capture(output);

        // Give the binary time to connect over loopback iroh and do the initial screen sync.
        tokio::time::sleep(Duration::from_millis(2000)).await;

        // Type a command with a distinctive marker; it round-trips to `sh` and back as a frame.
        client
            .write_input(b"echo koh_pty_marker\r")
            .expect("write keystrokes");
        let seen = wait_for(&buf, 0, "koh_pty_marker", 15).await;

        // Disconnect via the escape sequence (Ctrl-^ then '.'), then ensure teardown.
        let _ = client.write_input(&[0x1e, b'.']);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = client.kill();
        server_task.abort();
        let _ = std::fs::remove_file(&key_path);
        seen.expect("real client binary rendered the marker over the PTY");
    });
}

/// `Ctrl-^ Ctrl-Z` stops the client with SIGTSTP, as a terminal's suspend key would: the job
/// control shell that ran it sees a job stopped by SIGTSTP (`$?` is 128 + SIGTSTP; SIGSTOP would
/// make the shell report "Stopped (signal)"), and `fg` resumes the session.
#[test]
fn ctrl_z_suspends_the_client_with_sigtstp_and_fg_resumes_it() {
    runtime().expect("tokio runtime").block_on(async {
        let (server_id, server_port, server_task) = loopback_server().await.expect("server");
        let key_path =
            std::env::temp_dir().join(format!("koh-suspend-test-{}.key", std::process::id()));
        let _ = std::fs::remove_file(&key_path);

        // An interactive bash with job control, as a user's login shell would be.
        let (mut bash, output) = Pty::spawn(
            24,
            80,
            &[
                "env".to_owned(),
                "PS1=job$ ".to_owned(),
                "bash".to_owned(),
                "--norc".to_owned(),
                "--noprofile".to_owned(),
                "-i".to_owned(),
            ],
            "xterm-256color",
            &launcher(),
        )
        .expect("spawn bash");
        let buf = capture(output);
        let type_ = |bytes: &[u8]| bash.write_input(bytes).expect("type");

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
    });
}

/// The runtime for a test. `#[tokio::test]` is not used: its expansion `allow`s
/// `clippy::expect_used`, which koh forbids, and a `forbid` rejects that `allow`.
fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
}
