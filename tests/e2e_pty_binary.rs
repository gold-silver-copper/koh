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
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key};

/// The `koh` binary, as the launcher every program here starts through.
fn launcher() -> Launcher {
    Launcher::new(env!("CARGO_BIN_EXE_koh"))
}

/// A loopback server hosting `sh` for one connection: its id and IPv4 port, and its task.
async fn loopback_server() -> anyhow::Result<(String, u16, tokio::task::JoinHandle<()>)> {
    let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
    let server_id = server_ep.id().to_string();
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
        let (client, output) = Pty::spawn(
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
        let (bash, output) = Pty::spawn(
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

/// `koh id` for the key at `key`, creating it: the endpoint id, as the binary prints it.
fn endpoint_id(key: &std::path::Path) -> anyhow::Result<String> {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_koh"))
        .args(["id", "--key-file"])
        .arg(key)
        .output()?;
    anyhow::ensure!(out.status.success(), "koh id: {out:?}");
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// A `koh serve --local --port <port>` process hosting `sh` for `client`, once it reports ready.
fn serve_on_port(
    key: &std::path::Path,
    port: u16,
    client: &str,
) -> anyhow::Result<std::process::Child> {
    use std::io::BufRead as _;
    let mut server = std::process::Command::new(env!("CARGO_BIN_EXE_koh"))
        .args([
            "serve",
            "--local",
            "--port",
            &port.to_string(),
            "--allow",
            client,
        ])
        .args(["--shell", "sh", "--key-file"])
        .arg(key)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let stderr = server
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("no stderr pipe"))?;
    let (ready, is_ready) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // Read to the end, so the server never blocks on a full pipe.
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            if line.contains(&format!("udp port    : {port}")) {
                let _ = ready.send(());
            }
        }
    });
    if is_ready.recv_timeout(Duration::from_secs(20)).is_err() {
        let _ = server.kill();
        anyhow::bail!("the server never reported port {port}");
    }
    Ok(server)
}

/// Stop `server` as a service manager would, with SIGTERM, and wait for it to exit.
fn stop(mut server: std::process::Child) -> anyhow::Result<()> {
    let pid = fuxix::process::Pid::of(&server).ok_or_else(|| anyhow::anyhow!("no pid"))?;
    fuxix::process::kill(pid, fuxix::process::Signal::Term)?;
    for _ in 0..100 {
        if server.try_wait()?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = server.kill();
    anyhow::bail!("the server did not exit on SIGTERM")
}

/// A `koh serve --local --port` restarted under a connected client (a new process, the same key
/// and port) is found again: the client redials the address it dialed. The session died with the
/// old server, so the client gets a fresh one.
#[test]
fn a_client_redials_a_local_server_restarted_on_its_port() {
    runtime().expect("tokio runtime").block_on(async {
        let dir = std::env::temp_dir().join(format!("koh-restart-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).expect("a test dir");
        let (server_key, client_key) = (dir.join("server.key"), dir.join("client.key"));
        let server_id = endpoint_id(&server_key).expect("the server's id");
        let client_id = endpoint_id(&client_key).expect("the client's id");
        let port = std::net::UdpSocket::bind(("0.0.0.0", 0))
            .and_then(|socket| socket.local_addr())
            .expect("a free port")
            .port();

        let server = serve_on_port(&server_key, port, &client_id).expect("the server");
        let (client, output) = Pty::spawn(
            24,
            80,
            &[
                env!("CARGO_BIN_EXE_koh").to_owned(),
                "connect".to_owned(),
                server_id,
                "--direct".to_owned(),
                format!("127.0.0.1:{port}"),
                "--key-file".to_owned(),
                client_key.display().to_string(),
            ],
            "xterm-256color",
            &launcher(),
        )
        .expect("spawn client binary");
        let buf = capture(output);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        // A variable only this session holds, and an answer only a remote shell computes.
        client
            .write_input(b"X=kept; echo before_${X}_$((6*7))\r")
            .expect("type");
        let at = wait_for(&buf, 0, "before_kept_42", 20)
            .await
            .unwrap_or_else(|e| panic!("{e}"));

        stop(server).expect("stop the server");
        let at = wait_for(&buf, at, "reconnecting", 20)
            .await
            .unwrap_or_else(|e| panic!("{e}"));
        let server = serve_on_port(&server_key, port, &client_id).expect("the restarted server");

        // Typing while the client redials is dropped, so type until the new session answers.
        let mut seen = Err(String::new());
        for _ in 0..15 {
            client
                .write_input(b"echo after_${X:-fresh}_$((6*7))\r")
                .expect("type");
            seen = wait_for(&buf, at, "after_fresh_42", 2).await;
            if seen.is_ok() {
                break;
            }
        }

        let _ = client.write_input(&[0x1e, b'.']);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = client.kill();
        let stopped = stop(server);
        let _ = std::fs::remove_dir_all(&dir);
        stopped.expect("stop the restarted server");
        seen.unwrap_or_else(|e| panic!("the client found the restarted server: {e}"));
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
