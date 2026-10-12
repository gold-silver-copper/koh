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
#![forbid(clippy::disallowed_methods)]

use std::time::Duration;

use koh::pty::{Launcher, Pty};
use koh::transport_iroh::{bind_endpoint_local, generate_secret_key};
use koh_testkit::{command, Capture};

/// The `koh` binary, as the launcher every program here starts through.
fn launcher() -> Launcher {
    Launcher::new(env!("CARGO_BIN_EXE_koh"))
}

/// A loopback server hosting `sh` for the client whose key is at `client_key` (created if missing),
/// as `koh serve` does: its id and IPv4 port, and its task.
async fn loopback_server(
    client_key: &std::path::Path,
) -> anyhow::Result<(String, u16, tokio::task::JoinHandle<()>)> {
    let config = koh::server::ServeConfig {
        allow: vec![koh::transport_iroh::parse_endpoint_id(&endpoint_id(
            client_key,
        )?)?],
        command: vec!["sh".to_owned()],
        launcher: launcher(),
        ..koh::server::ServeConfig::default()
    };
    let hosting = koh::server::cli::Hosting::from_config(&config)?;
    let server_ep = bind_endpoint_local(generate_secret_key()?, true).await?;
    let server_id = server_ep.id().to_string();
    let server_port = server_ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
        .ok_or_else(|| anyhow::anyhow!("no IPv4 socket"))?;
    let task = koh_testkit::spawn(async move {
        let _ = koh::server::cli::serve_endpoint(
            server_ep,
            hosting,
            tokio_util::sync::CancellationToken::new(),
        )
        .await;
    });
    Ok((server_id, server_port, task))
}

#[test]
fn real_client_binary_renders_over_pty() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("pty-test").expect("a scratch directory");
            let key_path = dir.join("client.key");
            let (server_id, server_port, server_task) =
                loopback_server(&key_path).await.expect("server");

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
                &koh::pty::Reaper::start().expect("reaper"),
            )
            .expect("spawn client binary");
            let buf = Capture::new(output);

            // A command whose output only the remote `sh` prints (its echo is split), typed until the
            // session is up: it round-trips to `sh` and back as a frame.
            let seen = buf
                .type_until(0, "koh_pty_marker", 15, || {
                    let _ = client.write(b"echo koh_pty_''marker\r".to_vec());
                })
                .await;

            // Disconnect via the escape sequence (Ctrl-^ then '.').
            let _ = client.write(vec![0x1e, b'.']);
            drop(client);
            server_task.abort();
            seen.expect("real client binary rendered the marker over the PTY");
        });
}

/// `Ctrl-^ Ctrl-Z` stops the client with SIGTSTP, as a terminal's suspend key would: the job
/// control shell that ran it sees a job stopped by SIGTSTP (`$?` is 128 + SIGTSTP; SIGSTOP would
/// make the shell report "Stopped (signal)"), and `fg` resumes the session.
#[test]
fn ctrl_z_suspends_the_client_with_sigtstp_and_fg_resumes_it() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("suspend-test").expect("a scratch directory");
            let key_path = dir.join("client.key");
            let (server_id, server_port, server_task) =
                loopback_server(&key_path).await.expect("server");

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
                &koh::pty::Reaper::start().expect("reaper"),
            )
            .expect("spawn bash");
            let buf = Capture::new(output);
            let type_ = |bytes: &[u8]| bash.write(bytes.to_vec()).expect("type");

            let mut at = buf
                .wait_for(0, "job$ ", 10)
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
            // Only the remote shell, which then holds R, turns this into `ready_remote_42`, so it
            // proves the session is up.
            at = buf
                .type_until(at, "ready_remote_42", 20, || {
                    type_(b"R=remote; echo ready_${R}_$((6*7))\r");
                })
                .await
                .unwrap_or_else(|e| panic!("{e}"));

            type_(&[0x1e, 0x1a]);
            at = buf
                .wait_for(at, "job$ ", 10)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            type_(b"echo status=$?\r");
            let expected = format!("status={}", 128 + fuxix::process::Signal::Tstp.raw());
            at = buf
                .wait_for(at, &expected, 10)
                .await
                .unwrap_or_else(|e| panic!("{e}"));

            type_(b"fg\r");
            // Only the resumed session holds R: the local shell would print `back_local`.
            at = buf
                .type_until(at, "back_remote", 20, || {
                    type_(b"echo back_${R:-local}\r");
                })
                .await
                .unwrap_or_else(|e| panic!("{e}"));

            type_(&[0x1e, b'.']);
            buf.wait_for(at, "job$ ", 10)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            type_(b"exit\r");
            drop(bash);
            server_task.abort();
        });
}

/// `koh id` for the key at `key`, creating it: the endpoint id, as the binary prints it.
fn endpoint_id(key: &std::path::Path) -> anyhow::Result<String> {
    let out = command(env!("CARGO_BIN_EXE_koh"))?
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
    let mut server = command(env!("CARGO_BIN_EXE_koh"))?
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
    let logs = koh_testkit::stderr_lines(&mut server);
    let ready = format!("udp port    : {port}");
    if !std::iter::from_fn(|| logs.recv_timeout(Duration::from_secs(20)).ok())
        .any(|line| line.contains(&ready))
    {
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
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("restart-test").expect("a scratch directory");
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
                &koh::pty::Reaper::start().expect("reaper"),
            )
            .expect("spawn client binary");
            let buf = Capture::new(output);
            // A variable only this session holds, and an answer only a remote shell computes.
            let at = buf
                .type_until(0, "before_kept_42", 20, || {
                    let _ = client.write(b"X=kept; echo before_${X}_$((6*7))\r".to_vec());
                })
                .await
                .unwrap_or_else(|e| panic!("{e}"));

            stop(server).expect("stop the server");
            let at = buf
                .wait_for(at, "reconnecting", 20)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            let server =
                serve_on_port(&server_key, port, &client_id).expect("the restarted server");

            // Typing while the client redials is dropped, so type until the new session answers.
            let mut seen = Err(String::new());
            for _ in 0..15 {
                client
                    .write(b"echo after_${X:-fresh}_$((6*7))\r".to_vec())
                    .expect("type");
                seen = buf.wait_for(at, "after_fresh_42", 2).await;
                if seen.is_ok() {
                    break;
                }
            }

            let _ = client.write(vec![0x1e, b'.']);
            drop(client);
            stop(server).expect("stop the restarted server");
            seen.unwrap_or_else(|e| panic!("the client found the restarted server: {e}"));
        });
}
