//! The real `koh connect` on a PTY, so raw mode, the renderer and stdin passthrough run for real,
//! against a loopback server it dials with `--direct`: suspended and resumed by its shell, and
//! redialing a restarted `koh serve`.
#![forbid(clippy::disallowed_methods)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::{connected, endpoint_id, loopback_server, on_pty, serve, Served};
use koh_testkit::command;

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
                loopback_server(&endpoint_id(&key_path).expect("the client's id"))
                    .await
                    .expect("server");

            // An interactive bash with job control, as a user's login shell would be.
            let (bash, buf) = on_pty(&[
                "env".to_owned(),
                "PS1=job$ ".to_owned(),
                "bash".to_owned(),
                "--norc".to_owned(),
                "--noprofile".to_owned(),
                "-i".to_owned(),
            ])
            .expect("spawn bash");
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

/// `koh serve --local` hosting `sh` for `client`, as the key at `key`, on
/// `port` if given.
fn serve_local(key: &Path, port: Option<u16>, client: &str) -> anyhow::Result<Served> {
    let mut server = command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())?;
    server
        .args([
            "serve",
            "--local",
            "--allow",
            client,
            "--shell",
            "sh",
            "--key-file",
        ])
        .arg(key);
    if let Some(port) = port {
        server.args(["--port", &port.to_string()]);
    }
    Ok(serve(server)?.0)
}

/// Stop `server` as a service manager would, with SIGTERM, and wait for it to exit.
fn stop(mut server: Served) -> anyhow::Result<()> {
    let pid = fuxix::process::Pid::of(&server.child).ok_or_else(|| anyhow::anyhow!("no pid"))?;
    fuxix::process::kill(pid, fuxix::process::Signal::Term)?;
    for _ in 0..100 {
        if server.child.try_wait()?.is_some() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("the server did not exit on SIGTERM")
}

/// A `koh serve --local --port` restarted under a connected client (a new process, the same key
/// and port) is found again: the client redials the address it dialed. The session died with the
/// old server, and a redial goes back to its own session only, so the client ends saying so.
#[test]
fn a_client_redials_a_local_server_restarted_on_its_port() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("restart-test").expect("a scratch directory");
            let (server_key, client_key) = (dir.join("server.key"), dir.join("client.key"));
            let client_id = endpoint_id(&client_key).expect("the client's id");
            // The port the first server picked is the one the restarted server asks for.
            let server = serve_local(&server_key, None, &client_id).expect("the server");
            let port = server.port;
            // A variable only this session holds, and an answer only a remote shell computes.
            let (client, buf, at) = connected(
                &connect_argv(&server, &client_key),
                b"X=kept; echo before_${X}_$((6*7))\r",
                "before_kept_42",
            )
            .await
            .expect("the first session");

            stop(server).expect("stop the server");
            let at = buf
                .wait_for(at, "reconnecting", 20)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
            let server =
                serve_local(&server_key, Some(port), &client_id).expect("the restarted server");

            let seen = buf.wait_for(at, "no such session", 30).await;

            let _ = client.write(vec![0x1e, b'.']);
            drop(client);
            stop(server).expect("stop the restarted server");
            seen.unwrap_or_else(|e| panic!("the client found the restarted server: {e}"));
        });
}

/// The argv of `koh connect` to `server` on loopback, as the key at `key`.
fn connect_argv(server: &Served, key: &Path) -> [String; 7] {
    [
        env!("CARGO_BIN_EXE_koh"),
        "connect",
        &server.id,
        "--direct",
        &format!("127.0.0.1:{}", server.port),
        "--key-file",
        &key.display().to_string(),
    ]
    .map(str::to_owned)
}

/// A long line the terminal writes in one go, as an agent's terminal types it, runs at once: none
/// of it waits for a key typed after.
#[test]
fn a_long_line_written_in_one_go_runs_with_nothing_typed_after() {
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let dir = koh_testkit::scratch!("long-line-test").expect("a scratch directory");
            let (server_key, client_key) = (dir.join("server.key"), dir.join("client.key"));
            let client_id = endpoint_id(&client_key).expect("the client's id");
            let server = serve_local(&server_key, None, &client_id).expect("the server");
            let (client, buf, at) = connected(
                &connect_argv(&server, &client_key),
                b"echo up_$((6*7))\r",
                "up_42",
            )
            .await
            .expect("the session");

            // Only the remote shell turns this into `len_2000`; its echo shows `${#A}`.
            let line = format!("A={}; echo len_${{#A}}\r", "y".repeat(2000));
            client.write(line.into_bytes()).expect("type the line");
            let seen = buf.wait_for(at, "len_2000", 10).await;

            let _ = client.write(vec![0x1e, b'.']);
            drop(client);
            stop(server).expect("stop the server");
            seen.unwrap_or_else(|e| panic!("the whole line ran: {e}"));
        });
}
