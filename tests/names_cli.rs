//! The real `koh` binary's names for ids: `koh servers` and `koh clients`, `koh connect <name>`,
//! `koh serve` allowing the saved clients, `koh id` and `koh key reset` for both keys, and the menu
//! `koh` alone opens on a terminal (and help, off one).
//!
//! Every run has its own `HOME` and `XDG_CONFIG_HOME`, so the keys and lists live in a scratch
//! directory and the user's own `~/.config/koh` is never read or written.
#![forbid(clippy::disallowed_methods)]

#[expect(
    dead_code,
    reason = "the keys here are made by the binary itself, in its home"
)]
mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use common::{connected, loopback_server, on_pty, serve};
use koh_testkit::{command, Scratch};

#[cfg(target_os = "linux")]
#[test]
fn unwritable_stdout_and_stderr_do_not_panic() {
    let home = Home::new("failed-output").expect("scratch home");
    for discard_diagnostics in [false, true] {
        let mut command = home.command(&["help-agents"]).expect("spawn koh");
        command.stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("full"),
        );
        if discard_diagnostics {
            command.stderr(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open("/dev/full")
                    .expect("full"),
            );
        }
        let output = command.output().expect("run koh");
        assert_eq!(output.status.code(), Some(1));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
        assert!(!home.koh_dir().exists(), "help must not create identities");
    }
}

/// A home of its own, removed afterwards; its koh directory is `<home>/.config/koh`.
struct Home(Scratch);

impl Home {
    fn new(tag: &str) -> anyhow::Result<Self> {
        let dir = koh_testkit::scratch!(&format!("names-cli-{tag}"))?;
        std::fs::create_dir_all(dir.join(".config"))?;
        Ok(Self(dir))
    }

    fn koh_dir(&self) -> PathBuf {
        self.0.join(".config").join("koh")
    }

    /// `koh args…` in this home.
    fn command(&self, args: &[&str]) -> anyhow::Result<Command> {
        let mut koh = command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())?;
        koh.args(args)
            .env("HOME", self.0.path())
            .env("XDG_CONFIG_HOME", self.0.join(".config"));
        Ok(koh)
    }

    /// `koh args…` in this home, its stdin closed.
    fn koh(&self, args: &[&str]) -> anyhow::Result<Output> {
        Ok(self.command(args)?.stdin(Stdio::null()).output()?)
    }

    /// The argv that runs `koh args…` in this home, for a PTY (which takes no environment).
    fn argv(&self, args: &[&str]) -> Vec<String> {
        let mut argv = vec![
            "env".to_owned(),
            format!("HOME={}", self.0.display()),
            format!("XDG_CONFIG_HOME={}", self.0.join(".config").display()),
            env!("CARGO_BIN_EXE_koh").to_owned(),
        ];
        argv.extend(args.iter().map(|&a| a.to_owned()));
        argv
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A valid endpoint id, from a key of its own.
fn some_id(seed: u8) -> String {
    iroh::SecretKey::from_bytes(&[seed; 32])
        .public()
        .to_string()
}

#[test]
fn servers_are_added_listed_renamed_and_removed_by_name() {
    let home = Home::new("servers").unwrap();
    let id = some_id(1);
    let out = home.koh(&["servers"]).unwrap();
    assert!(
        out.status.success() && text(&out).contains("no servers saved"),
        "{}",
        text(&out)
    );
    let out = home
        .koh(&["servers", "add", "laptop", &id, "--direct", "10.0.0.2:4433"])
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let out = home.koh(&["servers"]).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("laptop {id} direct=10.0.0.2:4433\n")
    );
    let out = home.koh(&["servers", "add", "other", &id]).unwrap();
    assert!(
        !out.status.success() && text(&out).contains("already saved as"),
        "{}",
        text(&out)
    );
    assert!(home
        .koh(&["servers", "rename", "laptop", "desk"])
        .unwrap()
        .status
        .success());
    let saved = std::fs::read_to_string(home.koh_dir().join("servers")).unwrap();
    assert_eq!(saved, format!("desk {id} direct=10.0.0.2:4433\n"));
    assert!(home
        .koh(&["servers", "rm", "desk"])
        .unwrap()
        .status
        .success());
    let out = home.koh(&["servers", "rm", "desk"]).unwrap();
    assert!(
        !out.status.success() && text(&out).contains("not saved"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_bad_name_or_id_is_refused_on_the_command_line() {
    let home = Home::new("bad").unwrap();
    for args in [
        &["clients", "add", "-x", &some_id(1)][..],
        &["clients", "add", "phone", "not-an-id"][..],
        &["clients", "add", &some_id(2), &some_id(1)][..],
    ] {
        let out = home.koh(args).unwrap();
        assert!(!out.status.success(), "{args:?} was taken: {}", text(&out));
    }
    assert!(
        !home.koh_dir().join("clients").exists(),
        "nothing was saved"
    );
}

#[test]
fn connect_to_an_unsaved_name_lists_the_saved_ones() {
    let home = Home::new("unsaved").unwrap();
    home.koh(&["servers", "add", "laptop", &some_id(1)])
        .unwrap();
    let out = home.koh(&["connect", "desk"]).unwrap();
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("nor a saved server name") && said.contains("saved: laptop"),
        "{said}"
    );
}

/// `koh connect` with no terminal at all, as a script or an agent runs it, says what to use
/// instead, and dials nothing.
#[test]
fn connect_with_no_terminal_points_at_exec_and_cp() {
    let home = Home::new("no-terminal").unwrap();
    let mut koh = home.command(&["connect", &some_id(5)]).unwrap();
    // A session of its own, so no controlling terminal is inherited for `/dev/tty`.
    fuxix::process::lead_session(&mut koh, false);
    let out = koh.stdin(Stdio::null()).output().unwrap();
    let said = text(&out);
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("needs a terminal") && said.contains("koh exec SERVER -- COMMAND"),
        "{said}"
    );
}

#[test]
fn serve_without_allow_allows_the_saved_clients() {
    let home = Home::new("serve").unwrap();
    let out = home.koh(&["serve", "--local", "--shell", "sh"]).unwrap();
    assert!(!out.status.success(), "no clients: {}", text(&out));
    assert!(text(&out).contains("koh clients add"), "{}", text(&out));
    home.koh(&["clients", "add", "phone", &some_id(3)]).unwrap();
    // A hang-up drains the server, unless it was started ignoring them (`nohup`, which only Linux
    // reports): then a logout leaves it running, and SIGTERM still drains it.
    for nohup in [false, cfg!(target_os = "linux")] {
        let koh = env!("CARGO_BIN_EXE_koh");
        let mut server = command([koh, "nohup"][usize::from(nohup)], &koh_testkit::home!())
            .expect("spawn koh")
            .args(nohup.then_some(koh))
            .args(["serve", "--local", "--shell", "sh"])
            .env("HOME", home.0.path())
            .env("XDG_CONFIG_HOME", home.0.join(".config"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let logs = koh_testkit::stderr_lines(&mut server);
        let next = |what: &str| {
            std::iter::from_fn(|| logs.recv_timeout(Duration::from_secs(20)).ok())
                .find(|line| line.contains(what))
        };
        let banner = next("auth");
        let pid = fuxix::process::Pid::of(&server).unwrap();
        fuxix::process::kill(pid, fuxix::process::Signal::Hup).unwrap();
        let hung_up = next(["shutting down", "SIGHUP ignored"][usize::from(nohup)]);
        if nohup {
            fuxix::process::kill(pid, fuxix::process::Signal::Term).unwrap();
        }
        let drained = next("draining");
        let _ = server.kill();
        let _ = server.wait();
        let banner = banner.expect("the server's banner");
        assert!(banner.contains("allowlist (1 client(s))"), "{banner}");
        let hung_up = hung_up.expect("the hang-up seen");
        assert!(nohup || hung_up.contains("SIGHUP"), "{hung_up}");
        assert!(drained.is_some(), "nohup {nohup}: never drained");
    }
}

#[test]
fn id_prints_either_key_and_reset_removes_one_only_with_yes() {
    let home = Home::new("keys").unwrap();
    let id = |argv: &[&str]| {
        let out = home.koh(argv).unwrap();
        assert!(out.status.success(), "{}", text(&out));
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    };
    let (client, server) = (id(&["id"]), id(&["id", "server"]));
    assert!(client != server && server.len() == 64, "{client} {server}");
    assert_eq!(id(&["id", "client"]), client, "the same key again");
    // A server key that is there but no key is said so, not replaced.
    let server_key = home.koh_dir().join("server.key");
    std::fs::write(&server_key, [7; 31]).unwrap();
    std::fs::set_permissions(&server_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let out = home.koh(&["id", "server"]).unwrap();
    assert!(
        !out.status.success() && text(&out).contains("koh key reset"),
        "{}",
        text(&out)
    );
    let out = home.koh(&["key", "reset", "server"]).unwrap();
    assert!(
        !out.status.success() && text(&out).contains("--yes"),
        "{}",
        text(&out)
    );
    assert!(server_key.exists());
    let out = home.koh(&["key", "reset", "server", "--yes"]).unwrap();
    assert!(
        text(&out).contains("every client that connects here"),
        "{}",
        text(&out)
    );
    assert!(!server_key.exists());
}

#[test]
fn koh_alone_off_a_terminal_prints_help() {
    let home = Home::new("help").unwrap();
    let out = home.koh(&[]).unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert!(text(&out).contains("Usage"), "{}", text(&out));
    assert!(!home.koh_dir().exists(), "help touches nothing");
}

#[test]
fn koh_alone_on_a_terminal_opens_the_menu_and_q_leaves_it() {
    let home = Home::new("menu").unwrap();
    home.koh(&["servers", "add", "laptop", &some_id(1)])
        .unwrap();
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let (mut menu, buf) = on_pty(&home.argv(&[])).expect("spawn koh on a PTY");
            buf.wait_for(0, "koh — this machine", 10).await.unwrap();
            buf.wait_for(0, "1  laptop", 5).await.unwrap();
            menu.write(b"q\n".to_vec()).unwrap();
            let mut exited = false;
            for _ in 0..50 {
                if menu.try_wait().ok().flatten().is_some() {
                    exited = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            drop(menu);
            assert!(exited, "q left the menu; captured:\n{}", buf.text_from(0));
        });
}

#[test]
fn connect_by_name_dials_the_saved_server_where_it_was_saved() {
    let home = Home::new("connect").unwrap();
    koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            // The server allows this home's client, as `koh serve` would.
            let me = home.koh(&["id"]).unwrap();
            let (id, port, task) = loopback_server(String::from_utf8_lossy(&me.stdout).trim())
                .await
                .unwrap();
            let direct = format!("127.0.0.1:{port}");
            home.koh(&["servers", "add", "box", &id, "--direct", &direct])
                .unwrap();
            let argv = home.argv(&["connect", "box"]);
            let (client, ..) = connected(&argv, b"echo by''_name\r", "by_name")
                .await
                .unwrap();
            let _ = client.write(vec![0x1e, b'.']);
            drop(client);
            task.abort();
        });
}

/// Clients added and removed with `koh clients` take effect at a running server's next connection,
/// with no restart: a lost machine's key is refused at once.
#[test]
fn clients_added_and_removed_take_effect_on_a_running_server() {
    use koh::transport_iroh::{bind_endpoint_local, direct_addr, parse_endpoint_id};
    let home = Home::new("live-allowlist").unwrap();
    let me = home.koh(&["id"]).unwrap();
    let me = String::from_utf8_lossy(&me.stdout).trim().to_owned();
    home.koh(&["clients", "add", "other", &some_id(4)]).unwrap();
    let (server, _) = serve(
        home.command(&["serve", "--local", "--shell", "sh"])
            .unwrap(),
    )
    .unwrap();
    let at = direct_addr(
        parse_endpoint_id(&server.id).unwrap(),
        ([127, 0, 0, 1], server.port).into(),
    );
    let key = std::fs::read(home.koh_dir().join("client.key")).unwrap();
    let secret = iroh::SecretKey::from_bytes(&key.try_into().unwrap());
    let admitted = || {
        let (at, secret) = (at.clone(), secret.clone());
        async move {
            let endpoint = bind_endpoint_local(secret.clone(), false).await?;
            let admitted = koh::client::IrohConnector::new(endpoint.clone(), at, secret)
                .connect(
                    koh::request::Pick::Latest,
                    koh::terminal::Size::new(24, 80),
                    (None, None),
                )
                .await?;
            anyhow::Ok((endpoint, admitted))
        }
    };
    let outcomes = koh_testkit::multi_thread(2)
        .expect("tokio runtime")
        .block_on(async {
            let before = admitted().await.is_ok();
            home.koh(&["clients", "add", "me", &me]).unwrap();
            // Seen at the next read of the list, within two seconds.
            let mut live = admitted().await;
            let seen = tokio::time::Instant::now() + Duration::from_secs(10);
            while live.is_err() && tokio::time::Instant::now() < seen {
                live = admitted().await;
            }
            let added = live.is_ok();
            home.koh(&["clients", "rm", "me"]).unwrap();
            // The connection it already had is cut off too.
            let cut_off = match &live {
                Ok((_, admitted)) => {
                    tokio::time::timeout(Duration::from_secs(10), admitted.conn.closed())
                        .await
                        .is_ok()
                }
                Err(_) => false,
            };
            let removed = admitted().await.is_ok();
            (before, added, cut_off, removed)
        });
    drop(server);
    assert_eq!(
        outcomes,
        (false, true, true, false),
        "(before it was saved, once saved, its live connection once removed, once removed)"
    );
}
