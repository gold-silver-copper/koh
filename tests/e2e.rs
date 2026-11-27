//! End-to-end integration tests over real loopback iroh QUIC connections.
// (A test reads files of its own making.)
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use iroh::endpoint::{RecvStream, SendStream};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use koh::Exit;
use koh::client::Client;
use koh::keys::{Role, Route, load_or_create_key};
use koh::proto::{
    Attach, Attached, MAX_CHUNK, MAX_CTRL, Request, VIEW_FRAME, ViewInput, ViewOutput, ViewSize,
    recv_msg, send_msg,
};
use koh::server::{RunningServer, ServeOptions, start_server};

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

/// A server in this process that allows one client's key, with its other options from `more`.
struct Door {
    tmp: TempDir,
    srv: RunningServer,
    friend: iroh::SecretKey,
    route: Option<Route>,
}

impl Door {
    async fn open(tag: &str, more: ServeOptions) -> Self {
        let tmp = TempDir::new(tag);
        let friend = new_key(&tmp, "client.key");
        let (srv, route) = boot_server(&tmp, vec![friend.public()], more).await;
        Self {
            tmp,
            srv,
            friend,
            route,
        }
    }

    /// A client of `key` that has connected (and, `proves`, proved its key).
    async fn dial(&self, key: &iroh::SecretKey, proves: bool) -> koh::Result<Client> {
        let route = self.route.clone();
        Client::connect_direct(key.clone(), self.srv.endpoint_id, route, proves).await
    }

    /// The friend's client, connected and with its key proved.
    async fn client(&self) -> Client {
        self.dial(&self.friend, true).await.unwrap()
    }

    /// Waits until the friend is served, asking again for as long as the server is busy.
    async fn served(&self) {
        let serving = async {
            loop {
                let listed = match self.dial(&self.friend, false).await {
                    Ok(next) => {
                        let listed = next.jobs(None).await;
                        next.close().await;
                        listed
                    }
                    Err(busy) => Err(busy),
                };
                match listed {
                    Ok(_) => break,
                    Err(busy) => assert_eq!(busy.code, Exit::BUSY, "{busy:?}"),
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let served = tokio::time::timeout(Duration::from_secs(20), serving).await;
        served.expect("a place came back within 20 s");
    }

    async fn shut(self) {
        self.srv.shutdown().await;
    }
}

#[test]
fn exec_keeps_binary_stdout_and_stderr_apart_and_ends_with_the_commands_code() {
    let host = Host::start("exec", &[]);
    let script = "printf 'out\\000line\\n'; printf 'errline\\n' >&2; exit 42";
    let args = [
        &host.id,
        "--direct",
        &host.addr(),
        "-C",
        "/tmp",
        "--sh",
        script,
    ];
    let out = host
        .koh(&["exec"])
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        (out.status.code(), out.stdout, out.stderr),
        (Some(42), b"out\0line\n".to_vec(), b"errline\n".to_vec())
    );
}

#[tokio::test]
async fn headless_jobs_raw_logs_wait_timeout_names_and_order() {
    let door = Door::open("jobs", ServeOptions::default()).await;
    let client = door.client().await;
    let cwd = || Some(door.tmp.0.display().to_string());

    // A line of 200 is not wrapped at 80 columns: a job's log is what it wrote, with no PTY.
    let long_line = "X".repeat(200);
    let script = format!("sleep 0.3; printf '{long_line}\\n'; exit 7");
    let info = client.run_job(Some("long".into()), sh(&script), cwd());
    assert_eq!(info.await.unwrap().name, "long");
    // More seconds than the clock has: the job is waited for to its end.
    let waited = client.wait_job("long".into(), 200, Some(u64::MAX)).await;
    let waited = waited.unwrap();
    assert_eq!((waited.exit, waited.detail.as_str()), (7, "exited 7"));
    assert!(waited.tail.contains(&long_line));
    let mut log = Vec::new();
    let ended = client.logs_to("long".into(), None, true, false, &mut log);
    let (state, exit, _) = ended.await.unwrap().unwrap();
    assert_eq!((state.as_str(), exit), ("exited 7", Some(7)));
    assert!(String::from_utf8_lossy(&log).contains(&long_line));

    // A job given no name has the first free number; the list is the oldest first.
    let info = client.run_job(None, sh("sleep 60"), cwd()).await.unwrap();
    assert_eq!(info.name, "1");
    let timed = client.wait_job("1".into(), 10, Some(1)).await.unwrap();
    assert_eq!((timed.exit, timed.detail.as_str()), (124, "timed out"));
    let jobs = client.jobs(None).await.unwrap();
    let names: Vec<&str> = jobs.iter().map(|job| job.name.as_str()).collect();
    assert_eq!(names, ["long", "1"]);

    // A wait and a followed log end on the server when their client lets go of what it reads,
    // on a connection that lives: seen here as the server letting go of what the client sends.
    let (wait, follow) = (
        Request::WaitJob {
            name: "1".into(),
            tail: 10,
            timeout_secs: None,
        },
        Request::Logs {
            name: "1".into(),
            tail: None,
            all: false,
            follow: true,
        },
    );
    for request in [wait, follow] {
        let (send, recv) = client.request(&request).await.unwrap();
        drop(recv);
        let ended = tokio::time::timeout(Duration::from_secs(20), send.stopped()).await;
        assert!(ended.is_ok(), "still served: {request:?}");
    }
    client.kill_job("1".into(), 9).await.unwrap();
    client.close().await;
    door.shut().await;
}

/// `koh connect` as a person runs it, in a terminal of the test's own (a pty): what it drew there
/// and how it ended. It is killed when the test lets go of it, however the test ends.
struct InTerminal {
    koh: std::process::Child,
    tty: fs::File,
    drawn: Vec<u8>,
    /// Whether it says what it is when it is asked, as every terminal does (once: koh asks once).
    answers: bool,
}

impl Drop for InTerminal {
    fn drop(&mut self) {
        let _ = self.koh.kill();
        let _ = self.koh.wait();
    }
}

impl InTerminal {
    fn connect(config: &Path, runtime: &Path, args: &[&str]) -> Self {
        Self::connect_on(Self::pty(), config, runtime, args, true)
    }

    /// A terminal of 80 by 24: its end here, and the end a program has.
    fn pty() -> (fs::File, fs::File) {
        let size = fuxix::Winsize {
            rows: 24,
            cols: 80,
            xpixel: 800,
            ypixel: 480,
        };
        fuxix::pty(size).unwrap()
    }

    /// `koh connect` on this terminal: koh's controlling terminal (`its`), as a shell's is; or
    /// one that is only its standard input and output.
    fn connect_on(
        (tty, theirs): (fs::File, fs::File),
        config: &Path,
        runtime: &Path,
        args: &[&str],
        its: bool,
    ) -> Self {
        let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
        koh.env("KOH_CONFIG_DIR", config)
            .env("XDG_RUNTIME_DIR", runtime)
            .arg("connect")
            .args(args)
            .stdin(theirs.try_clone().unwrap())
            .stdout(theirs.try_clone().unwrap())
            .stderr(theirs);
        fuxix::new_session(&mut koh, its);
        Self {
            koh: koh.spawn().unwrap(),
            tty,
            drawn: Vec::new(),
            answers: true,
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
            if self.answers && self.drawn.windows(3).any(|asked| asked == b"\x1b[c") {
                self.answers = false;
                self.types(b"\x1b[?62c");
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

    /// Types into the terminal, all of it: a pty takes only so much at once (a kilobyte on
    /// macOS), and the rest when koh has read.
    fn types(&mut self, keys: &[u8]) {
        let (mut typed, deadline) = (0, Instant::now() + Duration::from_secs(20));
        while typed < keys.len() {
            assert!(
                Instant::now() < deadline,
                "koh took {typed} of {} bytes",
                keys.len()
            );
            match (&self.tty).write(&keys[typed..]) {
                Ok(n) => typed += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => panic!("typing: {e}"),
            }
        }
    }

    /// Whether koh has drawn `what` since its `from`th byte.
    fn drew(&self, from: usize, what: &[u8]) -> bool {
        let drawn = self.drawn.get(from..).unwrap_or_default();
        drawn.windows(what.len()).any(|drawn| drawn == what)
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

#[test]
fn cli_keys_and_peer_lists() {
    let tmp = TempDir::new("cli");
    let koh = |args: &[&str]| {
        let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
        let out = koh
            .env("KOH_CONFIG_DIR", &tmp.0)
            .args(args)
            .output()
            .unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };
    let (code, id) = koh(&["id"]);
    assert_eq!((code, id.trim().len()), (Some(0), 64));
    let added = koh(&[
        "servers",
        "add",
        "box",
        id.trim(),
        "--direct",
        "127.0.0.1:4433",
    ]);
    assert_eq!(added.0, Some(0));
    // A word more than `rm NAME` is a usage error, and nothing is removed.
    assert_eq!(koh(&["servers", "rm", "box", "extra"]).0, Some(2));
    assert!(koh(&["servers"]).1.contains("box "));
    assert_eq!(koh(&["servers", "rm", "box"]).0, Some(0));
    assert!(!koh(&["servers"]).1.contains("box "));
}

#[tokio::test]
async fn a_second_server_on_one_key_is_refused_until_the_first_stops() {
    let tmp = TempDir::new("serve-lock");
    let first = boot_server_on(&tmp, Vec::new()).await.unwrap();
    let refused = boot_server_on(&tmp, Vec::new()).await.err().unwrap();
    assert_eq!(refused.code, Exit::BUSY, "{refused:?}");
    assert!(refused.message.contains("server.key"), "{refused:?}");
    // The first stopped: the key is free (what marks it held is a lock, not a file's being
    // there: a server that was killed leaves the file, and nothing to clean up).
    first.shutdown().await;
    let again = boot_server_on(&tmp, Vec::new()).await;
    again
        .expect("a server once the first stopped")
        .shutdown()
        .await;
}

/// A server that allows `allow`, with its other options from `more`.
async fn boot_server(
    tmp: &TempDir,
    allow: Vec<iroh::EndpointId>,
    more: ServeOptions,
) -> (RunningServer, Option<Route>) {
    fs::create_dir_all(tmp.0.join("srv_cfg")).unwrap();
    let session_exe = more
        .session_exe
        .or_else(|| Some(PathBuf::from(env!("CARGO_BIN_EXE_koh"))));
    let srv = start_server(ServeOptions {
        key_file: Some(tmp.0.join("srv_cfg/server.key")),
        direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        allow,
        shell: Some("/bin/sh".into()),
        state_dir: Some(tmp.0.join("state")),
        session_exe,
        disable_relay: true,
        quiet: true,
        ..more
    })
    .await
    .unwrap();
    let route = Some(Route::Direct(srv.direct_addr.unwrap()));
    (srv, route)
}

/// A server on the key `boot_server` uses, or why it could not start.
async fn boot_server_on(tmp: &TempDir, allow: Vec<iroh::EndpointId>) -> koh::Result<RunningServer> {
    start_server(ServeOptions {
        key_file: Some(tmp.0.join("srv_cfg/server.key")),
        direct: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
        allow,
        state_dir: Some(tmp.0.join("state")),
        disable_relay: true,
        quiet: true,
        ..ServeOptions::default()
    })
    .await
}

fn new_key(tmp: &TempDir, name: &str) -> iroh::SecretKey {
    fs::create_dir_all(tmp.0.join("cli_cfg")).unwrap();
    load_or_create_key(Role::Client, Some(&tmp.0.join("cli_cfg").join(name))).unwrap()
}

#[tokio::test]
async fn connections_are_capped_before_auth_and_a_place_comes_back_when_one_ends() {
    let more = ServeOptions {
        max_connections: 2,
        proof_timeout: Duration::from_secs(60),
        ..ServeOptions::default()
    };
    let door = Door::open("max-conn", more).await;
    let stranger = new_key(&door.tmp, "stranger.key");
    // Two peers the server does not know, which prove nothing, hold both places.
    let first = door.dial(&stranger, false).await.unwrap();
    let second = door.dial(&stranger, false).await.unwrap();
    let third = door.dial(&door.friend, false).await.unwrap();
    let busy = third.jobs(None).await.unwrap_err();
    assert_eq!(busy.code, Exit::BUSY, "{busy:?}");
    third.close().await;
    // One of them goes: its place is the next client's.
    first.close().await;
    door.served().await;
    second.close().await;
    door.shut().await;
}

#[tokio::test]
async fn a_connection_that_proves_no_allowed_key_in_time_is_closed() {
    let more = ServeOptions {
        proof_timeout: Duration::from_secs(1),
        ..ServeOptions::default()
    };
    let door = Door::open("proof-deadline", more).await;
    let stranger = new_key(&door.tmp, "stranger.key");
    let silent = door.dial(&stranger, true).await.unwrap();
    let (known, since) = (door.client().await, Instant::now());
    known.jobs(None).await.unwrap();
    let conn = silent.connection();
    let closed = tokio::time::timeout(Duration::from_secs(20), conn.closed()).await;
    let closed = closed.expect("the silent connection was closed");
    let refused = koh::proto::CloseCode::Refused as u64;
    assert!(
        matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(close)
            if close.error_code.into_inner() == refused),
        "{closed:?}"
    );
    // One that proved its key in time stays past its own deadline. (The wait is the test.)
    tokio::time::sleep_until((since + Duration::from_millis(1500)).into()).await;
    known.jobs(None).await.unwrap();
    known.close().await;
    silent.close().await;
    door.shut().await;
}

#[test]
fn a_command_that_fails_gives_its_place_back_at_once() {
    let host = Host::start("close-on-error", &["--max-connections", "1"]);
    // No such job: the command fails after it connected. The server has one place, and the
    // next command must find it free, not wait out the first one's connection.
    assert_eq!(host.asked("jobs", &["no-such-job"]).0, Some(127));
    assert_eq!(host.asked("jobs", &[]).0, Some(0));
}

#[tokio::test]
async fn a_connection_s_place_comes_back_when_its_requests_have_ended() {
    let more = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let door = Door::open("place-requests", more).await;
    // A command that ignores SIGHUP, of a client that then leaves: it finishes in the 2 s the
    // server gives a command after its hangup. (It writes `deaf` once the trap is set, so the
    // client never leaves before the shell has read its first word.)
    let (deaf, ended) = (door.tmp.0.join("deaf"), door.tmp.0.join("ended"));
    let script = "trap '' HUP; : > deaf; sleep 1; : > ended";
    let exec = Request::Exec {
        argv: sh(script),
        cwd: Some(door.tmp.0.display().to_string()),
    };
    let client = door.dial(&door.friend, false).await.unwrap();
    let streams = client.request(&exec).await.unwrap();
    until("the command is deaf to a hangup", || deaf.exists());
    drop(streams);
    client.close().await;
    // The place stays the connection's until its command has ended, then is the next client's.
    door.served().await;
    assert!(ended.exists(), "served beside the command");
    door.shut().await;
}

#[test]
fn a_fifo_where_the_list_of_clients_is_holds_no_server() {
    let tmp = TempDir::new("fifo-list");
    // A FIFO nobody writes to, where the server reads who is allowed at every request: it is
    // read as a list of nobody, and whoever reads it is not kept waiting for a writer.
    drop(fuxix::fifo(tmp.0.join("clients")).unwrap());
    let key = tmp.0.join("server.key");
    let (tell, told) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tell.send(koh::keys::load_clients(Some(&key), |_, _| {}).map(|list| list.len()))
    });
    let read = told.recv_timeout(Duration::from_secs(20));
    assert!(matches!(read, Ok(Ok(0))), "{read:?}");
}

#[tokio::test]
async fn a_cap_out_of_range_is_a_usage_error_not_a_panic() {
    let tmp = TempDir::new("cap-range");
    for (max_connections, max_sessions, flag) in
        [(0, 64, "--max-connections"), (64, 65_536, "--max-sessions")]
    {
        let more = ServeOptions {
            key_file: Some(tmp.0.join("srv_cfg/server.key")),
            max_connections,
            max_sessions,
            quiet: true,
            disable_relay: true,
            ..ServeOptions::default()
        };
        let err = start_server(more).await.err().expect("a refusal");
        assert_eq!(err.code, Exit::USAGE, "{err:?}");
        assert!(err.message.contains(flag), "{err:?}");
    }
    // (Nothing was started for them: not even the key.)
    assert!(!tmp.0.join("srv_cfg").exists());
    for (flag, value) in [
        ("--max-connections", "18446744073709551615"),
        ("--max-sessions", "many"),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_koh"))
            .env("KOH_CONFIG_DIR", tmp.0.join("cli"))
            .args(["serve", "--no-relay", flag, value])
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{flag} {value}: {said}");
        assert!(said.contains(flag) && said.contains("1 to 65535"), "{said}");
    }
}

#[tokio::test]
async fn a_handshake_that_never_finishes_gives_its_place_back_at_the_deadline() {
    let more = ServeOptions {
        max_connections: 1,
        proof_timeout: Duration::from_secs(2),
        ..ServeOptions::default()
    };
    let door = Door::open("handshake", more).await;
    let server = door.srv.direct_addr.unwrap();
    // A peer whose packets reach the server and to whom nothing comes back: a socket that passes
    // on what it is sent and never reads the answers. Its handshake begins and cannot end, and it
    // sends its first packet again and again, which keeps the transport from giving it up.
    let bind = || tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0));
    let (front, back) = (bind().await.unwrap(), bind().await.unwrap());
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
        door.friend.clone(),
        door.srv.endpoint_id,
        Some(Route::Direct(front_addr)),
        false,
    ));
    let first = passed_on.wait_for(|count| *count > 0);
    let first = tokio::time::timeout(Duration::from_secs(20), first).await;
    first.expect("the stalled peer sent a packet").unwrap();
    // It has the server's one place: a client that comes now is told the server is busy.
    let early = door.dial(&door.friend, false).await.unwrap();
    let busy = early.jobs(None).await.unwrap_err();
    assert_eq!(busy.code, Exit::BUSY, "{busy:?}");
    early.close().await;
    // The deadline is counted from when the server took that up, handshake and all: two seconds
    // on, the place is the next client's, though the stalled peer is still sending.
    door.served().await;
    stalled.abort();
    forward.abort();
    door.shut().await;
}

#[tokio::test]
async fn a_client_refused_at_the_door_is_told_the_server_is_busy_too() {
    let more = ServeOptions {
        max_connections: 1,
        ..ServeOptions::default()
    };
    let door = Door::open("refused-busy", more).await;
    // One client has the place. A second is let connect to be told so, and has not asked yet: it
    // holds the one place there is for that. A third is refused before it has connected at all,
    // and that is the server being busy as much as the second's answer is: exit 75, not 3.
    let first = door.dial(&door.friend, false).await.unwrap();
    first.jobs(None).await.unwrap();
    let second = door.dial(&door.friend, false).await.unwrap();
    let third = door
        .dial(&door.friend, false)
        .await
        .err()
        .expect("a refusal");
    assert_eq!(third.code, Exit::BUSY, "{third:?}");
    assert!(third.message.contains("server busy"), "{third:?}");
    let told = second.jobs(None).await.unwrap_err();
    assert_eq!(told.code, Exit::BUSY, "{told:?}");
    second.close().await;
    first.close().await;
    door.shut().await;
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

/// `koh serve` as a process of its own, killed when this is dropped; the lines it says on its
/// standard error, read as it says them.
struct Served {
    server: std::process::Child,
    said: std::sync::mpsc::Receiver<String>,
}

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}

impl Served {
    fn spawn(serve: &mut Command) -> Self {
        use std::io::BufRead as _;
        let mut server = serve
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let (tell, said) = std::sync::mpsc::channel();
        let lines = std::io::BufReader::new(server.stderr.take().unwrap()).lines();
        std::thread::spawn(move || lines.map_while(Result::ok).try_for_each(|l| tell.send(l)));
        Self { server, said }
    }

    /// What follows `label` on a line the server says as it starts, twenty seconds at most.
    fn says(&mut self, label: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut all = String::new();
        loop {
            let long = deadline.saturating_duration_since(Instant::now());
            match self.said.recv_timeout(long) {
                Ok(line) => match line.strip_prefix(label) {
                    Some(rest) => return rest.trim().to_string(),
                    None => all.push_str(&line),
                },
                Err(_) => panic!("koh serve did not say {label:?}; it said {all:?}"),
            }
        }
    }
}

#[test]
fn koh_serve_keeps_its_state_under_its_user_without_kill_or_id() {
    let tmp = TempDir::new("no-helpers");
    let key = new_key(&tmp, "client.key");
    let empty = tmp.0.join("empty-bin");
    fs::create_dir_all(&empty).unwrap();
    // Neither kill(1) nor id(1) is needed on PATH: `koh serve` uses fuxix::uid() for its default
    // state directory and talks to job holders over `ctl` instead of spawning kill(1).
    let mut serve = Command::new(env!("CARGO_BIN_EXE_koh"));
    serve
        .args(["serve", "--direct", "127.0.0.1:0", "--no-relay", "--allow"])
        .arg(key.public().to_string())
        .env("PATH", &empty)
        .env("KOH_CONFIG_DIR", tmp.0.join("served_cfg"))
        .env("TMPDIR", &tmp.0)
        .env_remove("XDG_RUNTIME_DIR");
    let mine = fs::metadata(&tmp.0).unwrap().uid();
    let state = fs::canonicalize(&tmp.0).unwrap();
    assert_eq!(
        Served::spawn(&mut serve).says("sessions dir:"),
        format!("{}/koh-{mine}/fux/koh-sessions", state.display())
    );
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

/// The holder a pane's `status` names, once it names one.
fn holder_of(pane: &Path) -> String {
    let status = || fs::read_to_string(pane.join("status")).unwrap_or_default();
    let holder = || {
        let status = status();
        let first = status
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("holder "));
        first
            .filter(|pid| pid.parse::<u32>().is_ok())
            .map(String::from)
    };
    until("the pane's status names its holder", || holder().is_some());
    holder().unwrap_or_default()
}

#[test]
fn koh_fux_is_fux_and_a_holder_has_no_runtime() {
    let tmp = TempDir::new("koh-fux");
    let run = fs::canonicalize(&tmp.0).unwrap().join("run");
    // `koh fux start` is fux's, and the pane it starts is held by this same file under the word
    // `hold`: no `fux` is looked for.
    let named = run.join("ws/p");
    let args = ["fux", "start", named.to_str().unwrap(), "--", "sleep", "30"];
    let (code, pane, said) = koh(&run, &args);
    assert_eq!((code, pane.as_str()), (Some(0), args[2]), "{said}");
    let holder = holder_of(&named);
    let args = ps(&holder, "args=");
    let words: Vec<&str> = args.split_whitespace().collect();
    assert_eq!(words[..2], [env!("CARGO_BIN_EXE_koh"), "hold"], "{args}");
    // The holder is fux's code and nothing of koh's: the thread it began with and the one fux
    // waits for the program on. A runtime would be a thread for each core.
    if cfg!(target_os = "linux") {
        let threads = fs::read_dir(format!("/proc/{holder}/task")).unwrap();
        assert!(threads.count() <= 2);
    }
    fs::write(named.join("ctl"), "kill\n").unwrap();
}

#[tokio::test]
async fn a_message_with_more_after_it_is_no_message() {
    let door = Door::open("more-after", ServeOptions::default()).await;
    let (client, key) = (door.client().await, &door.friend);
    // A request as it is sent, and one byte more inside its frame.
    let conn = client.connection();
    let (mut send, mut recv) = koh::net::open_authed_stream(&conn, key).await.unwrap();
    let mut body = postcard::to_allocvec(&Request::Jobs { name: None }).unwrap();
    body.push(0);
    koh::proto::send_frame(&mut send, &body).await.unwrap();
    // The server reads no request in it, and answers none: it closes the connection.
    let answer = recv_msg::<koh::proto::Reply>(&mut recv, MAX_CTRL);
    let answer = tokio::time::timeout(Duration::from_secs(20), answer).await;
    assert!(matches!(answer, Ok(Err(_))), "{answer:?}");
    client.close().await;
    door.shut().await;
}

// ---- sessions: a real `koh serve`, real `koh connect` ---------------------------

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

fn screen(dir: &Path) -> String {
    fs::read_to_string(dir.join("shown/screen")).unwrap_or_default()
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
        // The holders of the sessions that live are ended: each keeps its folder locked. (A
        // pane a test wrote by hand names a holder that is none, or is some other process.)
        for pane in fs::read_dir(&self.sessions).into_iter().flatten().flatten() {
            let folder = fuxix::open(pane.path(), false).map(|folder| folder.try_lock_shared());
            if matches!(folder, Ok(Err(fs::TryLockError::WouldBlock))) {
                signal(&holder_of(&pane.path()), "-KILL");
            }
        }
        if let Some(jobs) = self.sessions.parent().map(|fux| fux.join("koh-jobs")) {
            for pane in fs::read_dir(jobs).into_iter().flatten().flatten() {
                if let Ok(mut ctl) = fuxix::open_fifo(pane.path().join("ctl")) {
                    let _ = ctl.write_all(b"kill 9\n");
                }
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
            .env("HOME", self.tmp.0.join("home"));
        let mut served = Served::spawn(&mut serve);
        self.id = served.says("koh server id:");
        self.sessions = PathBuf::from(served.says("sessions dir:"));
        self.served = Some(served);
    }

    /// Stops the server as Ctrl-C does, and waits until it is gone.
    fn stop(&mut self) {
        self.stop_by("-INT");
    }

    fn stop_by(&mut self, how: &str) {
        let mut served = self.served.take().unwrap();
        signal(&served.server.id().to_string(), how);
        wait_child(&mut served.server, 15, "koh serve stop");
    }

    fn pane(&self, name: &str) -> PathBuf {
        self.sessions.join(name)
    }

    fn attach(&self, asks: &[&str], program: &[String]) -> InTerminal {
        let addr = self.addr();
        let mut args = vec![self.id.as_str(), "--direct", &addr];
        args.extend_from_slice(asks);
        if !program.is_empty() {
            args.push("--");
            args.extend(program.iter().map(String::as_str));
        }
        InTerminal::connect(&self.tmp.0.join("cli_cfg"), &self.tmp.0.join("crun"), &args)
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

#[test]
fn koh_connect_in_a_terminal_has_its_keys_and_ends_when_the_program_does() {
    let host = Host::start("connect-tty", &[]);
    let pane = host.pane("1");
    let program = "stty -icanon -echo; echo READY; od -An -tx1 -N2; head -c 1 >/dev/null; exit 7";
    // The detach key, Ctrl-] and a dot: koh leaves with 0, and the session runs on.
    let mut first = host.attach(&[], &sh(program));
    first.until("the terminal shows READY", |tty| tty.drew(0, b"READY"));
    first.types(b"\x1d.");
    assert_eq!(first.ends(), Some(0));
    assert_eq!(fs::read_to_string(pane.join("state")).unwrap(), "running\n");
    // koh's key typed twice is the key's own byte, typed to the program; and C-b is no key of
    // koh's: it is the session's as it is typed.
    let mut second = host.attach(&["--session", "1"], &[]);
    second.until("the terminal shows READY", |tty| tty.drew(0, b"READY"));
    second.types(b"\x1d\x1d\x02");
    let typed = |_: &mut InTerminal| {
        screen(&pane).split_whitespace().collect::<Vec<_>>() == ["READY", "1d", "02"]
    };
    second.until("the program reads the two bytes", typed);
    // The terminal's size is the session's, also when it changes.
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
    // type the detach key at a session that is over. No local session files were created.
    second.types(b"x");
    assert_eq!(second.ends(), Some(7));
    assert_eq!(names_in(&host.tmp.0.join("crun")), [""; 0]);
}

#[test]
fn viewer_reconnects_after_serve_restarts_and_a_killed_server_leaves_no_viewer() {
    let mut host = Host::start("view-restart", &[]);
    let mut tty = host.attach(&["--session", "s"], &[]);
    let pane = host.pane("s");
    tty.until("the session is shown", |_| viewers(&host).len() == 1);
    let holder = holder_of(&pane);
    // Stopped as Ctrl-C does, and as a service is told to end (`systemctl restart`): its
    // clients hear of it at once, and not after the eight seconds of silence that end a link
    // that died. What is typed meanwhile is held, and typed when the server is back.
    for how in ["-INT", "-TERM"] {
        let drawn = tty.drawn.len();
        host.stop_by(how);
        let told = Instant::now();
        tty.until("link down", |tty| tty.drew(drawn, b"no link"));
        assert!(
            told.elapsed() < Duration::from_secs(5),
            "{how}: {:?}",
            told.elapsed()
        );
        tty.types(format!("echo back-''{how}\n").as_bytes());
        host.serve();
        let back = format!("back-{how}");
        tty.until("held input after reconnect", |tty| {
            tty.drew(drawn, back.as_bytes())
        });
    }
    assert_eq!(holder_of(&pane), holder);
    // Killed outright, its viewer killed with it (the server is stopped first: it removes the
    // folder of a viewer it sees end): the server that starts next removes what that viewer
    // left, and the client is shown the session again.
    let viewer = viewers(&host)[0].trim_start_matches(".view.").to_string();
    let server = host.served.as_ref().unwrap().server.id().to_string();
    signal(&server, "-STOP");
    until("the server is stopped", || {
        ps(&server, "stat=").starts_with('T')
    });
    signal(&viewer, "-KILL");
    signal(&server, "-KILL");
    let drawn = tty.drawn.len();
    tty.until("link down", |tty| tty.drew(drawn, b"no link"));
    assert_eq!(viewers(&host).len(), 1);
    host.served = None;
    host.serve();
    tty.types(b"echo again-''42\n");
    tty.until("the session is shown again", |tty| {
        tty.drew(drawn, b"again-42")
    });
    assert!(viewers(&host).len() == 1 && !viewers(&host).contains(&format!(".view.{viewer}")));
    tty.types(b"exit 7\n");
    assert_eq!(tty.ends(), Some(7));
}

#[test]
fn one_session_draws_to_two_terminals_and_survives_hangup() {
    let host = Host::start("view-two", &[]);
    // The first on a pty that is no controlling terminal of its own.
    let (config, runtime) = (host.tmp.0.join("cli_cfg"), host.tmp.0.join("crun"));
    let asks = ["--direct", &host.addr(), &host.id, "--session", "s"];
    let mut a = InTerminal::connect_on(InTerminal::pty(), &config, &runtime, &asks, false);
    a.types(b"printf '\\033[?1049h'; echo fullscreen-$((6*7))\n");
    a.until("alternate screen", |tty| tty.drew(0, b"fullscreen-42"));
    // A second terminal comes to the session: it is shown the screen as it is now. (This one is
    // a terminal that draws what it is sent, a pane of fux's: a viewer sends the cells that
    // changed, and a line of text is not one run of bytes.)
    let b = InPane::connect(&host, "second", &[], &["--session", "s"]);
    let shows = |what: &str| b.says("shown/screen").contains(what);
    until("the second terminal shows the current screen", || {
        shows("fullscreen-42")
    });
    // The first is closed: its koh ends with 0, its viewer with it, and the second goes on to
    // the session's end.
    drop(std::mem::replace(
        &mut a.tty,
        fs::File::open("/dev/null").unwrap(),
    ));
    assert_eq!(a.ends(), Some(0));
    until("its viewer is gone", || viewers(&host).len() == 1);
    b.types(b"echo still-''here\n");
    until("the second terminal goes on", || shows("still-here"));
    b.types(b"exit 9\n");
    assert_eq!(b.ends(), "exited 9");
}

/// An attach as a test asks it: of the session `name`, or of a new one running `program`.
fn asks(name: Option<&str>, program: &[String]) -> Attach {
    Attach {
        name: name.map(String::from),
        new: name.is_none(),
        size: ViewSize {
            cols: 80,
            rows: 24,
            ..ViewSize::default()
        },
        argv: program.to_vec(),
        cwd: None,
        run: None,
        client: 7,
        term: "xterm-256color".into(),
        keyboard: 0,
        colours: String::new(),
    }
}

/// An attach by the client in this process: the stream, and what the server said of the session.
async fn attach(client: &Client, asks: Attach) -> koh::Result<(SendStream, RecvStream, Attached)> {
    let (send, mut recv) = client.request(&Request::Attach(asks)).await?;
    let attached = recv_msg(&mut recv, MAX_CTRL).await?;
    Ok((send, recv, attached))
}

/// Reads a session's stream to its end: its last word, if it had one.
async fn drawn(from: &mut RecvStream) -> Option<i32> {
    loop {
        match koh::proto::recv_msg_opt::<ViewOutput>(from, VIEW_FRAME).await {
            Ok(Some(ViewOutput::Bytes(_))) => {}
            Ok(Some(ViewOutput::Exit(code))) => return Some(code),
            _ => return None,
        }
    }
}

/// The viewers of a server's sessions that run now: the folders they have in koh's fux session.
fn viewers(host: &Host) -> Vec<String> {
    let all = names_in(host.sessions.parent().unwrap());
    let viewers = all.into_iter().filter(|name| name.starts_with(".view."));
    viewers.collect()
}

/// A program for a session that takes what is typed as it is typed, into the file `out`: it
/// says READY once its terminal is raw, and then reads.
fn reads_into(out: &Path) -> Vec<String> {
    let script = "stty raw -echo; echo READY; exec cat > \"$0\"";
    ["sh", "-c", script, out.to_str().unwrap()]
        .map(String::from)
        .to_vec()
}

/// `koh connect` in a terminal that answers what it is asked: a pane of fux's, in a session of
/// the test's own, whose program `koh connect` is. The pane is the terminal, and its files say
/// what a terminal would show: `screen`, `modes`, `cursor`, and which screen (`shown`).
struct InPane(PathBuf);

/// What a terminal says it is like: the files of its session, and what is in them.
type Like<'a> = &'a [(&'a str, &'a str)];

impl Drop for InPane {
    fn drop(&mut self) {
        signal(&holder_of(&self.0), "-KILL");
    }
}

impl InPane {
    /// A terminal `tag` of the colours and the keyboard's flags its session's files say, and
    /// `koh connect` to the host in it.
    fn connect(host: &Host, tag: &str, like: Like, asks: &[&str]) -> Self {
        let root = host.tmp.0.join(tag);
        let pane = root.join("fux/main/terminal");
        fs::create_dir_all(root.join("fux")).unwrap();
        for (name, text) in like {
            fs::write(root.join("fux").join(name), text).unwrap();
        }
        let mut start = host.koh(&["fux", "start", pane.to_str().unwrap(), "--"]);
        start.args([env!("CARGO_BIN_EXE_koh"), "connect", &host.id]);
        start.args(["--direct", &host.addr()]).args(asks);
        start.env("XDG_RUNTIME_DIR", &root).env("COLUMNS", "80");
        let started = start.env("LINES", "24").output().unwrap();
        assert!(started.status.success(), "{started:?}");
        InPane(pane)
    }

    fn says(&self, what: &str) -> String {
        fs::read_to_string(self.0.join(what)).unwrap_or_default()
    }

    /// Whether the terminal is as a program finds one: the main screen, nothing asked of it
    /// (no mouse, no pastes marked), the cursor shown.
    fn is_put_back(&self) -> bool {
        let main =
            fs::read_link(self.0.join("shown")).is_ok_and(|shown| shown == Path::new("main"));
        main && self.says("modes").trim().is_empty() && self.says("cursor").contains("shown")
    }

    fn types(&self, keys: &[u8]) {
        let mut typed = fuxix::open(self.0.join("in"), true).unwrap();
        typed.write_all(keys).unwrap();
    }

    /// `koh connect`'s process number, once its `status` says it, and how it ended once it
    /// has (`state`).
    fn pid(&self) -> String {
        let pid = || {
            let status = self.says("status");
            let pid = status.lines().find_map(|line| line.strip_prefix("pid "));
            pid.filter(|pid| pid.parse::<u32>().is_ok())
                .map(String::from)
        };
        until("the terminal's status names koh", || pid().is_some());
        pid().unwrap_or_default()
    }

    fn ends(&self) -> String {
        let state = || self.says("state").trim().to_string();
        until("koh connect ends", || {
            !["", "running"].contains(&state().as_str())
        });
        state()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_is_a_pane_kept_by_koh_hold_and_shown_by_a_viewer_on_the_server() {
    let host = Host::start("pane", &[]);
    let client = host.client().await;
    let sleeps = ["sleep".to_string(), "30".into()];
    let (_send, _from, attached) = attach(&client, asks(None, &sleeps)).await.unwrap();
    // The session is a folder in koh's own fux session, beneath its state, which it printed;
    // its run is the one its holder wrote there.
    let state = fs::canonicalize(host.tmp.0.join("run/koh")).unwrap();
    assert_eq!(host.sessions, state.join("fux/koh-sessions"));
    let (pane, server) = (
        host.pane(&attached.name),
        host.served.as_ref().unwrap().server.id(),
    );
    assert_eq!(fux::run_of(&pane), Some(attached.run));
    // Its holder is this binary under the word `hold`, with the lock on the folder: fux's proof
    // that it lives. It is no child of `koh serve`. Its viewer is this binary too, a child of
    // `koh serve`.
    let words = |pid: &str| {
        let args = ps(pid, "args=");
        let words = args.split_whitespace().take(2).map(String::from);
        words.collect::<Vec<_>>()
    };
    let holder = holder_of(&pane);
    assert_eq!(words(&holder), [env!("CARGO_BIN_EXE_koh"), "hold"]);
    assert_ne!(ps(&holder, "ppid="), server.to_string());
    assert!(fs::File::open(&pane).unwrap().try_lock_shared().is_err());
    until("the viewer is there", || viewers(&host).len() == 1);
    let viewer = viewers(&host)[0].trim_start_matches(".view.").to_string();
    assert_eq!(words(&viewer), [env!("CARGO_BIN_EXE_koh"), "view-session"]);
    assert_eq!(ps(&viewer, "ppid="), server.to_string());
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sessions_are_capped_and_the_oldest_ended_one_makes_room() {
    let host = Host::start("capped", &["--max-sessions", "3"]);
    let client = host.client().await;
    let run = |who: u64, script: &str| {
        let asks = Attach {
            client: who,
            ..asks(None, &sh(script))
        };
        attach(&client, asks)
    };
    // Two sessions that have ended, the older first, and one that runs.
    for who in [1, 2] {
        let (_send, mut from, _) = run(who, "exit 0").await.unwrap();
        assert_eq!(drawn(&mut from).await, Some(0));
    }
    let _third = run(3, "exec sleep 30").await.unwrap();
    // A new one takes the place of the oldest that ended, and not of the newer.
    let _fourth = run(4, "exec sleep 30").await.unwrap();
    until("the oldest ended one made room", || {
        names_in(&host.sessions) == ["2", "3", "4"]
    });
    let _fifth = run(5, "exec sleep 30").await.unwrap();
    // (Named by the first free number, as every session given no name is.)
    until("the other ended one made room", || {
        names_in(&host.sessions) == ["1", "3", "4"]
    });
    // With all running there is no room: the client is told the server is busy, and nothing
    // starts.
    let err = run(6, "exec sleep 30").await.unwrap_err();
    assert!(
        err.code == Exit::BUSY && err.message.contains("--max-sessions"),
        "{err:?}"
    );
    assert_eq!(names_in(&host.sessions), ["1", "3", "4"]);
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attach_ends_with_its_stream_and_its_viewer_is_gone_before_its_folder() {
    let host = Host::start("ends", &[]);
    let client = host.client().await;
    // A client that stops reading its stream and keeps its connection, under a program that
    // draws nothing more and with more typed than the program reads: the server waits on
    // neither end for it. The attach ends, and its viewer goes.
    let deaf = sh("stty -echo; echo READY; exec sleep 300");
    let (mut send, mut from, attached) = attach(&client, asks(None, &deaf)).await.unwrap();
    until("the program is ready", || {
        screen(&host.pane(&attached.name)).contains("READY")
    });
    // (Four megabytes, or until what is typed waits: a message not taken in a second.)
    let pasted = ViewInput::Bytes(vec![b'p'; 8 << 10]);
    for _ in 0..512 {
        let sent = send_msg(&mut send, &pasted, VIEW_FRAME);
        match tokio::time::timeout(Duration::from_secs(1), sent).await {
            Ok(Ok(())) => {}
            _ => break,
        }
    }
    assert_eq!(viewers(&host).len(), 1);
    from.stop(0u32.into()).unwrap();
    until("the viewer of a stream that was stopped is gone", || {
        viewers(&host).is_empty()
    });
    // A viewer that does not leave in its second (stopped, here) is killed and waited for
    // before its folder goes: when the folder is gone, so is the process.
    client.close().await;
    let mut tty = host.attach(&["--session", "z"], &[]);
    tty.until("the viewer is there", |_| viewers(&host).len() == 1);
    let viewer = viewers(&host)[0].trim_start_matches(".view.").to_string();
    signal(&viewer, "-STOP");
    tty.types(b"\x1d.");
    assert_eq!(tty.ends(), Some(0));
    until("the stopped viewer's folder is gone", || {
        viewers(&host).is_empty()
    });
    assert_eq!(ps(&viewer, "stat="), "", "the viewer outlived its folder");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_attach_ends_the_clients_older_stream_first_and_is_to_the_run_it_names() {
    let host = Host::start("older", &[]);
    let client = host.client().await;
    let out = host.tmp.0.join("out");
    let (mut older, mut old, attached) = attach(&client, asks(None, &reads_into(&out)))
        .await
        .unwrap();
    let pane = host.pane(&attached.name);
    until("the program is ready", || screen(&pane).contains("READY"));
    until("the older stream's viewer is there", || {
        viewers(&host).len() == 1
    });
    let viewer = viewers(&host);
    let typed = |keys: &[u8]| ViewInput::Bytes(keys.to_vec());
    send_msg(&mut older, &typed(b"aaaa"), VIEW_FRAME)
        .await
        .unwrap();
    // (Typed, and not on its way: what a stream has not typed when it is ended may be lost.)
    until("the program has read the older stream's bytes", || {
        fs::read(&out).unwrap_or_default() == b"aaaa"
    });
    // The same client attaches anew to the run. Once it is answered the older stream's viewer
    // has left, and its stream has ended without a last word: it was cut, not ended.
    let again = Attach {
        run: Some(attached.run),
        ..asks(Some(&attached.name), &[])
    };
    let (mut newer, _from, _) = attach(&client, again.clone()).await.unwrap();
    assert!(
        viewers(&host).iter().all(|now| !viewer.contains(now)),
        "{:?}",
        viewers(&host)
    );
    assert_eq!(drawn(&mut old).await, None);
    send_msg(&mut newer, &typed(b"bbbb"), VIEW_FRAME)
        .await
        .unwrap();
    until("the program has read both", || {
        fs::read(&out).unwrap_or_default() == b"aaaabbbb"
    });
    // Asked for a run the name has not, a client is answered with none, and nothing it says of
    // its terminal is written for a session that only has the name.
    let keyboard = host.sessions.parent().unwrap().join("keyboard");
    let other = Attach {
        run: Some(attached.run ^ 1),
        keyboard: 9,
        ..again
    };
    let err = attach(&client, other).await.unwrap_err();
    assert_eq!(err.code, Exit::NOT_FOUND, "{err:?}");
    assert!(
        err.message.contains("another run has the session's name 1"),
        "{err:?}"
    );
    assert_eq!(fs::read_to_string(keyboard).unwrap(), "0\n");
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connect_with_no_name_is_to_the_newest_session_that_lives() {
    let host = Host::start("newest", &[]);
    let client = host.client().await;
    // `first` and `second` run on; `third`, started after them, has ended. (`status` times
    // that are the same go by name, which is the order they were started in.)
    let sleeps = ["sleep".to_string(), "100".into()];
    for name in ["first", "second"] {
        attach(&client, asks(Some(name), &sleeps)).await.unwrap();
    }
    attach(&client, asks(Some("third"), &sh("exit 0")))
        .await
        .unwrap();
    let third = || fs::File::open(host.pane("third")).unwrap();
    until("third has ended", || third().try_lock_shared().is_ok());
    let nameless = Attach {
        new: false,
        ..asks(None, &[])
    };
    assert_eq!(attach(&client, nameless).await.unwrap().2.name, "second");
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_says_what_no_client_says_is_refused_or_loses_its_stream() {
    let host = Host::start("says", &[]);
    let client = host.client().await;
    let session = host.sessions.parent().unwrap().to_path_buf();
    let sleeps = ["sleep".to_string(), "100".into()];
    // What a client says of its terminal is a name and three colours: anything else is refused
    // before a session is started or a file written.
    let not_said: [fn(&mut Attach); 7] = [
        |asks| asks.term = "xterm\n256".into(),
        |asks| asks.term = "x".repeat(65),
        |asks| asks.colours = "layout #000000\n".into(),
        |asks| asks.colours = "background #1c1c1c\n../../told #000000\n".into(),
        |asks| asks.colours = "background #1c1c1c\n".repeat(4),
        |asks| asks.colours = "cursor #000000\n".repeat(4),
        |asks| asks.colours = "cursor #000000\r\n".into(),
    ];
    for not_said in not_said {
        let mut asks = asks(None, &sleeps);
        not_said(&mut asks);
        let err = attach(&client, asks.clone()).await.unwrap_err();
        assert_eq!(err.code, Exit::USAGE, "{asks:?}");
    }
    // And an attach that is refused for another reason changes nothing: what it says of its
    // terminal is written once it will be shown a session, and not before. A run of no
    // session, a name there is no session of; and a program that cannot be started leaves no
    // session's name behind, with a name or without one.
    let told = Attach {
        keyboard: 9,
        colours: "foreground #aabbcc\n".into(),
        ..asks(None, &sleeps)
    };
    let none = ["/no/such/koh-test-program".to_string()];
    let refused = [
        (Some(1), None, &sleeps[..], Exit::USAGE),
        (Some(1), Some("nosuch"), &sleeps[..], Exit::NOT_FOUND),
        (None, Some("dead"), &none[..], Exit::CANNOT_START),
        (None, None, &none[..], Exit::CANNOT_START),
    ];
    for (run, name, program, code) in refused {
        let asks = Attach {
            run,
            name: name.map(String::from),
            new: run.is_none() && name.is_none(),
            argv: program.to_vec(),
            ..told.clone()
        };
        let err = attach(&client, asks.clone()).await.unwrap_err();
        assert_eq!(err.code, code, "{asks:?}: {err:?}");
        assert_eq!(names_in(&host.sessions), [""; 0], "{err:?}");
        let told = ["keyboard", "colours"].map(|file| session.join(file).exists());
        assert!(code == Exit::CANNOT_START || told == [false; 2], "{err:?}");
    }
    // On the stream a client types and tells its terminal's size, a message of 16 KiB at most:
    // one that is longer ends the stream, with nothing of it typed.
    let (mut send, mut from, _) = attach(&client, asks(None, &sleeps)).await.unwrap();
    let long = ViewInput::Bytes(vec![b'x'; VIEW_FRAME + 1]);
    send_msg(&mut send, &long, MAX_CHUNK).await.unwrap();
    let ended = tokio::time::timeout(Duration::from_secs(20), drawn(&mut from)).await;
    assert_eq!(ended.expect("the stream lived on"), None);
    until("its viewer is gone", || viewers(&host).is_empty());
    client.close().await;
}

#[test]
fn the_exit_code_is_the_programs_and_not_zero_without_one() {
    let host = Host::start("code", &[]);
    // The program's status; of one a signal ended, 128 and the signal; of one whose holder was
    // killed, which left `state` at `running` with no lock, 1 and no 0. An ended session stays,
    // and a later client is shown the same and ends the same.
    let ends = [
        ("1", "exit 7", 7),
        ("2", "kill -9 $$", 137),
        ("3", "echo SHOWN; exec sleep 30", 1),
    ];
    for (name, script, code) in ends {
        let mut tty = host.attach(&["--new"], &sh(script));
        if code == 1 {
            tty.until("the session is shown", |tty| tty.drew(0, b"SHOWN"));
            signal(&holder_of(&host.pane(name)), "-KILL");
        }
        assert_eq!(tty.ends(), Some(code), "{script}");
        assert_eq!(host.attach(&["--session", name], &[]).ends(), Some(code));
    }
    assert_eq!(viewers(&host), [""; 0]);
}

#[test]
fn koh_connect_asks_its_terminal_what_it_is_like_and_puts_it_back_however_it_ends() {
    let host = Host::start("terminal", &[]);
    let session = host.sessions.parent().unwrap().to_path_buf();
    // A program that takes the alternate screen, the mouse and pastes marked, and hides the cursor.
    let modes = r"printf '\033[?1049h\033[?1002h\033[?1006h\033[?2004h\033[?25l\033[5;5HMODES-%s' ON; exec sleep 600";
    let like = [
        ("colours", "foreground #d0d0d0\nbackground #1c1c1c\n"),
        ("keyboard", "5\n"),
    ];
    // A terminal that says its colours and takes the keyboard's flags 1 and 4 is asked before
    // anything was dialled, and its answers are in the server's session, where the programs of
    // its panes are answered from; one that knows neither tells no colours (the file is as it
    // was) and has the plain keyboard. Told to end, hung up as by a terminal that is closed, or
    // left by its user, koh puts the terminal back before it goes, and the session runs on.
    let starts = ["--session", "s", "--", "sh", "-c", modes];
    let ways: [(Like, &[&str], &str, &str); 3] = [
        (&like, &starts, "-TERM", "5\n"),
        (&[], &starts[..2], "-HUP", "0\n"),
        (&[], &starts[..2], "", "0\n"),
    ];
    for (n, (like_it, asks, how, keyboard)) in ways.into_iter().enumerate() {
        let terminal = InPane::connect(&host, &format!("t{n}"), like_it, asks);
        until("the terminal shows the program, its modes on", || {
            terminal.says("shown/screen").contains("MODES-ON")
                && terminal.says("modes").contains("mouse")
        });
        let told = |file: &str| fs::read_to_string(session.join(file)).unwrap();
        assert_eq!(
            (told("colours"), told("keyboard")),
            (like[0].1.into(), keyboard.into())
        );
        match how {
            "" => terminal.types(b"\x1d."),
            how => signal(&terminal.pid(), how),
        }
        assert_eq!(terminal.ends(), "exited 0", "{how}");
        until("the terminal is put back", || terminal.is_put_back());
    }
    // The session's program was typed nothing, by any of the three, and no viewer is left.
    assert_eq!(screen(&host.pane("s")).trim(), "MODES-ON");
    until("the viewers are gone", || viewers(&host).is_empty());
}

#[test]
fn a_sessions_program_is_told_the_terminals_colours_and_has_its_keys_in_the_form_it_asked_for() {
    let host = Host::start("told", &[]);
    // A program that asks its terminal for its background and, having set the keyboard's
    // first flag, which flags are in force; and then writes all it reads into `out`.
    let asks = r#"stty raw -echo; printf '\033]11;?\033\\\033[>1u\033[?u'; exec cat > "$0""#;
    // In a terminal that tells no colours and does not know the kitty keyboard protocol, the
    // program is told that no flag is in force, and no colour; Escape, typed, is the one byte.
    // In one that says its colours and takes the keyboard's flags, the program is told the
    // background and that its flag is in force; and Escape, which such a terminal sends in the
    // protocol's form once the flag is set there, reaches the program in that form.
    let like = [
        ("colours", "foreground #d0d0d0\nbackground #1c1c1c\n"),
        ("keyboard", "5\n"),
    ];
    let terminals: [(&str, Like, &str, &[u8]); 2] = [
        ("plain", &[], "\x1b[?0u", b"\x1b"),
        (
            "kitty",
            &like,
            "\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\\x1b[?1u",
            b"\x1b[27u",
        ),
    ];
    for (tag, like, told, escape) in terminals {
        let out = host.tmp.0.join(format!("{tag}.out"));
        let program = [
            "--session",
            tag,
            "--",
            "sh",
            "-c",
            asks,
            out.to_str().unwrap(),
        ];
        let terminal = InPane::connect(&host, tag, like, &program);
        let read = || fs::read(&out).unwrap_or_default();
        until("the program is told what its terminal is", || {
            read() == told.as_bytes()
        });
        if tag == "kitty" {
            until("the flag is set in the client's terminal", || {
                terminal.says("modes").contains("keys1")
            });
        }
        terminal.types(escape);
        let typed = [told.as_bytes(), escape].concat();
        until("Escape is typed in the form it asked for", || {
            read() == typed
        });
        // koh's key leaves in that form too, and the terminal is as it was.
        if tag == "kitty" {
            terminal.types(b"\x1b[93;5u.");
            assert_eq!(terminal.ends(), "exited 0");
            until("the terminal is put back", || {
                terminal.is_put_back() && !terminal.says("modes").contains("keys")
            });
            assert_eq!(read(), typed);
        }
    }
}

#[test]
fn a_terminal_that_answers_nothing_is_asked_once_and_one_that_answers_in_pieces_is_heard() {
    let mut host = Host::start("late", &[]);
    let session = host.sessions.parent().unwrap().to_path_buf();
    let out = host.tmp.0.join("out");
    let asked = |tty: &InTerminal| tty.drawn.windows(3).filter(|s| s == b"\x1b[c").count();
    // A terminal that answers nothing: koh waits a second for it, and goes on with the plain
    // keyboard and no colours.
    let mut tty = host.attach(&["--session", "s"], &reads_into(&out));
    tty.answers = false;
    tty.until("it is asked", |tty| tty.drew(0, b"\x1b[c"));
    let began = Instant::now();
    tty.until("the program is ready", |tty| tty.drew(0, b"READY"));
    assert!(
        began.elapsed() >= Duration::from_millis(900),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "0\n");
    assert!(!session.join("colours").exists());
    // What it sends after the wait was typed, whatever its form: koh looks for no answer in
    // it, and drops none of it. (An answer that comes late is typed into the session so, once.)
    let late = b"\x1b[?5u\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\\x1b[?62;4c\x1b]1hello\x07x";
    tty.types(late);
    until("what has an answer's form is typed, to the byte", || {
        fs::read(&out).unwrap_or_default() == late
    });
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "0\n");
    assert!(!session.join("colours").exists());
    // The server goes and comes back: koh dials again and attaches again, and asks its
    // terminal nothing again. (So a terminal that answers nothing costs its second once.)
    host.stop();
    tty.until("link down", |tty| tty.drew(0, b"no link"));
    host.serve();
    tty.types(b"y");
    tty.until("typed on return", |_| {
        fs::read(&out).unwrap_or_default() == [&late[..], b"y"].concat()
    });
    assert_eq!(asked(&tty), 1);
    // A terminal that answers in pieces, within the wait: its flags, a colour cut in two, and
    // what it is, cut in two, with a key right after it. The answers are heard, and the key
    // is the session's first. (The pauses are for the pieces to come in reads of their own;
    // together they are the easier test.)
    let out = host.tmp.0.join("out.pieces");
    let mut slow = host.attach(&["--session", "p"], &reads_into(&out));
    slow.answers = false;
    slow.until("it is asked", |tty| tty.drew(0, b"\x1b[c"));
    for piece in [
        &b"\x1b[?5u\x1b]11;rgb:12"[..],
        b"34/abcd/00ff\x1b\\\x1b[?6",
        b"2;4cz",
    ] {
        slow.types(piece);
        std::thread::sleep(Duration::from_millis(30));
    }
    slow.until("the program is ready", |tty| tty.drew(0, b"READY"));
    assert_eq!(fs::read_to_string(session.join("keyboard")).unwrap(), "5\n");
    assert_eq!(
        fs::read_to_string(session.join("colours")).unwrap(),
        "background #12ab00\n"
    );
    until("the key after its answers is typed", || {
        fs::read(&out).unwrap_or_default() == b"z"
    });
}

#[test]
fn what_was_typed_before_the_key_that_leaves_is_typed() {
    let host = Host::start("before", &[]);
    // What is typed right before `Ctrl-] .`, in one write with it (a paste and the key, a fast
    // hand): koh leaves, and the session has it, all of it and in its order. More than a pty
    // holds at once (a kilobyte on macOS), so that the last of it waits on the server for the
    // viewer to read what is before it, while the client is leaving; and less than the second
    // koh gives that on its way out may type on a slow machine (README: "it has a second for
    // that"; at 40 KB a macOS runner typed some 35 KB in it).
    let typed: Vec<u8> = (0..1500)
        .flat_map(|n| format!("{n:07}\n").into_bytes())
        .collect();
    let out = host.tmp.0.join("out");
    let mut tty = host.attach(&["--session", "s"], &reads_into(&out));
    tty.until("the program is ready", |tty| tty.drew(0, b"READY"));
    tty.types(&[&typed[..], b"\x1d."].concat());
    assert_eq!(tty.ends(), Some(0));
    until("the program has read all that was typed", || {
        fs::read(&out).unwrap_or_default() == typed
    });
    until("the viewer is gone", || viewers(&host).is_empty());
}

#[test]
fn a_session_that_ends_with_typing_unread_ends_for_its_client_at_once() {
    let host = Host::start("unread", &[]);
    // A program that reads nothing, with more typed meanwhile than its pane takes, so that the
    // viewer's own terminal holds what the viewer has not read; and it ends. The viewer has
    // left when the server looks for that, and nothing waits a second for a viewer that is
    // gone to read it: the client has the program's status then.
    let gate = host.tmp.0.join("gate");
    let script = "stty -echo; echo READY; until [ -e \"$0\" ]; do sleep 0.05; done; exit 42";
    let program = ["sh", "-c", script, gate.to_str().unwrap()].map(String::from);
    let mut tty = host.attach(&["--session", "s"], &program);
    tty.until("the program is ready", |tty| tty.drew(0, b"READY"));
    let state = || fs::read_to_string(host.pane("s").join("state")).unwrap_or_default();
    let (burst, mut over, mut full) = (vec![b'x'; 64 << 10], None, 0);
    let ended = loop {
        // (As much as the terminal takes, and nothing once koh is gone; what koh draws is read.)
        // Once the terminal has taken nothing a hundred times running, the program ends.
        match (&tty.tty).write(&burst) {
            Ok(1..) => full = 0,
            _ => full += 1,
        }
        if full == 100 {
            fs::write(&gate, "").unwrap();
        }
        let mut drawn = [0; 4096];
        while let Ok(n @ 1..) = (&tty.tty).read(&mut drawn) {
            tty.drawn.extend_from_slice(&drawn[..n]);
        }
        if over.is_none() && state().starts_with("exited") {
            over = Some(Instant::now());
        }
        if let Some(ended) = tty.koh.try_wait().unwrap() {
            break ended.code();
        }
        assert!(full < 10_000, "koh is still there");
        std::thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(ended, Some(42));
    // From the program's end to koh's, well under the second that was waited; and koh never
    // said that there was no link: there was one, and the session's last word on it.
    let after = over.map(|over| over.elapsed());
    assert!(
        after.is_some_and(|after| after < Duration::from_millis(800)),
        "{after:?}"
    );
    assert!(!tty.drew(0, b"no link"));
}

#[test]
fn koh_connect_ends_when_it_is_told_to_though_its_terminal_takes_nothing() {
    let host = Host::start("stalled", &[]);
    // A terminal that takes nothing more (one behind a path that is stuck), under a program
    // that goes on printing: koh's writing to it waits, and so would putting it back. Told to
    // end, koh ends all the same, each of the three ways, and soon.
    for (how, code) in [("-TERM", 0), ("-HUP", 0), ("-INT", 130)] {
        // (Every cell of another colour than the one before it: a screen of it is many bytes.)
        let draws = r"while :; do printf '\033[31mfl\033[32moo\033[33md-\033[34mof\033[35m-l\033[36min\033[37mes'; done";
        let flood = ["sh", "-c", draws].map(String::from);
        let mut tty = host.attach(&["--session", how.trim_start_matches('-')], &flood);
        tty.until("the flood is drawn", |tty| {
            tty.drawn.windows(2).any(|drawn| drawn == b"es")
        });
        // (Not read from here on: what koh writes fills the terminal, and waits.)
        std::thread::sleep(Duration::from_secs(3));
        let told = Instant::now();
        signal(&tty.koh.id().to_string(), how);
        let ended = loop {
            match tty.koh.try_wait().unwrap() {
                Some(ended) => break ended.code(),
                None => assert!(
                    told.elapsed() < Duration::from_secs(2),
                    "{how}: still there"
                ),
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(ended, Some(code), "{how}");
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
    ["sh", "-c", "--", script].map(String::from).to_vec()
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

    fn session(&self, name: &str, program: &[String], ready: &str) -> PathBuf {
        let mut tty = self.attach(&["--session", name], program);
        let pane = self.pane(name);
        tty.until(ready, |_| screen(&pane).contains(ready));
        tty.types(b"\x1d.");
        assert_eq!(tty.ends(), Some(0));
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
    let mut live = host.attach(&["--session", "live"], &marking_shell(&host));
    let pane = host.pane("live");
    until("the shell has its prompt", || screen(&pane).contains('$'));
    assert_eq!(
        host.attach(&["--session", "done"], &sh("exit 7")).ends(),
        Some(7)
    );
    let mut dead = host.attach(&["--session", "dead"], &marking_shell(&host));
    let killed = host.pane("dead");
    until("the third has its prompt", || screen(&killed).contains('$'));
    fs::write(killed.join("in"), "sleep 30\n").unwrap();
    let marks = || fs::read_to_string(killed.join("marks")).unwrap_or_default();
    until("its command runs", || marks().ends_with(" output\n"));
    signal(&holder_of(&killed), "-KILL");
    assert_eq!(dead.ends(), Some(1));
    // One a holder that is gone left with a tab in its title is printed with `?`, as a job's
    // command: the title is the last field.
    fs::write(killed.join("title"), "a\tb\n").unwrap();
    // A line a session, the oldest first, its fields after one tab each: name, attached or
    // detached, state, busy or idle, exit=N or exit=-, COLSxROWS, and the title.
    let list = || -> Vec<String> {
        let (code, list, said) = host.asked("sessions", &[]);
        assert_eq!(code, Some(0), "{said}");
        list.lines().map(|line| line.replace('\t', "|")).collect()
    };
    let gate = host.tmp.0.join("gate");
    let waits = format!(
        "sh -c 'until [ -e {} ]; do sleep 0.1; done; exit 5'\n",
        gate.display()
    );
    let listed = list();
    let starts = [
        "live|attached|running|idle|",
        "done|detached|exited 7|idle|exit=-|",
        "dead|detached|ended|idle|",
    ];
    let ends = ["|80x24|", "|80x24|", "|80x24|a?b"];
    assert_eq!(listed.len(), 3, "{listed:?}");
    for ((line, start), end) in listed.iter().zip(starts).zip(ends) {
        let fields = line.matches('|').count() + 1;
        assert!(
            line.starts_with(start) && line.ends_with(end) && fields == 7,
            "{listed:?}"
        );
    }
    // A command runs from where its output begins (the last mark is `output`) to its end,
    // which has its code. A session whose holder is gone runs no command, whatever its marks
    // say (the last mark of the one that was killed is still its command's `output`).
    fs::write(pane.join("in"), waits).unwrap();
    until("the command runs", || {
        list()[0].starts_with("live|attached|running|busy|")
    });
    fs::write(&gate, "").unwrap();
    until("the command has ended", || {
        list()[0].starts_with("live|attached|running|idle|exit=5|")
    });
    // The client leaves: the session is not attached.
    signal(&live.koh.id().to_string(), "-TERM");
    assert_eq!(live.ends(), Some(0));
    until("the session has no client", || {
        list()[0].starts_with("live|detached|")
    });
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
    // Without `--last` it is the screen that is shown.
    let (code, shown, said) = host.asked("output", &["--session", "1"]);
    assert_eq!((code, shown.as_str()), (Some(0), rows.as_str()), "{said}");
    // A name that is no session's is not found.
    let (code, _, said) = host.asked("output", &["--session", "none"]);
    assert_eq!(code, Some(127), "{said}");
    assert!(said.contains("no session none"), "{said}");
    // Nor is a name that is none a path: the folder above the sessions is no session, also
    // where it looks like a pane.
    let above = host.sessions.parent().unwrap();
    fs::create_dir_all(above.join("shown")).unwrap();
    fs::write(above.join("status"), "holder 1\n").unwrap();
    fs::write(above.join("run"), format!("{:032x}\n", 1)).unwrap();
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
    let (code, waited, said) = host.asked("wait", &["--session", "s", "--timeout", "1"]);
    assert_eq!((code, said.as_str()), (Some(124), "· timed out\n"));
    assert!(began.elapsed() >= Duration::from_secs(1));
    assert_eq!(waited, screen(&pane));
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
    // above the prompt), and of two commands that ended the code and output are the first's.
    let no_lf = r"printf '\r\n'; m C; printf no-lf; m 'D;6'; printf '\r\n'; prompt";
    let blank = r"printf '\033[H\033[2J'; m C; printf '\r\n'; m 'D;0'";
    let steps = [
        "m 'D;4'",
        "ran one 7",
        MOVES[0],
        "ran two 9; ran three 5",
        no_lf,
        blank,
    ];
    let moving = host.session("m", &marks_by_steps(&steps), "$");
    let last_is = |want: &str| {
        let (code, last, said) = recipe(&["last", moving.to_str().unwrap()]);
        assert_eq!((code, last.as_str()), (Some(0), want), "{said}");
        assert_eq!(last, host.asked("output", &["--session", "m", "--last"]).1);
    };
    // An end with no output marked before it, and none before that, is of the screen.
    stepped(&moving, 1);
    last_is(&screen(&moving));
    stepped(&moving, 2);
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
    stepped(&moving, 3);
    std::thread::sleep(Duration::from_millis(500));
    assert!(!wait.ended(), "{:?}", wait.said());
    stepped(&moving, 4);
    until("the recipe's wait ends", || wait.ended());
    let (code, printed, said) = wait.said();
    assert_eq!((code, printed.as_str()), (Some(9), "two\n"), "{said}");
    // A command's output with no line break at its end is its last line all the same, and one
    // empty line on an otherwise blank screen is that line.
    stepped(&moving, 5);
    last_is("no-lf\n");
    stepped(&moving, 6);
    last_is("\n");
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
        timeout_secs: Some(8),
    };
    client.request(&asked).await.unwrap().1
}

/// What a wait was answered: its exit code and its text.
async fn waited(wait: RecvStream) -> (i32, String) {
    let (exit, text, _) = told(wait).await;
    (exit, text)
}

/// The same, and the word it was answered with.
async fn told(mut wait: RecvStream) -> (i32, String, String) {
    let ended: koh::proto::WaitResult = recv_msg(&mut wait, MAX_CTRL).await.unwrap();
    let text = koh::proto::recv_pieces(&mut wait).await.unwrap();
    (ended.exit, String::from_utf8(text).unwrap(), ended.detail)
}

/// Whether a wait has said nothing for four looks of the server's.
async fn silent(wait: &mut RecvStream) -> bool {
    let look = Duration::from_millis(400);
    tokio::time::timeout(look, wait.read(&mut [0; 1]))
        .await
        .is_err()
}

/// A session of `marks_by_steps`, and how many of its steps are done.
struct Stepped(PathBuf, u32);

impl Stepped {
    fn start(host: &Host, steps: &[&str]) -> Self {
        Self(host.session("s", &marks_by_steps(steps), "$"), 0)
    }

    /// Has the next step done, and gives the pane's `marks` after it.
    fn step(&mut self) -> String {
        self.1 += 1;
        stepped(&self.0, self.1)
    }
}

/// Has a session of `marks_by_steps` do its next step, the `done`th, and gives the pane's
/// `marks` once its title says so: the two as one round of the holder's left them, read
/// between two looks at the same even `generation`. (A round writes `title` before `marks`:
/// read one after the other and no more, the marks may be those of the round before, which
/// under load is one from the middle of the step.)
fn stepped(pane: &Path, done: u32) -> String {
    fs::write(pane.join("in"), "\n").unwrap();
    let title = format!("done-{done}\n");
    let read = |name: &str| fs::read_to_string(pane.join(name)).unwrap_or_default();
    let mut marks = String::new();
    until(&title, || {
        let number = read("generation");
        let even = number.trim().parse::<u64>().is_ok_and(|n| n % 2 == 0);
        let said = read("title");
        marks = read("marks");
        even && said == title && read("generation") == number
    });
    marks
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
        stepped(&pane, done)
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
    let door = Door::open("many", ServeOptions::default()).await;
    let client = door.client().await;
    // As many ended panes as `--max-sessions` may keep, each with a title as long as fux
    // writes one: more than a message holds.
    let sessions = door.tmp.0.join("state/fux/koh-sessions");
    for n in 1..=4500 {
        let pane = sessions.join(n.to_string());
        fs::create_dir(&pane).unwrap();
        fs::write(pane.join("status"), "holder 1\npid 1\n").unwrap();
        fs::write(pane.join("run"), format!("{n:032x}\n")).unwrap();
        fs::write(pane.join("title"), "t".repeat(256) + "\n").unwrap();
    }
    let list = client.sessions().await.unwrap();
    assert_eq!(list.len(), 4500);
    assert!(
        list.iter()
            .all(|session| session.title.len() == 256 && session.state == "ended")
    );
    client.close().await;
    door.shut().await;
}

#[test]
fn a_wait_for_a_job_and_a_session_at_once_is_a_usage_error() {
    let tmp = TempDir::new("wait-usage");
    // A wait is for a job or for a session; what is a job's alone is not said of a session.
    for more in [&["build"][..], &["--tail", "5"]] {
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

// The sequences of the second round of reviews, each against fux's holder: what a full `marks`
// could not say, and its count of the marks it dropped does.

/// So many times `body`, as one step of a session's program.
fn times(n: u32, body: &str) -> String {
    format!("i=0; while [ $i -lt {n} ]; do {body}; i=$((i + 1)); done")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_sees_a_commands_end_in_a_shell_that_clears_at_every_command() {
    let host = Host::start("clears", &[]);
    // `clear; echo hi N`, 255 times, in a pane of 80 by 24: the file is full, and every mark
    // of it but the last few is at one place. Then a command that ends with 4, and 16 more.
    let clears = times(
        255,
        r"printf '\r\n'; m C; printf '\033[H\033[2Jhi %s\r\n' $i; m 'D;0'; prompt",
    );
    let more = times(16, "ran more $((i + 10))");
    let mut session = Stepped::start(&host, &[&clears, "ran four 4", &more, "ran fresh 3"]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    session.step();
    session.step();
    assert_eq!(waited(wait).await, (4, "four\n".to_string()));
    // And a wait asked afresh after those.
    let wait = waits(&client, "s").await;
    session.step();
    assert_eq!(waited(wait).await, (3, "fresh\n".to_string()));
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_screen_that_moves_ends_nothing_where_every_mark_is_on_it() {
    let host = Host::start("on-screen", &[]);
    // `clear` 255 times and `true`: a full file whose first mark is still on the screen. A
    // command begins, scrolls the screen down, and ends with 5 only later.
    let clears = times(
        255,
        r"printf '\r\n'; m C; printf '\033[H\033[2J'; m 'D;0'; prompt",
    );
    let begun = r"printf '\r\n'; m C; printf '\033[1T'";
    let steps = [
        &clears,
        r"printf '\r\n'; m C; m 'D;0'; prompt",
        begun,
        "m 'D;5'; prompt",
    ];
    let mut session = Stepped::start(&host, &steps);
    session.step();
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let mut wait = waits(&client, "s").await;
    let scrolled = session.step();
    assert!(
        silent(&mut wait).await,
        "the wait ended at a scroll down: {scrolled:?}"
    );
    session.step();
    assert_eq!(waited(wait).await.0, 5);
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_line_inserted_ends_nothing_where_a_shell_clears_at_each_prompt() {
    let host = Host::start("inserted", &[]);
    // 260 commands, each at a prompt drawn on a cleared screen: a full file on three rows.
    let cleared = r"printf '\033[H\033[2J'; prompt; printf '\r\n'; m C; printf 'x\r\n'; m 'D;7'";
    let fill = times(260, cleared) + "; prompt";
    let mut session = Stepped::start(&host, &[&fill, MOVES[0], "ran after 3"]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let mut wait = waits(&client, "s").await;
    let inserted = session.step();
    assert!(
        silent(&mut wait).await,
        "the wait ended at a line inserted: {inserted:?}"
    );
    session.step();
    assert_eq!(waited(wait).await, (3, "after\n".to_string()));
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn more_marks_than_a_pane_keeps_between_two_looks_are_said_and_not_guessed() {
    let host = Host::start("burst", &[]);
    // One command has ended; then the marks of 300, in one write: more than the file keeps.
    let one = r#"s="$s\r\n\033]133;C\007burst-$i\r\n\033]133;D;$((i % 100))\007\033]133;A\007\$ \033]133;B\007""#;
    let burst = format!(r#"s=; {}; printf "$s""#, times(300, one));
    let mut session = Stepped::start(&host, &["ran one 7", &burst]);
    session.step();
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    // The server looks ten times a second, and the holder writes the burst in as many rounds
    // as it reads it in. So that all of it is between two looks, the server stands still
    // from the look the wait was asked with until the pane has the whole burst: a look in the
    // middle would find the first command, or the oldest of that moment.
    let server = host.served.as_ref().unwrap().server.id().to_string();
    let state = || {
        let ps = Command::new("ps")
            .args(["-o", "state=", "-p", &server])
            .output();
        String::from_utf8_lossy(&ps.unwrap().stdout).into_owned()
    };
    signal(&server, "-STOP");
    until("the server is stopped", || state().contains('T'));
    let marks = session.step();
    signal(&server, "-CONT");
    assert_eq!(marks.lines().count(), 1000);
    let (code, text, said) = told(wait).await;
    // The first that ended is not there any more. The wait gives the oldest that is, and says
    // that it is not known to be the first.
    let kept = marks.lines().filter(|mark| mark.contains(" end")).count();
    let oldest = 300 - kept;
    assert!(said.contains("marks came and went unread"), "{said}");
    assert_eq!(
        (code, text),
        ((oldest % 100) as i32, format!("burst-{oldest}\n")),
        "{said}"
    );
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_end_is_the_first_where_the_files_oldest_marks_are_alike() {
    let host = Host::start("alike", &[]);
    // Three commands and a clear, which puts their marks at one place; 247 more, and the file
    // is full with those alike at its front. Then an empty line entered, whose `end` has the
    // code of the command before, and a command that ends with 22: the first is the first.
    let quiet = r"printf '\r\n'; m C; m 'D;0'; prompt";
    let fill = format!(
        "{quiet}; {quiet}; {quiet}; printf '\\r\\n'; m C; printf '\\033[H\\033[2J'; m 'D;0'; prompt; {}",
        times(247, "ran fill 1")
    );
    let entered = r"printf '\r\n'; m 'D;1'; prompt; ran second 22";
    let mut session = Stepped::start(&host, &[&fill, entered]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    session.step();
    assert_eq!(waited(wait).await, (1, "fill\n".to_string()));
    client.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_end_is_seen_where_a_prompt_drawn_again_left_a_full_file_short() {
    let host = Host::start("short", &[]);
    // A full file. A command ends with 77; a prompt with no `end` (Ctrl-C); a clear and the
    // prompt anew, which takes two marks back: 998 lines, and six were dropped.
    let after = r"ran hello 77; printf '^C\r\n'; prompt; printf '\033[H\033[2J'; prompt";
    let mut session = Stepped::start(&host, &[&times(260, "ran fill 0"), after]);
    assert_eq!(session.step().lines().count(), 1000);
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    assert_eq!(session.step().lines().count(), 998);
    // (What it printed went with the clear, unless the wait looked before that.)
    assert_eq!(waited(wait).await.0, 77);
    client.close().await;
}

#[tokio::test]
async fn each_client_dials_from_its_own_key_and_proves_the_client_key() {
    let tmp = TempDir::new("ephemeral-dial");
    let key = new_key(&tmp, "client.key");
    let (srv, route) = boot_server(&tmp, vec![key.public()], ServeOptions::default()).await;
    let dial = || Client::connect_direct(key.clone(), srv.endpoint_id, route.clone(), false);

    let (a, b) = (dial().await.unwrap(), dial().await.unwrap());
    assert!(srv.endpoint.remote_info(key.public()).await.is_none());
    let (r1, r2) = tokio::join!(a.jobs(None), b.jobs(None));
    assert!(r1.unwrap().is_empty() && r2.unwrap().is_empty());
    a.close().await;
    b.close().await;

    let cfg = koh::net::transport_config(false);
    let (e1, _, _) = koh::net::connect_server(srv.endpoint_id, route.clone(), cfg.clone())
        .await
        .unwrap();
    let (e2, _, _) = koh::net::connect_server(srv.endpoint_id, route, cfg)
        .await
        .unwrap();
    assert_ne!(e1.id(), key.public());
    assert_ne!(e2.id(), key.public());
    assert_ne!(e1.id(), e2.id());
    assert!(srv.endpoint.remote_info(e1.id()).await.is_some());
    assert!(srv.endpoint.remote_info(e2.id()).await.is_some());
    e1.close().await;
    e2.close().await;
    srv.shutdown().await;
}

#[test]
fn clients_file_rejects_extra_fields_and_keeps_valid_lines() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;

    let tmp = TempDir::new("clients-parse");
    let (key, file) = (tmp.0.join("server.key"), tmp.0.join("clients"));
    let k = iroh::SecretKey::from_bytes(&[1; 32]).public();
    let rows = [
        ("# comment".into(), None),
        (String::new(), None),
        (format!("full {k}"), Some("full")),
        (format!("ws {k}   "), Some("ws")),
        (format!("cp {k} cp=/srv"), None),
        (format!("ex {k} exec=~/a b"), None),
        (format!("t1 {k} copy=/srv"), None),
        (format!("t2 {k} # inline"), None),
        (format!("t3 {k} --cp /srv\x1b[2K"), None),
        ("bad_id notakey".into(), None),
        ("lone_word".into(), None),
        (format!("cr {k}\r"), Some("cr")),
    ];
    let text: Vec<_> = rows.iter().map(|(l, _)| l.as_str()).collect();
    // No trailing LF: exercises a bare trailing `\r` on the last line.
    fs::write(&file, text.join("\n")).unwrap();

    let mut skipped = Vec::new();
    let entries =
        koh::keys::load_clients(Some(&key), |n, l| skipped.push((n, l.to_string()))).unwrap();
    let want: Vec<_> = rows.iter().filter_map(|(_, w)| *w).collect();
    let got: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(got, want);
    let skipped_want: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, (l, w))| w.is_none() && !l.is_empty() && !l.starts_with('#'))
        .map(|(i, (l, _))| (i + 1, l.clone()))
        .collect();
    assert_eq!(skipped, skipped_want);

    let cli = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_koh"));
        c.arg("clients").arg("--key-file").arg(&key).args(args);
        c
    };
    let out = cli(&[]).output().unwrap();
    assert!(out.status.success());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    for name in &want {
        assert!(stdout.contains(&format!("{name} ")), "{stdout}");
    }
    assert_eq!(stderr.lines().count(), skipped_want.len(), "{stderr}");
    for (n, line) in &skipped_want {
        let expected = format!("koh: clients:{n}: ignored, not NAME ID: {line:?}");
        assert!(stderr.contains(&expected), "missing {expected} in {stderr}");
    }

    for flag in ["--cp", "--exec"] {
        let res = cli(&["add", "bad", &k.to_string(), flag, "/srv"])
            .output()
            .unwrap();
        assert_eq!(res.status.code(), Some(2), "{flag}");
    }
    let not_utf8 = Command::new(env!("CARGO_BIN_EXE_koh"))
        .arg("servers")
        .arg(OsStr::from_bytes(b"\xff"))
        .output()
        .unwrap();
    assert_eq!(not_utf8.status.code(), Some(2));
    assert!(not_utf8.stdout.is_empty());
    assert_eq!(not_utf8.stderr, b"koh: arguments must be valid UTF-8\n");

    // `rm` on a skipped name fails and leaves the file unchanged; `add`, `rename`, and `rm` of
    // accepted names warn about skipped lines on stderr and rewrite from accepted lines only.
    let before = format!("old {k} cp=/srv\nother {k}\n");
    fs::write(&file, &before).unwrap();
    let rm_old = cli(&["rm", "old"]).output().unwrap();
    assert!(!rm_old.status.success());
    let rm_err = String::from_utf8_lossy(&rm_old.stderr);
    assert!(rm_err.contains("koh: clients:1: ignored") && rm_err.contains("no client named"));
    assert_eq!(fs::read_to_string(&file).unwrap(), before);
    let added = cli(&["add", "alice", &k.to_string()]).output().unwrap();
    assert!(added.status.success());
    assert!(String::from_utf8_lossy(&added.stderr).contains("koh: clients:1: ignored"));
    assert!(cli(&["rename", "alice", "bob"]).status().unwrap().success());
    let names: Vec<_> = koh::keys::load_clients(Some(&key), |_, _| {})
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["other", "bob"]);
    assert!(cli(&["rm", "other"]).status().unwrap().success());
    assert_eq!(fs::read_to_string(&file).unwrap(), format!("bob {k}\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_refuses_scoped_and_unknown_field_clients_lines() {
    let tmp = TempDir::new("clients-enforce");
    let bot_cfg = tmp.0.join("bot_cfg");
    let crun = tmp.0.join("crun");
    for d in [tmp.0.join("srv_cfg"), bot_cfg.clone(), crun.clone()] {
        fs::create_dir_all(d).unwrap();
    }
    let valid = new_key(&tmp, "v.key");
    let cp_key = load_or_create_key(Role::Client, Some(&bot_cfg.join("client.key"))).unwrap();
    let exec_key = new_key(&tmp, "ex.key");
    let typo = new_key(&tmp, "t.key");
    let clients_file = tmp.0.join("srv_cfg/clients");
    let skipped_only = format!(
        "cpbot {} cp=/srv\nexecbot {} exec=/srv\ntypo {} copy=/srv\nold_valid {} cp=/srv\n",
        cp_key.public(),
        exec_key.public(),
        typo.public(),
        valid.public()
    );
    fs::write(
        &clients_file,
        format!("{skipped_only}valid {}\n", valid.public()),
    )
    .unwrap();

    let (srv, route) = boot_server(&tmp, Vec::new(), ServeOptions::default()).await;
    let addr = srv.direct_addr.unwrap().to_string();
    let srv_id = srv.endpoint_id.to_string();
    let dial = |k| Client::connect_direct(k, srv.endpoint_id, route.clone(), false);
    let marker = tmp.0.join("ran");
    let touch = vec![
        "/bin/sh".into(),
        "-c".into(),
        "--".into(),
        format!("touch {}", marker.display()),
    ];
    for refused in [cp_key, exec_key, typo] {
        let cl = dial(refused).await.unwrap();
        assert_eq!(
            cl.exec(touch.clone(), None).await.unwrap_err().code,
            Exit::REFUSED
        );
        cl.close().await;
    }
    assert!(!marker.exists(), "refused key ran a command");

    // Refused `koh connect` via the binary exits 4 promptly (no infinite retry) and creates no session.
    let mut terminal = InTerminal::connect(
        &bot_cfg,
        &crun,
        &[&srv_id, "--direct", &addr, "--session", "s"],
    );
    assert_eq!(terminal.ends(), Some(4), "refused connect must exit 4");
    assert_eq!(names_in(&tmp.0.join("state/fux/koh-sessions")), [""; 0]);

    // Same id on a skipped line and a good line is allowed; removing the good line revokes it.
    let v = dial(valid).await.unwrap();
    assert!(v.jobs(None).await.unwrap().is_empty());
    assert_eq!(v.exec(vec!["true".into()], None).await.unwrap(), 0);
    fs::write(&clients_file, &skipped_only).unwrap();
    assert_eq!(v.jobs(None).await.unwrap_err().code, Exit::REFUSED);
    v.close().await;
    srv.shutdown().await;
}

fn wait_child(child: &mut std::process::Child, secs: u64, what: &str) -> std::process::ExitStatus {
    let until = Instant::now() + Duration::from_secs(secs);
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            return st;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what} timed out after {secs}s");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn box_sh(host: &Host, script: &str) {
    let addr = host.addr();
    let add = ["servers", "add", "box", &host.id, "--direct", &addr];
    assert!(host.koh(&add).status().unwrap().success());
    let bin = Path::new(env!("CARGO_BIN_EXE_koh")).parent().unwrap();
    let mut paths = vec![bin.to_path_buf()];
    if let Some(old) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&old));
    }
    let mut child = Command::new("/bin/sh")
        .args(["-ec", script])
        .current_dir(&host.tmp.0)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("KOH_CONFIG_DIR", host.tmp.0.join("cli_cfg"))
        .env("XDG_RUNTIME_DIR", host.tmp.0.join("crun"))
        .env("XDG_CONFIG_HOME", host.tmp.0.join("xdg_cfg"))
        .env("HOME", host.tmp.0.join("home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "test")
        .env("GIT_AUTHOR_EMAIL", "test@example.com")
        .env("GIT_COMMITTER_NAME", "test")
        .env("GIT_COMMITTER_EMAIL", "test@example.com")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out_r = child.stdout.take().unwrap();
    let mut err_r = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_r.read_to_end(&mut b);
        b
    });
    let err_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_r.read_to_end(&mut b);
        b
    });
    let status = wait_child(&mut child, 30, "box_sh");
    let (stdout, stderr) = (out_t.join().unwrap(), err_t.join().unwrap());
    assert!(
        status.success(),
        "status={status:?}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
    );
}

#[test]
fn exec_exits_when_remote_command_ends_even_with_open_stdin() {
    let host = Host::start("exec-open-stdin", &[]);
    let addr = host.addr();
    let run_open = |args: &[&str]| {
        let mut child = host
            .koh(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let _hold = child.stdin.take().unwrap();
        let mut out = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = out.read_to_end(&mut buf);
            buf
        });
        let st = wait_child(&mut child, 5, "koh with open stdin");
        (st.code(), reader.join().unwrap())
    };
    let (rc, out) = run_open(&[
        "exec",
        &host.id,
        "--direct",
        &addr,
        "--",
        "/bin/sh",
        "-c",
        "printf 'hi\\n'; exit 7",
    ]);
    assert_eq!((rc, out.as_slice()), (Some(7), b"hi\n".as_slice()));
    let awk = "BEGIN { for (i = 0; i < 4096; i++) printf \"0123456789abcdef0123456789abcdef\\n\" }";
    let (rc, out) = run_open(&["exec", &host.id, "--direct", &addr, "--", "awk", awk]);
    assert_eq!(rc, Some(0));
    assert_eq!(out, b"0123456789abcdef0123456789abcdef\n".repeat(4096));
    let (rc, out) = run_open(&[
        "rsh",
        "--direct",
        &addr,
        &host.id,
        "printf 'rsh-hi\\n'; exit 11",
    ]);
    assert_eq!((rc, out.as_slice()), (Some(11), b"rsh-hi\n".as_slice()));

    // At every open-fd limit where `koh exec` can bind, both stdout and stderr arrive
    // without needing spare descriptors to duplicate them. (At marginal limits 11-12, iroh's
    // background probes can print a socket warning to stderr, so stderr is matched by marker.)
    box_sh(
        &host,
        "found=0
         for n in 10 11 12 13 14 15 16 18 20 24 32; do
           set +e
           (ulimit -n \"$n\" 2>/dev/null && exec koh exec box -- /bin/sh -c 'printf O; printf ERRMARK >&2') >o 2>e
           rc=$?
           set -e
           if [ \"$rc\" = 0 ]; then
             found=1
             [ \"$(cat o)\" = O ]
             grep -q ERRMARK e
           fi
         done
         [ \"$found\" = 1 ]",
    );
}

#[test]
fn exec_and_rsh_handle_nonblocking_socketpair() {
    use std::net::Shutdown;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;

    let host = Host::start("nonblock-sock", &[]);
    let addr = host.addr();

    // Non-blocking stdin: send second line only after first has been echoed; wait for child first.
    let (mut peer, sock) = UnixStream::pair().unwrap();
    sock.set_nonblocking(true).unwrap();
    let mut peer_r = peer.try_clone().unwrap();
    let mut child = host
        .koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "cat; exit 37",
        ])
        .stdin(OwnedFd::from(sock.try_clone().unwrap()))
        .stdout(OwnedFd::from(sock))
        .spawn()
        .unwrap();
    let (echoed_tx, echoed_rx) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        let mut notified = false;
        while let Ok(n @ 1..) = peer_r.read(&mut buf) {
            got.extend_from_slice(&buf[..n]);
            if !notified && got.starts_with(b"hello\n") {
                notified = true;
                let _ = echoed_tx.send(());
            }
        }
        got
    });
    peer.write_all(b"hello\n").unwrap();
    echoed_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("first line was not echoed");
    peer.write_all(b"world\n").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        wait_child(&mut child, 10, "nonblock stdin").code(),
        Some(37)
    );
    assert_eq!(reader.join().unwrap(), b"hello\nworld\n");

    // Non-blocking stdout and stderr: 1.5 MiB (exceeds default Unix socket buffers) with a
    // delayed small-buffer reader arrives whole on each stream.
    let expected: Vec<u8> = (0..15000)
        .flat_map(|i| format!("{i:099}\n").into_bytes())
        .collect();
    for (to_stderr, code) in [(false, 19), (true, 17)] {
        let (mut peer, sock) = UnixStream::pair().unwrap();
        sock.set_nonblocking(true).unwrap();
        let redir = if to_stderr { " >&2" } else { "" };
        let cmd = format!(
            "awk 'BEGIN {{ for (i = 0; i < 15000; i++) printf \"%099d\\n\", i }}'{redir}; exit {code}"
        );
        let mut child_cmd = host.koh(&["rsh", "--direct", &addr, &host.id, &cmd]);
        if to_stderr {
            child_cmd.stderr(OwnedFd::from(sock));
        } else {
            child_cmd
                .stdin(OwnedFd::from(sock.try_clone().unwrap()))
                .stdout(OwnedFd::from(sock));
        }
        let mut child = child_cmd.spawn().unwrap();
        drop(child_cmd);
        peer.shutdown(Shutdown::Write).unwrap();
        let reader = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            let mut out = Vec::new();
            let mut buf = [0u8; 256];
            while let Ok(n @ 1..) = peer.read(&mut buf) {
                out.extend_from_slice(&buf[..n]);
            }
            out
        });
        let st = wait_child(&mut child, 15, "nonblock output");
        let out = reader.join().unwrap();
        assert_eq!(st.code(), Some(code));
        assert_eq!(out.len(), expected.len());
        assert_eq!(out, expected);
    }
}

#[test]
fn rsh_options_rsync_and_git() {
    let host = Host::start("rsh-e2e", &[]);
    let direct_cmd = format!(
        "koh rsh --direct {} {} printf ok >o
         [ \"$(cat o)\" = ok ]
         koh servers add -box {} --direct {}
         koh rsh -- -box printf ok >o
         [ \"$(cat o)\" = ok ]",
        host.addr(),
        host.id,
        host.id,
        host.addr(),
    );
    box_sh(
        &host,
        &format!(
            "set +e; koh rsh box 'printf out; printf err >&2; exit 9' >o 2>e; rc=$?; set -e
             [ \"$rc\" = 9 ]
             [ \"$(cat o)\" = out ]
             [ \"$(cat e)\" = err ]
             printf 'in\\n' | koh rsh box cat >o
             [ \"$(cat o)\" = in ]
             koh rsh -- box printf %s --json >o
             [ \"$(cat o)\" = --json ]
             {direct_cmd}
             for f in -G -o -l -p --json; do
               set +e; koh rsh \"$f\" box --json >o 2>e; rc=$?; set -e
               [ \"$rc\" = 2 ]
               [ ! -s o ]
               grep -Fq -- \"$f\" e
               grep -Fq 'rsh does not support' e
             done
             set +e; koh rsh nosuchhostxyz printf %s --json >o 2>e; rc=$?; set -e
             [ \"$rc\" = 2 ]
             [ ! -s o ]
             [ -s e ]
             set +e; koh rsh box >o 2>e; rc=$?; set -e
             [ \"$rc\" = 2 ]
             [ ! -s o ]
             grep -Fq usage e"
        ),
    );

    // Commands over MAX_CTRL (1 MiB) exit 2 (usage) for both rsh and exec, skipping only on E2BIG.
    let big_word = "x".repeat(130);
    for head in [&["rsh", "box"][..], &["exec", "box", "--"][..]] {
        let mut over = host.koh(head);
        for _ in 0..9000 {
            over.arg(&big_word);
        }
        match over
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
        {
            Ok(out) => {
                assert_eq!(out.status.code(), Some(2));
                assert!(out.stdout.is_empty());
                assert!(String::from_utf8_lossy(&out.stderr).contains("1048576"));
            }
            Err(e) if e.kind() == std::io::ErrorKind::ArgumentListTooLong => {}
            Err(e) => panic!("unexpected spawn error for {head:?}: {e}"),
        }
    }

    let (src, dst) = (host.tmp.0.join("src"), host.tmp.0.join("home/dst"));
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::create_dir_all(src.join("target")).unwrap();
    fs::create_dir_all(dst.join("target")).unwrap();
    let big: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
    fs::write(src.join("big.bin"), &big).unwrap();
    fs::write(src.join("sub/with space.txt"), b"spaced\n").unwrap();
    std::os::unix::fs::symlink("sub/with space.txt", src.join("link_s")).unwrap();
    fs::write(src.join("target/ignored.txt"), b"skip").unwrap();
    fs::write(dst.join("stray.txt"), b"bye").unwrap();
    fs::write(dst.join("target/keep.txt"), b"stay").unwrap();

    box_sh(
        &host,
        "tar -C src -cf - . | koh rsh box 'mkdir -p tardst && tar -C tardst -xf -'",
    );
    let tar_f = host.tmp.0.join("home/tardst/sub/with space.txt");
    assert_eq!(fs::read(tar_f).unwrap(), b"spaced\n");

    if Command::new("rsync").arg("--version").output().is_err() {
        eprintln!("skipping rsync in rsh_options_rsync_and_git: rsync not installed");
    } else {
        let sync = "rsync -a --delete --exclude target -e 'koh rsh' src/ box:dst/";
        box_sh(&host, sync);
        assert_eq!(fs::read(dst.join("big.bin")).unwrap(), big);
        assert_eq!(
            fs::read(dst.join("sub/with space.txt")).unwrap(),
            b"spaced\n"
        );
        let link = fs::read_link(dst.join("link_s")).unwrap();
        assert_eq!(link, Path::new("sub/with space.txt"));
        assert!(!dst.join("stray.txt").exists() && !dst.join("target/ignored.txt").exists());
        assert_eq!(fs::read(dst.join("target/keep.txt")).unwrap(), b"stay");

        let inos = || {
            (
                fs::metadata(dst.join("big.bin")).unwrap().ino(),
                fs::metadata(dst.join("sub/with space.txt")).unwrap().ino(),
            )
        };
        let before = inos();
        box_sh(&host, sync);
        assert_eq!(inos(), before, "second rsync rewrote unchanged files");

        box_sh(&host, "rsync -a -e 'koh rsh' box:dst/ pulled/");
        assert_eq!(fs::read(host.tmp.0.join("pulled/big.bin")).unwrap(), big);
        let p_sp = host.tmp.0.join("pulled/sub/with space.txt");
        assert_eq!(fs::read(p_sp).unwrap(), b"spaced\n");
        let p_lk = fs::read_link(host.tmp.0.join("pulled/link_s")).unwrap();
        assert_eq!(p_lk, Path::new("sub/with space.txt"));
    }

    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping git in rsh_options_rsync_and_git: git not installed");
    } else {
        box_sh(
            &host,
            "koh rsh box git init -q --bare demo.git
             mkdir work
             cd work
             git init -q
             printf 'from-git\\n' > hello.txt
             git add hello.txt
             git commit -qm init
             GIT_SSH_COMMAND='koh rsh' git push box:demo.git HEAD:refs/heads/main
             cd ..
             GIT_SSH_COMMAND='koh rsh' git clone -b main box:demo.git cloned",
        );
        let cloned = host.tmp.0.join("cloned/hello.txt");
        assert_eq!(fs::read(cloned).unwrap(), b"from-git\n");
    }
}

struct KillPid {
    path: PathBuf,
    disarmed: bool,
}

impl KillPid {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            disarmed: false,
        }
    }

    fn dead_within(&mut self, secs: u64, what: &str) {
        let pid = fs::read_to_string(&self.path)
            .unwrap_or_default()
            .trim()
            .to_string();
        assert!(!pid.is_empty(), "{what}: empty pid");
        let deadline = Instant::now() + Duration::from_secs(secs);
        while pid_running(&pid) {
            if Instant::now() >= deadline {
                panic!("{what}: pid {pid} still alive after {secs}s");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        self.disarmed = true;
    }
}

impl Drop for KillPid {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        if let Ok(pid) = fs::read_to_string(&self.path) {
            let pid = pid.trim();
            if !pid.is_empty() && pid_running(pid) {
                signal(pid, "-KILL");
            }
        }
    }
}

fn pid_running(pid: &str) -> bool {
    let out = Command::new("ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .ok();
    out.is_some_and(|o| {
        let s = String::from_utf8_lossy(&o.stdout);
        let t = s.trim();
        !t.is_empty() && !t.starts_with('Z')
    })
}

fn read_exact_bounded<const N: usize, R: std::io::Read + Send + 'static>(
    mut r: R,
    child: &mut std::process::Child,
    secs: u64,
    what: &str,
) -> ([u8; N], R) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; N];
        let res = r.read_exact(&mut buf).map(|()| (buf, r));
        let _ = tx.send(res);
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: read_exact failed: {e}");
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: read_exact timed out after {secs}s");
        }
    }
}

fn run_bounded(cmd: &mut Command, secs: u64, what: &str) -> std::process::Output {
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out_r = child.stdout.take().unwrap();
    let mut err_r = child.stderr.take().unwrap();
    let out_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out_r.read_to_end(&mut b);
        b
    });
    let err_t = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err_r.read_to_end(&mut b);
        b
    });
    let status = wait_child(&mut child, secs, what);
    std::process::Output {
        status,
        stdout: out_t.join().unwrap(),
        stderr: err_t.join().unwrap(),
    }
}

/// A minimal raw QUIC peer for tests that control the server's reply/close sequence.
struct RawExecPeer {
    tmp: TempDir,
    ep: iroh::Endpoint,
    id: String,
    addr: String,
    task: tokio::task::JoinHandle<()>,
}

impl RawExecPeer {
    async fn start<F, Fut>(tag: &'static str, mut respond: F) -> Self
    where
        F: FnMut(iroh::endpoint::Connection, SendStream, RecvStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = bool> + Send,
    {
        let tmp = TempDir::new(tag);
        fs::create_dir_all(tmp.0.join("cli_cfg")).unwrap();
        fs::create_dir_all(tmp.0.join("crun")).unwrap();
        let srv_key = load_or_create_key(Role::Server, Some(&tmp.0.join("srv.key"))).unwrap();
        let id = srv_key.public().to_string();
        let ep = koh::net::bind_server(
            srv_key,
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            true,
        )
        .await
        .unwrap();
        let addr = ep.bound_sockets()[0].to_string();
        let ep_srv = ep.clone();
        let task = tokio::spawn(async move {
            while let Some(incoming) = ep_srv.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let Ok((send, mut recv)) = conn.accept_bi().await else {
                    continue;
                };
                if koh::net::verify_client(&conn, &mut recv).await.is_err() {
                    continue;
                }
                let Ok(_): koh::Result<Request> = recv_msg(&mut recv, MAX_CTRL).await else {
                    continue;
                };
                if !respond(conn, send, recv).await {
                    break;
                }
            }
        });
        Self {
            tmp,
            ep,
            id,
            addr,
            task,
        }
    }

    fn koh(&self, target: &str, extra: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_koh"));
        cmd.args(["exec", target, "--direct", &self.addr])
            .args(extra)
            .args(["--", "true"])
            .env("KOH_CONFIG_DIR", self.tmp.0.join("cli_cfg"))
            .env("XDG_RUNTIME_DIR", self.tmp.0.join("crun"))
            .stdin(std::process::Stdio::null());
        cmd
    }

    async fn close(self) {
        self.ep.close().await;
        self.task.abort();
        let _ = self.task.await;
    }
}

#[test]
fn exec_b_simultaneous_four_mib_each_way_no_deadlock() {
    let host = Host::start("exec-b", &[]);
    let addr = host.addr();
    let n = 4 * 1024 * 1024;
    let sent_in: Vec<u8> = (0..n).map(|i| ((i * 31 + 17) % 256) as u8).collect();
    let sent_out: Vec<u8> = (0..n).map(|i| ((i * 131 + 7) % 256) as u8).collect();
    let out_file = host.tmp.0.join("out.bin");
    let in_file = host.tmp.0.join("in.bin");
    fs::write(&out_file, &sent_out).unwrap();
    let out_arg = out_file.display().to_string();
    let in_arg = in_file.display().to_string();

    // Remote writes 4 MiB stdout BEFORE reading 4 MiB stdin; client writes stdin while reading stdout.
    let mut child = host
        .koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "cat \"$1\"; cat > \"$2\"",
            "_",
            &out_arg,
            &in_arg,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin_pipe = child.stdin.take().unwrap();
    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let expected_in = sent_in.clone();
    let writer = std::thread::spawn(move || {
        let _ = stdin_pipe.write_all(&sent_in);
    });
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(n);
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let st = wait_child(&mut child, 15, "4 MiB bidirectional exec");
    let _ = writer.join();
    let got_out = reader.join().unwrap();
    let got_err = err_reader.join().unwrap();
    assert!(
        st.success(),
        "expected exit 0, got {st:?}; stderr={}",
        String::from_utf8_lossy(&got_err)
    );
    assert_eq!(got_out.len(), sent_out.len(), "stdout byte count");
    assert!(got_out == sent_out, "stdout bytes mismatch");
    let got_in = fs::read(&in_file).unwrap();
    assert_eq!(got_in.len(), expected_in.len(), "stdin byte count");
    assert!(got_in == expected_in, "stdin bytes mismatch");
}

#[test]
fn exec_c_broken_stdout_pipe_returns_141_and_hangs_up_producer() {
    let host = Host::start("exec-c", &[]);
    let addr = host.addr();
    let pid_file = host.tmp.0.join("yes.pid");
    let mut guard = KillPid::new(pid_file.clone());
    let pid_arg = pid_file.display().to_string();

    let mut child = host
        .koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exec yes",
            "_",
            &pid_arg,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let (head, stdout) =
        read_exact_bounded::<2, _>(child.stdout.take().unwrap(), &mut child, 10, "exec-c y");
    assert_eq!(&head, b"y\n");
    drop(stdout);

    let st = wait_child(&mut child, 10, "koh exec with closed stdout pipe");
    guard.dead_within(10, "remote yes after stdout EPIPE");
    assert_eq!(
        st.code(),
        Some(141),
        "expected 141 on stdout EPIPE, got {st:?}"
    );
}

#[tokio::test]
async fn exec_d_link_lost_after_start_exits_255_not_3() {
    let (drop_tx, drop_rx) = tokio::sync::oneshot::channel::<()>();
    let drop_rx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(drop_rx)));
    let peer = RawExecPeer::start("exec-d", move |conn, mut send, _recv| {
        let drop_rx = drop_rx.clone();
        async move {
            let _ = send_msg(&mut send, &koh::proto::Reply::Ok, MAX_CTRL).await;
            let _ = send_msg(
                &mut send,
                &koh::proto::ExecServerMsg::Stdout(b"started\n".to_vec()),
                MAX_CHUNK,
            )
            .await;
            if let Some(rx) = drop_rx.lock().await.take() {
                let _ = rx.await;
            }
            conn.close(0u32.into(), b"lost");
            false
        }
    })
    .await;

    // (d1) Server that is never reached (Client::connect fails) still exits 3.
    let wrong_id = load_or_create_key(Role::Server, Some(&peer.tmp.0.join("wrong.key")))
        .unwrap()
        .public()
        .to_string();
    let mut unreach = peer.koh(&wrong_id, &["--relay-url", "http://127.0.0.1:1"]);
    let unreach_out =
        tokio::task::spawn_blocking(move || run_bounded(&mut unreach, 10, "unreachable exec"))
            .await
            .unwrap();
    assert_eq!(
        unreach_out.status.code(),
        Some(3),
        "expected 3 when server never reached, got {:?}; stderr={}",
        unreach_out.status,
        String::from_utf8_lossy(&unreach_out.stderr)
    );

    // (d2) Link lost after Reply::Ok and output exits 255 (not 3), preserving received stdout.
    let mut child = peer
        .koh(&peer.id, &[])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let out_r = child.stdout.take().unwrap();
    let (mut child, got_started, _out_r) = tokio::task::spawn_blocking(move || {
        let (buf, out_r) = read_exact_bounded::<8, _>(out_r, &mut child, 10, "exec-d started");
        (child, buf, out_r)
    })
    .await
    .unwrap();
    assert_eq!(&got_started, b"started\n");
    let _ = drop_tx.send(());
    let (st, stderr) = tokio::task::spawn_blocking(move || {
        let st = wait_child(&mut child, 10, "exec-d lost link");
        let mut err = Vec::new();
        let _ = child.stderr.take().unwrap().read_to_end(&mut err);
        (st, err)
    })
    .await
    .unwrap();
    peer.close().await;
    assert_eq!(
        st.code(),
        Some(255),
        "expected 255 on lost link after start, got {st:?}; stderr={}",
        String::from_utf8_lossy(&stderr)
    );
}

#[test]
fn exec_e_stdout_write_error_exits_1_not_0() {
    let host = Host::start("exec-e", &[]);
    let addr = host.addr();
    let out_file = host.tmp.0.join("zero-limit.out");

    // Portable non-EPIPE stdout write failure (EFBIG on both Linux and macOS):
    // ignore SIGXFSZ and cap file size at 0 blocks so writing to stdout returns EFBIG.
    let mut cmd = Command::new("/bin/sh");
    cmd.args([
        "-c",
        "trap '' XFSZ; ulimit -f 0; exec \"$1\" exec \"$2\" --direct \"$3\" -- printf 'hello\\n' > \"$4\"",
        "_",
        env!("CARGO_BIN_EXE_koh"),
        &host.id,
        &addr,
        &out_file.display().to_string(),
    ])
    .env("KOH_CONFIG_DIR", host.tmp.0.join("cli_cfg"))
    .env("XDG_RUNTIME_DIR", host.tmp.0.join("crun"))
    .env("HOME", host.tmp.0.join("home"))
    .stdin(std::process::Stdio::null());
    let out = run_bounded(&mut cmd, 10, "koh exec with EFBIG stdout");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "expected exit 1 on stdout EFBIG, got {:?}; stderr={stderr}",
        out.status
    );
    assert!(
        stderr.contains("write:"),
        "expected write error on stderr, got {stderr:?}"
    );
}

#[test]
fn exec_f_sh_and_rsh_handle_leading_dash_command() {
    let host = Host::start("exec-f", &[]);
    let addr = host.addr();
    let cases = [
        (
            vec![
                "exec",
                &host.id,
                "--direct",
                &addr,
                "--sh",
                "-nosuchcmd 2>/dev/null; echo sh-dash-ok",
            ],
            "sh-dash-ok\n",
            "exec --sh leading dash",
        ),
        (
            vec![
                "rsh",
                "--direct",
                &addr,
                &host.id,
                "-nosuchcmd 2>/dev/null; echo rsh-dash-ok",
            ],
            "rsh-dash-ok\n",
            "rsh leading dash",
        ),
    ];
    for (args, expected, what) in cases {
        let out = run_bounded(&mut host.koh(&args), 10, what);
        assert!(
            out.status.success(),
            "{what} failed: {:?}; stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
    }
}

#[tokio::test]
async fn exec_g_stream_eof_without_exit_status_exits_255_not_0() {
    let peer = RawExecPeer::start("exec-g", |_conn, mut send, _recv| async move {
        let _ = send_msg(&mut send, &koh::proto::Reply::Ok, MAX_CTRL).await;
        let _ = send_msg(
            &mut send,
            &koh::proto::ExecServerMsg::Stdout(b"partial\n".to_vec()),
            MAX_CHUNK,
        )
        .await;
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(10), send.stopped()).await;
        false
    })
    .await;
    let mut cmd = peer.koh(&peer.id, &[]);
    let out = tokio::task::spawn_blocking(move || run_bounded(&mut cmd, 10, "exec-g"))
        .await
        .unwrap();
    peer.close().await;
    assert_eq!(
        out.status.code(),
        Some(255),
        "expected 255 on stream EOF without Exit, got {:?}; stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"partial\n");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no exit status came"),
        "expected missing-status stderr, got {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn exec_hangup_kills_hup_ignoring_group_member() {
    let host = Host::start("exec-group-member", &[]);
    let addr = host.addr();
    let pid_file = host.tmp.0.join("worker.pid");
    let mut guard = KillPid::new(pid_file.clone());
    let pid_arg = pid_file.display().to_string();

    // Leader dies on SIGHUP while its same-group worker ignores SIGHUP; SIGKILL must still kill it.
    let mut child = host
        .koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "cat >/dev/null; (trap '' HUP; echo READY; exec sleep 301) & echo $! > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; wait",
            "_",
            &pid_arg,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (ready, _out) = read_exact_bounded::<6, _>(
        child.stdout.take().unwrap(),
        &mut child,
        10,
        "group member READY",
    );
    assert_eq!(&ready, b"READY\n");
    until("worker pid written", || pid_file.is_file());

    signal(&child.id().to_string(), "-TERM");
    let st = wait_child(&mut child, 10, "koh exec on SIGTERM (group member)");
    assert_eq!(st.code(), Some(143), "expected 143, got {st:?}");
    guard.dead_within(10, "HUP-ignoring group member");
}

#[test]
fn exec_signal_exits_while_stdout_pipe_is_blocked() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    let host = Host::start("exec-sig-blocked", &[]);
    let addr = host.addr();
    let usr1 = tokio::signal::unix::SignalKind::user_defined1().as_raw_value();

    for nonblocking in [false, true] {
        let tag = if nonblocking { "nonblock" } else { "blocking" };
        let pid_file = host.tmp.0.join(format!("yes-{tag}.pid"));
        let mut guard = KillPid::new(pid_file.clone());
        let pid_arg = pid_file.display().to_string();

        let mut cmd = host.koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exec yes",
            "_",
            &pid_arg,
        ]);
        cmd.stderr(std::process::Stdio::piped());
        let (mut child, reader_box): (std::process::Child, Box<dyn std::io::Read + Send>) =
            if nonblocking {
                let (peer, sock) = UnixStream::pair().unwrap();
                sock.set_nonblocking(true).unwrap();
                cmd.stdout(OwnedFd::from(sock));
                let child = cmd.spawn().unwrap();
                drop(cmd);
                (child, Box::new(peer))
            } else {
                cmd.stdout(std::process::Stdio::piped());
                let mut child = cmd.spawn().unwrap();
                let out = child.stdout.take().unwrap();
                (child, Box::new(out))
            };

        // Read 1 byte, keep read end open without draining so write_wait blocks on full pipe.
        let (one, mut reader_box) = read_exact_bounded::<1, _>(
            reader_box,
            &mut child,
            10,
            &format!("sig-blocked first byte ({tag})"),
        );
        assert_eq!(&one, b"y");
        std::thread::sleep(Duration::from_millis(500));

        signal(&child.id().to_string(), "-USR1");
        let st = wait_child(&mut child, 10, &format!("koh exec USR1 blocked ({tag})"));
        assert_eq!(
            st.code(),
            Some(128 + usr1),
            "expected 128+USR1={} ({tag}), got {st:?}",
            128 + usr1
        );
        let mut got = one.to_vec();
        let _ = reader_box.read_to_end(&mut got);
        assert!(
            got.iter().enumerate().all(|(i, &b)| b == b"y\n"[i % 2]),
            "captured bytes ({tag}) are not a prefix of `y\\n` repeated (len={})",
            got.len()
        );
        guard.dead_within(10, &format!("remote yes ({tag})"));
    }
}

#[tokio::test]
async fn exec_signal_before_reply_ok_closes_link() {
    let (got_req_tx, got_req_rx) = tokio::sync::oneshot::channel();
    let (stopped_tx, stopped_rx) = tokio::sync::oneshot::channel();
    let got_req_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(got_req_tx)));
    let stopped_tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(stopped_tx)));
    let peer = RawExecPeer::start("exec-sig-pre-ok", move |_conn, send, _recv| {
        let got_req_tx = got_req_tx.clone();
        let stopped_tx = stopped_tx.clone();
        async move {
            if let Some(tx) = got_req_tx.lock().await.take() {
                let _ = tx.send(());
            }
            // Hold Reply::Ok back; expect the client's SIGTERM to close the link promptly.
            let saw_stop = tokio::time::timeout(Duration::from_secs(10), send.stopped())
                .await
                .is_ok();
            if let Some(tx) = stopped_tx.lock().await.take() {
                let _ = tx.send(saw_stop);
            }
            false
        }
    })
    .await;

    let mut child = peer
        .koh(&peer.id, &[])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    tokio::time::timeout(Duration::from_secs(10), got_req_rx)
        .await
        .expect("server did not receive Request::Exec")
        .unwrap();
    signal(&child.id().to_string(), "-TERM");
    let st =
        tokio::task::spawn_blocking(move || wait_child(&mut child, 10, "koh exec pre-Ok TERM"))
            .await
            .unwrap();
    let saw_stop = tokio::time::timeout(Duration::from_secs(10), stopped_rx)
        .await
        .expect("server task timed out")
        .unwrap();
    peer.close().await;
    assert_eq!(
        st.code(),
        Some(143),
        "expected 143 on pre-Ok SIGTERM, got {st:?}"
    );
    assert!(
        saw_stop,
        "server did not observe link close on pre-Ok SIGTERM"
    );
}

#[test]
fn exec_stdin_closed_early_does_not_hang_sender() {
    let host = Host::start("exec-early-stdin", &[]);
    let addr = host.addr();

    // Remote closes stdin early while client still sends 64 MiB: no hang, stdout arrives, exit 0.
    let mut child = host
        .koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "exec 0<&-; sleep 1; echo done",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin_pipe = child.stdin.take().unwrap();
    let mut stdout_pipe = child.stdout.take().unwrap();
    let writer = std::thread::spawn(move || {
        let block = vec![0u8; 64 << 10];
        for _ in 0..1024 {
            if stdin_pipe.write_all(&block).is_err() {
                break;
            }
        }
    });
    let reader = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut b);
        b
    });
    let st = wait_child(&mut child, 10, "early stdin close with 64 MiB sender");
    let _ = writer.join();
    assert!(st.success(), "expected exit 0, got {st:?}");
    assert_eq!(reader.join().unwrap(), b"done\n");
}

#[test]
fn exec_serve_shutdown_with_hup_ignoring_exec_and_live_session() {
    let mut host = Host::start("exec-srv-shut", &[]);
    let addr = host.addr();

    // Start a live `koh connect` session alongside a HUP-ignoring `koh exec` with /dev/null stdin.
    let mut tty = host.attach(&[], &sh("echo SESSION_UP; exec sleep 60"));
    tty.until("session is up", |t| {
        t.drawn.windows(10).any(|w| w == b"SESSION_UP")
    });

    let pid_file = host.tmp.0.join("hup-exec.pid");
    let mut guard = KillPid::new(pid_file.clone());
    let pid_arg = pid_file.display().to_string();
    let mut exec_child = host
        .koh(&[
            "exec",
            &host.id,
            "--direct",
            &addr,
            "--",
            "/bin/sh",
            "-c",
            "trap '' HUP; echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; echo READY; exec sleep 600",
            "_",
            &pid_arg,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (ready, _out) = read_exact_bounded::<6, _>(
        exec_child.stdout.take().unwrap(),
        &mut exec_child,
        10,
        "serve shutdown READY",
    );
    assert_eq!(&ready, b"READY\n");

    // SIGTERM to `koh serve`: must finish within 8 s and kill the HUP-ignoring exec command.
    let t0 = Instant::now();
    host.stop_by("-TERM");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(8),
        "koh serve shutdown took {elapsed:?} (>= 8 s)"
    );
    let st = wait_child(&mut exec_child, 10, "koh exec on serve SIGTERM");
    assert_eq!(st.code(), Some(255), "expected 255, got {st:?}");
    guard.dead_within(10, "HUP-ignoring exec after serve SIGTERM");
    tty.types(b"\x1d.");
    let _ = tty.ends();
}

fn job_cmd(host: &Host, sub: &str, args: &[&str], secs: u64) -> std::process::Output {
    let addr = host.addr();
    let mut full = vec![sub, &host.id, "--direct", &addr];
    full.extend_from_slice(args);
    run_bounded(&mut host.koh(&full), secs, sub)
}

#[test]
fn job_survives_serve_kill_and_restart() {
    let mut host = Host::start("job-restart", &[]);
    let addr = host.addr();
    let go = host.tmp.0.join("go");
    let go_arg = go.display().to_string();

    assert!(
        job_cmd(
            &host,
            "run",
            &[
                "--name",
                "persist",
                "--",
                "/bin/sh",
                "-c",
                "echo before; while [ ! -f \"$1\" ]; do sleep 0.05; done; echo after; exit 7",
                "_",
                &go_arg,
            ],
            10,
        )
        .status
        .success()
    );

    // Kill `koh serve` outright and start it again on the same key and state directory.
    host.stop_by("-KILL");
    host.serve();

    // Start `logs -f` from a fresh client while the job is still running, then release it.
    let mut follow = host
        .koh(&[
            "logs", &host.id, "--direct", &addr, "persist", "--all", "--follow",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (first, mut follow_out) = read_exact_bounded::<7, _>(
        follow.stdout.take().unwrap(),
        &mut follow,
        10,
        "logs -f before after restart",
    );
    assert_eq!(&first, b"before\n");
    fs::write(&go, b"go\n").unwrap();

    let mut rest = Vec::new();
    let f_st = wait_child(&mut follow, 10, "koh logs -f after restart");
    let _ = follow_out.read_to_end(&mut rest);
    assert_eq!(f_st.code(), Some(7));
    assert_eq!(
        [first.as_slice(), rest.as_slice()].concat(),
        b"before\nafter\n"
    );

    let waited = job_cmd(&host, "wait", &["persist", "--tail", "10"], 10);
    assert_eq!(waited.status.code(), Some(7));
    assert_eq!(waited.stdout, b"before\nafter\n");
}

#[test]
fn job_multi_megabyte_log_streams_exact_content() {
    let host = Host::start("job-multimb", &[]);
    // ~3.39 MiB (>50 64 KiB chunks) of unique numbered lines: any dropped, duplicated, or
    // reordered chunk fails the content check without starving neighbour tests on CI.
    let expected: String = (1..=500_000).map(|n| format!("{n}\n")).collect();

    assert!(
        job_cmd(
            &host,
            "run",
            &["--name", "seqlog", "--", "seq", "1", "500000"],
            10
        )
        .status
        .success()
    );
    assert!(
        job_cmd(&host, "wait", &["seqlog", "--timeout", "20"], 25)
            .status
            .success()
    );
    let whole = job_cmd(&host, "logs", &["seqlog", "--all"], 25);
    assert!(whole.status.success());
    assert!(
        whole.stdout == expected.as_bytes(),
        "streamed log content mismatch"
    );
}

#[test]
fn jobs_lists_a_line_a_job_the_command_last() {
    let host = Host::start("job-list", &[]);
    let args = ["--name", "tabbed", "--", "sh", "-c", "exit 3", "a\tb"];
    assert_eq!(job_cmd(&host, "run", &args, 10).stdout, b"tabbed\n");
    let waited = job_cmd(&host, "wait", &["tabbed", "--timeout", "10"], 15);
    assert_eq!(waited.status.code(), Some(3));
    // Name, state, age and the command, the rest of the line: a tab in it is shown as `?`,
    // as fux writes it, and as koh prints it when the folder's `status` has one.
    let status = host
        .sessions
        .parent()
        .unwrap()
        .join("koh-jobs/tabbed/status");
    for written in ["a?b", "a\tb"] {
        let was = fs::read_to_string(&status).unwrap();
        assert!(was.contains("command sh -c exit 3 a?b\n"), "{was:?}");
        fs::write(&status, was.replace("a?b", written)).unwrap();
        let listed = String::from_utf8(job_cmd(&host, "jobs", &[], 10).stdout).unwrap();
        let fields: Vec<&str> = listed.strip_suffix('\n').unwrap().split('\t').collect();
        let [name, state, age, command] = fields[..] else {
            panic!("{listed:?}")
        };
        assert_eq!(
            (name, state, command),
            ("tabbed", "exited 3", "sh -c exit 3 a?b")
        );
        let secs = age.strip_suffix('s').map(str::parse::<u64>);
        assert!(secs.is_some_and(|n| n.is_ok()), "{age}");
    }
}

#[test]
fn job_kill_ctl_default_invalid_and_ended() {
    let host = Host::start("job-kill-ctl", &[]);

    assert!(
        job_cmd(&host, "run", &["--name", "dflt", "--", "sleep", "60"], 10)
            .status
            .success()
    );
    assert!(job_cmd(&host, "kill", &["dflt"], 10).status.success());
    assert_eq!(
        job_cmd(&host, "wait", &["dflt", "--timeout", "10"], 15)
            .status
            .code(),
        Some(143)
    );

    // Signal 0 (outside what ctl takes) is a usage error (exit 2).
    assert_eq!(
        job_cmd(&host, "kill", &["dflt", "--signal", "0"], 10)
            .status
            .code(),
        Some(2)
    );

    // Killing an already-ended job exits 0 and says so on stderr.
    let ended = job_cmd(&host, "kill", &["dflt"], 10);
    assert!(ended.status.success());
    assert!(String::from_utf8_lossy(&ended.stderr).contains("not running"));
}

#[test]
fn job_leader_exit_hangs_up_group_child() {
    let host = Host::start("job-child-hup", &[]);
    let pid_file = host.tmp.0.join("straggler.pid");
    let mut guard = KillPid::new(pid_file.clone());
    let pid_arg = pid_file.display().to_string();

    assert!(
        job_cmd(
            &host,
            "run",
            &[
                "--name",
                "spawner",
                "--",
                "/bin/sh",
                "-c",
                "sleep 60 & echo $! > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; echo done",
                "_",
                &pid_arg,
            ],
            10,
        )
        .status
        .success()
    );
    let waited = job_cmd(&host, "wait", &["spawner", "--timeout", "10"], 15);
    assert!(waited.status.success() && waited.stdout == b"done\n");
    guard.dead_within(5, "straggler child left by job leader");
}

#[test]
fn job_reader_never_mixes_replacement_run() {
    let host = Host::start("job-replace-race", &[]);
    let addr = host.addr();
    let jobs_dir = host.sessions.parent().unwrap().join("koh-jobs");

    for (name, msg) in [("rep", "OLD_RUN"), ("rep_new", "NEW_RUN")] {
        let script = format!("printf '{msg}\\n'; sleep 30");
        assert!(
            job_cmd(
                &host,
                "run",
                &["--name", name, "--", "/bin/sh", "-c", &script],
                10
            )
            .status
            .success()
        );
        let out = jobs_dir.join(name).join("out");
        until("marker written", || {
            fs::read(&out)
                .unwrap_or_default()
                .starts_with(msg.as_bytes())
        });
    }

    // Start `wait` first, then `logs -f` and wait until `OLD_RUN\n` arrives (synchronizing on
    // server acceptance without a fixed sleep) before killing `rep` and swapping `rep_new` in.
    let mut waiter = host
        .koh(&[
            "wait",
            &host.id,
            "--direct",
            &addr,
            "rep",
            "--tail",
            "5",
            "--timeout",
            "2",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut follower = host
        .koh(&["logs", &host.id, "--direct", &addr, "rep", "-f"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (seen, mut f_stdout_pipe) = read_exact_bounded::<8, _>(
        follower.stdout.take().unwrap(),
        &mut follower,
        10,
        "OLD_RUN",
    );
    assert_eq!(&seen, b"OLD_RUN\n");

    let pane = jobs_dir.join("rep");
    if let Ok(mut ctl) = fuxix::open_fifo(pane.join("ctl")) {
        let _ = ctl.write_all(b"kill 9\n");
    }
    until("old rep holder dropped lock", || {
        !matches!(
            fuxix::open(&pane, false).map(|f| f.try_lock_shared()),
            Ok(Err(fs::TryLockError::WouldBlock))
        )
    });
    fs::remove_dir_all(&pane).unwrap();
    fs::rename(jobs_dir.join("rep_new"), &pane).unwrap();

    let f_st = wait_child(&mut follower, 10, "follower after replace");
    let mut f_rest = Vec::new();
    let _ = f_stdout_pipe.read_to_end(&mut f_rest);
    let f_out = follower.wait_with_output().unwrap();
    let w_st = wait_child(&mut waiter, 10, "waiter after replace");
    let w_out = waiter.wait_with_output().unwrap();
    let (f_stdout, f_stderr) = (
        String::from_utf8_lossy(&f_rest),
        String::from_utf8_lossy(&f_out.stderr),
    );
    let (w_stdout, w_stderr) = (
        String::from_utf8_lossy(&w_out.stdout),
        String::from_utf8_lossy(&w_out.stderr),
    );

    let ok_old = |code: Option<i32>, err: &str| {
        !err.contains("running")
            && ((code == Some(1) && err.contains("started anew")) || code == Some(137))
    };
    assert!(
        !f_stdout.contains("NEW_RUN") && ok_old(f_st.code(), &f_stderr),
        "follower mixed replacement: status={f_st:?} stdout={f_stdout:?} stderr={f_stderr:?}"
    );
    let waiter_ok = (w_stdout.contains("OLD_RUN")
        && !w_stdout.contains("NEW_RUN")
        && ok_old(w_st.code(), &w_stderr))
        || (w_st.code() == Some(127) && w_stdout.is_empty())
        || (w_stdout.contains("NEW_RUN")
            && !w_stdout.contains("OLD_RUN")
            && w_st.code() == Some(124)
            && w_stderr.contains("timed out"));
    assert!(
        waiter_ok,
        "waiter mixed replacement: status={w_st:?} stdout={w_stdout:?} stderr={w_stderr:?}"
    );
}

#[test]
fn job_logs_broken_pipe_and_non_utf8_wait_tail() {
    let host = Host::start("job-io-edge", &[]);
    let addr = host.addr();

    // 1. `logs -f` piped to a consumer that reads 1 byte and closes its pipe ends with 141.
    assert!(
        job_cmd(
            &host,
            "run",
            &[
                "--name",
                "chatter",
                "--",
                "/bin/sh",
                "-c",
                "i=0; while [ $i -lt 500 ]; do printf 'LINE-%04d\\n' $i; sleep 0.02; i=$((i+1)); done",
            ],
            10,
        )
        .status
        .success()
    );
    let mut follow = host
        .koh(&["logs", &host.id, "--direct", &addr, "chatter", "-f"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (byte, stdout) =
        read_exact_bounded::<1, _>(follow.stdout.take().unwrap(), &mut follow, 10, "first byte");
    assert_eq!(&byte, b"L");
    drop(stdout);
    assert_eq!(
        wait_child(&mut follow, 10, "logs -f after closed stdout pipe").code(),
        Some(141)
    );
    let _ = job_cmd(&host, "kill", &["chatter", "--signal", "9"], 10);

    // 2. Non-UTF-8 output (~3 MiB of 0xff, expanding to ~9 MiB > MAX_FRAME if uncapped) still
    // delivers the job's real exit status (7) on `wait --tail 1`.
    assert!(
        job_cmd(
            &host,
            "run",
            &[
                "--name",
                "binff",
                "--",
                "/bin/sh",
                "-c",
                "dd if=/dev/zero bs=1048576 count=3 2>/dev/null | tr '\\000' '\\377'; exit 7",
            ],
            15,
        )
        .status
        .success()
    );
    assert_eq!(
        job_cmd(
            &host,
            "wait",
            &["binff", "--tail", "1", "--timeout", "20"],
            25
        )
        .status
        .code(),
        Some(7)
    );
}

#[test]
fn job_run_name_lifecycle_and_start_errors() {
    let host = Host::start("job-lifecycle", &[]);

    // Running name is refused; once ended, the same name is replaced cleanly.
    assert!(
        job_cmd(&host, "run", &["--name", "dup", "--", "sleep", "30"], 10)
            .status
            .success()
    );
    let refused = job_cmd(&host, "run", &["--name", "dup", "--", "true"], 10);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("already running"));

    assert!(
        job_cmd(&host, "kill", &["dup", "--signal", "9"], 10)
            .status
            .success()
    );
    let _ = job_cmd(&host, "wait", &["dup", "--timeout", "10"], 15);
    assert!(
        job_cmd(&host, "run", &["--name", "dup", "--", "echo", "second"], 10)
            .status
            .success()
    );
    let w = job_cmd(&host, "wait", &["dup", "--timeout", "10"], 15);
    assert!(w.status.success() && w.stdout == b"second\n");

    // Missing executable -> exit 127 (no folder left behind); missing cwd -> exit 126.
    assert_eq!(
        job_cmd(
            &host,
            "run",
            &["--name", "nf", "--", "/no/such/koh-job-prog"],
            10
        )
        .status
        .code(),
        Some(127)
    );
    assert!(!host.sessions.parent().unwrap().join("koh-jobs/nf").exists());
    assert_eq!(
        job_cmd(
            &host,
            "run",
            &["-C", "/no/such/koh-job-dir", "--name", "nc", "--", "true"],
            10,
        )
        .status
        .code(),
        Some(126)
    );
}

#[test]
fn job_logs_follow_ends_when_leftover_child_keeps_writing() {
    let host = Host::start("job-follow-leftover", &[]);
    let addr = host.addr();
    let pid_file = host.tmp.0.join("yes.pid");
    let _guard = KillPid::new(pid_file.clone());
    let pid_arg = pid_file.display().to_string();

    // Leader spawns a HUP-ignoring `yes` that keeps appending to `out`, then exits 3.
    // `logs -f --tail 10` must observe the leader's exit and end with 3 instead of hanging.
    assert!(
        job_cmd(
            &host,
            "run",
            &[
                "--name",
                "noisy",
                "--",
                "/bin/sh",
                "-c",
                "trap '' HUP; yes & echo $! > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exit 3",
                "_",
                &pid_arg,
            ],
            10,
        )
        .status
        .success()
    );
    until("yes pid written", || pid_file.is_file());

    let mut follow = host
        .koh(&[
            "logs", &host.id, "--direct", &addr, "noisy", "--tail", "10", "-f",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = follow.stdout.take().unwrap();
    let drainer = std::thread::spawn(move || {
        let mut buf = [0u8; 64 << 10];
        let mut n = 0usize;
        while let Ok(k @ 1..) = out.read(&mut buf) {
            n += k;
        }
        n
    });
    let st = wait_child(&mut follow, 10, "logs -f with noisy leftover child");
    assert!(drainer.join().unwrap() > 0);
    assert_eq!(st.code(), Some(3));
}
