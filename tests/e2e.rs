//! End-to-end integration tests over real loopback iroh QUIC connections.
// (A test reads files of its own making.)
#![allow(clippy::disallowed_methods)]

use std::fs;
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

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
        let (srv, route) = boot_server(&tmp, vec![friend.public()], more)
            .await
            .unwrap();
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

    /// Waits `secs` until the friend is served, asking again for as long as the server is busy.
    async fn served(&self, secs: u64) {
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
        let served = tokio::time::timeout(Duration::from_secs(secs), serving).await;
        served.expect("a place came back in time");
    }

    async fn shut(self) {
        self.srv.shutdown().await;
    }
}

#[test]
fn exec_keeps_binary_stdout_and_stderr_apart_and_a_line_with_a_leading_dash_is_a_command() {
    let host = Host::start("exec", &[]);
    let (id, addr) = (host.id.as_str(), host.addr());
    let script = "printf 'out\\000line\\n'; printf 'errline\\n' >&2; exit 42";
    let args = ["exec", id, "--direct", &addr, "-C", "/tmp", "--sh", script];
    let out = run_bounded(&mut host.koh(&args), 20, "exec");
    let printed = (b"out\0line\n".to_vec(), b"errline\n".to_vec());
    assert_eq!(
        (out.status.code(), (out.stdout, out.stderr)),
        (Some(42), printed)
    );
    // `exec --sh` and `rsh` run a line that begins with `-` as `/bin/sh -c -- LINE`.
    let line = "-nosuchcmd 2>/dev/null; echo dash-ok";
    let exec = ["exec", id, "--direct", &addr, "--sh", line];
    let rsh = ["rsh", "--direct", &addr, id, line];
    for args in [&exec[..], &rsh[..]] {
        let out = run_bounded(&mut host.koh(args), 20, args[0]);
        assert_eq!(
            (out.status.code(), out.stdout),
            (Some(0), b"dash-ok\n".to_vec()),
            "{args:?}"
        );
    }
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
    let info = client.run_job(None, sh("true"), cwd()).await.unwrap();
    assert_eq!(info.name, "2", "with 1 there");
    let timed = client.wait_job("1".into(), 10, Some(1)).await.unwrap();
    assert_eq!((timed.exit, timed.detail.as_str()), (124, "timed out"));
    let jobs = client.jobs(None).await.unwrap();
    let names: Vec<&str> = jobs.iter().map(|job| job.name.as_str()).collect();
    assert_eq!(names, ["long", "1", "2"]);

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
    koh: Child,
    /// The terminal's end here, until it is closed.
    master: Option<fs::File>,
    drawn: Vec<u8>,
    /// Whether it says what it is when it is asked, as every terminal does (once: koh asks once).
    answers: bool,
}

impl Drop for InTerminal {
    fn drop(&mut self) {
        let _ = self.koh.kill();
        // (The terminal goes first: on macOS a koh killed is not gone while what it wrote waits.)
        drop(self.master.take());
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
            master: Some(tty),
            drawn: Vec::new(),
            answers: true,
        }
    }

    fn tty(&self) -> &fs::File {
        self.master.as_ref().unwrap()
    }

    /// Waits until a terminal takes no more of what its program writes (its `slave` end is not
    /// writable), 20 s at most.
    fn takes_no_more(slave: &fs::File) {
        use std::os::fd::AsFd as _;
        let full = || fuxix::wait([(Some(slave.as_fd()), fuxix::POLLOUT)], 0);
        until("the terminal takes no more", || matches!(full(), Ok([0])));
    }

    /// Waits until `done` says so, reading meanwhile what koh draws (a terminal nobody reads
    /// holds its program up). Twenty seconds is the most any of it may take.
    fn until(&mut self, what: &str, mut done: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let mut some = [0u8; 4096];
            while let Some(Ok(n @ 1..)) = self.master.as_ref().map(|mut tty| tty.read(&mut some)) {
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
            match self.tty().write(&keys[typed..]) {
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

    /// Tells koh to end `how`, and gives the code it ended with: soon, in two seconds. (koh's
    /// own are 250 ms for its terminal and 500 ms for its server; a loaded runner needs the rest.)
    fn told(&mut self, how: &str) -> Option<i32> {
        let told = Instant::now();
        signal(&self.koh.id().to_string(), how);
        loop {
            let ended = self.koh.try_wait().unwrap();
            assert!(
                told.elapsed() < Duration::from_secs(2),
                "{how}: still there"
            );
            if let Some(ended) = ended {
                return ended.code();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
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
fn cli_keys_peer_lists_and_usage_errors() {
    let tmp = TempDir::new("cli");
    let (code, id, _) = koh(&tmp.0, &["id"]);
    assert_eq!((code, id.len()), (Some(0), 64));
    let add = ["servers", "add", "box", &id, "--direct", "127.0.0.1:4433"];
    assert_eq!(koh(&tmp.0, &add).0, Some(0));
    // A word more than `rm NAME` is a usage error, and nothing is removed.
    assert_eq!(koh(&tmp.0, &["servers", "rm", "box", "extra"]).0, Some(2));
    assert!(koh(&tmp.0, &["servers"]).1.contains("box "));
    assert_eq!(koh(&tmp.0, &["servers", "rm", "box"]).0, Some(0));
    assert!(!koh(&tmp.0, &["servers"]).1.contains("box "));
    // So is a wait for a job and a session at once (what is a job's alone is not said of a
    // session), a cap of `koh serve` out of its range, and an argument that is no UTF-8.
    for more in [&["build"][..], &["--tail", "5"]] {
        let args = [&["wait", "nowhere", "--session", "s"], more].concat();
        assert_eq!(koh(&tmp.0, &args).0, Some(2), "{more:?}");
    }
    let caps = [
        ("--max-connections", "18446744073709551615"),
        ("--max-sessions", "65536"),
        ("--max-sessions", "many"),
    ];
    for (flag, value) in caps {
        // (And a flag that is none after it: a cap taken is no server that runs on.)
        let (code, _, said) = koh(&tmp.0, &["serve", "--no-relay", flag, value, "--none"]);
        assert!(
            code == Some(2) && said.contains(flag) && said.contains("1 to 65535"),
            "{said}"
        );
    }
    // (Nothing was started for them: not even the key.)
    assert!(!tmp.0.join("server.key").exists());
    use std::os::unix::ffi::OsStrExt as _;
    let not_utf8 = Command::new(env!("CARGO_BIN_EXE_koh"))
        .arg(std::ffi::OsStr::from_bytes(b"\xff"))
        .output();
    assert_eq!(not_utf8.unwrap().status.code(), Some(2));
}

#[tokio::test]
async fn a_second_server_on_one_key_is_refused_until_the_first_stops() {
    let tmp = TempDir::new("serve-lock");
    let on_the_key = || boot_server(&tmp, Vec::new(), ServeOptions::default());
    let (first, _) = on_the_key().await.unwrap();
    let refused = on_the_key().await.err().unwrap();
    assert_eq!(refused.code, Exit::BUSY, "{refused:?}");
    assert!(refused.message.contains("server.key"), "{refused:?}");
    // The first stopped: the key is free (what marks it held is a lock, not a file's being
    // there: a server that was killed leaves the file, and nothing to clean up).
    first.shutdown().await;
    let (again, _) = on_the_key().await.expect("a server once the first stopped");
    again.shutdown().await;
}

/// A server that allows `allow`, with its other options from `more`, or why it could not start.
async fn boot_server(
    tmp: &TempDir,
    allow: Vec<iroh::EndpointId>,
    more: ServeOptions,
) -> koh::Result<(RunningServer, Option<Route>)> {
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
    .await?;
    let route = Some(Route::Direct(srv.direct_addr.unwrap()));
    Ok((srv, route))
}

fn new_key(tmp: &TempDir, name: &str) -> iroh::SecretKey {
    fs::create_dir_all(tmp.0.join("cli_cfg")).unwrap();
    load_or_create_key(Role::Client, Some(&tmp.0.join("cli_cfg").join(name))).unwrap()
}

#[tokio::test]
async fn connections_are_capped_before_auth_and_a_place_comes_back_when_one_ends() {
    let more = ServeOptions {
        max_connections: 1,
        proof_timeout: Duration::from_secs(60),
        ..ServeOptions::default()
    };
    let door = Door::open("max-conn", more).await;
    let stranger = new_key(&door.tmp, "stranger.key");
    // A peer the server does not know, which proves nothing, holds the one place. A second is
    // let connect to be told so, and has not asked yet: it holds the one place there is for
    // that. A third is refused before it has connected at all, and that is the server being
    // busy as much as the second's answer is: exit 75, not 3.
    let first = door.dial(&stranger, false).await.unwrap();
    let second = door.dial(&door.friend, false).await.unwrap();
    let third = door
        .dial(&door.friend, false)
        .await
        .err()
        .expect("a refusal");
    assert!(
        third.code == Exit::BUSY && third.message.contains("server busy"),
        "{third:?}"
    );
    assert_eq!(second.jobs(None).await.unwrap_err().code, Exit::BUSY);
    second.close().await;
    // The first goes: its place is the next client's.
    first.close().await;
    door.served(20).await;
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
    // Closed within 5 s, five times its deadline: the time is the rule.
    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    let closed = closed.expect("the silent connection was closed within 5 s");
    let refused = koh::proto::CloseCode::Refused as u64;
    assert!(
        matches!(&closed, iroh::endpoint::ConnectionError::ApplicationClosed(close) if close.error_code.into_inner() == refused),
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
    // A command that ignores SIGHUP, of a client that then leaves: it finishes well within the
    // 2 s the server gives a command after its hangup (with `sleep 1`, one loaded run in 23 was
    // served first). (It writes `deaf` once the trap is set, so the client never leaves before
    // the shell has read its first word.)
    let (deaf, ended) = (door.tmp.0.join("deaf"), door.tmp.0.join("ended"));
    let script = "trap '' HUP; : > deaf; sleep 0.5; : > ended";
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
    door.served(20).await;
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
    door.served(8).await;
    assert!(!stalled.is_finished(), "the stalled peer gave up by itself");
    stalled.abort();
    forward.abort();
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
    server: Child,
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
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
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

/// `koh` run with `args`, its configuration and runtime directory `dir`: how it ended, and what
/// it said on its standard output and its standard error.
fn koh(dir: &Path, args: &[&str]) -> (Option<i32>, String, String) {
    let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
    koh.env("XDG_RUNTIME_DIR", dir)
        .env("KOH_CONFIG_DIR", dir)
        .args(args);
    let said = koh.stdin(Stdio::null()).output().unwrap();
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
        let mut host = Self {
            tmp,
            served: None,
            port: 0,
            extra: extra.iter().map(|arg| arg.to_string()).collect(),
            id: String::new(),
            sessions: PathBuf::new(),
        };
        host.serve();
        host
    }

    fn key(&self, who: &str) -> iroh::SecretKey {
        load_or_create_key(Role::Client, Some(&self.tmp.0.join(who).join("client.key"))).unwrap()
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// Starts the server: the first time on a port the system gives it, and anew after `stop`
    /// on that port and the same state.
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
        let bound: SocketAddr = served.says("listening:").parse().unwrap();
        self.port = bound.port();
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
        self.attach_on(InTerminal::pty(), asks, program, true)
    }

    fn attach_on(
        &self,
        pty: (fs::File, fs::File),
        asks: &[&str],
        program: &[String],
        its: bool,
    ) -> InTerminal {
        let addr = self.addr();
        let mut args = vec![self.id.as_str(), "--direct", &addr];
        args.extend_from_slice(asks);
        if !program.is_empty() {
            args.push("--");
            args.extend(program.iter().map(String::as_str));
        }
        let (config, runtime) = (self.tmp.0.join("cli_cfg"), self.tmp.0.join("crun"));
        InTerminal::connect_on(pty, &config, &runtime, &args, its)
    }

    /// A `koh` of the client's, with its key and a runtime directory of its own.
    fn koh(&self, args: &[&str]) -> Command {
        let mut koh = Command::new(env!("CARGO_BIN_EXE_koh"));
        koh.args(args)
            .env("KOH_CONFIG_DIR", self.tmp.0.join("cli_cfg"))
            .env("XDG_RUNTIME_DIR", self.tmp.0.join("crun"))
            .env("HOME", self.tmp.0.join("home"))
            .stdin(Stdio::null())
            .stdout(Stdio::null());
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
    fuxix::set_winsize(second.tty(), size).unwrap();
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
    // Killed outright, the server leaves a viewer that reads the end of its terminal and goes.
    let viewer = viewers(&host)[0].trim_start_matches(".view.").to_string();
    signal(
        &host.served.as_ref().unwrap().server.id().to_string(),
        "-KILL",
    );
    until("the viewer has gone by itself", || !pid_running(&viewer));
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
    drop(a.master.take());
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
        // A program on the main screen is drawn on the terminal's alternate screen.
        let shown = || fs::read_link(terminal.0.join("shown")).unwrap_or_default();
        until("the viewer draws on the alternate screen", || {
            shown() == Path::new("alt")
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
    // (From when the test read the question, which can be well after koh asked it: half the
    // second, so that a reader late by up to that cannot fail a koh that waits it whole.)
    let began = Instant::now();
    tty.until("the program is ready", |tty| tty.drew(0, b"READY"));
    assert!(
        began.elapsed() >= Duration::from_millis(500),
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

// (Linux only: on macOS CI the terminal went on taking and this never came to hold what is unread.)
#[cfg(target_os = "linux")]
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
    let (burst, mut over, mut full, ready) = (vec![b'x'; 64 << 10], None, 0, Instant::now());
    let ended = loop {
        // (As much as the terminal takes, and nothing once koh is gone; what koh draws is read.)
        // Once the terminal has refused what is typed 100 times running, all of it held up behind the
        // program, the program ends.
        match tty.tty().write(&burst) {
            Err(_) => full += 1,
            Ok(_) if full < 100 => full = 0,
            Ok(_) => {}
        }
        if full == 100 {
            fs::write(&gate, "").unwrap();
        }
        let setup = ready.elapsed() < Duration::from_secs(10) || full >= 100;
        assert!(
            setup,
            "setup: the terminal took all that was typed for 10 s"
        );
        let mut drawn = [0; 4096];
        while let Ok(n @ 1..) = tty.tty().read(&mut drawn) {
            tty.drawn.extend_from_slice(&drawn[..n]);
        }
        if over.is_none() && state().starts_with("exited") {
            over = Some(Instant::now());
        }
        if let Some(ended) = tty.koh.try_wait().unwrap() {
            break ended.code();
        }
        assert!(ready.elapsed().as_secs() < 20, "koh is still there");
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
fn koh_connect_started_on_a_terminal_that_takes_nothing_ends_when_it_is_told_to() {
    let host = Host::start("stalled-first", &[]);
    let (config, runtime) = (host.tmp.0.join("cli_cfg"), host.tmp.0.join("crun"));
    // A terminal that takes nothing from before koh starts (another program has filled it,
    // and nobody reads): koh cannot ask it what it is like, and waits for nothing to do so.
    // Told to end, it ends, each of the three ways: told as soon as it has made the terminal
    // raw (it echoes no more), as a rule before anything is drawn. (koh has no controlling terminal here;
    // a shell's child has one and is not its controlling process: koh's code runs alike in
    // both. macOS ends a controlling process only once its terminal takes what waits.)
    for (how, code) in [("-TERM", 0), ("-HUP", 0), ("-INT", 130)] {
        let (tty, theirs) = InTerminal::pty();
        let mut fills = Command::new("sh");
        fills
            .args(["-c", "stty raw echo <&1; exec head -c 4194304 /dev/zero"])
            .stdout(theirs.try_clone().unwrap());
        let _fills = Waits(fills.spawn().unwrap());
        InTerminal::takes_no_more(&theirs);
        let name = how.trim_start_matches('-');
        let asks = [&host.id, "--direct", &host.addr(), "--session", name];
        let mut stty = Command::new("stty");
        stty.arg("-a").stdin(theirs.try_clone().unwrap());
        let mut koh = InTerminal::connect_on((tty, theirs), &config, &runtime, &asks, false);
        until("the terminal is raw", || {
            let said = stty.output().unwrap().stdout;
            String::from_utf8_lossy(&said)
                .split_whitespace()
                .any(|flag| flag == "-echo")
        });
        assert_eq!(koh.told(how), Some(code), "{how}");
        drop(koh); // (before the filler: see InTerminal's drop)
    }
}

#[test]
fn koh_connect_ends_when_it_is_told_to_though_its_terminal_takes_nothing() {
    let host = Host::start("stalled", &[]);
    // A terminal that takes nothing more (one behind a path that is stuck), under a program
    // that goes on printing: koh's writing to it waits, and so would putting it back. Told to
    // end, koh ends all the same, each of the three ways, and soon. Left by its user meanwhile
    // (`Ctrl-] .`), it waits for its terminal to take what puts it back, as a program waits for
    // its terminal (2 s: more than leaving takes it else), and ends then; or once told to.
    let rows = [
        ("-TERM", 0, false),
        ("-HUP", 0, false),
        ("-INT", 130, false),
        ("-INT", 130, true), // (told while it waits: it ends as it was told to, not as it was left)
        ("", 0, true),
    ];
    for (n, (how, code, left)) in rows.into_iter().enumerate() {
        // (Every cell of another colour than the one before it: a screen of it is many bytes.)
        let draws = r"while :; do printf '\033[31mfl\033[32moo\033[33md-\033[34mof\033[35m-l\033[36min\033[37mes'; done";
        let flood = ["sh", "-c", draws].map(String::from);
        let (pty, asks) = (InTerminal::pty(), ["--session", &format!("s{n}")]);
        let slave = pty.1.try_clone().unwrap();
        let mut tty = host.attach_on(pty, &asks, &flood, false); // (not its: see above)
        tty.until("the flood is drawn", |tty| {
            tty.drawn.windows(2).any(|drawn| drawn == b"es")
        });
        // (Not read from here on: what koh writes fills the terminal, and waits.)
        InTerminal::takes_no_more(&slave);
        if left {
            // (Full once its kernel has moved what it holds to where it is read: Linux does so
            // a while after, and takes a few KiB more meanwhile.)
            std::thread::sleep(Duration::from_millis(300));
            InTerminal::takes_no_more(&slave);
            tty.types(b"\x1d.");
            std::thread::sleep(Duration::from_secs(2));
            assert!(tty.koh.try_wait().unwrap().is_none(), "{how}: gone");
        }
        let from = tty.drawn.len();
        match how {
            "" => {
                tty.until("the terminal is put back", |tty| {
                    tty.drew(from, b"\x1b[?1049l")
                });
                assert_eq!(tty.ends(), Some(0));
            }
            how => assert_eq!(tty.told(how), Some(code), "{how}"),
        }
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
        koh.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        let said = koh.output().unwrap();
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        (said.status.code(), text(&said.stdout), text(&said.stderr))
    }

    /// `koh wait` for the session `s` of this server, started, with whatever else it is told.
    fn waits(&self, more: &[&str]) -> Waits {
        let mut koh = self.koh(&["wait", &self.id, "--direct", &self.addr()]);
        koh.args(["--session", "s"])
            .args(more)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
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
struct Waits(Child);

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
    // (The server tells a client its session's end before it lets go of the client's place.)
    until("the two that ended are detached", || {
        list()
            .iter()
            .skip(1)
            .all(|line| line.contains("|detached|"))
    });
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
    let last = || host.asked("output", &["--session", "1", "--last"]);
    // A pane of ten rows, forty wide; and so much output that `history` has become `history.1`.
    // That command's output began in `history.1`: all of it is there, in pieces.
    fs::write(pane.join("ctl"), "resize 40 10\n").unwrap();
    until("the pane takes the size", || {
        fs::read_to_string(pane.join("size")).unwrap() == "40 10\n"
    });
    fs::write(pane.join("in"), "seq 1 800000\n").unwrap();
    let marks = || fs::read_to_string(pane.join("marks")).unwrap_or_default();
    // (The screen is read before the marks: a round of the holder writes them in that order.)
    until("the command has ended, its output in history.1 too", || {
        screen(&pane).contains("\n800000\n") && marks().ends_with(" command\n")
    });
    assert!(pane.join("history.1").is_file());
    let numbers: String = (1..=800_000).map(|n| format!("{n}\n")).collect();
    let (code, flood, said) = last();
    assert!(code == Some(0) && flood == numbers, "{said}");
    // A command that prints 26 lines, one of them wider than the pane: what it printed, each
    // line whole, from where its output began to where it ended, history and screen: not the
    // command, not the prompt after it.
    let lines: Vec<String> = (1..=26)
        .map(|n| match n {
            24 => "wide-".repeat(20),
            n => format!("line-{n}"),
        })
        .collect();
    let printf = format!("printf '%s\\n' {}\n", lines.join(" "));
    fs::write(pane.join("in"), printf).unwrap();
    let printed = lines.join("\n") + "\n";
    until("output --last is what it printed", || {
        last() == (Some(0), printed.clone(), String::new())
    });
    // Without `--last` it is the screen that is shown.
    let (code, shown, said) = host.asked("output", &["--session", "1"]);
    assert_eq!((code, shown), (Some(0), screen(&pane)), "{said}");
    // A name that is no session's is not found; nor is a name that is none a path: the folder
    // above the sessions is no session, also where it looks like a pane.
    assert_eq!(host.asked("output", &["--session", "none"]).0, Some(127));
    let above = host.sessions.parent().unwrap();
    fs::create_dir_all(above.join("shown")).unwrap();
    fs::write(above.join("status"), "holder 1\n").unwrap();
    fs::write(above.join("run"), format!("{:032x}\n", 1)).unwrap();
    fs::write(above.join("shown/screen"), "not a session's\n").unwrap();
    let (code, shown, said) = host.asked("output", &["--session", ".."]);
    assert_eq!((code, shown.as_str()), (Some(127), ""), "{said}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_session_returns_the_commands_code_or_124_or_the_sessions_end() {
    let host = Host::start("wait", &[]);
    let pane = host.session("s", &marking_shell(&host), "$");
    // No command ends: when the time given is over it is 124, with the screen as it is.
    let began = Instant::now();
    let (code, shown, _) = host.asked("wait", &["--session", "s", "--timeout", "1"]);
    assert_eq!((code, shown), (Some(124), screen(&pane)));
    assert!(began.elapsed() >= Duration::from_secs(1));
    // A wait returns when one more command has ended than when it was asked, with that
    // command's code and what it printed. (When the server takes the request the test cannot
    // see: it types the same command again until the wait has returned.)
    let mut wait = host.waits(&["--timeout", "30"]);
    until("koh wait returns", || {
        fs::write(pane.join("in"), "sh -c 'echo waited; exit 42'\n").unwrap();
        std::thread::sleep(Duration::from_millis(250));
        wait.ended()
    });
    let (code, printed, said) = wait.said();
    assert_eq!((code, printed.as_str()), (Some(42), "waited\n"), "{said}");
    // A wait the server has taken: the program ends, and the wait ends with its status and its
    // last screen. Asked of a session that has ended, it says the same at once. (A session of
    // its own: no retry of the one before is left to end it.)
    let ends = host.session(
        "e",
        &sh("echo ready; read line; echo bye-$line; exit 3"),
        "ready",
    );
    let client = host.client().await;
    let wait = waits(&client, "e").await;
    fs::write(ends.join("in"), "now\n").unwrap();
    let (code, shown) = waited(wait).await;
    assert!(code == 3 && shown.contains("bye-now"), "{code} {shown:?}");
    let (code, again, said) = host.asked("wait", &["--session", "e"]);
    assert_eq!((code, again), (Some(3), shown), "{said}");
    // One that ends with its last command: the wait is that command's, not the session's.
    let l = host.session("l", &marks_by_steps(&["m 'D;7'; exit 0"]), "$");
    let wait = waits(&client, "l").await;
    fs::write(l.join("in"), "\n").unwrap();
    assert_eq!(waited(wait).await.0, 7);
    // Of one whose holder was killed nothing says how it ended: that is 1, not 0. And a name
    // that is no session's is not found.
    let dead = host.session("dead", &sh("echo ready; sleep 30"), "ready");
    // (Of a session no command of which has ended, `output --last` is its screen.)
    let last = host.asked("output", &["--session", "dead", "--last"]);
    assert_eq!((last.0, last.1), (Some(0), screen(&dead)));
    signal(&holder_of(&dead), "-KILL");
    until("the holder is gone", || {
        fs::File::open(&dead).unwrap().try_lock_shared().is_ok()
    });
    assert_eq!(host.asked("wait", &["--session", "dead"]).0, Some(1));
    assert_eq!(host.asked("wait", &["--session", "none"]).0, Some(127));
    client.close().await;
}

#[test]
fn the_recipes_of_help_agents_read_what_the_commands_read() {
    // The script is plain sh: it is run as it is, and with dash and mawk, and with busybox's
    // ash, awk and sleep, first on its PATH as `sh`, `awk` and `sleep`, where they are here.
    recipes("");
    recipes("sh=dash awk=mawk");
    recipes("sh=busybox awk=busybox sleep=busybox");
}

fn recipes(tools: &str) {
    let host = Host::start("recipes", &[]);
    // (Its first `date` of a wait is after it has asked what has ended: a `date` of the test's
    // says so, first on the script's PATH.)
    let (bin, path) = (host.tmp.0.join("bin"), std::env::var("PATH").unwrap());
    let (date, asked) = (bin.join("date"), host.tmp.0.join("asked"));
    fs::create_dir(&bin).unwrap();
    for (name, tool) in tools.split(' ').filter_map(|named| named.split_once('=')) {
        let mut paths = std::env::split_paths(&path).map(|dir| dir.join(tool));
        let Some(at) = paths.find(|at| at.is_file()) else {
            return eprintln!("the recipes with {tools:?}: skipped, there is no {tool}");
        };
        std::os::unix::fs::symlink(at, bin.join(name)).unwrap();
    }
    eprintln!("the recipes with {tools:?}: run");
    let wraps = format!(
        "#!/bin/sh\n: > '{}'\nPATH='{path}' exec date \"$@\"\n",
        asked.display()
    );
    fs::write(&date, wraps).unwrap();
    fs::set_permissions(&date, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    let pane = host.session("s", &marking_shell(&host), "$");
    // The script is the end of what `koh help-agents` prints, from its first line on; the help
    // itself has none of it.
    let (_, help, _) = koh(&host.tmp.0, &["help-agents"]);
    let script = host.tmp.0.join("sessions.sh");
    fs::write(&script, &help[help.find("#!/bin/sh").unwrap()..]).unwrap();
    assert!(!koh(&host.tmp.0, &["--help"]).1.contains("#!/bin/sh"));
    let dir = host.sessions.to_str().unwrap();
    let recipe = |args: &[&str]| {
        let mut sh = Command::new("sh");
        sh.arg(&script).args(args);
        sh.env("PATH", format!("{}:{path}", bin.display()));
        sh.stdout(Stdio::piped()).stderr(Stdio::piped());
        sh
    };
    let asks = |pane: &Path| {
        let _ = fs::remove_file(&asked);
        let wait = recipe(&["wait", pane.to_str().unwrap(), "30"]).spawn();
        until("the recipe's wait has asked", || asked.exists());
        Waits(wait.unwrap())
    };
    let run = |args: &[&str]| {
        let said = recipe(args).output().unwrap();
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        (said.status.code(), text(&said.stdout), text(&said.stderr))
    };
    // Run on the server, where the folders are, it lists, shows and waits as the commands do.
    let pane_dir = pane.to_str().unwrap();
    fs::write(pane.join("in"), "sh -c 'echo from-the-recipe; exit 9'\n").unwrap();
    until("the command has ended", || {
        host.asked("sessions", &[]).1.contains("\texit=9\t")
    });
    let listed = run(&["list", dir]);
    assert_eq!(
        (listed.0, listed.1.as_str()),
        (Some(0), "s\talive\trunning\t80x24\tidle\t9\t\n")
    );
    let (code, last, _) = run(&["last", pane_dir]);
    assert_eq!((code, last.as_str()), (Some(0), "from-the-recipe\n"));
    assert_eq!(last, host.asked("output", &["--session", "s", "--last"]).1);
    let (code, shown, said) = run(&["wait", pane_dir, "1"]);
    assert_eq!((code, shown), (Some(124), screen(&pane)), "{said}");
    assert_eq!(run(&["screen", pane_dir]).1, screen(&pane));
    // The session ends: the recipe's wait ends with the program's status.
    fs::write(pane.join("in"), "exit 3\n").unwrap();
    assert_eq!(run(&["wait", pane_dir, "20"]).0, Some(3));
    assert_eq!(
        run(&["list", dir]).1,
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
        let (code, last, said) = run(&["last", moving.to_str().unwrap()]);
        assert_eq!((code, last.as_str()), (Some(0), want), "{said}");
        assert_eq!(last, host.asked("output", &["--session", "m", "--last"]).1);
    };
    // An end with no output marked before it, and none before that, is of the screen.
    stepped(&moving, 1);
    last_is(&screen(&moving));
    stepped(&moving, 2);
    let mut wait = asks(&moving);
    stepped(&moving, 3);
    // (Time for it to look at the moved marks: the wait is the test.)
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
    let (code, list, said) = run(&["list", dir]);
    assert!(
        code == Some(0) && list.starts_with("bare\tended\t\t0x0\tidle\t-\t\n"),
        "{list:?} {said}"
    );
    // A session that ends with its last command: the wait is that command's, not the session's.
    let ends = host.session("e", &marks_by_steps(&["m 'D;7'; exit 0"]), "$");
    let mut wait = asks(&ends);
    fs::write(ends.join("in"), "\n").unwrap();
    assert_eq!(wait.said().0, Some(7), "{tools:?}");
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
/// taken the request. (Its time is a watchdog's: a wait that says nothing is the test's.)
async fn waits(client: &Client, session: &str) -> RecvStream {
    let asked = Request::WaitSession {
        session: session.into(),
        timeout_secs: Some(60),
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

/// A session `name` of `marks_by_steps`, and how many of its steps are done.
struct Stepped(PathBuf, u32);

impl Stepped {
    fn start(host: &Host, name: &str, steps: &[&str]) -> Self {
        Self(host.session(name, &marks_by_steps(steps), "$"), 0)
    }

    /// Has the next step done, and gives the pane's `marks` after it.
    fn step(&mut self) -> String {
        self.1 += 1;
        stepped(&self.0, self.1)
    }
}

/// Holds the server still (stopped, and seen to be) while `then` runs: what it does falls
/// between two of the server's looks.
fn still<T>(host: &Host, then: impl FnOnce() -> T) -> T {
    let server = host.served.as_ref().unwrap().server.id().to_string();
    signal(&server, "-STOP");
    until("the server is stopped", || {
        ps(&server, "stat=").starts_with('T')
    });
    let done = then();
    signal(&server, "-CONT");
    done
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

/// So many times `body`, as one step of a session's program.
fn times(n: u32, body: &str) -> String {
    format!("i=0; while [ $i -lt {n} ]; do {body}; i=$((i + 1)); done")
}

/// A case of the test below: steps; how many are done before a wait is asked, and whether
/// `marks` is full by then; how many next end nothing; whether the rest come between two of
/// the server's looks; the code the wait is answered, and what was printed.
type Case<'a> = (&'a [&'a str], u32, bool, u32, bool, (i32, Option<&'a str>));

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_gives_the_first_end_since_it_was_asked_and_marks_that_only_moved_end_nothing() {
    let host = Host::start("moved", &[]);
    let client = host.client().await;
    // Each a session: steps; how many are done before the wait is asked, and whether `marks`
    // is full by then (a thousand: it drops one for each it takes); how many come next that end
    // nothing, each looked at by the server; whether the rest come between two of its looks;
    // and what the wait is answered: a code, and what that command printed (where it is kept).
    let fill = times(260, "ran fill 0");
    let cleared = r"printf '\r\n'; m C; printf '\033[H\033[2Jfour\r\n'; m 'D;4'; prompt";
    let clears = times(
        255,
        r"printf '\r\n'; m C; printf '\033[H\033[2Jhi %s\r\n' $i; m 'D;0'; prompt",
    );
    let more = times(16, "ran more $((i + 10))");
    let all_on_screen = times(
        255,
        r"printf '\r\n'; m C; printf '\033[H\033[2J'; m 'D;0'; prompt",
    );
    let quiet = r"printf '\r\n'; m C; m 'D;0'; prompt";
    let at_prompts = times(
        260,
        r"printf '\033[H\033[2J'; prompt; printf '\r\n'; m C; printf 'x\r\n'; m 'D;7'",
    ) + "; prompt";
    let alike = format!(
        "{quiet}; {quiet}; {quiet}; printf '\\r\\n'; m C; printf '\\033[H\\033[2J'; m 'D;0'; prompt; {}",
        times(247, "ran fill 1")
    );
    let [a, b, c, d] = MOVES;
    let begun = r"printf '\r\n'; m C; printf '\033[1T'";
    let entered = r"printf '\r\n'; m 'D;1'; prompt; ran second 22";
    let short = r"ran hello 77; printf '^C\r\n'; prompt; printf '\033[H\033[2J'; prompt";
    #[rustfmt::skip]
    let cases: [Case; 9] = [
        // The four ways a screen moves its marks, few marks and all on the screen; then full.
        (&["ran one 7", a, b, c, d, "ran two 9"], 1, false, 4, false, (9, Some("two\n"))),
        (&[&fill, a, b, c, d, cleared], 1, true, 4, false, (4, Some("four\n"))),
        // Two commands end before the wait looks again: one typed while the other ran.
        (&["ran one 7", "ran two 0; ran three 5"], 1, false, 0, true, (0, Some("two\n"))),
        // A shell that clears at every command: every mark of a full file but the last few is
        // at one place. A command's end there, and one asked for afresh after more.
        (&[&clears, "ran four 4", &more], 1, true, 0, false, (4, Some("four\n"))),
        (&[&clears, "ran four 4", &more, "ran fresh 3"], 3, true, 0, false, (3, Some("fresh\n"))),
        // A full file whose first mark is on the screen: a command scrolls it down, and ends
        // with 5 only later.
        (&[&all_on_screen, quiet, begun, "m 'D;5'; prompt"], 2, true, 1, false, (5, None)),
        // A full file on three rows, a shell that clears at each prompt: a line inserted.
        (&[&at_prompts, a, "ran after 3"], 1, true, 1, false, (3, Some("after\n"))),
        // A full file whose oldest marks are alike; an empty line entered, whose `end` has the
        // code of the command before, then one that ends with 22: the first is the first.
        (&[&alike, entered], 1, true, 0, false, (1, Some("fill\n"))),
        // A command ends with 77, a prompt with no `end` (Ctrl-C), a clear and the prompt anew,
        // which takes two marks back. (What it printed went with the clear, unless the wait
        // looked before that.)
        (&[&fill, short], 1, true, 0, false, (77, None)),
    ];
    for (n, (steps, asked, full, nothing, between, (code, printed))) in
        cases.into_iter().enumerate()
    {
        let mut session = Stepped::start(&host, &format!("s{n}"), steps);
        let mut marks = String::new();
        while session.1 < asked {
            marks = session.step();
        }
        assert!(
            !full || marks.lines().count() == 1000,
            "case {n}: {marks:?}"
        );
        let mut wait = waits(&client, &format!("s{n}")).await;
        for _ in 0..nothing {
            let marks = session.step();
            assert!(
                silent(&mut wait).await,
                "case {n}: the wait ended at {marks:?}"
            );
        }
        let rest = |session: &mut Stepped| {
            while session.1 < steps.len() as u32 {
                session.step();
            }
        };
        match between {
            true => still(&host, || rest(&mut session)),
            false => rest(&mut session),
        }
        let (got, text) = waited(wait).await;
        assert_eq!(
            (got, printed.is_none_or(|printed| printed == text)),
            (code, true),
            "case {n}: {text:?}"
        );
    }
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
    let listed = client.sessions().await.unwrap();
    assert!(listed.iter().all(|s| s.title == "t".repeat(256)));
    let mut names: Vec<u32> = listed.iter().map(|s| s.name.parse().unwrap()).collect();
    names.sort();
    assert!(names.into_iter().eq(1..=4500));
    client.close().await;
    door.shut().await;
}

// The sequences of the second round of reviews, each against fux's holder: what a full `marks`
// could not say, and its count of the marks it dropped does.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn more_marks_than_a_pane_keeps_between_two_looks_are_said_and_not_guessed() {
    let host = Host::start("burst", &[]);
    // One command has ended; then the marks of 300, in one write: more than the file keeps.
    let one = r#"s="$s\r\n\033]133;C\007burst-$i\r\n\033]133;D;$((i % 100))\007\033]133;A\007\$ \033]133;B\007""#;
    let burst = format!(r#"s=; {}; printf "$s""#, times(300, one));
    let mut session = Stepped::start(&host, "s", &["ran one 7", &burst]);
    session.step();
    let client = host.client().await;
    let wait = waits(&client, "s").await;
    // So that all of the burst is between two looks (the holder writes it in as many rounds
    // as it reads it in), the server stands still from the look the wait was asked with until
    // the pane has the whole burst.
    let marks = still(&host, || session.step());
    assert_eq!(marks.lines().count(), 1000);
    let (code, text, said) = told(wait).await;
    // The first that ended is not there any more. The wait gives the oldest that is, and says
    // that it is not known to be the first.
    let oldest = 300 - marks.lines().filter(|mark| mark.contains(" end")).count();
    assert!(said.contains("marks came and went unread"), "{said}");
    assert_eq!(
        (code, text),
        ((oldest % 100) as i32, format!("burst-{oldest}\n")),
        "{said}"
    );
    client.close().await;
}

#[tokio::test]
async fn each_client_dials_from_its_own_key_and_proves_the_client_key() {
    let door = Door::open("ephemeral-dial", ServeOptions::default()).await;
    let (key, route) = (door.friend.public(), door.route.clone());
    // Two clients of one key are served at once, and the server never meets the key as a
    // transport's: each dials from a key of its own, and proves the client's in a request.
    let (a, b) = (door.client().await, door.client().await);
    let (r1, r2) = tokio::join!(a.jobs(None), b.jobs(None));
    assert!(r1.unwrap().is_empty() && r2.unwrap().is_empty());
    assert!(door.srv.endpoint.remote_info(key).await.is_none());
    let cfg = koh::net::transport_config(false);
    let dial = || koh::net::connect_server(door.srv.endpoint_id, route.clone(), cfg.clone());
    let ((e1, _, _), (e2, _, _)) = (dial().await.unwrap(), dial().await.unwrap());
    assert!(e1.id() != key && e2.id() != key && e1.id() != e2.id());
    e1.close().await;
    e2.close().await;
    a.close().await;
    b.close().await;
    door.shut().await;
}

#[test]
fn clients_file_rejects_extra_fields_and_keeps_valid_lines() {
    let tmp = TempDir::new("clients-parse");
    let (key, file) = (tmp.0.join("server.key"), tmp.0.join("clients"));
    let k = iroh::SecretKey::from_bytes(&[1; 32]).public();
    // Each line of the file, and whether it is a client: NAME ID and no more, a comment and a
    // blank line are none, nor is a line that is said again on its own (its control bytes
    // escaped). The last has no line feed after its `\r`.
    let rows = [
        ("# comment".into(), None),
        (String::new(), None),
        (format!("full {k}"), Some("full")),
        (format!("ws {k}   "), Some("ws")),
        (format!("cp {k} cp=/srv"), None),
        (format!("t2 {k} # inline"), None),
        (format!("t3 {k} --cp /srv\x1b[2K"), None),
        ("bad_id notakey".into(), None),
        ("lone_word".into(), None),
        (format!("cr {k}\r"), Some("cr")),
    ];
    let text: Vec<_> = rows.iter().map(|(l, _)| l.as_str()).collect();
    fs::write(&file, text.join("\n")).unwrap();
    let cli = |args: &[&str]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_koh"));
        let out = c
            .arg("clients")
            .arg("--key-file")
            .arg(&key)
            .args(args)
            .output()
            .unwrap();
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        (out.status.code(), text(&out.stdout), text(&out.stderr))
    };
    let (code, listed, said) = cli(&[]);
    let names: Vec<_> = listed.lines().filter_map(|l| l.split(' ').next()).collect();
    assert_eq!((code, names), (Some(0), ["full", "ws", "cr"].to_vec()));
    let ignored = rows
        .iter()
        .enumerate()
        .filter(|(_, (l, w))| w.is_none() && !l.is_empty() && !l.starts_with('#'));
    let ignored: Vec<_> = ignored
        .map(|(i, (l, _))| format!("koh: clients:{}: ignored, not NAME ID: {l:?}", i + 1))
        .collect();
    assert_eq!(said.lines().collect::<Vec<_>>(), ignored);
    // `rm` of an ignored name fails and leaves the file as it was; `add`, `rename` and `rm` of
    // clients say what they ignore and write the clients alone.
    let before = format!("old {k} cp=/srv\nother {k}\n");
    fs::write(&file, &before).unwrap();
    let (code, _, said) = cli(&["rm", "old"]);
    assert!(
        code != Some(0) && said.contains("clients:1: ignored") && said.contains("no client named")
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), before);
    assert!(
        cli(&["add", "alice", &k.to_string()])
            .2
            .contains("clients:1: ignored")
    );
    assert_eq!(cli(&["rename", "alice", "bob"]).0, Some(0));
    assert_eq!(cli(&["rm", "other"]).0, Some(0));
    assert_eq!(fs::read_to_string(&file).unwrap(), format!("bob {k}\n"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_refuses_scoped_and_unknown_field_clients_lines() {
    let tmp = TempDir::new("clients-enforce");
    let (bot_cfg, crun) = (tmp.0.join("bot_cfg"), tmp.0.join("crun"));
    for d in [tmp.0.join("srv_cfg"), bot_cfg.clone(), crun.clone()] {
        fs::create_dir_all(d).unwrap();
    }
    let valid = new_key(&tmp, "v.key");
    let scoped = load_or_create_key(Role::Client, Some(&bot_cfg.join("client.key"))).unwrap();
    // A key on a line with more than NAME ID is no client's; one that is also on a line of its
    // own is.
    let (file, v) = (tmp.0.join("srv_cfg/clients"), valid.public());
    let ignored = format!("cpbot {} cp=/srv\nold_valid {v} cp=/srv\n", scoped.public());
    fs::write(&file, format!("{ignored}valid {v}\n")).unwrap();
    let (srv, route) = boot_server(&tmp, Vec::new(), ServeOptions::default())
        .await
        .unwrap();
    let dial = |k| Client::connect_direct(k, srv.endpoint_id, route.clone(), false);
    let marker = tmp.0.join("ran");
    let refused = dial(scoped).await.unwrap();
    let touch = sh(&format!("touch {}", marker.display()));
    assert_eq!(
        refused.exec(touch, None).await.unwrap_err().code,
        Exit::REFUSED
    );
    refused.close().await;
    assert!(!marker.exists(), "refused key ran a command");
    // A refused `koh connect` exits 4 at once (it is not dialled again), and starts nothing.
    let (id, addr) = (
        srv.endpoint_id.to_string(),
        srv.direct_addr.unwrap().to_string(),
    );
    let asks = [&id, "--direct", &addr, "--session", "s"];
    assert_eq!(InTerminal::connect(&bot_cfg, &crun, &asks).ends(), Some(4));
    assert_eq!(names_in(&tmp.0.join("state/fux/koh-sessions")), [""; 0]);
    // The file is read at every request, on a connection that lives: the line taken away
    // revokes the key. A file that is no UTF-8 is no list of anyone, its good line before the
    // bad byte too. (A file that cannot be read is said as a failure, 1, where that reply comes
    // before the close that refuses, 4.)
    let (good, mixed) = (format!("valid {v}\n"), format!("{ignored}valid {v}\n"));
    let lists = [
        (ignored.into_bytes(), Exit::REFUSED),
        ([good.as_bytes(), b"\xff\n"].concat(), Exit::FAILED),
    ];
    for (list, or) in lists {
        fs::write(&file, &mixed).unwrap();
        let client = dial(valid.clone()).await.unwrap();
        assert_eq!(client.exec(vec!["true".into()], None).await.unwrap(), 0);
        fs::write(&file, &list).unwrap();
        let refused = client.jobs(None).await.unwrap_err().code;
        let said = String::from_utf8_lossy(&list);
        assert!(
            [Exit::REFUSED, or].contains(&refused),
            "{refused:?}: {said}"
        );
        client.close().await;
    }
    srv.shutdown().await;
}

fn wait_child(child: &mut Child, secs: u64, what: &str) -> std::process::ExitStatus {
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
    // (`box` is this host, on every call: adding a name again replaces it.)
    let addr = host.addr();
    let add = ["servers", "add", "box", &host.id, "--direct", &addr];
    assert!(host.koh(&add).status().unwrap().success());
    let bin = Path::new(env!("CARGO_BIN_EXE_koh")).parent().unwrap();
    let mut paths = vec![bin.to_path_buf()];
    if let Some(old) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&old));
    }
    let mut sh = Command::new("/bin/sh");
    sh.args(["-ec", script])
        .current_dir(&host.tmp.0)
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("KOH_CONFIG_DIR", host.tmp.0.join("cli_cfg"))
        .env("XDG_RUNTIME_DIR", host.tmp.0.join("crun"))
        .env("XDG_CONFIG_HOME", host.tmp.0.join("xdg_cfg"))
        .env("HOME", host.tmp.0.join("home"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    for who in ["AUTHOR", "COMMITTER"] {
        sh.env(format!("GIT_{who}_NAME"), "test")
            .env(format!("GIT_{who}_EMAIL"), "test@example.com");
    }
    let out = run_bounded(&mut sh, 120, "box_sh");
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    assert!(
        out.status.success(),
        "{:?}\n{}\n{}",
        out.status,
        text(&out.stdout),
        text(&out.stderr)
    );
}

#[test]
fn exec_exits_when_remote_command_ends_even_with_open_stdin() {
    let host = Host::start("exec-open-stdin", &[]);
    let addr = host.addr();
    // Its standard input a pipe that stays open: the command's end is koh's, with all it
    // printed (more than a pipe holds, too).
    let awk = "BEGIN { for (i = 0; i < 4096; i++) printf \"0123456789abcdef0123456789abcdef\\n\" }";
    let ways: [(&[&str], i32, Vec<u8>); 3] = [
        (
            &[
                "exec",
                &host.id,
                "--direct",
                &addr,
                "--sh",
                "printf 'hi\\n'; exit 7",
            ],
            7,
            b"hi\n".to_vec(),
        ),
        (
            &["exec", &host.id, "--direct", &addr, "--", "awk", awk],
            0,
            b"0123456789abcdef0123456789abcdef\n".repeat(4096),
        ),
        (
            &[
                "rsh",
                "--direct",
                &addr,
                &host.id,
                "printf 'rsh-hi\\n'; exit 11",
            ],
            11,
            b"rsh-hi\n".to_vec(),
        ),
    ];
    for (args, code, printed) in ways {
        let mut koh = host.koh(args);
        let (stdin, _open) = std::io::pipe().unwrap();
        let out = run_bounded(koh.stdin(stdin), 20, "koh with open stdin");
        assert_eq!(
            (out.status.code(), out.stdout),
            (Some(code), printed),
            "{args:?}"
        );
    }
    // A terminal's input is sent as its end: `cat` there ends at once.
    let (_tty, terminal) = InTerminal::pty();
    let mut koh = host.koh(&[
        "exec",
        &host.id,
        "--direct",
        &addr,
        "--sh",
        "cat; echo after",
    ]);
    let out = run_bounded(koh.stdin(terminal), 20, "exec on a terminal");
    assert_eq!(
        (out.status.code(), out.stdout),
        (Some(0), b"after\n".to_vec())
    );
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
    let host = Host::start("nonblock-sock", &[]);
    let addr = host.addr();
    // Non-blocking stdin: the second line is sent only after the first has been echoed.
    let (mut peer, sock) = UnixStream::pair().unwrap();
    sock.set_nonblocking(true).unwrap();
    let mut child = host
        .koh(&["exec", &host.id, "--direct", &addr, "--sh", "cat; exit 37"])
        .stdin(OwnedFd::from(sock.try_clone().unwrap()))
        .stdout(OwnedFd::from(sock))
        .spawn()
        .unwrap();
    peer.write_all(b"hello\n").unwrap();
    let (echoed, mut peer_r) =
        read_exact_bounded::<6, _>(peer.try_clone().unwrap(), &mut child, 20, "echo");
    assert_eq!(&echoed, b"hello\n");
    peer.write_all(b"world\n").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    assert_eq!(
        wait_child(&mut child, 20, "nonblock stdin").code(),
        Some(37)
    );
    let mut rest = Vec::new();
    peer_r.read_to_end(&mut rest).unwrap();
    assert_eq!(rest, b"world\n");
    // Non-blocking stdout and stderr: 1.5 MiB (more than a Unix socket's buffer) to a reader
    // that comes late with a small buffer arrives whole on each stream. (The wait only lets the
    // buffer fill: a reader at once is the easier test.)
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
        let mut koh = host.koh(&["rsh", "--direct", &addr, &host.id, &cmd]);
        match to_stderr {
            true => koh.stderr(OwnedFd::from(sock)),
            false => koh
                .stdin(OwnedFd::from(sock.try_clone().unwrap()))
                .stdout(OwnedFd::from(sock)),
        };
        let mut child = koh.spawn().unwrap();
        drop(koh);
        peer.shutdown(Shutdown::Write).unwrap();
        let reader = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            let (mut out, mut buf) = (Vec::new(), [0u8; 256]);
            while let Ok(n @ 1..) = peer.read(&mut buf) {
                out.extend_from_slice(&buf[..n]);
            }
            out
        });
        assert_eq!(
            wait_child(&mut child, 20, "nonblock output").code(),
            Some(code)
        );
        assert!(reader.join().unwrap() == expected, "{to_stderr}");
    }
}

#[test]
fn rsh_options_rsync_and_git() {
    let host = Host::start("rsh-e2e", &[]);
    // Options before the host are koh's, and those it has none of are refused; after the host
    // and after `--` they are the command's.
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
             koh rsh --direct {addr} {id} printf ok >o
             [ \"$(cat o)\" = ok ]
             koh servers add -box {id} --direct {addr}
             koh rsh -- -box printf ok >o
             [ \"$(cat o)\" = ok ]
             for f in -G -o -l -p --json; do
               set +e; koh rsh \"$f\" box --json >o 2>e; rc=$?; set -e
               [ \"$rc\" = 2 ]
               [ ! -s o ]
               grep -Fq -- \"$f\" e
             done
             set +e; koh rsh nosuchhostxyz printf %s --json >o 2>e; rc=$?; set -e
             [ \"$rc\" = 2 ]
             [ ! -s o ]
             set +e; koh rsh box >o 2>e; rc=$?; set -e
             [ \"$rc\" = 2 ]
             grep -Fq usage e",
            addr = host.addr(),
            id = host.id,
        ),
    );
    // A command over a request's bound (1 MiB) is a usage error, for rsh and exec (unless the
    // system takes no such command line at all).
    let big_word = "x".repeat(130);
    for head in [&["rsh", "box"][..], &["exec", "box", "--"][..]] {
        let mut over = host.koh(head);
        over.args(std::iter::repeat_n(&big_word, 9000));
        match over.stderr(Stdio::piped()).output() {
            Ok(out) => assert_eq!(out.status.code(), Some(2)),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ArgumentListTooLong),
        }
    }
    // rsync and git through `koh rsh`, where they are installed: a binary file there and back,
    // and a push and a clone.
    let big: Vec<u8> = (0..(256 * 1024)).map(|i| (i % 251) as u8).collect();
    fs::create_dir_all(host.tmp.0.join("src")).unwrap();
    fs::write(host.tmp.0.join("src/big.bin"), &big).unwrap();
    if Command::new("rsync").arg("--version").output().is_ok() {
        box_sh(
            &host,
            "rsync -a -e 'koh rsh' src/ box:dst/\nrsync -a -e 'koh rsh' box:dst/ pulled/",
        );
        assert_eq!(fs::read(host.tmp.0.join("home/dst/big.bin")).unwrap(), big);
        assert_eq!(fs::read(host.tmp.0.join("pulled/big.bin")).unwrap(), big);
    }
    if Command::new("git").arg("--version").output().is_ok() {
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
        assert_eq!(
            fs::read(host.tmp.0.join("cloned/hello.txt")).unwrap(),
            b"from-git\n"
        );
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

    /// The pid the file says, once it says one (it is written after it is made).
    fn pid(&self) -> String {
        let pid = || {
            fs::read_to_string(&self.path)
                .unwrap_or_default()
                .trim()
                .to_string()
        };
        until("the pid is written", || pid().parse::<u32>().is_ok());
        pid()
    }

    fn dead_within(&mut self, secs: u64, what: &str) {
        let pid = self.pid();
        let deadline = Instant::now() + Duration::from_secs(secs);
        while pid_running(&pid) {
            assert!(
                Instant::now() < deadline,
                "{what}: pid {pid} still alive after {secs}s"
            );
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
    child: &mut Child,
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (out, err) = (
        drain(child.stdout.take().unwrap()),
        drain(child.stderr.take().unwrap()),
    );
    let status = wait_child(&mut child, secs, what);
    let (stdout, stderr) = (out.join().unwrap(), err.join().unwrap());
    std::process::Output {
        status,
        stdout,
        stderr,
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
            .stdin(Stdio::null());
        cmd
    }

    async fn close(self) {
        self.ep.close().await;
        self.task.abort();
        let _ = self.task.await;
    }
}

impl Host {
    /// `koh exec` of this host: `/bin/sh -c SCRIPT _ ARGS…`, its output piped.
    fn exec(&self, script: &str, args: &[&str]) -> Command {
        let (id, addr) = (&self.id, self.addr());
        let mut koh = self.koh(&[
            "exec", id, "--direct", &addr, "--", "/bin/sh", "-c", script, "_",
        ]);
        koh.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        koh
    }

    /// One of the client's commands about this host, started, its output piped.
    fn spawned(&self, command: &str, args: &[&str]) -> Child {
        let mut koh = self.koh(&[command, &self.id, "--direct", &self.addr()]);
        koh.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        koh.spawn().unwrap()
    }
}

/// All that `from` gives, read on a thread of its own.
fn drain(mut from: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut all = Vec::new();
        let _ = from.read_to_end(&mut all);
        all
    })
}

#[test]
fn exec_b_simultaneous_four_mib_each_way_no_deadlock() {
    let host = Host::start("exec-b", &[]);
    let n = 4 << 20;
    let sent_in: Vec<u8> = (0..n).map(|i| ((i * 31 + 17) % 256) as u8).collect();
    let sent_out: Vec<u8> = (0..n).map(|i| ((i * 131 + 7) % 256) as u8).collect();
    let (out_file, in_file) = (host.tmp.0.join("out.bin"), host.tmp.0.join("in.bin"));
    fs::write(&out_file, &sent_out).unwrap();
    // The remote writes 4 MiB to stdout before it reads 4 MiB of stdin; the client writes
    // stdin while it reads stdout.
    let files = [out_file.to_str().unwrap(), in_file.to_str().unwrap()];
    let mut koh = host.exec("cat \"$1\"; cat > \"$2\"", &files);
    let mut child = koh.stdin(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&sent_in).map(|()| sent_in));
    let got_out = drain(child.stdout.take().unwrap());
    assert!(wait_child(&mut child, 30, "4 MiB each way").success());
    let sent_in = writer.join().unwrap().unwrap();
    assert!(got_out.join().unwrap() == sent_out, "stdout");
    assert!(fs::read(&in_file).unwrap() == sent_in, "stdin");
}

#[test]
fn exec_c_broken_stdout_pipe_returns_141_and_hangs_up_producer() {
    let host = Host::start("exec-c", &[]);
    let pid_file = host.tmp.0.join("yes.pid");
    let mut guard = KillPid::new(pid_file.clone());
    let script = "echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exec yes";
    let mut child = host
        .exec(script, &[pid_file.to_str().unwrap()])
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let (head, out) = read_exact_bounded::<2, _>(out, &mut child, 20, "exec-c y");
    assert_eq!(&head, b"y\n");
    drop(out);
    let st = wait_child(&mut child, 20, "koh exec with closed stdout pipe");
    assert_eq!(st.code(), Some(141));
    guard.dead_within(20, "remote yes after stdout EPIPE");
}

#[tokio::test]
async fn exec_d_link_lost_after_start_exits_255_not_3() {
    let (lose, lost) = tokio::sync::oneshot::channel::<()>();
    let lost = std::sync::Arc::new(tokio::sync::Mutex::new(Some(lost)));
    let peer = RawExecPeer::start("exec-d", move |conn, mut send, _recv| {
        let lost = lost.clone();
        async move {
            let _ = send_msg(&mut send, &koh::proto::Reply::Ok, MAX_CTRL).await;
            let started = koh::proto::ExecServerMsg::Stdout(b"started\n".to_vec());
            let _ = send_msg(&mut send, &started, MAX_CHUNK).await;
            if let Some(lost) = lost.lock().await.take() {
                let _ = lost.await;
            }
            conn.close(0u32.into(), b"lost");
            false
        }
    })
    .await;
    // A server that is never reached is 3. (Within the 15 s a dial is given.)
    let wrong = load_or_create_key(Role::Server, Some(&peer.tmp.0.join("wrong.key")));
    let wrong = wrong.unwrap().public().to_string();
    let mut unreached = peer.koh(&wrong, &["--relay-url", "http://127.0.0.1:1"]);
    let unreached =
        tokio::task::spawn_blocking(move || run_bounded(&mut unreached, 30, "unreached"));
    assert_eq!(unreached.await.unwrap().status.code(), Some(3));
    // A link lost after the answer and some output is 255, not 3, and that output is kept.
    let mut koh = peer.koh(&peer.id, &[]);
    let mut child = koh.stdout(Stdio::piped()).spawn().unwrap();
    let ended = tokio::task::spawn_blocking(move || {
        let out = child.stdout.take().unwrap();
        let (started, _out) = read_exact_bounded::<8, _>(out, &mut child, 20, "exec-d started");
        let _ = lose.send(());
        (started, wait_child(&mut child, 20, "exec-d lost link"))
    });
    let (started, st) = ended.await.unwrap();
    peer.close().await;
    assert_eq!((&started, st.code()), (b"started\n", Some(255)));
}

#[test]
fn exec_e_stdout_write_error_exits_1_not_0() {
    let host = Host::start("exec-e", &[]);
    // A stdout whose writes fail, and not with a closed pipe (EFBIG, on Linux and macOS: a
    // file of at most 0 blocks, and SIGXFSZ ignored): koh says so and ends with 1.
    let out_file = host.tmp.0.join("zero-limit.out");
    let script = "trap '' XFSZ; ulimit -f 0; exec \"$1\" exec \"$2\" --direct \"$3\" -- printf 'hello\\n' > \"$4\"";
    let (koh, file) = (env!("CARGO_BIN_EXE_koh"), out_file.to_str().unwrap());
    let mut sh = Command::new("/bin/sh");
    sh.args(["-c", script, "_", koh, &host.id, &host.addr(), file])
        .env("KOH_CONFIG_DIR", host.tmp.0.join("cli_cfg"))
        .env("XDG_RUNTIME_DIR", host.tmp.0.join("crun"))
        .stdin(Stdio::null());
    let out = run_bounded(&mut sh, 20, "koh exec with EFBIG stdout");
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.code() == Some(1) && said.contains("write:"),
        "{said}"
    );
}

#[tokio::test]
async fn exec_g_stream_eof_without_exit_status_exits_255_not_0() {
    let peer = RawExecPeer::start("exec-g", |_conn, mut send, _recv| async move {
        let _ = send_msg(&mut send, &koh::proto::Reply::Ok, MAX_CTRL).await;
        let partial = koh::proto::ExecServerMsg::Stdout(b"partial\n".to_vec());
        let _ = send_msg(&mut send, &partial, MAX_CHUNK).await;
        let _ = send.finish();
        let _ = tokio::time::timeout(Duration::from_secs(20), send.stopped()).await;
        false
    })
    .await;
    let mut cmd = peer.koh(&peer.id, &[]);
    let out = tokio::task::spawn_blocking(move || run_bounded(&mut cmd, 20, "exec-g"));
    let out = out.await.unwrap();
    peer.close().await;
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        (out.status.code(), out.stdout),
        (Some(255), b"partial\n".to_vec()),
        "{said}"
    );
    assert!(said.contains("no exit status came"), "{said}");
}

#[test]
fn exec_hangup_kills_hup_ignoring_group_member() {
    let host = Host::start("exec-group-member", &[]);
    let pid_file = host.tmp.0.join("worker.pid");
    let mut guard = KillPid::new(pid_file.clone());
    // The leader ends at its hangup; a worker of its group that ignores SIGHUP is killed.
    let script = "cat >/dev/null; (trap '' HUP; echo READY; exec sleep 301) & echo $! > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; wait";
    let mut child = host
        .exec(script, &[pid_file.to_str().unwrap()])
        .spawn()
        .unwrap();
    let out = child.stdout.take().unwrap();
    let (ready, _out) = read_exact_bounded::<6, _>(out, &mut child, 20, "group member READY");
    assert_eq!(&ready, b"READY\n");
    guard.pid();
    signal(&child.id().to_string(), "-TERM");
    let st = wait_child(&mut child, 20, "koh exec on SIGTERM (group member)");
    assert_eq!(st.code(), Some(143));
    guard.dead_within(20, "HUP-ignoring group member");
}

#[test]
fn exec_signal_exits_while_stdout_pipe_is_blocked() {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    let host = Host::start("exec-sig-blocked", &[]);
    let usr1 = tokio::signal::unix::SignalKind::user_defined1().as_raw_value();
    // Told to end while its write to a stdout that nobody reads waits (a pipe, and a socket
    // that does not block): it ends with the signal's code, what was written is a start of
    // what the command wrote, and the command is gone.
    for nonblocking in [false, true] {
        let pid_file = host.tmp.0.join(format!("yes-{nonblocking}.pid"));
        let mut guard = KillPid::new(pid_file.clone());
        let script = "echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exec yes";
        let mut cmd = host.exec(script, &[pid_file.to_str().unwrap()]);
        let (mut child, out): (_, Box<dyn std::io::Read + Send>) = match nonblocking {
            true => {
                let (peer, sock) = UnixStream::pair().unwrap();
                sock.set_nonblocking(true).unwrap();
                (
                    cmd.stdout(OwnedFd::from(sock)).spawn().unwrap(),
                    Box::new(peer),
                )
            }
            false => {
                let mut child = cmd.spawn().unwrap();
                let out = child.stdout.take().unwrap();
                (child, Box::new(out))
            }
        };
        drop(cmd);
        let (one, mut out) = read_exact_bounded::<1, _>(out, &mut child, 20, "first byte");
        // (Time for what is not read to fill the pipe: sooner, the write does not wait, and the
        // test is the easier one.)
        std::thread::sleep(Duration::from_millis(500));
        signal(&child.id().to_string(), "-USR1");
        let st = wait_child(&mut child, 20, "koh exec USR1 blocked");
        assert_eq!(st.code(), Some(128 + usr1), "nonblocking {nonblocking}");
        let mut got = one.to_vec();
        let _ = out.read_to_end(&mut got);
        assert!(got.iter().enumerate().all(|(i, &b)| b == b"y\n"[i % 2]));
        guard.dead_within(20, "remote yes");
    }
}

#[tokio::test]
async fn exec_signal_before_reply_ok_closes_link() {
    let (asked, was_asked) = tokio::sync::oneshot::channel();
    let (stopped, was_stopped) = tokio::sync::oneshot::channel();
    let tell = std::sync::Arc::new(tokio::sync::Mutex::new(Some((asked, stopped))));
    let peer = RawExecPeer::start("exec-sig-pre-ok", move |_conn, send, _recv| {
        let tell = tell.clone();
        async move {
            // No answer: the client's SIGTERM must close the link at once.
            if let Some((asked, stopped)) = tell.lock().await.take() {
                let _ = asked.send(());
                let saw = tokio::time::timeout(Duration::from_secs(20), send.stopped()).await;
                let _ = stopped.send(saw.is_ok());
            }
            false
        }
    })
    .await;
    let mut child = peer.koh(&peer.id, &[]).spawn().unwrap();
    let asked = tokio::time::timeout(Duration::from_secs(20), was_asked).await;
    asked.expect("the request came").unwrap();
    signal(&child.id().to_string(), "-TERM");
    let st = tokio::task::spawn_blocking(move || wait_child(&mut child, 20, "pre-Ok TERM"));
    let st = st.await.unwrap();
    let saw = tokio::time::timeout(Duration::from_secs(30), was_stopped).await;
    peer.close().await;
    assert_eq!(
        (st.code(), saw.ok().and_then(Result::ok)),
        (Some(143), Some(true))
    );
}

#[test]
fn exec_stdin_closed_early_does_not_hang_sender() {
    let host = Host::start("exec-early-stdin", &[]);
    // The remote closes stdin at once while the client still sends 64 MiB: the command's end
    // and output are koh's all the same.
    let mut koh = host.exec("exec 0<&-; sleep 1; echo done", &[]);
    let mut child = koh.stdin(Stdio::piped()).spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || {
        let block = vec![0u8; 64 << 10];
        (0..1024).try_for_each(|_| stdin.write_all(&block))
    });
    let out = drain(child.stdout.take().unwrap());
    assert!(wait_child(&mut child, 20, "early stdin close").success());
    let _ = writer.join();
    assert_eq!(out.join().unwrap(), b"done\n");
}

#[test]
fn exec_serve_shutdown_with_hup_ignoring_exec_and_live_session() {
    let mut host = Host::start("exec-srv-shut", &[]);
    // A live `koh connect` beside a `koh exec` whose command ignores SIGHUP: SIGTERM to
    // `koh serve` ends it (within `stop_by`'s fifteen seconds), the exec with 255, and kills
    // the command.
    let mut tty = host.attach(&[], &sh("echo SESSION_UP; exec sleep 60"));
    tty.until("session is up", |tty| tty.drew(0, b"SESSION_UP"));
    let pid_file = host.tmp.0.join("hup-exec.pid");
    let mut guard = KillPid::new(pid_file.clone());
    let script =
        "trap '' HUP; echo $$ > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; echo READY; exec sleep 600";
    let mut exec = host
        .exec(script, &[pid_file.to_str().unwrap()])
        .spawn()
        .unwrap();
    let out = exec.stdout.take().unwrap();
    let (ready, _out) = read_exact_bounded::<6, _>(out, &mut exec, 20, "serve shutdown READY");
    assert_eq!(&ready, b"READY\n");
    host.stop_by("-TERM");
    assert_eq!(
        wait_child(&mut exec, 20, "koh exec on serve SIGTERM").code(),
        Some(255)
    );
    guard.dead_within(20, "HUP-ignoring exec after serve SIGTERM");
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
    let go = host.tmp.0.join("go");
    let script = "echo before; while [ ! -f \"$1\" ]; do sleep 0.05; done; echo after; exit 7";
    let run = [
        "--name",
        "persist",
        "--",
        "/bin/sh",
        "-c",
        script,
        "_",
        go.to_str().unwrap(),
    ];
    assert!(job_cmd(&host, "run", &run, 20).status.success());
    // `koh serve` killed outright and started again on the same key and state: a fresh client
    // follows the job's log to its end, and waits for it.
    host.stop_by("-KILL");
    host.serve();
    let mut follow = host.spawned("logs", &["persist", "--all", "--follow"]);
    let out = follow.stdout.take().unwrap();
    let (first, out) = read_exact_bounded::<7, _>(out, &mut follow, 20, "logs -f before");
    assert_eq!(&first, b"before\n");
    fs::write(&go, b"go\n").unwrap();
    let rest = drain(out);
    assert_eq!(
        wait_child(&mut follow, 20, "koh logs -f after restart").code(),
        Some(7)
    );
    assert_eq!(rest.join().unwrap(), b"after\n");
    let waited = job_cmd(&host, "wait", &["persist", "--tail", "10"], 20);
    assert_eq!(
        (waited.status.code(), waited.stdout),
        (Some(7), b"before\nafter\n".to_vec())
    );
}

#[test]
fn job_multi_megabyte_log_streams_exact_content() {
    let host = Host::start("job-multimb", &[]);
    // Some 3.4 MiB (more than fifty chunks of 64 KiB) of numbered lines: a chunk dropped,
    // twice or out of its order fails it.
    let expected: String = (1..=500_000).map(|n| format!("{n}\n")).collect();
    let run = ["--name", "seqlog", "--", "seq", "1", "500000"];
    assert!(job_cmd(&host, "run", &run, 20).status.success());
    assert!(
        job_cmd(&host, "wait", &["seqlog", "--timeout", "20"], 25)
            .status
            .success()
    );
    let whole = job_cmd(&host, "logs", &["seqlog", "--all"], 25);
    assert!(whole.status.success() && whole.stdout == expected.as_bytes());
    // A reader that takes a byte and closes its pipe ends `koh logs` with 141.
    let mut logs = host.spawned("logs", &["seqlog", "--all"]);
    let out = logs.stdout.take().unwrap();
    drop(read_exact_bounded::<1, _>(
        out,
        &mut logs,
        20,
        "the log's first byte",
    ));
    assert_eq!(
        wait_child(&mut logs, 20, "koh logs, its pipe closed").code(),
        Some(141)
    );
}

#[test]
fn jobs_lists_a_line_a_job_the_command_last() {
    let host = Host::start("job-list", &[]);
    let args = ["--name", "tabbed", "--sh", "exit 3"];
    assert_eq!(job_cmd(&host, "run", &args, 20).stdout, b"tabbed\n");
    let waited = job_cmd(&host, "wait", &["tabbed", "--timeout", "10"], 20);
    assert_eq!(waited.status.code(), Some(3));
    // Name, state, age and the command, the rest of the line: `--sh LINE` is `/bin/sh -c --
    // LINE`, and a tab a folder's `status` has in it is shown as `?`.
    let status = host
        .sessions
        .parent()
        .unwrap()
        .join("koh-jobs/tabbed/status");
    let was = fs::read_to_string(&status).unwrap();
    fs::write(&status, was.replace("exit 3\n", "exit 3 a\tb\n")).unwrap();
    let listed = String::from_utf8(job_cmd(&host, "jobs", &[], 20).stdout).unwrap();
    let fields: Vec<&str> = listed.trim_end().split('\t').collect();
    let [name, state, age, command] = fields[..] else {
        panic!("{listed:?}")
    };
    let line = (name, state, command);
    assert_eq!(line, ("tabbed", "exited 3", "/bin/sh -c -- exit 3 a?b"));
    let secs = age.strip_suffix('s').map(str::parse::<u64>);
    assert!(secs.is_some_and(|secs| secs.is_ok()), "{age}");
}

#[test]
fn job_kill_ctl_default_invalid_and_ended() {
    let host = Host::start("job-kill-ctl", &[]);
    let code = |sub, args: &[&str]| job_cmd(&host, sub, args, 20).status.code();
    // `koh kill` is SIGTERM; signal 0 (no signal ctl takes) is a usage error; and a job that
    // has ended is killed with 0, saying it is not running.
    assert_eq!(
        code("run", &["--name", "dflt", "--", "sleep", "60"]),
        Some(0)
    );
    assert_eq!(code("kill", &["dflt"]), Some(0));
    assert_eq!(code("wait", &["dflt", "--timeout", "10"]), Some(143));
    assert_eq!(code("kill", &["dflt", "--signal", "0"]), Some(2));
    let ended = job_cmd(&host, "kill", &["dflt"], 20);
    assert!(
        ended.status.success() && String::from_utf8_lossy(&ended.stderr).contains("not running")
    );
}

#[test]
fn job_leader_exit_hangs_up_group_child() {
    let host = Host::start("job-child-hup", &[]);
    let pid_file = host.tmp.0.join("straggler.pid");
    let mut guard = KillPid::new(pid_file.clone());
    // The leader ends; the `sleep` it left in its group is hung up.
    let script = "sleep 60 & echo $! > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; echo done";
    let run = [
        "--name",
        "spawner",
        "--",
        "/bin/sh",
        "-c",
        script,
        "_",
        pid_file.to_str().unwrap(),
    ];
    assert!(job_cmd(&host, "run", &run, 20).status.success());
    let waited = job_cmd(&host, "wait", &["spawner", "--timeout", "10"], 20);
    assert!(waited.status.success() && waited.stdout == b"done\n");
    guard.dead_within(20, "straggler child left by job leader");
}

#[test]
fn job_reader_never_mixes_replacement_run() {
    let host = Host::start("job-replace-race", &[]);
    let jobs = host.sessions.parent().unwrap().join("koh-jobs");
    // Two runs; the second is put in the first's place while a follower reads the first.
    for (name, msg) in [("rep", "OLD_RUN"), ("rep_new", "NEW_RUN")] {
        let script = format!("printf '{msg}\\n'; sleep 30");
        let run = ["--name", name, "--", "/bin/sh", "-c", &script];
        assert!(job_cmd(&host, "run", &run, 20).status.success());
        let out = jobs.join(name).join("out");
        until("marker written", || {
            fs::read(&out)
                .unwrap_or_default()
                .starts_with(msg.as_bytes())
        });
    }
    let mut follower = host.spawned("logs", &["rep", "-f"]);
    let out = follower.stdout.take().unwrap();
    let (seen, out) = read_exact_bounded::<8, _>(out, &mut follower, 20, "OLD_RUN");
    assert_eq!(&seen, b"OLD_RUN\n");
    // The old run, which runs on, is moved away whole (a folder removed file by file is, for a
    // moment, a run with no state), and the new put in its place.
    let pane = jobs.join("rep");
    fs::rename(&pane, jobs.join("rep_old")).unwrap();
    fs::rename(jobs.join("rep_new"), &pane).unwrap();
    // The follower has none of the new run: it says the job was started anew.
    let (rest, said) = (drain(out), drain(follower.stderr.take().unwrap()));
    let st = wait_child(&mut follower, 20, "follower after replace");
    let (rest, said) = (
        rest.join().unwrap(),
        String::from_utf8(said.join().unwrap()).unwrap(),
    );
    assert!(
        st.code() == Some(1)
            && said.contains("started anew")
            && !String::from_utf8_lossy(&rest).contains("NEW_RUN"),
        "{st:?} {said}"
    );
}

#[test]
fn job_logs_broken_pipe_and_non_utf8_wait_tail() {
    let host = Host::start("job-io-edge", &[]);
    // `logs -f` to a reader that takes a byte and closes its pipe ends with 141.
    // (It writes until it is killed: there is more to write once the pipe is closed.)
    let script = "while :; do echo LINE; sleep 0.02; done";
    let run = ["--name", "chatter", "--", "/bin/sh", "-c", script];
    assert!(job_cmd(&host, "run", &run, 20).status.success());
    let mut follow = host.spawned("logs", &["chatter", "-f"]);
    let out = follow.stdout.take().unwrap();
    let (byte, out) = read_exact_bounded::<1, _>(out, &mut follow, 20, "first byte");
    assert_eq!(&byte, b"L");
    drop(out);
    assert_eq!(
        wait_child(&mut follow, 20, "logs -f, its pipe closed").code(),
        Some(141)
    );
    let _ = job_cmd(&host, "kill", &["chatter", "--signal", "9"], 20);
    // Output that is no UTF-8 (3 MiB of 0xff, some 9 MiB, over a frame, if each were made a
    // replacement character): `wait --tail 1` has the job's code all the same.
    let script = "dd if=/dev/zero bs=1048576 count=3 2>/dev/null | tr '\\000' '\\377'; exit 7";
    let run = ["--name", "binff", "--", "/bin/sh", "-c", script];
    assert!(job_cmd(&host, "run", &run, 20).status.success());
    let waited = job_cmd(
        &host,
        "wait",
        &["binff", "--tail", "1", "--timeout", "20"],
        25,
    );
    assert_eq!(waited.status.code(), Some(7));
}

#[test]
fn job_run_name_lifecycle_and_start_errors() {
    let host = Host::start("job-lifecycle", &[]);
    let run = |args: &[&str]| job_cmd(&host, "run", args, 20);
    let code = |args: &[&str]| run(args).status.code();
    // A name that is no session's name (fux's own among them) is a usage error.
    for bad in [
        "-",
        "colours",
        "keyboard",
        "layout",
        ".hidden",
        "a/b",
        &"x".repeat(65),
    ] {
        assert_eq!(code(&["--name", bad, "--", "true"]), Some(2), "{bad}");
    }
    // A name that runs is refused; once it has ended, it is started anew.
    assert_eq!(code(&["--name", "dup", "--", "sleep", "30"]), Some(0));
    let refused = run(&["--name", "dup", "--", "true"]);
    assert_eq!(refused.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("already running"));
    let killed = job_cmd(&host, "kill", &["dup", "--signal", "9"], 20);
    assert!(killed.status.success());
    // Killed by the signal it was told: `killed 9`, and its wait is 128 + 9.
    let waited = job_cmd(&host, "wait", &["dup", "--timeout", "10"], 20);
    let said = String::from_utf8_lossy(&waited.stderr);
    assert_eq!(waited.status.code(), Some(137), "{said}");
    assert!(said.contains("killed 9"), "{said}");
    assert_eq!(code(&["--name", "dup", "--", "echo", "second"]), Some(0));
    let second = || job_cmd(&host, "wait", &["dup", "--timeout", "10"], 20);
    assert!(second().status.success() && second().stdout == b"second\n");
    // A folder to start in that is not there is 126, and is refused before the ended run of
    // that name is removed; a program that is not there is 127, and leaves no folder.
    let nowhere = ["-C", "/no/such/koh-job-dir", "--name", "dup", "--", "true"];
    assert_eq!(code(&nowhere), Some(126));
    assert_eq!(second().stdout, b"second\n");
    assert_eq!(
        code(&["--name", "nf", "--", "/no/such/koh-job-prog"]),
        Some(127)
    );
    assert!(!host.sessions.parent().unwrap().join("koh-jobs/nf").exists());
}

#[test]
fn job_logs_follow_ends_when_leftover_child_keeps_writing() {
    let host = Host::start("job-follow-leftover", &[]);
    let pid_file = host.tmp.0.join("yes.pid");
    let guard = KillPid::new(pid_file.clone());
    // The leader leaves a `yes` that ignores SIGHUP and goes on writing to `out`, and ends
    // with 3: `logs -f --tail 10` ends with 3 when the leader does.
    let script = "trap '' HUP; yes & echo $! > \"$1.tmp\" && mv \"$1.tmp\" \"$1\"; exit 3";
    let run = [
        "--name",
        "noisy",
        "--",
        "/bin/sh",
        "-c",
        script,
        "_",
        pid_file.to_str().unwrap(),
    ];
    assert!(job_cmd(&host, "run", &run, 20).status.success());
    guard.pid();
    let mut follow = host.spawned("logs", &["noisy", "--tail", "10", "-f"]);
    let out = drain(follow.stdout.take().unwrap());
    let st = wait_child(&mut follow, 20, "logs -f with noisy leftover child");
    assert!(!out.join().unwrap().is_empty());
    assert_eq!(st.code(), Some(3));
}
