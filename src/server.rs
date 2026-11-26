//! `koh serve`: QUIC listener, TLS-bound client auth,
//! raw exec, headless jobs, and sessions, which are fux panes (`session`).

use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::AsyncReadExt as _;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};

use crate::jobs::Jobs;
use crate::keys::{
    Role, expand_home, hold_for_serving, home_dir, load_clients, load_or_create_key,
};
use crate::net::{bind_server, close_with, verify_client};
use crate::proto::{
    CloseCode, ExecServerMsg, MAX_CHUNK, MAX_CTRL, Reply, Request, encode, recv_msg, send_msg,
    send_pieces,
};
use crate::session::Sessions;
use crate::{Exit, KohError, Result, after};

pub struct ServeOptions {
    pub key_file: Option<PathBuf>,
    pub direct: Option<SocketAddr>,
    pub allow: Vec<EndpointId>,
    pub shell: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub disable_relay: bool,
    /// An endpoint that is there, of the server's key, in place of one bound here: a test's,
    /// on a link of its own. `koh serve` gives none.
    pub endpoint: Option<iroh::Endpoint>,
    /// This binary, where the process that serves is another: a test's. It is run as fux, as a
    /// session's holder and as its viewer. `koh serve` gives none.
    pub session_exe: Option<PathBuf>,
    pub quiet: bool,
    /// Most connections held at once, each counted from when the server takes it up, before it
    /// proves a key.
    pub max_connections: usize,
    /// Most sessions kept at once, running or ended: folders in the sessions' folder.
    pub max_sessions: usize,
    /// How long a connection has, from when the server takes it up, to finish its handshake and
    /// prove a key the server allows before it is closed.
    pub proof_timeout: Duration,
}

/// How long a connection turned away as busy has, from when the server takes it up, to connect
/// and ask: it is told as soon as it asks, and at the latest then. One that has not connected by
/// then is dropped without being told.
const BUSY_WAIT: Duration = Duration::from_secs(2);

/// How long the requests of a connection that is gone have to end by themselves, before they
/// are ended: the connection keeps its place until none is left.
const LEFT_WAIT: Duration = Duration::from_secs(5);

/// How long an `exec` command whose client left has after SIGHUP before its group gets SIGKILL.
const HANGUP_WAIT: Duration = Duration::from_secs(2);

/// The CLI's default for `--max-connections`.
const DEFAULT_MAX_CONNECTIONS: usize = 64;
/// The CLI's default for `--max-sessions`.
const DEFAULT_MAX_SESSIONS: usize = 64;

/// `n` as a cap that `flag` may set: from 1 to 65535.
pub fn cap(flag: &str, n: usize) -> Result<usize> {
    if (1..=65_535).contains(&n) {
        Ok(n)
    } else {
        Err(KohError::usage(format!(
            "{flag} takes a number from 1 to 65535"
        )))
    }
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            key_file: None,
            direct: None,
            allow: Vec::new(),
            shell: None,
            state_dir: None,
            disable_relay: false,
            endpoint: None,
            session_exe: None,
            quiet: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            proof_timeout: Duration::from_secs(10),
        }
    }
}

struct ServerState {
    key_file: Option<PathBuf>,
    extra_allow: Vec<EndpointId>,
    jobs: Jobs,
    sessions: Sessions,
    proof_timeout: Duration,
}

impl ServerState {
    fn authorize(&self, id: EndpointId) -> Result<()> {
        if self.extra_allow.contains(&id) {
            return Ok(());
        }
        let clients = load_clients(self.key_file.as_deref(), |_, _| {})?;
        if clients.iter().any(|c| c.id == id) {
            return Ok(());
        }
        Err(KohError::refused("client key is not in clients list"))
    }
}

pub struct RunningServer {
    pub endpoint_id: EndpointId,
    pub direct_addr: Option<SocketAddr>,
    pub endpoint: iroh::Endpoint,
    /// What takes this server's connections. It holds the lock that keeps a second server off the
    /// key, so the key is held exactly for as long as connections are taken.
    task: tokio::task::JoinHandle<()>,
}

impl RunningServer {
    /// Closes the endpoint, waits for connection tasks (and active exec hangups) to finish,
    /// and lets go of the key.
    pub async fn shutdown(mut self) {
        self.endpoint.close().await;
        let _ = (&mut self.task).await;
    }
}

/// A server that is dropped takes no more connections, and so lets go of its key.
impl Drop for RunningServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Starts a server in-process (used by both `koh serve` CLI and loopback integration tests).
pub async fn start_server(opts: ServeOptions) -> Result<RunningServer> {
    let max_connections = cap("--max-connections", opts.max_connections)?;
    let max_sessions = cap("--max-sessions", opts.max_sessions)?;
    let secret = load_or_create_key(Role::Server, opts.key_file.as_deref())?;
    let serving = hold_for_serving(opts.key_file.as_deref())?;
    let endpoint_id = secret.public();
    let endpoint = match opts.endpoint {
        Some(endpoint) => endpoint,
        None => bind_server(secret, opts.direct, opts.disable_relay).await?,
    };
    let direct_addr = endpoint.bound_sockets().into_iter().next();

    let base = opts.state_dir.unwrap_or_else(default_state_dir);
    let default_shell = opts
        .shell
        .or_else(|| std::env::var("SHELL").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "/bin/sh".to_string());
    let sessions = Sessions::new(&base, max_sessions, default_shell, opts.session_exe)?;
    let jobs = Jobs::new(&base, sessions.exe())?;
    let sessions_dir = sessions.dir().to_path_buf();

    let state = Arc::new(ServerState {
        key_file: opts.key_file,
        extra_allow: opts.allow,
        jobs,
        sessions,
        proof_timeout: opts.proof_timeout,
    });

    if !opts.quiet {
        let mut err = std::io::stderr().lock();
        let _ = writeln!(err, "koh server id: {endpoint_id}");
        if let Some(addr) = direct_addr {
            let _ = writeln!(err, "listening:     {addr}");
        }
        let _ = writeln!(err, "sessions dir:  {}", sessions_dir.display());
    }

    // A connection holds one of `max_connections` places from when it is taken up here, before
    // anything is known of the peer, until it is gone; and it has `proof_timeout` from then to
    // finish its handshake and prove a key the server allows, or its place is the next one's.
    // (That is when this loop comes to it, after its first packet: the time the packet waited for
    // the loop is not counted.) With no place free, as many more are let connect, in `BUSY_WAIT`
    // at most, only to be told the server is busy; past those, a peer is refused unheard.
    let places = Arc::new(Semaphore::new(max_connections));
    let turned_away = Arc::new(Semaphore::new(max_connections));
    let ep_accept = endpoint.clone();
    let task = tokio::spawn(async move {
        let _serving = serving;
        let mut connections = JoinSet::new();
        loop {
            let incoming = tokio::select! {
                Some(_) = connections.join_next() => continue,
                incoming = ep_accept.accept() => incoming,
            };
            let Some(incoming) = incoming else { break };
            let came = Instant::now();
            if let Ok(place) = places.clone().try_acquire_owned() {
                let (st, prove_by) = (state.clone(), after(came, state.proof_timeout));
                connections.spawn(async move {
                    // (A handshake that is dropped is gone: the transport closes it.)
                    if let Ok(Ok(conn)) = timeout_at(prove_by, incoming.into_future()).await {
                        handle_connection(conn, st, prove_by).await;
                    }
                    drop(place);
                });
            } else if let Ok(place) = turned_away.clone().try_acquire_owned() {
                connections.spawn(async move {
                    let told_by = after(came, BUSY_WAIT);
                    if let Ok(Ok(conn)) = timeout_at(told_by, incoming.into_future()).await {
                        // (Once the client has connected and asks, so that it reads why.)
                        let _ = timeout_at(told_by, conn.accept_bi()).await;
                        close_with(&conn, CloseCode::Busy);
                    }
                    drop(place);
                });
            } else {
                incoming.refuse();
            }
        }
        while connections.join_next().await.is_some() {}
    });

    Ok(RunningServer {
        endpoint_id,
        direct_addr,
        endpoint,
        task,
    })
}

/// CLI entrypoint for `koh serve`.
pub async fn run_serve(opts: ServeOptions) -> Result<()> {
    fuxix::own_children();
    let running = start_server(opts).await?;
    // (Told to end as a service is, it closes as on Ctrl-C: its clients hear of it at once.)
    let told = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    let mut told = told.map_err(|e| KohError::failed(format!("SIGTERM: {e}")))?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = told.recv() => {}
    }
    running.shutdown().await;
    Ok(())
}

/// Where jobs and sessions are kept when no `--state-dir` says: in the user's runtime directory,
/// or else in the temporary directory under the effective user id (`fuxix::uid`).
fn default_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir).join("koh");
    }
    std::env::temp_dir().join(format!("koh-{}", fuxix::uid()))
}

/// Serves a connection's requests until it is gone. It is closed if by `prove_by` (so long after
/// the server took it up) no request of it has proved a key the server allows: a peer that
/// proves nothing does not keep its place.
///
/// Each request is a task of the connection's own, and no task of a request is started but as
/// one of these or of its request's: when this returns none is left, so the place its caller
/// then gives back is one that nothing uses. Once the connection is gone they have `LEFT_WAIT`
/// to end, and what has not ended by then is ended.
async fn handle_connection(conn: Connection, state: Arc<ServerState>, prove_by: Instant) {
    let proven = Arc::new(AtomicBool::new(false));
    let deadline = tokio::time::sleep_until(prove_by);
    tokio::pin!(deadline);
    let mut unproven = true;
    let mut requests = JoinSet::new();
    loop {
        let (mut send, mut recv) = tokio::select! {
            // (One that has ended is kept no longer.)
            Some(_) = requests.join_next() => continue,
            () = &mut deadline, if unproven => {
                if !proven.load(Ordering::Relaxed) {
                    close_with(&conn, CloseCode::Refused);
                    break;
                }
                unproven = false;
                continue;
            }
            accepted = conn.accept_bi() => match accepted {
                Ok(streams) => streams,
                Err(_) => break,
            },
        };
        let conn_clone = conn.clone();
        let st = state.clone();
        let proven = proven.clone();
        requests.spawn(async move {
            let client_id = match verify_client(&conn_clone, &mut recv).await {
                Ok(id) => id,
                Err(_) => {
                    close_with(&conn_clone, CloseCode::Refused);
                    return;
                }
            };
            if let Err(err) = st.authorize(client_id) {
                let _ = send_msg(&mut send, &Reply::from_err(&err), MAX_CTRL).await;
                let _ = send.finish();
                close_with(&conn_clone, CloseCode::Refused);
                return;
            }
            proven.store(true, Ordering::Relaxed);
            let req: Request = match recv_msg(&mut recv, MAX_CTRL).await {
                Ok(r) => r,
                Err(_) => {
                    close_with(&conn_clone, CloseCode::Protocol);
                    return;
                }
            };
            if let Err(err) = dispatch(req, &st, &mut send, recv).await {
                let _ = send_msg(&mut send, &Reply::from_err(&err), MAX_CTRL).await;
            }
            let _ = send.finish();
        });
    }
    let ended = async { while requests.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(LEFT_WAIT, ended).await;
    requests.shutdown().await;
}

fn resolve_cwd(cwd: Option<&str>) -> Result<PathBuf> {
    match cwd {
        Some(dir) => expand_home(Path::new(dir)),
        None => home_dir(),
    }
}

async fn dispatch(
    req: Request,
    state: &ServerState,
    send: &mut SendStream,
    recv: RecvStream,
) -> Result<()> {
    match req {
        Request::Exec { argv, cwd } => {
            let dir = resolve_cwd(cwd.as_deref())?;
            handle_exec(&argv, &dir, send, recv).await
        }
        Request::Run { name, argv, cwd } => {
            let dir = resolve_cwd(cwd.as_deref())?;
            let info = state.jobs.run(name, argv, &dir).await?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &info, MAX_CTRL).await
        }
        Request::Jobs { name } => {
            let list = state.jobs.list(name).await?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &list, MAX_CTRL).await
        }
        Request::Logs {
            name,
            tail,
            all,
            follow,
        } => state.jobs.logs(&name, tail, all, follow, send).await,
        Request::Kill { name, signal } => {
            let info = state.jobs.kill(&name, signal).await?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &info, MAX_CTRL).await
        }
        Request::WaitJob {
            name,
            tail,
            timeout_secs,
        } => state.jobs.wait(&name, tail, timeout_secs, send).await,
        Request::Attach(asked) => {
            let dir = resolve_cwd(asked.cwd.as_deref())?;
            state.sessions.attach(asked, &dir, send, recv).await
        }
        // The three that read a session's folder.
        Request::Sessions => {
            let list = encode(&state.sessions.list().await?, usize::MAX)?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_pieces(send, &list).await
        }
        Request::Output { session, last } => {
            let text = state.sessions.output(&session, last).await?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_pieces(send, &text).await
        }
        Request::WaitSession {
            session,
            timeout_secs,
        } => state.sessions.wait(&session, timeout_secs, send).await,
    }
}

fn build_command(argv: &[String], cwd: &Path) -> Result<std::process::Command> {
    if !cwd.is_dir() {
        return Err(KohError::new(
            Exit::CANNOT_START,
            "cannot_start",
            format!("no such directory: {}", cwd.display()),
        ));
    }
    let Some((prog, args)) = argv.split_first() else {
        return Err(KohError::usage("missing command"));
    };
    let mut cmd = std::process::Command::new(prog);
    cmd.args(args).current_dir(cwd);
    Ok(cmd)
}

/// Raw non-PTY exec: separate stdout/stderr, raw stdin, and group hangup whenever the client goes.
async fn handle_exec(
    argv: &[String],
    cwd: &Path,
    send: &mut SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let mut std_cmd = build_command(argv, cwd)?;
    fuxix::new_session(&mut std_cmd, false);
    let mut child = tokio::process::Command::from(std_cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            let code = if e.kind() == std::io::ErrorKind::NotFound {
                Exit::NOT_FOUND
            } else {
                Exit::CANNOT_START
            };
            KohError::new(code, "cannot_start", format!("spawn exec: {e}"))
        })?;
    let pgid = child.id();

    let stdin = child.stdin.take();
    let input = async move {
        if let Some(mut pipe) = stdin {
            let _ = tokio::io::copy(&mut recv, &mut pipe).await;
        }
        drop(recv);
        std::future::pending::<()>().await
    };
    let stopped = send.stopped();
    let output = async {
        send_msg(send, &Reply::Ok, MAX_CTRL).await.ok()?;
        let (mut stdout, mut stderr) = (child.stdout.take(), child.stderr.take());
        let (mut out, mut err) = (vec![0u8; 32 << 10], vec![0u8; 32 << 10]);
        loop {
            let msg = tokio::select! {
                slice = exec_pipe(&mut stdout, &mut out), if stdout.is_some() => {
                    slice.ok()?.map(ExecServerMsg::Stdout)
                }
                slice = exec_pipe(&mut stderr, &mut err), if stderr.is_some() => {
                    slice.ok()?.map(ExecServerMsg::Stderr)
                }
                else => break,
            };
            if let Some(msg) = msg {
                send_msg(send, &msg, MAX_CHUNK).await.ok()?;
            }
        }
        let status = child.wait().await.ok()?;
        Some(
            status
                .code()
                .or_else(|| status.signal().map(|s| 128 + s))
                .unwrap_or(1),
        )
    };
    let done = tokio::select! {
        _ = stopped => None,
        done = output => done,
        () = input => None,
    };
    if let Some(code) = done {
        let _ = send_msg(send, &ExecServerMsg::Exit(code), MAX_CTRL).await;
    } else {
        hang_up(pgid, &mut child).await;
    }
    Ok(())
}

async fn exec_pipe<R: tokio::io::AsyncRead + Unpin>(
    pipe: &mut Option<R>,
    buf: &mut [u8],
) -> std::io::Result<Option<Vec<u8>>> {
    if let Some(reader) = pipe {
        let n = reader.read(buf).await?;
        if n > 0 {
            return Ok(buf.get(..n).map(<[u8]>::to_vec));
        }
    }
    *pipe = None;
    Ok(None)
}

/// Hangs up the command of a client that has gone: SIGHUP to its group, `HANGUP_WAIT`,
/// SIGKILL to its group, then reaps the leader (kept unreaped until the last signal so
/// its number stays pinned as the group's id).
async fn hang_up(pgid: Option<u32>, child: &mut tokio::process::Child) {
    let Some(pid) = pgid.and_then(|p| i32::try_from(p).ok()).filter(|&p| p > 1) else {
        return;
    };
    if let Err(err) = fuxix::signal_to(-pid, 1) {
        let said = format!("koh: a command whose client went was not hung up: {err}");
        let _ = writeln!(std::io::stderr(), "{said}");
    }
    tokio::time::sleep(HANGUP_WAIT).await;
    let _ = fuxix::signal_to(-pid, 9);
    let _ = child.wait().await;
}
