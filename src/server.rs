//! `koh serve`: QUIC listener, TLS-bound client auth, scoped authorization,
//! raw exec, headless jobs, delta sync, and fux-backed interactive sessions.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::Semaphore;
use tokio::time::{Instant, timeout_at};

use crate::jobs::JobManager;
use crate::keys::{
    ClientEntry, Role, Scope, expand_home, hold_for_serving, home_dir, load_clients,
    load_or_create_key, render_qr,
};
use crate::net::{bind_server, close_with, verify_client};
use crate::pane::{AttachSpec, PaneSession, SessionManager};
use crate::proto::{
    ClientEvent, CloseCode, ExecClientMsg, ExecServerMsg, LogMsg, MAX_CHUNK, MAX_CTRL, MAX_FRAME,
    Reply, Request, ScreenFrame, ServerEvent, SyncMsg, recv_msg, send_msg, spawn_msg_reader,
};
use crate::sync::{receive_tree, send_tree};
use crate::{Exit, KohError, Result};

pub struct ServeOptions {
    pub key_file: Option<PathBuf>,
    pub direct: Option<SocketAddr>,
    pub allow: Vec<EndpointId>,
    pub shell: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub disable_relay: bool,
    pub quiet: bool,
    /// Most connections held at once, each counted from when the server takes it up, before it
    /// proves a key.
    pub max_connections: usize,
    /// Most sessions kept at once, running or ended.
    pub max_sessions: usize,
    /// How long a connection has, from when the server takes it up, to finish its handshake and
    /// prove a key the server allows before it is closed.
    pub proof_timeout: Duration,
}

/// How long a connection turned away as busy has, from when the server takes it up, to connect
/// and ask: it is told as soon as it asks, and at the latest then. One that has not connected by
/// then is dropped without being told.
const BUSY_WAIT: Duration = Duration::from_secs(2);

/// The time `long` after `from`. More than thirty years is thirty years, the timer's own "never":
/// a time the clock cannot say (`Duration::MAX` is one) would panic where it is added. (And were
/// the clock itself that near its end, the time is `from`: a deadline that has come.)
fn after(from: Instant, long: Duration) -> Instant {
    const NEVER: Duration = Duration::from_secs(30 * 365 * 86_400);
    from.checked_add(long.min(NEVER)).unwrap_or(from)
}

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
    default_shell: String,
    jobs: Arc<Mutex<JobManager>>,
    sessions: Arc<Mutex<SessionManager>>,
    proof_timeout: Duration,
}

impl ServerState {
    fn authorize(&self, id: EndpointId) -> Result<Scope> {
        if self.extra_allow.contains(&id) {
            return Ok(Scope::Full);
        }
        let clients: Vec<ClientEntry> = load_clients(self.key_file.as_deref())?;
        if let Some(entry) = clients.into_iter().find(|c| c.id == id) {
            return Ok(entry.scope);
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
    /// Stops taking connections, lets go of the key and closes the endpoint.
    pub async fn shutdown(mut self) {
        self.task.abort();
        // (Until what took connections is gone, and the lock with it: the key is free when this returns.)
        let _ = (&mut self.task).await;
        self.endpoint.close().await;
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
    let endpoint = bind_server(secret, opts.direct, opts.disable_relay).await?;
    let direct_addr = endpoint.bound_sockets().into_iter().next();

    let base = match opts.state_dir {
        Some(dir) => dir,
        None => default_state_dir(&serving)?,
    };
    let jobs = Arc::new(Mutex::new(JobManager::new(base.join("jobs"))?));
    let sessions = SessionManager::new(base.join("sessions"), max_sessions)?;
    let sessions = Arc::new(Mutex::new(sessions));
    let default_shell = opts
        .shell
        .or_else(|| std::env::var("SHELL").ok().filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "/bin/sh".to_string());

    let state = Arc::new(ServerState {
        key_file: opts.key_file,
        extra_allow: opts.allow,
        default_shell,
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
        let _ = writeln!(err, "sessions dir:  {}", base.join("sessions").display());
        let _ = writeln!(err, "{}", render_qr(&endpoint_id));
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
        while let Some(incoming) = ep_accept.accept().await {
            let came = Instant::now();
            if let Ok(place) = places.clone().try_acquire_owned() {
                let (st, prove_by) = (state.clone(), after(came, state.proof_timeout));
                tokio::spawn(async move {
                    // (A handshake that is dropped is gone: the transport closes it.)
                    if let Ok(Ok(conn)) = timeout_at(prove_by, incoming.into_future()).await {
                        handle_connection(conn, st, prove_by).await;
                    }
                    drop(place);
                });
            } else if let Ok(place) = turned_away.clone().try_acquire_owned() {
                tokio::spawn(async move {
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
    let _ = tokio::signal::ctrl_c().await;
    running.shutdown().await;
    Ok(())
}

/// Where jobs and sessions are kept when no `--state-dir` says: in the user's runtime directory,
/// or else in the temporary directory under the user's number. (std does not tell who runs
/// this process; the owner of `serving`, the lock file this server made beside its key, does.)
fn default_state_dir(serving: &fs::File) -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR")
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir).join("koh"));
    }
    let uid = serving
        .metadata()
        .map_err(|e| KohError::failed(format!("stat the serve lock: {e}")))?
        .uid();
    Ok(std::env::temp_dir().join(format!("koh-{uid}")))
}

/// Serves a connection's requests until it is gone. It is closed if by `prove_by` (so long after
/// the server took it up) no request of it has proved a key the server allows: a peer that
/// proves nothing does not keep its place.
async fn handle_connection(conn: Connection, state: Arc<ServerState>, prove_by: Instant) {
    let proven = Arc::new(AtomicBool::new(false));
    let deadline = tokio::time::sleep_until(prove_by);
    tokio::pin!(deadline);
    let mut unproven = true;
    loop {
        let (mut send, mut recv) = tokio::select! {
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
        tokio::spawn(async move {
            let client_id = match verify_client(&conn_clone, &mut recv).await {
                Ok(id) => id,
                Err(_) => {
                    close_with(&conn_clone, CloseCode::Refused);
                    return;
                }
            };
            let scope = match st.authorize(client_id) {
                Ok(scope) => scope,
                Err(err) => {
                    let _ = send_msg(&mut send, &Reply::from_err(&err), MAX_CTRL).await;
                    let _ = send.finish();
                    close_with(&conn_clone, CloseCode::Refused);
                    return;
                }
            };
            proven.store(true, Ordering::Relaxed);
            let req: Request = match recv_msg(&mut recv, MAX_CTRL).await {
                Ok(r) => r,
                Err(_) => {
                    close_with(&conn_clone, CloseCode::Protocol);
                    return;
                }
            };
            if let Err(err) = dispatch(req, scope, &st, &mut send, recv).await {
                let _ = send_msg(&mut send, &Reply::from_err(&err), MAX_CTRL).await;
            }
            let _ = send.finish();
        });
    }
}

fn resolve_cwd(cwd: Option<&str>) -> Result<PathBuf> {
    match cwd {
        Some(dir) => expand_home(Path::new(dir)),
        None => home_dir(),
    }
}

async fn dispatch(
    req: Request,
    scope: Scope,
    state: &ServerState,
    send: &mut SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    match req {
        Request::Exec { argv, cwd, shell } => {
            let dir = resolve_cwd(cwd.as_deref())?;
            scope.check_exec(&dir)?;
            handle_exec(&argv, &dir, shell, send, recv).await
        }
        Request::Run {
            name,
            argv,
            cwd,
            shell,
        } => {
            let dir = resolve_cwd(cwd.as_deref())?;
            scope.check_exec(&dir)?;
            let info = JobManager::start(&state.jobs, name, &argv, &dir, shell)?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &info, MAX_CTRL).await
        }
        Request::Jobs { name } => {
            scope.check_full()?;
            let list = {
                let guard = state
                    .jobs
                    .lock()
                    .map_err(|_| KohError::internal("jobs lock"))?;
                guard.list(name.as_deref())?
            };
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &list, MAX_CTRL).await
        }
        Request::Logs {
            name,
            tail,
            all,
            follow,
        } => {
            scope.check_full()?;
            let handle = {
                let guard = state
                    .jobs
                    .lock()
                    .map_err(|_| KohError::internal("jobs lock"))?;
                guard.get(&name)?
            };
            let (log_path, mut rx, started) = (handle.log_path, handle.state_rx, handle.started);
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            let initial =
                crate::jobs::read_log_tail(&log_path, if all { None } else { tail.or(Some(200)) })?;
            let mut offset = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
            if !initial.is_empty() {
                for chunk in initial.chunks(64 << 10) {
                    send_msg(send, &LogMsg::Data(chunk.to_vec()), MAX_CHUNK).await?;
                }
            }
            if follow {
                loop {
                    let meta_len = fs::metadata(&log_path).map(|m| m.len()).unwrap_or(offset);
                    if meta_len > offset
                        && let Ok(mut f) = fs::File::open(&log_path)
                    {
                        use std::io::{Read as _, Seek as _, SeekFrom};
                        if f.seek(SeekFrom::Start(offset)).is_ok() {
                            let mut buf = vec![0u8; 64 << 10];
                            while let Ok(n @ 1..) = f.read(&mut buf) {
                                if let Some(slice) = buf.get(..n) {
                                    send_msg(send, &LogMsg::Data(slice.to_vec()), MAX_CHUNK)
                                        .await?;
                                }
                                offset += n as u64;
                            }
                        }
                    }
                    let (st, exit) = rx.borrow().clone();
                    if st != "running" {
                        send_msg(
                            send,
                            &LogMsg::Done {
                                state: st,
                                exit,
                                age_secs: started.elapsed().as_secs(),
                            },
                            MAX_CTRL,
                        )
                        .await?;
                        break;
                    }
                    tokio::select! {
                        _ = rx.changed() => {}
                        () = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
                    }
                }
            } else {
                let (st, exit) = rx.borrow().clone();
                send_msg(
                    send,
                    &LogMsg::Done {
                        state: st,
                        exit,
                        age_secs: started.elapsed().as_secs(),
                    },
                    MAX_CTRL,
                )
                .await?;
            }
            Ok(())
        }
        Request::Kill { name, signal } => {
            scope.check_full()?;
            let info = {
                let guard = state
                    .jobs
                    .lock()
                    .map_err(|_| KohError::internal("jobs lock"))?;
                guard.kill(&name, signal)?
            };
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &info, MAX_CTRL).await
        }
        Request::WaitJob {
            name,
            text,
            tail,
            timeout_secs,
        } => {
            scope.check_full()?;
            let handle = {
                let guard = state
                    .jobs
                    .lock()
                    .map_err(|_| KohError::internal("jobs lock"))?;
                guard.get(&name)?
            };
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            let res =
                crate::jobs::wait_job(handle.log_path, handle.state_rx, text, tail, timeout_secs)
                    .await?;
            send_msg(send, &res, MAX_FRAME).await
        }
        Request::CpPush {
            dst,
            excludes,
            delete,
            preserve_mtime,
            dry_run,
        } => {
            let dst = expand_home(Path::new(&dst))?;
            scope.check_cp(&dst)?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            let landed = receive_tree(
                &dst,
                &excludes,
                delete,
                preserve_mtime,
                dry_run,
                send,
                &mut recv,
            )
            .await;
            say_failure(send, landed).await;
            Ok(())
        }
        Request::CpPull {
            src,
            excludes,
            preserve_root,
            ..
        } => {
            let src = expand_home(Path::new(&src))?;
            scope.check_cp(&src)?;
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            let sent = send_tree(&src, &excludes, preserve_root, send, &mut recv).await;
            say_failure(send, sent).await;
            Ok(())
        }
        Request::Sessions => {
            scope.check_full()?;
            let list = {
                let guard = state
                    .sessions
                    .lock()
                    .map_err(|_| KohError::internal("sessions lock"))?;
                guard.list()
            };
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &list, MAX_CTRL).await
        }
        Request::Output { session, last } => {
            scope.check_full()?;
            let sess = {
                let guard = state
                    .sessions
                    .lock()
                    .map_err(|_| KohError::internal("sessions lock"))?;
                guard.get(session)?
            };
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            send_msg(send, &sess.output(last), MAX_FRAME).await
        }
        Request::WaitSession {
            session,
            timeout_secs,
        } => {
            scope.check_full()?;
            let sess = {
                let guard = state
                    .sessions
                    .lock()
                    .map_err(|_| KohError::internal("sessions lock"))?;
                guard.get(session)?
            };
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            let res = sess.wait_command(timeout_secs).await?;
            send_msg(send, &res, MAX_FRAME).await
        }
        Request::Attach {
            session,
            new,
            cols,
            rows,
            cell_w,
            cell_h,
            argv,
            cwd,
        } => {
            scope.check_full()?;
            let dir = resolve_cwd(cwd.as_deref())?;
            let (sess, created_new, _attached) = {
                let mut guard = state
                    .sessions
                    .lock()
                    .map_err(|_| KohError::internal("sessions lock"))?;
                guard.attach_or_create(AttachSpec {
                    requested: session,
                    new,
                    cols,
                    rows,
                    cell_w,
                    cell_h,
                    argv: &argv,
                    cwd: &dir,
                    default_shell: &state.default_shell,
                })?
            };
            send_msg(send, &Reply::Ok, MAX_CTRL).await?;
            // On reattach to an existing session, don't replay stale pre-existing bell/clipboard.
            let (mut last_clip_seq, mut last_notice_seq) = if created_new {
                (0, 0)
            } else {
                sess.current_event_seqs()
            };
            let mut sent_pics = BTreeSet::new();
            let mut last_sent: Option<ScreenFrame> = None;

            let mut rx = sess.subscribe();
            sess.resize(cols, rows, cell_w, cell_h);

            // Send initial frame immediately.
            let initial = rx.borrow_and_update().clone();
            let ended = initial.state != "running";
            send_frame_update(
                &sess,
                initial,
                &mut last_sent,
                &mut sent_pics,
                &mut last_clip_seq,
                &mut last_notice_seq,
                send,
            )
            .await?;
            // A session whose program has ended changes no more: its screen was the last there is
            // to send. (Waiting for more would keep it attached for as long as its client stays.)
            if ended {
                return Ok(());
            }

            // Bridge client events -> PTY and watch frames -> client (cancel-safe reader task).
            let mut client_rx = spawn_msg_reader::<ClientEvent>(recv, MAX_CHUNK);
            loop {
                tokio::select! {
                    changed = rx.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let frame = rx.borrow_and_update().clone();
                        let done = frame.state != "running";
                        if send_frame_update(
                            &sess,
                            frame,
                            &mut last_sent,
                            &mut sent_pics,
                            &mut last_clip_seq,
                            &mut last_notice_seq,
                            send,
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                        if done {
                            break;
                        }
                    }
                    ev = client_rx.recv() => {
                        match ev {
                            Some(Ok(ClientEvent::Input(bytes))) => {
                                let _ = sess.write_input(&bytes);
                            }
                            Some(Ok(ClientEvent::Resize { cols, rows, cell_w, cell_h })) => {
                                sess.resize(cols, rows, cell_w, cell_h);
                            }
                            Some(Ok(ClientEvent::Colours(text))) => {
                                sess.set_colours(&text);
                            }
                            Some(Ok(ClientEvent::Keyboard(flags))) => {
                                sess.set_keyboard(flags);
                            }
                            Some(Ok(ClientEvent::Detach)) | Some(Err(_)) | None => break,
                        }
                    }
                }
            }
            Ok(())
        }
    }
}

/// Tells the other end of a copy why this end stopped: the answer to its request was sent
/// before the copy began, so the reason goes as a message of the copy.
async fn say_failure<T>(send: &mut SendStream, done: Result<T>) {
    if let Err(err) = done {
        let _ = send_msg(send, &SyncMsg::Failed((&err).into()), MAX_CTRL).await;
    }
}

async fn send_frame_update(
    sess: &PaneSession,
    mut frame: ScreenFrame,
    last_sent: &mut Option<ScreenFrame>,
    sent_pics: &mut BTreeSet<u32>,
    last_clip_seq: &mut u64,
    last_notice_seq: &mut u64,
    send: &mut SendStream,
) -> Result<()> {
    // Transfer each referenced picture payload at most once per attach stream.
    let active_ids = frame.referenced_picture_ids();
    for id in &active_ids {
        if sent_pics.insert(*id)
            && let Some(blob) = sess.picture_blob(*id)
        {
            send_msg(send, &ServerEvent::Picture(blob), MAX_FRAME).await?;
        }
    }
    sent_pics.retain(|id| active_ids.contains(id));

    if let Some((seq, bytes)) = sess.clipboard_since(*last_clip_seq) {
        *last_clip_seq = seq;
        frame.clipboard_seq = seq;
        frame.clipboard = Some(bytes);
    } else {
        frame.clipboard_seq = *last_clip_seq;
        frame.clipboard = None;
    }
    if let Some((seq, msg)) = sess.notice_since(*last_notice_seq) {
        *last_notice_seq = seq;
        frame.notice_seq = seq;
        frame.notice = Some(msg);
    } else {
        frame.notice_seq = *last_notice_seq;
        frame.notice = None;
    }

    let event = match last_sent.as_ref().and_then(|prev| frame.diff(prev)) {
        Some(delta) => ServerEvent::Delta(delta),
        None => ServerEvent::Full(frame.clone()),
    };
    send_msg(send, &event, MAX_FRAME).await?;

    frame.clipboard = None;
    frame.notice = None;
    *last_sent = Some(frame);
    Ok(())
}

/// Raw non-PTY exec: separate stdout/stderr, binary-clean, stdin EOF, and SIGHUP on client drop.
async fn handle_exec(
    argv: &[String],
    cwd: &Path,
    shell: bool,
    send: &mut SendStream,
    recv: RecvStream,
) -> Result<()> {
    let mut std_cmd = crate::jobs::build_command(argv, cwd, shell)?;
    fuxix::new_session(&mut std_cmd, false);
    let mut cmd = tokio::process::Command::from(std_cmd);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        let code = if e.kind() == std::io::ErrorKind::NotFound {
            Exit::NOT_FOUND
        } else {
            Exit::CANNOT_START
        };
        KohError::new(code, "cannot_start", format!("spawn exec: {e}"))
    })?;
    let pgid = child.id();
    send_msg(send, &Reply::Ok, MAX_CTRL).await?;

    let mut child_stdin = child.stdin.take();
    let mut child_stdout = child.stdout.take();
    let mut child_stderr = child.stderr.take();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<ExecServerMsg>(32);

    let tx1 = out_tx.clone();
    let stdout_task = tokio::spawn(async move {
        if let Some(mut out) = child_stdout.take() {
            let mut buf = vec![0u8; 32 << 10];
            while let Ok(n @ 1..) = out.read(&mut buf).await {
                if let Some(slice) = buf.get(..n)
                    && tx1
                        .send(ExecServerMsg::Stdout(slice.to_vec()))
                        .await
                        .is_err()
                {
                    break;
                }
            }
        }
    });
    let tx2 = out_tx.clone();
    let stderr_task = tokio::spawn(async move {
        if let Some(mut err) = child_stderr.take() {
            let mut buf = vec![0u8; 32 << 10];
            while let Ok(n @ 1..) = err.read(&mut buf).await {
                if let Some(slice) = buf.get(..n)
                    && tx2
                        .send(ExecServerMsg::Stderr(slice.to_vec()))
                        .await
                        .is_err()
                {
                    break;
                }
            }
        }
    });
    drop(out_tx);

    let mut disconnected = false;
    let mut stdin_open = true;
    let mut stdin_rx = spawn_msg_reader::<ExecClientMsg>(recv, MAX_CHUNK);
    loop {
        tokio::select! {
            msg = out_rx.recv() => {
                match msg {
                    Some(m) => {
                        if send_msg(send, &m, MAX_CHUNK).await.is_err() {
                            disconnected = true;
                            break;
                        }
                    }
                    None => break,
                }
            }
            ev = stdin_rx.recv(), if stdin_open => {
                match ev {
                    Some(Ok(ExecClientMsg::Stdin(bytes))) => {
                        if let Some(stdin) = child_stdin.as_mut() {
                            let _ = stdin.write_all(&bytes).await;
                        }
                    }
                    Some(Ok(ExecClientMsg::Eof)) => {
                        stdin_open = false;
                        drop(child_stdin.take());
                    }
                    Some(Err(_)) | None => {
                        disconnected = true;
                        drop(child_stdin.take());
                        break;
                    }
                }
            }
        }
    }

    if disconnected && let Some(pid) = pgid {
        let _ = crate::jobs::signal_group(pid, 1); // SIGHUP
    }
    let _ = stdout_task.await;
    let _ = stderr_task.await;
    let code = match child.wait().await {
        Ok(status) => status
            .code()
            .or_else(|| status.signal().map(|s| 128 + s))
            .unwrap_or(1),
        Err(_) => 1,
    };
    if !disconnected {
        let _ = send_msg(send, &ExecServerMsg::Exit(code), MAX_CTRL).await;
    }
    Ok(())
}
