//! Client operations for koh: exec, headless jobs, delta cp/--sync, and sessions. A session
//! is mirrored here, a copy of its pane's folder on the server that koh makes and alone
//! writes (`carry::Mirror`): `koh mount` keeps one for any `fux view`, `cat` or script, and
//! `koh connect` shows a private one with fux's viewer in this process.

use std::collections::VecDeque;
use std::fs::{self, DirBuilder, File};
use std::hash::{BuildHasher as _, RandomState};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::fd::AsFd as _;
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayUrl, SecretKey};
use tokio::io::AsyncReadExt as _;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot, watch};

use crate::carry::{Fault, Mirror};
use crate::keys::{Role, load_or_create_key, resolve_server};
use crate::net::{close_error, connect_server, dial, map_conn_err, open_authed_stream};
use crate::proto::{
    Attach, Attached, ExecClientMsg, ExecServerMsg, FromMirror, JobInfo, LogMsg, MAX_CHUNK,
    MAX_CTRL, MAX_FRAME, MAX_HELD, MAX_TYPED, Reply, Request, SessionInfo, SyncSummary, ToMirror,
    WaitResult, decode, recv_msg, recv_msg_opt, recv_pieces, send_msg, session_name,
    spawn_msg_reader,
};
use crate::sync::{receive_tree, send_tree};
use crate::{Exit, KohError, Result};

#[derive(Clone, Debug, Default)]
pub struct DialOptions {
    pub key_file: Option<PathBuf>,
    pub direct: Option<SocketAddr>,
    pub relay: Option<RelayUrl>,
    pub json: bool,
}

/// Which session `koh connect` and `koh mount` ask for: one by its name, started if there is
/// none of it; or with no name the newest that lives, or a new one (always, with `new` or a
/// program).
#[derive(Clone, Debug, Default)]
pub struct ConnectOptions {
    pub session: Option<String>,
    pub new: bool,
    pub argv: Vec<String>,
    pub cwd: Option<String>,
}

pub struct Client {
    secret: SecretKey,
    endpoint: Endpoint,
    /// Where the server is, for a connection made anew on the same endpoint.
    addr: EndpointAddr,
    conn: Connection,
}

/// A session's text as it was sent, in pieces: what of it is no UTF-8 is shown as U+FFFD.
async fn text(recv: &mut RecvStream) -> Result<String> {
    let text = recv_pieces(recv).await?;
    Ok(String::from_utf8_lossy(&text).into_owned())
}

impl Client {
    pub async fn connect(target: &str, opts: &DialOptions, interactive: bool) -> Result<Self> {
        let secret = load_or_create_key(Role::Client, opts.key_file.as_deref())?;
        let (server_id, route) = resolve_server(
            target,
            opts.key_file.as_deref(),
            opts.direct,
            opts.relay.clone(),
        )?;
        Self::connect_direct(secret, server_id, route, interactive).await
    }

    pub async fn connect_direct(
        secret: SecretKey,
        server_id: iroh::EndpointId,
        route: Option<crate::keys::Route>,
        interactive: bool,
    ) -> Result<Self> {
        let (endpoint, addr, conn) =
            connect_server(secret.clone(), server_id, route, interactive).await?;
        Ok(Self {
            secret,
            endpoint,
            addr,
            conn,
        })
    }

    /// A new connection on the endpoint there is, after the one before was lost.
    pub async fn redial(&mut self) -> Result<()> {
        self.conn.close(0u32.into(), b"redial");
        self.conn = dial(&self.endpoint, self.addr.clone()).await?;
        Ok(())
    }

    /// Returns a handle to the active QUIC connection.
    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub async fn request(&self, req: &Request) -> Result<(SendStream, RecvStream)> {
        let (mut send, mut recv) = open_authed_stream(&self.conn, &self.secret).await?;
        send_msg(&mut send, req, MAX_CTRL)
            .await
            .map_err(|e| close_error(&self.conn).unwrap_or(e))?;
        let reply: Reply = recv_msg(&mut recv, MAX_CTRL)
            .await
            .map_err(|e| map_conn_err(&self.conn, e.message))?;
        reply.into_result()?;
        Ok((send, recv))
    }

    pub async fn close(self) {
        self.conn.close(0u32.into(), b"");
        self.endpoint.close().await;
    }

    /// Raw non-PTY exec with separate stdout/stderr, stdin EOF, and exit code passthrough.
    pub async fn exec(
        &self,
        argv: Vec<String>,
        cwd: Option<String>,
        shell: bool,
        stdin_bytes: Option<Vec<u8>>,
        capture_json: bool,
    ) -> Result<(i32, Vec<u8>, Vec<u8>)> {
        let (mut send, mut recv) = self.request(&Request::Exec { argv, cwd, shell }).await?;

        let stdin_task = tokio::spawn(async move {
            if let Some(data) = stdin_bytes {
                for chunk in data.chunks(32 << 10) {
                    if send_msg(&mut send, &ExecClientMsg::Stdin(chunk.to_vec()), MAX_CHUNK)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                let _ = send_msg(&mut send, &ExecClientMsg::Eof, MAX_CTRL).await;
            } else if !std::io::stdin().is_terminal() {
                let mut stdin = tokio::io::stdin();
                let mut buf = vec![0u8; 32 << 10];
                loop {
                    match stdin.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if let Some(slice) = buf.get(..n)
                                && send_msg(
                                    &mut send,
                                    &ExecClientMsg::Stdin(slice.to_vec()),
                                    MAX_CHUNK,
                                )
                                .await
                                .is_err()
                            {
                                return;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let _ = send_msg(&mut send, &ExecClientMsg::Eof, MAX_CTRL).await;
            } else {
                let _ = send_msg(&mut send, &ExecClientMsg::Eof, MAX_CTRL).await;
            }
            let _ = send.finish();
        });

        let mut cap_out = Vec::new();
        let mut cap_err = Vec::new();
        let mut exit_code = 0i32;
        while let Some(msg) = recv_msg_opt::<ExecServerMsg>(&mut recv, MAX_CHUNK).await? {
            match msg {
                ExecServerMsg::Stdout(bytes) => {
                    if capture_json {
                        cap_out.extend_from_slice(&bytes);
                    } else {
                        let _ = std::io::stdout().write_all(&bytes);
                        let _ = std::io::stdout().flush();
                    }
                }
                ExecServerMsg::Stderr(bytes) => {
                    if capture_json {
                        cap_err.extend_from_slice(&bytes);
                    } else {
                        let _ = std::io::stderr().write_all(&bytes);
                        let _ = std::io::stderr().flush();
                    }
                }
                ExecServerMsg::Exit(code) => {
                    exit_code = code;
                    break;
                }
            }
        }
        stdin_task.abort();
        Ok((exit_code, cap_out, cap_err))
    }

    pub async fn run_job(
        &self,
        name: Option<String>,
        argv: Vec<String>,
        cwd: Option<String>,
        shell: bool,
    ) -> Result<JobInfo> {
        let (_, mut recv) = self
            .request(&Request::Run {
                name,
                argv,
                cwd,
                shell,
            })
            .await?;
        recv_msg(&mut recv, MAX_CTRL).await
    }

    pub async fn jobs(&self, name: Option<String>) -> Result<Vec<JobInfo>> {
        let (_, mut recv) = self.request(&Request::Jobs { name }).await?;
        recv_msg(&mut recv, MAX_CTRL).await
    }

    pub async fn logs(
        &self,
        name: String,
        tail: Option<usize>,
        all: bool,
        follow: bool,
    ) -> Result<(Vec<u8>, String, Option<i32>, u64)> {
        let (_, mut recv) = self
            .request(&Request::Logs {
                name,
                tail,
                all,
                follow,
            })
            .await?;
        let mut buf = Vec::new();
        let mut final_state = String::new();
        let mut final_exit = None;
        let mut age = 0u64;
        while let Some(msg) = recv_msg_opt::<LogMsg>(&mut recv, MAX_CHUNK).await? {
            match msg {
                LogMsg::Data(bytes) => {
                    if follow {
                        let _ = std::io::stdout().write_all(&bytes);
                        let _ = std::io::stdout().flush();
                    } else {
                        buf.extend_from_slice(&bytes);
                    }
                }
                LogMsg::Done {
                    state,
                    exit,
                    age_secs,
                } => {
                    final_state = state;
                    final_exit = exit;
                    age = age_secs;
                    break;
                }
            }
        }
        Ok((buf, final_state, final_exit, age))
    }

    pub async fn kill_job(&self, name: String, signal: i32) -> Result<JobInfo> {
        let (_, mut recv) = self.request(&Request::Kill { name, signal }).await?;
        recv_msg(&mut recv, MAX_CTRL).await
    }

    pub async fn wait_job(
        &self,
        name: String,
        text: Option<String>,
        tail: usize,
        timeout_secs: Option<u64>,
    ) -> Result<WaitResult> {
        let (_, mut recv) = self
            .request(&Request::WaitJob {
                name,
                text,
                tail,
                timeout_secs,
            })
            .await?;
        recv_msg(&mut recv, MAX_FRAME).await
    }

    /// The server's sessions, each as its folder there says it is.
    pub async fn sessions(&self) -> Result<Vec<SessionInfo>> {
        let (_, mut recv) = self.request(&Request::Sessions).await?;
        decode(&recv_pieces(&mut recv).await?, usize::MAX)
    }

    /// What a session shows, or with `last` what its last command printed.
    pub async fn output(&self, session: String, last: bool) -> Result<String> {
        let (_, mut recv) = self.request(&Request::Output { session, last }).await?;
        text(&mut recv).await
    }

    /// Waits until one more command of the session's shell has ended, or the session has.
    pub async fn wait_session(
        &self,
        session: String,
        timeout_secs: Option<u64>,
    ) -> Result<WaitResult> {
        let asked = Request::WaitSession {
            session,
            timeout_secs,
        };
        let (_, mut recv) = self.request(&asked).await?;
        let mut waited: WaitResult = recv_msg(&mut recv, MAX_CTRL).await?;
        waited.tail = text(&mut recv).await?;
        Ok(waited)
    }

    pub async fn cp_push(
        &self,
        local_src: &Path,
        remote_dst: String,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        self.cp_push_many(
            &[local_src.to_path_buf()],
            &remote_dst,
            &excludes,
            delete,
            preserve_mtime,
            dry_run,
        )
        .await
    }

    pub async fn cp_push_many(
        &self,
        local_srcs: &[PathBuf],
        remote_dst: &str,
        excludes: &[String],
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        if local_srcs.is_empty() {
            return Err(KohError::usage("cp requires at least one source"));
        }
        if local_srcs.len() > 1 && delete {
            return Err(KohError::usage("--delete requires a single source"));
        }
        let preserve_root = local_srcs.len() > 1;
        let mut total = SyncSummary {
            dry_run,
            ..SyncSummary::default()
        };
        for src in local_srcs {
            let (mut send, mut recv) = self
                .request(&Request::CpPush {
                    dst: remote_dst.to_string(),
                    excludes: excludes.to_vec(),
                    delete,
                    preserve_mtime,
                    dry_run,
                })
                .await?;
            let part = send_tree(src, excludes, preserve_root, &mut send, &mut recv).await?;
            total.merge(part);
        }
        Ok(total)
    }

    pub async fn cp_pull(
        &self,
        remote_src: String,
        local_dst: &Path,
        excludes: Vec<String>,
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        self.cp_pull_many(
            &[remote_src],
            local_dst,
            &excludes,
            delete,
            preserve_mtime,
            dry_run,
        )
        .await
    }

    pub async fn cp_pull_many(
        &self,
        remote_srcs: &[String],
        local_dst: &Path,
        excludes: &[String],
        delete: bool,
        preserve_mtime: bool,
        dry_run: bool,
    ) -> Result<SyncSummary> {
        if remote_srcs.is_empty() {
            return Err(KohError::usage("cp requires at least one source"));
        }
        if remote_srcs.len() > 1 && delete {
            return Err(KohError::usage("--delete requires a single source"));
        }
        let preserve_root = remote_srcs.len() > 1;
        let mut total = SyncSummary {
            dry_run,
            ..SyncSummary::default()
        };
        for src in remote_srcs {
            let (mut send, mut recv) = self
                .request(&Request::CpPull {
                    src: src.clone(),
                    excludes: excludes.to_vec(),
                    delete,
                    preserve_mtime,
                    dry_run,
                    preserve_root,
                })
                .await?;
            let part = receive_tree(
                local_dst,
                excludes,
                delete,
                preserve_mtime,
                dry_run,
                &mut send,
                &mut recv,
            )
            .await?;
            total.merge(part);
        }
        Ok(total)
    }

    /// One attach: the request and the server's answer to it. What goes wrong is said with
    /// whether it is the last word (the server's refusal, or its refusal of this key) or a
    /// link that is not there, to be tried again.
    async fn attach(&self, asks: &Attach) -> Attaching {
        let asked = async {
            let (mut send, mut recv) = open_authed_stream(&self.conn, &self.secret).await?;
            send_msg(&mut send, &Request::Attach(asks.clone()), MAX_CTRL).await?;
            let reply: Reply = recv_msg(&mut recv, MAX_CTRL).await?;
            Ok((send, recv, reply))
        };
        let (send, mut recv, reply) = asked.await.map_err(|e: KohError| {
            let closed = close_error(&self.conn);
            let last = closed.as_ref().is_some_and(|e| e.code == Exit::REFUSED);
            (last, closed.unwrap_or(e))
        })?;
        reply.into_result().map_err(|e| (true, e))?;
        // (An answer that is over its bound or is none is refused, as a message of a round
        // is; the transport's end is not. The server chose the name, and a mirror's default
        // place is made of it: a name it is, and no path. And a client that comes again is
        // given the run it named, or types nothing.)
        let attached: Attached = match recv_msg(&mut recv, MAX_CTRL).await {
            Ok(attached) => attached,
            Err(e) if e.code == Exit::FAILED => return Err((true, refused(&e.message))),
            Err(e) => return Err((false, e)),
        };
        let name = &attached.name;
        match (
            session_name(name),
            asks.run.is_none_or(|run| run == attached.run),
        ) {
            (true, true) => Ok((send, recv, attached)),
            (true, false) => Err((true, another_run(name))),
            (false, _) => Err((true, refused("a session's name that is none"))),
        }
    }

    /// An attach after a link went: a new stream on the connection if it lives (iroh may have
    /// moved it), and on a new connection of the same endpoint if it does not, or brings no
    /// answer in five seconds. On the new connection it has five seconds to be answered too.
    async fn attach_again(&mut self, asks: &Attach) -> Attaching {
        let answer = Duration::from_secs(5);
        if self.conn.close_reason().is_none() {
            match tokio::time::timeout(answer, self.attach(asks)).await {
                Ok(Err((false, _))) | Err(_) => {}
                Ok(answered) => return answered,
            }
        }
        // (A dial is given five seconds: one begun while there was no path sends again ever
        // more seldom, and would be found waiting long after the path is back.)
        let dialled = tokio::time::timeout(Duration::from_secs(5), self.redial()).await;
        let timed_out = |_| (false, KohError::unreachable("timed out dialing server"));
        dialled.map_err(timed_out)?.map_err(|e| (false, e))?;
        let answered = tokio::time::timeout(answer, self.attach(asks)).await;
        let unanswered = |_| (false, KohError::unreachable("the server did not answer"));
        answered.map_err(unanswered)?
    }

    /// `koh connect`: a session in this terminal. Its mirror is in a private folder, shown by
    /// fux's viewer in this process with koh's own keys (`Ctrl-] .` and `C-b d` leave it), and
    /// both are gone when it ends. Ends with the session's program, with its status.
    pub async fn connect_interactive(self, opts: ConnectOptions) -> Result<i32> {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            self.close().await;
            return Err(KohError::usage(
                "`koh connect` requires a terminal (for scripts/agents use `exec`, `run`, `mount`)",
            ));
        }
        let tty = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map(File::from);
        let size = tty.and_then(|tty| fuxix::winsize(&tty)).ok();
        let (cols, rows) = size.map_or((80, 24), |size| (size.cols.max(1), size.rows.max(1)));
        // The first attach comes before the terminal is touched: what the server refuses is
        // said on a terminal that is as it was.
        let asks = opts.asks(cols, rows);
        let made = async {
            let (send, recv, attached) = self.attach(&asks).await.map_err(|(_, e)| e)?;
            let temp = TempConnectDir::create()?;
            let (session, keys) = (temp.0.join("session"), temp.0.join("keys"));
            let failed = |e: std::io::Error| KohError::failed(format!("{}: {e}", temp.0.display()));
            fs::create_dir_all(session.join("connect")).map_err(failed)?;
            fs::write(session.join("connect/layout"), "* remote focus=remote\n").map_err(failed)?;
            install_detach_keys(&keys)?;
            // (The mirror's folder is made here, and is koh's alone to write: what it holds is
            // what the last whole round left, and nothing else is trusted to be there.)
            let pane = session.join("connect/remote");
            let mirror = Mirror::make(&pane).map_err(failed)?;
            Ok((
                temp,
                session,
                keys,
                pane,
                mirror,
                asks.again(&attached),
                (send, recv),
            ))
        };
        let (temp, session, keys, pane, mirror, asks, link) = match made.await {
            Ok(made) => made,
            Err(err) => {
                self.close().await;
                return Err(err);
            }
        };
        // (The viewer's FIFO, in the folder it makes for itself in the session: what is
        // written there is said in its corner.)
        let corner = session.join(format!(".view.{}/ctl", std::process::id()));
        let (stop, stopped) = watch::channel(false);
        let stop = Arc::new(stop);
        let (ready, first) = oneshot::channel();
        let says = Some(corner.clone());
        // Told to end (its terminal closed, as a rule), koh leaves as if its user had: the
        // carrying is stopped, which also ends the wait for a first round that has not come;
        // the viewer, if there is one yet, is told to go; and the private folder goes with
        // them. (A signal in the moment before this task listens has its own way: koh dies
        // of it, and a private folder made in that moment stays.)
        let left = Arc::new(AtomicBool::new(false));
        let (leaves, viewer, stops) = (left.clone(), corner.clone(), stop.clone());
        let signals = tokio::spawn(async move {
            told_to_end().await;
            leaves.store(true, Ordering::Relaxed);
            let _ = stops.send(true);
            quit_viewer(&viewer).await;
        });
        let mut carried = tokio::spawn(async move {
            let mut client = self;
            let carried = carry(
                &mut client,
                &pane,
                mirror,
                asks,
                link,
                says,
                Some(ready),
                stopped,
            )
            .await;
            // (A server that is not there to hear of the end is not waited for: whoever left
            // the viewer is at a terminal.)
            let _ = tokio::time::timeout(Duration::from_millis(500), client.close()).await;
            carried
        });
        // The viewer starts once the mirror has a whole round: it finds a pane, with its FIFOs.
        let mut ended = None;
        let viewed = if first.await.is_ok() {
            let view =
                tokio::task::spawn_blocking(move || fux::view(session, "connect".into(), keys));
            tokio::pin!(view);
            tokio::select! {
                // The viewer left: its user did, or it could not go on.
                viewed = &mut view => viewed,
                // The session ended, or koh cannot go on: the viewer is told to leave, once it
                // has drawn what there was.
                carried = &mut carried => {
                    ended = Some(carried);
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    tokio::select! {
                        viewed = &mut view => viewed,
                        () = quit_viewer(&corner) => view.await,
                    }
                }
            }
        } else {
            Ok(Ok(()))
        };
        let _ = stop.send(true);
        let ended = match ended {
            Some(ended) => ended,
            None => match tokio::time::timeout(Duration::from_secs(3), &mut carried).await {
                Ok(ended) => ended,
                Err(_) => {
                    carried.abort();
                    Ok(Ok(0))
                }
            },
        };
        drop(temp);
        signals.abort();
        if left.load(Ordering::Relaxed) {
            return Ok(0);
        }
        match (viewed, ended) {
            (Ok(Err(why)), _) => Err(KohError::failed(why)),
            (Err(e), _) => Err(KohError::internal(format!("fux view thread: {e}"))),
            (_, Err(e)) => Err(KohError::internal(format!("the session's task: {e}"))),
            (_, Ok(ended)) => ended,
        }
    }

    /// `koh mount`: a mirror of a session in `place`, or with none in koh's own fux session on
    /// this machine (`K/fux/koh-mounts/SERVER.NAME`), for any `fux view`, `cat` or script to
    /// look at and write to, until the session ends or koh is stopped (SIGINT, SIGTERM, or
    /// SIGHUP as from a terminal that is closed). koh
    /// makes the folder (one that is there is not taken) and removes it when the mount ends.
    pub async fn mount(
        self,
        opts: ConnectOptions,
        place: Option<PathBuf>,
        server: &str,
    ) -> Result<i32> {
        let asks = opts.asks(80, 24);
        let not_made = |dir: &Path, e: std::io::Error| {
            let why = "koh makes a mirror's folder, and takes none that is there";
            KohError::failed(format!("{}: {e} ({why})", dir.display()))
        };
        let made = async {
            // (A place that is taken is said before anything is asked of the server.)
            if let Some(dir) = place
                .as_ref()
                .filter(|dir| fs::symlink_metadata(dir).is_ok())
            {
                return Err(not_made(dir, std::io::ErrorKind::AlreadyExists.into()));
            }
            let (send, recv, attached) = self.attach(&asks).await.map_err(|(_, e)| e)?;
            let dir = match place {
                Some(dir) => dir,
                None => default_mount(server, &attached.name)?,
            };
            // (Made here, and koh's alone to write from here on: see `connect_interactive`.)
            let mirror = Mirror::make(&dir).map_err(|e| not_made(&dir, e))?;
            Ok((dir, mirror, asks.again(&attached), (send, recv)))
        };
        let (dir, mirror, asks, link) = match made.await {
            Ok(made) => made,
            Err(err) => {
                self.close().await;
                return Err(err);
            }
        };
        let _ = writeln!(
            std::io::stderr(),
            "mirroring remote session at {}",
            dir.display()
        );
        let (stop, stopped) = watch::channel(false);
        let signals = tokio::spawn(async move {
            told_to_end().await;
            let _ = stop.send(true);
        });
        let mut client = self;
        let carried = carry(&mut client, &dir, mirror, asks, link, None, None, stopped).await;
        signals.abort();
        let _ = tokio::time::timeout(Duration::from_millis(500), client.close()).await;
        let _ = fs::remove_dir_all(&dir);
        carried
    }
}

/// What an attach gives: the stream and what the server said of the session; or what went
/// wrong, and whether that is the last word.
type Attaching = std::result::Result<(SendStream, RecvStream, Attached), (bool, KohError)>;

impl ConnectOptions {
    /// A first attach as these options ask it, for a terminal of this size. (The client's
    /// number is chosen here, once.)
    fn asks(self, cols: u16, rows: u16) -> Attach {
        Attach {
            format: fux::FORMAT,
            name: self.session,
            new: self.new,
            cols,
            rows,
            argv: self.argv,
            cwd: self.cwd,
            run: None,
            client: RandomState::new().hash_one(std::process::id()),
        }
    }
}

impl Attach {
    /// Every later attach of the client that was answered `attached`: to that run of that
    /// name, and to nothing else.
    fn again(&self, attached: &Attached) -> Attach {
        Attach {
            name: Some(attached.name.clone()),
            new: false,
            argv: Vec::new(),
            cwd: None,
            run: Some(attached.run),
            ..self.clone()
        }
    }
}

/// Where `koh mount` puts a mirror it is given no place for: in a workspace of a fux session
/// of koh's own on this machine, under the server's name and the session's (a pane's kind of
/// name, so a viewer of that workspace shows it).
fn default_mount(server: &str, session: &str) -> Result<PathBuf> {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty());
    let koh = var("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("koh"))
        .or_else(|| var("HOME").map(|dir| PathBuf::from(dir).join(".cache/koh")));
    let Some(koh) = koh else {
        return Err(KohError::failed(
            "no place for a mirror: neither XDG_RUNTIME_DIR nor HOME is set (name a directory: koh mount SERVER DIR)",
        ));
    };
    let mounts = koh.join("fux").join("koh-mounts");
    let made = DirBuilder::new()
        .mode(0o700)
        .recursive(true)
        .create(&mounts);
    made.map_err(|e| KohError::failed(format!("{}: {e}", mounts.display())))?;
    let letters = |c: char| {
        if c.is_ascii_alphanumeric() || c == '-' {
            c
        } else {
            '_'
        }
    };
    // (A pane's name is 64 characters at most: the server's part is cut to fit, and with no
    // room for any of it the name is the session's own.)
    let room = 63usize.saturating_sub(session.len());
    let server: String = server.chars().map(letters).take(room).collect();
    Ok(mounts.join(match server.is_empty() {
        true => session.to_string(),
        false => format!("{server}.{session}"),
    }))
}

/// What was written to a mirror's two FIFOs and no link has taken whole yet.
struct Typed {
    /// Typed bytes, in their order.
    bytes: Vec<u8>,
    /// The last line of `ctl` that asked for a size.
    asked: Option<Vec<u8>>,
    /// A line of `ctl` that has not ended yet.
    line: Vec<u8>,
    /// What the thread that reads the two FIFOs hands over: bytes of `in` (false) or of `ctl`.
    read: mpsc::UnboundedReceiver<(bool, Vec<u8>)>,
    /// How many typed bytes were read and no stream has taken: with `MAX_HELD` of them `in` is
    /// read no more, its pipe fills, and whoever writes to it waits.
    held: Arc<AtomicUsize>,
}

/// A line of `ctl` is 1,280 bytes at most, as fux has it: a longer one is dropped.
const CTL_LINE: usize = 1280;

impl Typed {
    /// Starts the one thread that reads the mirror's two FIFOs, link or no link, for as long
    /// as what it reads is taken from it. It waits on them as fux does on a pane's (`poll`).
    fn of(mirror: Arc<Mutex<Mirror>>) -> Typed {
        let (read, taken) = mpsc::unbounded_channel();
        let held = Arc::new(AtomicUsize::new(0));
        let counted = held.clone();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while !read.is_closed() {
                // (The FIFOs the mirror has now: a round makes them, and a round removes them.)
                let [input, ctl] = {
                    let mirror = mirror.lock().unwrap_or_else(PoisonError::into_inner);
                    ["in", "ctl"]
                        .map(|name| mirror.fifo(name).and_then(|fifo| fifo.try_clone().ok()))
                };
                let room = MAX_HELD.saturating_sub(counted.load(Ordering::Relaxed));
                let wanted = [input.as_ref().filter(|_| room > 0), ctl.as_ref()];
                let fifos = wanted.map(|fifo| (fifo.map(|fifo| fifo.as_fd()), fuxix::POLLIN));
                // (With no room it looks again soon: a stream may have taken some.)
                let Ok(ready) = fuxix::wait(fifos, if room > 0 { 50 } else { 5 }) else {
                    break;
                };
                for ((fifo, lined), ready) in wanted.into_iter().zip([false, true]).zip(ready) {
                    let most = if lined {
                        buffer.len()
                    } else {
                        room.min(buffer.len())
                    };
                    let into = buffer.get_mut(..most).unwrap_or_default();
                    let got = fifo.filter(|_| ready != 0).map(|mut fifo| fifo.read(into));
                    if let Some(Ok(n @ 1..)) = got {
                        counted.fetch_add(if lined { 0 } else { n }, Ordering::Relaxed);
                        let _ = read.send((lined, buffer.get(..n).unwrap_or_default().to_vec()));
                    }
                }
            }
        });
        Typed {
            bytes: Vec::new(),
            asked: None,
            line: Vec::new(),
            read: taken,
            held,
        }
    }

    /// A message the stream has taken whole: what it carried is held no more. Says how many
    /// typed bytes those were.
    fn taken(&mut self, message: FromMirror) -> usize {
        match message {
            FromMirror::Write { name, bytes } if name == "in" => {
                let typed = bytes.len().min(self.bytes.len());
                self.bytes.drain(..typed);
                self.held.fetch_sub(typed, Ordering::Relaxed);
                typed
            }
            FromMirror::Write { bytes, .. } => {
                self.asked.take_if(|asked| *asked == bytes);
                0
            }
            _ => 0,
        }
    }

    /// Waits for what was written to one of the mirror's FIFOs: typed bytes are kept; the
    /// lines of `ctl` that ended are given.
    async fn typing(&mut self) -> Vec<Vec<u8>> {
        match self.read.recv().await {
            Some((false, bytes)) => self.bytes.extend(bytes),
            Some((true, bytes)) => {
                let lines = fux::lines(&mut self.line, &bytes, CTL_LINE);
                let lines = lines.into_iter().flatten();
                return lines.map(|line| format!("{line}\n").into_bytes()).collect();
            }
            None => std::future::pending().await,
        }
        Vec::new()
    }
}

/// Something done to the mirror, on the blocking pool: its files are read and written there.
async fn with<T: Send + 'static>(
    mirror: &Arc<Mutex<Mirror>>,
    work: impl FnOnce(&mut Mirror) -> T + Send + 'static,
) -> Result<T> {
    let mirror = mirror.clone();
    let work = move || work(&mut mirror.lock().unwrap_or_else(PoisonError::into_inner));
    let done = tokio::task::spawn_blocking(work).await;
    done.map_err(|e| KohError::internal(format!("the mirror's work: {e}")))
}

/// A line for whoever looks at the session: in the corner of koh's viewer (a line to its
/// FIFO), or with no viewer on standard error.
fn say(corner: Option<&Path>, line: &str) {
    match corner {
        Some(ctl) => {
            if let Ok(mut ctl) = fuxix::open(ctl, true) {
                let _ = ctl.write_all(format!("{line}\n").as_bytes());
            }
        }
        None => _ = writeln!(std::io::stderr(), "koh: {line}"),
    }
}

/// What became of a link.
enum Link {
    /// The server said that nothing follows: the session is over.
    Ended,
    /// The client was told to stop.
    Stopped,
    /// The transport ended, a round stood still, or the mirror could not be written.
    Broken,
}

/// Carries a session into its mirror `dir` over one link after another, until the session
/// ends (its program's status), the client is stopped (0) or the server says a last word.
/// `asks` is what each new attach asks; `ready` is told when the mirror has its first whole
/// round. Without a link, what is typed is held and the mirror is as its last round left it.
#[allow(clippy::too_many_arguments)]
async fn carry(
    client: &mut Client,
    dir: &Path,
    mirror: Mirror,
    asks: Attach,
    first: (SendStream, RecvStream),
    corner: Option<PathBuf>,
    mut ready: Option<oneshot::Sender<()>>,
    mut stop: watch::Receiver<bool>,
) -> Result<i32> {
    let (mirror, corner) = (Arc::new(Mutex::new(mirror)), corner.as_deref());
    let (mut typed, mut link) = (Typed::of(mirror.clone()), Some(first));
    loop {
        let (send, recv) = match link.take() {
            Some(link) => link,
            None => match away(client, &asks, &mut typed, corner, &mut stop).await? {
                Some(link) => link,
                None => return Ok(0),
            },
        };
        let told = dir.parent().and_then(Path::parent);
        match linked(
            &mirror, send, recv, &mut typed, told, corner, &mut ready, &mut stop,
        )
        .await?
        {
            Link::Stopped => return Ok(0),
            Link::Broken => with(&mirror, Mirror::discard).await?,
            // The exit code is the program's, from the mirror's `state`; and never 0 where
            // that does not say the program exited with it.
            Link::Ended => {
                let mut state = String::new();
                let file = fuxix::open_regular(dir.join("state"));
                let _ = file.map(|file| file.take(64).read_to_string(&mut state));
                let said = "the session ended without saying how";
                return crate::pane::code(&state).ok_or_else(|| KohError::failed(said));
            }
        }
    }
}

/// Without a link: says so, tries again after today's delays (0.2, 0.5, 1, 2, then 5 s), and
/// reads the mirror's FIFOs meanwhile. Typed bytes are held; of `ctl` only the last line that asks for
/// a size is, and any other line is dropped, which is said. Gives the new link, or none if
/// the client was stopped; the server's last word ends the client.
async fn away(
    client: &mut Client,
    asks: &Attach,
    typed: &mut Typed,
    corner: Option<&Path>,
    stop: &mut watch::Receiver<bool>,
) -> Result<Option<(SendStream, RecvStream)>> {
    let since = Instant::now();
    // (Said again each second: a viewer's corner is cleared by the next key.)
    let mut said = tokio::time::interval(Duration::from_secs(1));
    for tries in 0u32.. {
        let attempt = async {
            tokio::time::sleep(reconnect_delay(tries)).await;
            client.attach_again(asks).await
        };
        tokio::pin!(attempt);
        let attached = loop {
            tokio::select! {
                _ = stop.changed() => return Ok(None),
                attached = &mut attempt => break attached,
                _ = said.tick() => {
                    let held = "what is typed is held";
                    match since.elapsed().as_secs() {
                        0 => say(corner, &format!("no link: {held}")),
                        secs => say(corner, &format!("no link for {secs} s: {held}")),
                    }
                }
                lines = typed.typing() => for line in lines {
                    match line.starts_with(b"resize ") {
                        true => typed.asked = Some(line),
                        false => say(corner, "no link: a line written to ctl was dropped"),
                    }
                },
            }
        };
        match attached {
            Ok((send, recv, _)) => {
                say(corner, "the link is back");
                return Ok(Some((send, recv)));
            }
            Err((true, e)) => {
                let lost = match typed.bytes.len() {
                    0 => String::new(),
                    n => format!(" ({n} typed bytes were not sent)"),
                };
                return Err(KohError::new(
                    e.code,
                    e.kind,
                    format!("{}{lost}", e.message),
                ));
            }
            Err((false, _)) => {}
        }
    }
    Ok(None)
}

/// One link, from the mirror's list to the link's end. What the server sends is a round's
/// messages, held beside the mirror until the round is whole. What is written to the
/// mirror's FIFOs is sent as it is read, and forgotten when the stream has taken all of its
/// message: what it did not take whole is kept for the next link, and nothing is sent twice.
#[allow(clippy::too_many_arguments)]
async fn linked(
    mirror: &Arc<Mutex<Mirror>>,
    mut send: SendStream,
    recv: RecvStream,
    typed: &mut Typed,
    told: Option<&Path>,
    corner: Option<&Path>,
    ready: &mut Option<oneshot::Sender<()>>,
    stop: &mut watch::Receiver<bool>,
) -> Result<Link> {
    let list = with(mirror, Mirror::has).await?;
    let list = list.map_err(|e| KohError::failed(format!("the mirror cannot be read: {e}")))?;
    let mut from = spawn_msg_reader::<ToMirror>(recv, MAX_CHUNK);
    // What is sent goes through one writer, a message at a time, which gives each back once
    // the stream has taken all of it: a round is applied while typed bytes wait for the link.
    let (out, mut queue) = mpsc::channel::<FromMirror>(1);
    let (taken, mut took) = mpsc::unbounded_channel::<FromMirror>();
    let writer = async move {
        while let Some(message) = queue.recv().await {
            let sent = send_msg(&mut send, &message, MAX_CHUNK).await;
            if sent.is_err() || taken.send(message).is_err() {
                break;
            }
        }
    };
    tokio::pin!(writer);
    // First the list; then the size that was asked for while away; then what was typed.
    let ctl = |bytes: Vec<u8>| FromMirror::Write {
        name: "ctl".into(),
        bytes,
    };
    let mut waits = VecDeque::from([FromMirror::Has(list)]);
    waits.extend(typed.asked.clone().map(ctl));
    // How many of the typed bytes the writer has been handed; when the open round is thrown
    // away; and what the viewer here last wrote of its terminal.
    let (mut offered, mut due, mut seen) = (0, None::<Instant>, [None, None]);
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    let link = loop {
        let more = !waits.is_empty() || offered < typed.bytes.len();
        tokio::select! {
            _ = stop.changed() => break Ok(Link::Stopped),
            () = &mut writer => break Ok(Link::Broken),
            permit = out.reserve(), if more => {
                let Ok(permit) = permit else { break Ok(Link::Broken) };
                let message = waits.pop_front().unwrap_or_else(|| {
                    let piece = typed.bytes.get(offered..).unwrap_or_default();
                    let piece = piece.get(..piece.len().min(MAX_TYPED)).unwrap_or_default();
                    offered += piece.len();
                    FromMirror::Write { name: "in".into(), bytes: piece.to_vec() }
                });
                permit.send(message);
            }
            Some(message) = took.recv() => offered = offered.saturating_sub(typed.taken(message)),
            message = from.recv() => {
                let message = match message {
                    Some(Ok(message)) => message,
                    // A message over its bound, or none that is known: refused, as one that
                    // the mirror refuses. Anything else is the transport's end.
                    Some(Err(e)) if e.code == Exit::FAILED => break Err(refused(&e.message)),
                    _ => break Ok(Link::Broken),
                };
                let done = message == ToMirror::Done;
                let take = move |mirror: &mut Mirror| (mirror.take(message, Instant::now()), mirror.due());
                let (taken, until) = with(mirror, take).await?;
                due = until;
                match taken {
                    Ok(true) => break Ok(Link::Ended),
                    Ok(false) if done => _ = ready.take().map(|ready| ready.send(())),
                    Ok(false) => {}
                    Err(Fault::Refused(what)) => break Err(refused(&what)),
                    Err(Fault::Failed(what)) => {
                        say(corner, &format!("the mirror was not written: {what}"));
                        break Ok(Link::Broken);
                    }
                }
            }
            lines = typed.typing() => for line in lines {
                if line.starts_with(b"resize ") {
                    typed.asked = Some(line.clone());
                }
                waits.push_back(ctl(line));
            },
            // An open round that stands still is the transport's end.
            () = async { tokio::time::sleep_until(due.unwrap_or_else(Instant::now).into()).await }, if due.is_some() => {
                break Ok(Link::Broken);
            }
            // What the viewer here wrote of its terminal, at each attach and when it changes.
            _ = tick.tick() => for (name, seen) in ["colours", "keyboard"].into_iter().zip(&mut seen) {
                let Some(file) = told.map(|session| session.join(name)) else { continue };
                let stamp = fs::metadata(&file).ok().filter(|file| file.is_file()).map(fux::stamp);
                // (Read when it is a file and another than was read, as fux's holder reads
                // it: without waiting, and no more than a message holds.)
                if stamp.is_some() && stamp != *seen {
                    let mut bytes = Vec::new();
                    let read = fuxix::open(&file, false).map(|file| file.take(MAX_TYPED as u64 + 1).read_to_end(&mut bytes));
                    if matches!(read, Ok(Ok(_))) && bytes.len() <= MAX_TYPED {
                        waits.push_back(FromMirror::Told { name: name.into(), bytes });
                    }
                }
                *seen = stamp;
            },
        }
    };
    // Every way out to another link takes what the writer says the stream took before any of
    // it is offered again: what a stream took is never sent again. (The one way out that
    // takes nothing, a mirror whose work could not be done, ends the client.)
    while let Ok(message) = took.try_recv() {
        typed.taken(message);
    }
    link
}

/// What a client is told that comes again to a name another run has by now.
fn another_run(name: &str) -> KohError {
    let why = format!("another run has the session's name {name}: nothing is typed into it");
    KohError::new(Exit::NOT_FOUND, "not_found", why)
}

/// Waits until this process is told to end: interrupted, terminated, or hung up, as a terminal
/// that is closed hangs up what runs in it.
async fn told_to_end() {
    let told = |kind| async move {
        match signal(kind) {
            Ok(mut told) => _ = told.recv().await,
            Err(_) => std::future::pending().await,
        }
    };
    tokio::select! {
        () = told(SignalKind::interrupt()) => {}
        () = told(SignalKind::terminate()) => {}
        () = told(SignalKind::hangup()) => {}
    }
}

/// A message no server may send ends the client, saying which. Nothing was changed by it.
fn refused(what: &str) -> KohError {
    KohError::failed(format!(
        "the server sent what a mirror does not take: {what}"
    ))
}

/// Tells koh's viewer to leave, once its FIFO is there to be told.
async fn quit_viewer(ctl: &Path) {
    for _ in 0..200 {
        if let Ok(mut ctl) = fuxix::open(ctl, true)
            && ctl.write_all(b"quit\n").is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

struct TempConnectDir(PathBuf);

impl TempConnectDir {
    fn create() -> Result<Self> {
        let base_root = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        fs::create_dir_all(&base_root)
            .map_err(|e| KohError::failed(format!("mkdir {}: {e}", base_root.display())))?;
        let pid = std::process::id();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for attempt in 0..64u32 {
            let path = base_root.join(format!("koh-connect-{pid}-{nanos}-{attempt}"));
            match DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(KohError::failed(format!("mkdir {}: {e}", path.display())));
                }
            }
        }
        Err(KohError::failed(
            "could not allocate unique temp connect directory",
        ))
    }
}

impl Drop for TempConnectDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// koh's keys for its viewer. A key's script runs in a folder the viewer makes for it, where `pane`
/// is a link to the pane that has the keys.
fn install_detach_keys(keys_dir: &Path) -> Result<()> {
    const SCRIPTS: [(&str, &[u8]); 4] = [
        ("C-]/dot", b"#!/bin/sh\n# detach\necho quit\n"),
        (
            "C-]/C-]",
            b"#!/bin/sh\n# send C-]\n[ -p pane/in ] && printf '\\035' 1<>pane/in\n",
        ),
        ("C-b/d", b"#!/bin/sh\n# detach\necho quit\n"),
        (
            "C-b/C-b",
            b"#!/bin/sh\n# send C-b\n[ -p pane/in ] && printf '\\002' 1<>pane/in\n",
        ),
    ];
    for (rel, body) in SCRIPTS {
        let path = keys_dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| KohError::failed(format!("mkdir {}: {e}", parent.display())))?;
        }
        fs::write(&path, body)
            .map_err(|e| KohError::failed(format!("write {}: {e}", path.display())))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| KohError::failed(format!("chmod {}: {e}", path.display())))?;
    }
    Ok(())
}

fn reconnect_delay(attempt: u32) -> Duration {
    match attempt {
        0 => Duration::from_millis(200),
        1 => Duration::from_millis(500),
        2 => Duration::from_secs(1),
        3 => Duration::from_secs(2),
        _ => Duration::from_secs(5),
    }
}

/// Helper for `--sync DIR` before `exec` or `run`.
pub async fn sync_before_command(
    client: &Client,
    local_dir: &Path,
    cwd: Option<&str>,
    excludes: Vec<String>,
    quiet: bool,
) -> Result<(String, SyncSummary)> {
    let remote_dir = match cwd {
        Some(c) => c.to_string(),
        None => local_dir
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.is_empty() && *n != ".")
            .map(String::from)
            .ok_or_else(|| KohError::usage("--sync . requires -C REMOTE_DIR"))?,
    };
    let summary = client
        .cp_push(local_dir, remote_dir.clone(), excludes, false, false, false)
        .await?;
    if !quiet {
        let changed = summary.added.len() + summary.updated.len();
        let _ = writeln!(
            std::io::stderr(),
            "synced {} -> {} ({changed} changed, {} unchanged, {} bytes)",
            local_dir.display(),
            remote_dir,
            summary.unchanged,
            summary.bytes_transferred
        );
    }
    Ok((remote_dir, summary))
}

/// Parses a signal name or number for `koh kill --signal`.
pub fn parse_signal(s: &str) -> Result<i32> {
    if let Ok(n) = s.parse::<i32>() {
        return Ok(n);
    }
    match s.to_ascii_uppercase().trim_start_matches("SIG") {
        "HUP" => Ok(1),
        "INT" => Ok(2),
        "QUIT" => Ok(3),
        "KILL" => Ok(9),
        "TERM" => Ok(15),
        _ => Err(KohError::usage(format!("unknown signal {s:?}"))),
    }
}

/// Wait duration helper used by tests & CLI.
pub fn timeout_duration(secs: Option<u64>) -> Option<Duration> {
    secs.map(Duration::from_secs)
}
