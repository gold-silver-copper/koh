//! Client operations for koh: exec, headless jobs, delta cp/--sync, and sessions. A session
//! is shown by a viewer that runs on the server: `koh connect` writes what that draws to its
//! terminal and sends what is typed there, and keeps nothing of the session here.

use std::collections::VecDeque;
use std::fs::File;
use std::hash::{BuildHasher as _, RandomState};
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::fd::AsFd as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use iroh::endpoint::{Connection, QuicTransportConfig, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, RelayUrl, SecretKey};
use tokio::io::AsyncReadExt as _;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant as Timer;

use crate::keys::{Role, load_or_create_key, resolve_server};
use crate::net::{
    close_error, connect_server, dial, map_conn_err, open_authed_stream, transport_config,
    view_transport_config,
};
use crate::proto::{
    Attach, Attached, ExecClientMsg, ExecServerMsg, JobInfo, LogMsg, MAX_CHUNK, MAX_CTRL,
    MAX_FRAME, Reply, Request, SessionInfo, SyncSummary, VIEW_FRAME, ViewInput, ViewOutput,
    ViewSize, WaitResult, decode, recv_msg, recv_msg_opt, recv_pieces, send_msg, session_name,
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

/// Which session `koh connect` asks for: one by its name, started if there is none of it; or
/// with no name the newest that lives, or a new one (always, with `new` or a program).
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
    pub async fn connect(target: &str, opts: &DialOptions, waiting: bool) -> Result<Self> {
        Self::connect_with(target, opts, transport_config(waiting)).await
    }

    pub async fn connect_view(target: &str, opts: &DialOptions) -> Result<Self> {
        Self::connect_with(target, opts, view_transport_config()).await
    }

    async fn connect_with(
        target: &str,
        opts: &DialOptions,
        config: QuicTransportConfig,
    ) -> Result<Self> {
        let secret = load_or_create_key(Role::Client, opts.key_file.as_deref())?;
        let (server_id, route) = resolve_server(
            target,
            opts.key_file.as_deref(),
            opts.direct,
            opts.relay.clone(),
        )?;
        Self::connect_route(secret, server_id, route, config).await
    }

    pub async fn connect_direct(
        secret: SecretKey,
        server_id: iroh::EndpointId,
        route: Option<crate::keys::Route>,
        interactive: bool,
    ) -> Result<Self> {
        Self::connect_route(secret, server_id, route, transport_config(interactive)).await
    }

    async fn connect_route(
        secret: SecretKey,
        server_id: iroh::EndpointId,
        route: Option<crate::keys::Route>,
        config: QuicTransportConfig,
    ) -> Result<Self> {
        let (endpoint, addr, conn) =
            connect_server(secret.clone(), server_id, route, config).await?;
        Ok(Self {
            secret,
            endpoint,
            addr,
            conn,
        })
    }

    /// A client on an endpoint that is there, with the server dialled at `addr`: a test's, on
    /// a link of its own. No command of koh's makes one so.
    pub async fn connect_on(
        secret: SecretKey,
        endpoint: Endpoint,
        addr: EndpointAddr,
    ) -> Result<Self> {
        let conn = dial(&endpoint, addr.clone()).await?;
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
        // (An answer that is over its bound or is none is the last word; the transport's end
        // is not. A name it is, and no path. And a client that comes again is given the run
        // it named, or types nothing.)
        let attached: Attached = recv_msg(&mut recv, MAX_CTRL)
            .await
            .map_err(|e| (e.code == Exit::FAILED, e))?;
        let refused = |what: &str| {
            (
                true,
                KohError::failed(format!("the server answered {what}")),
            )
        };
        match (
            session_name(&attached.name),
            asks.run.is_none_or(|run| run == attached.run),
        ) {
            (true, true) => Ok((send, recv, attached)),
            (true, false) => Err(refused("with another run than the one that was asked for")),
            (false, _) => Err(refused("with a session's name that is none")),
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

    /// `koh connect`: a session in this terminal. The session's viewer runs on the server;
    /// what it draws is written here as it comes, and what is typed here is sent to it. Ends
    /// with the session's program, with its status; or with 0 when its user leaves it
    /// (`Ctrl-] .`) or the terminal is closed. The terminal is asked what it is like here, once;
    /// nothing is asked of it across the link, where an answer could come late.
    pub async fn connect_interactive(self, opts: ConnectOptions) -> Result<i32> {
        let (input, output) = (std::io::stdin(), std::io::stdout());
        if !input.is_terminal() || !output.is_terminal() {
            self.close().await;
            return Err(KohError::usage(
                "`koh connect` requires a terminal (for scripts/agents use `exec`, `run`)",
            ));
        }
        let end = |end: std::os::fd::BorrowedFd| end.try_clone_to_owned().map(File::from);
        let ends = end(input.as_fd()).and_then(|input| Ok((input, end(output.as_fd())?)));
        let (input, output) = ends.map_err(terminal_error)?;
        self.connect_terminal(opts, input, output).await
    }

    /// `koh connect` on any terminal: `input` is read and `output` written, as they are (a
    /// test gives a pty's end, or a pipe's). Whatever ends it, the terminal is put back first.
    pub async fn connect_terminal(
        mut self,
        opts: ConnectOptions,
        input: File,
        output: File,
    ) -> Result<i32> {
        let told = |kind| signal(kind).map_err(terminal_error);
        let (mut interrupt, mut hangup, mut terminate) = (
            told(SignalKind::interrupt())?,
            told(SignalKind::hangup())?,
            told(SignalKind::terminate())?,
        );
        let mut console = Console::open(input, output)?;
        // Told to end (its terminal closed, as a rule), koh leaves as if its user had.
        let ended = tokio::select! {
            ended = self.session(opts, &mut console) => ended,
            _ = interrupt.recv() => Ok(130),
            _ = hangup.recv() => Ok(0),
            _ = terminate.recv() => Ok(0),
        };
        console.close().await;
        // (A server that is not there to hear of the end is not waited for.)
        let _ = tokio::time::timeout(Duration::from_millis(500), self.close()).await;
        ended
    }

    /// A session from its first attach to its end: attached, shown while the link holds, and
    /// attached again when it does not, to the same run. While there is no link the terminal
    /// is its own again and says so; what is typed then is held for the return, but the key
    /// that leaves, which leaves at once.
    async fn session(&mut self, opts: ConnectOptions, console: &mut Console) -> Result<i32> {
        // The terminal is asked what it is like, once, before the first attach, which says it;
        // what is typed meanwhile is the session's first keys.
        let mut keys = Keys::default();
        let terminal = match Terminal::ask(console, &mut keys).await {
            Ok(terminal) => terminal,
            Err(code) => return Ok(code),
        };
        let mut asks = Attach {
            name: opts.session,
            new: opts.new,
            size: console.size(),
            argv: opts.argv,
            cwd: opts.cwd,
            run: None,
            client: RandomState::new().hash_one(std::process::id()),
            term: terminal.term,
            keyboard: terminal.keyboard,
            colours: terminal.colours,
        };
        console.flags = asks.keyboard != 0;
        // (A new session that is given no name is asked for once: asked again after an answer
        // that was lost, it would be started twice.)
        let once = asks.name.is_none() && (asks.new || !asks.argv.is_empty());
        let mut attempt = 0;
        loop {
            asks.size = console.size();
            let answer = {
                let attaching = async {
                    match attempt {
                        0 if asks.run.is_none() => self.attach(&asks).await,
                        _ => {
                            tokio::time::sleep(reconnect_delay(attempt)).await;
                            self.attach_again(&asks).await
                        }
                    }
                };
                tokio::pin!(attaching);
                loop {
                    tokio::select! {
                        answer = &mut attaching => break answer,
                        typed = console.typed.recv() => match typed.map(|typed| keys.take(&typed, false, !console.ever)) {
                            Some(None) => {}
                            Some(Some(code)) => return Ok(code),
                            None => return Ok(0),
                        }
                    }
                }
            };
            let (mut send, mut recv) = match answer {
                Ok((send, recv, attached)) => {
                    asks = Attach {
                        name: Some(attached.name),
                        new: false,
                        argv: Vec::new(),
                        cwd: None,
                        run: Some(attached.run),
                        ..asks
                    };
                    (send, recv)
                }
                Err((false, _)) if !(once && asks.run.is_none()) => {
                    attempt += 1;
                    console.say(NO_LINK).await;
                    continue;
                }
                Err((_, e)) => return Err(e),
            };
            let shown = console.show(&mut send, &mut recv, &mut keys, asks.size);
            if let Some(code) = shown.await? {
                return Ok(code);
            }
            // The link is lost. Its streams are let go, the terminal is put back at once
            // (nothing of the viewer's stays on while away), and it says so.
            let _ = send.reset(0u32.into());
            let _ = recv.stop(0u32.into());
            console.reset().await;
            console.say(NO_LINK).await;
            attempt = 1;
        }
    }
}

/// What an attach gives: the stream and what the server said of the session; or what went
/// wrong, and whether that is the last word.
type Attaching = std::result::Result<(SendStream, RecvStream, Attached), (bool, KohError)>;

/// The most typed bytes that wait for a link. More that is typed while there is none is lost.
const MAX_HELD: usize = 64 << 10;

/// What the terminal says while there is no link, on one line of its own screen: written over
/// when it is said again, and wiped when koh ends.
const NO_LINK: &[u8] = b"\rkoh: no link; reconnecting (Ctrl-] . leaves)\x1b[K";

fn terminal_error(e: std::io::Error) -> KohError {
    KohError::failed(format!("the terminal: {e}"))
}

/// What `koh connect`'s terminal says of itself, asked by the client, once: no viewer asks
/// across a link, where an answer may come late and be taken for typing.
#[derive(Default)]
struct Terminal {
    /// Its `TERM`, if that is a name a server takes.
    term: String,
    /// The kitty keyboard flags it takes: 0 if it does not know the protocol, or did not say.
    keyboard: u8,
    /// Its foreground, background and cursor colours, as lines of fux's `colours` file.
    colours: String,
}

impl Terminal {
    /// Asks the terminal for the keyboard's flags (set, read back, given back), for three
    /// colours, and last what it is, which every terminal answers; and reads it until that
    /// answer has come or a second is over. What came before that answer's end are its
    /// answers, and that is all the telling of answers from typing there is: what came after
    /// it was typed, and so was all of it where that answer did not come (nothing is known of
    /// such a terminal: no colours, the plain keyboard). It is not asked again. Or the code
    /// koh ends with, if its own key was typed meanwhile or the terminal closed.
    async fn ask(console: &mut Console, keys: &mut Keys) -> std::result::Result<Terminal, i32> {
        const ASKS: &[u8] =
            b"\x1b[>31u\x1b[?u\x1b[<u\x1b]10;?\x1b\\\x1b]11;?\x1b\\\x1b]12;?\x1b\\\x1b[c";
        let (mut said, until) = (Vec::new(), Timer::now() + Duration::from_secs(1));
        let asked = console.write(ASKS.to_vec()).await;
        while asked && what_it_is(&said).is_none() {
            match tokio::time::timeout_at(until, console.typed.recv()).await {
                Ok(Some(read)) => said.extend(read),
                Ok(None) => return Err(0),
                Err(_) => break,
            }
        }
        let (answers, typed) = said.split_at(what_it_is(&said).unwrap_or(0));
        keys.take(typed, false, true).map_or(Ok(()), Err)?;
        Ok(Terminal::said(answers))
    }

    /// What its answers say.
    fn said(answers: &[u8]) -> Terminal {
        let term = std::env::var("TERM").unwrap_or_default();
        let named = term.len() <= 64 && term.bytes().all(|b| b.is_ascii_graphic());
        let mut terminal = Terminal {
            term: if named { term } else { String::new() },
            ..Terminal::default()
        };
        for part in String::from_utf8_lossy(answers).split('\x1b') {
            let flags = part
                .strip_prefix("[?")
                .and_then(|flags| flags.strip_suffix('u'));
            terminal.keyboard = flags.map_or(terminal.keyboard, |flags| flags.parse().unwrap_or(0));
            // `]11;rgb:1c1c/1c1c/1c1c`, ended by the next part or by BEL: of each of the three
            // its first eight bits.
            let colour = part
                .strip_prefix(']')
                .and_then(|answer| answer.split_once(";rgb:"));
            let Some((which, value)) = colour else {
                continue;
            };
            let name = ["foreground", "background", "cursor"]
                .into_iter()
                .zip(["10", "11", "12"]);
            let name = name.into_iter().find(|(_, number)| *number == which);
            let parts: Vec<&str> = value.trim_end_matches('\x07').split('/').collect();
            let hex = |part: &&str| part.len() >= 2 && part.bytes().all(|b| b.is_ascii_hexdigit());
            if let (Some((name, _)), [r, g, b], true) =
                (name, parts.as_slice(), parts.iter().all(hex))
            {
                let two = |part: &str| part.get(..2).unwrap_or_default().to_lowercase();
                terminal.colours += &format!("{name} #{}{}{}\n", two(r), two(g), two(b));
            }
        }
        terminal
    }
}

/// Where a terminal's answer to "what are you" ends in what it sent: after `ESC [ ? 62;4 c`.
fn what_it_is(said: &[u8]) -> Option<usize> {
    (0..said.len()).find_map(|at| {
        let numbers = said.get(at..)?.strip_prefix(b"\x1b[?")?;
        let length = numbers
            .iter()
            .take_while(|b| b.is_ascii_digit() || **b == b';');
        let length = length.count();
        (numbers.get(length) == Some(&b'c')).then_some(at + length + 4)
    })
}

/// The client's terminal, raw from the start to the end: read by a thread and written by
/// another, as a terminal is read and written, which waits. (So it is any terminal: a pty
/// that is no controlling terminal, and one a kernel's event queue does not take.)
struct Console {
    /// The terminal itself: its size is asked of it, and its mode goes back when it is let go.
    raw: fuxix::Raw,
    tty: File,
    /// What is typed, a read at a time; closed when the terminal is.
    typed: mpsc::Receiver<Vec<u8>>,
    /// What is written, a piece at a time; and the thread that writes it, until this is closed.
    out: Option<mpsc::Sender<Vec<u8>>>,
    writer: Option<std::thread::JoinHandle<()>>,
    /// Whether a viewer has drawn since the terminal was last put back; whether one ever
    /// has; and whether the terminal has said that there is no link.
    drawn: bool,
    ever: bool,
    said: bool,
    /// Whether the viewer set the keyboard's flags aside (the terminal takes some): they are
    /// taken back with the rest then, and else not, for they would be the user's shell's.
    flags: bool,
}

/// What puts the terminal back from whatever a viewer left it in, the viewer not being there to:
/// what was cut is ended (a sequence, a string), then what a frame begins is ended and the
/// scroll region is the whole screen, and then all that fux's viewer puts back when it leaves
/// (its modes off, the main screen, the title; the keyboard's flags taken back if it set them
/// aside, `flags`).
fn reset(flags: bool) -> Vec<u8> {
    let leaving = String::from_utf8_lossy(fux::LEAVING);
    let leaving = leaving.replace("\x1b[<u", if flags { "\x1b[<u" } else { "" });
    [b"\x18\x1b\\\x1b[?2026l\x1b[r", leaving.as_bytes()].concat()
}

impl Console {
    fn open(input: File, mut output: File) -> Result<Console> {
        let tty = input.try_clone().map_err(terminal_error)?;
        let raw = tty.try_clone().and_then(|tty| fuxix::raw_mode(tty, b""));
        let (keys, typed) = mpsc::channel(4);
        let (out, mut written) = mpsc::channel::<Vec<u8>>(1);
        std::thread::spawn(move || {
            let (mut input, mut piece) = (input, [0; 4096]);
            loop {
                match input.read(&mut piece) {
                    Ok(n @ 1..) => {
                        let typed = piece.get(..n).unwrap_or_default().to_vec();
                        if keys.blocking_send(typed).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    _ => break,
                }
            }
        });
        let writer = std::thread::spawn(move || {
            while let Some(bytes) = written.blocking_recv() {
                if output.write_all(&bytes).is_err() {
                    break;
                }
            }
        });
        Ok(Console {
            raw: raw.map_err(terminal_error)?,
            tty,
            typed,
            out: Some(out),
            writer: Some(writer),
            drawn: false,
            ever: false,
            said: false,
            flags: false,
        })
    }

    fn size(&self) -> ViewSize {
        size(&self.tty)
    }

    /// Writes to the terminal, once what was written before is written: whether it took it.
    async fn write(&self, bytes: Vec<u8>) -> bool {
        match &self.out {
            Some(out) => out.send(bytes).await.is_ok(),
            None => false,
        }
    }

    /// Puts the terminal back, if a viewer drew on it since it last was.
    async fn reset(&mut self) {
        if std::mem::take(&mut self.drawn) {
            self.write(reset(self.flags)).await;
        }
    }

    async fn say(&mut self, words: &[u8]) {
        self.said = true;
        self.write(words.to_vec()).await;
    }

    /// Lets the terminal go: put back, what it said of the link wiped, all of that written
    /// (a terminal that takes nothing is given a quarter of a second), and then its mode.
    async fn close(mut self) {
        self.reset().await;
        if self.said {
            self.write(b"\r\x1b[K".to_vec()).await;
        }
        self.out = None;
        if let Some(writer) = self.writer.take() {
            let written = tokio::task::spawn_blocking(move || writer.join());
            let _ = tokio::time::timeout(Duration::from_millis(250), written).await;
        }
        drop(self.raw);
    }

    /// One link's time: what the viewer draws is written to the terminal, a piece at a time
    /// (the next is read when this one is written: no more is read ahead than the stream's
    /// window), and what is typed is sent, with the terminal's size when it is another than
    /// the viewer has. Gives the exit code at the session's end, or none when the link is lost.
    async fn show(
        &mut self,
        send: &mut SendStream,
        recv: &mut RecvStream,
        keys: &mut Keys,
        size: ViewSize,
    ) -> Result<Option<i32>> {
        let Console {
            tty,
            typed,
            out,
            drawn,
            ever,
            ..
        } = self;
        let first = !*ever;
        // (The viewer's first bytes: it has set its pty raw, and nothing typed is echoed there.)
        let ready = Notify::new();
        let draws = async {
            loop {
                match recv_msg::<ViewOutput>(recv, VIEW_FRAME).await {
                    Ok(ViewOutput::Bytes(bytes)) => {
                        (*drawn, *ever) = (true, true);
                        let written = match out {
                            Some(out) => out.send(bytes).await.is_ok(),
                            None => false,
                        };
                        if !written {
                            return Ok(Some(0));
                        }
                        ready.notify_one();
                    }
                    Ok(ViewOutput::Exit(code)) => return Ok(Some(code)),
                    Err(e) if e.code == Exit::UNREACHABLE => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
        };
        let types = async {
            loop {
                tokio::select! {
                    biased;
                    () = ready.notified() => break,
                    more = typed.recv() => match more.map(|more| keys.take(&more, false, first)) {
                        Some(None) => {}
                        Some(code) => return Ok(code),
                        None => return Ok(Some(0)),
                    }
                }
            }
            let mut looks = tokio::time::interval(Duration::from_millis(100));
            let mut has = size;
            loop {
                let message = tokio::select! {
                    _ = looks.tick() => {
                        let now = self::size(tty);
                        if now == has {
                            continue;
                        }
                        has = now;
                        ViewInput::Resize(now)
                    }
                    next = keys.next(typed) => match next {
                        Ok(bytes) => ViewInput::Bytes(bytes),
                        Err(code) => return Ok(Some(code)),
                    }
                };
                if send_msg(send, &message, VIEW_FRAME).await.is_err() {
                    return Ok(None);
                }
            }
        };
        tokio::select! { ended = draws => ended, ended = types => ended }
    }
}

fn size(tty: &File) -> ViewSize {
    let size = fuxix::winsize(tty).unwrap_or_default();
    ViewSize {
        cols: if size.cols == 0 { 80 } else { size.cols },
        rows: if size.rows == 0 { 24 } else { size.rows },
        xpixel: size.xpixel,
        ypixel: size.ypixel,
    }
}

/// What was typed and is not sent, read a key at a time as fux's viewer reads one, so that
/// koh's own key is known in whatever form the terminal sends it, and a message has whole keys:
/// an arrow key or a character that came in two reads is sent in one piece. A byte is in a
/// message once, and a message that was handed to a stream is never sent again: what is typed
/// may be lost with a link, and is never typed twice.
///
/// koh has one key, as ssh has: `Ctrl-] .` leaves, with a link or without one. `Ctrl-] Ctrl-]`
/// is one Ctrl-] typed, and any other key after Ctrl-] is typed after it. What a terminal marks
/// as pasted is text, and no key. Before any screen was drawn Ctrl-C ends koh too. Nothing else
/// is looked for in what is typed: every other byte is the session's, as it came.
#[derive(Default)]
struct Keys {
    /// What was read and is no whole key yet: the start of an escape sequence, of a character
    /// of several bytes, or of the mark that ends a paste.
    raw: Vec<u8>,
    /// What is to be sent, in messages: `held` bytes of it, `MAX_HELD` at most.
    ready: VecDeque<Vec<u8>>,
    held: usize,
    /// When the terminal was last read, and whether what it left unfinished was taken as it
    /// stands since: an Escape that nothing follows is a key.
    last: Option<Timer>,
    /// Ctrl-] was typed, as these bytes, and the next key says what it meant. Behind it, in
    /// their order, what came since that is no key going down (4 KiB at most).
    prefix: Option<Vec<u8>>,
    /// The 10 ms took an Escape by itself as the key, and typed it; and whether Ctrl-] waited
    /// before it. If the next read shows a slow path had cut koh's own key after its first
    /// byte, it is koh's key all the same.
    cut: Option<bool>,
    /// In a paste the terminal marks, up to the mark of its end.
    pasting: bool,
}

impl Keys {
    /// Takes what was read of the terminal, for the session; and says with what code koh ends,
    /// if a key of its own ends it: `Ctrl-] .` (0), or Ctrl-C while no screen was ever drawn
    /// (`first`: 130). With `whole` no more is coming for now.
    fn take(&mut self, typed: &[u8], whole: bool, first: bool) -> Option<i32> {
        const END: &[u8] = b"\x1b[201~";
        let mut at = 0;
        if !typed.is_empty() {
            self.last = Some(Timer::now());
            if let Some(held) = self.cut.take().filter(|_| self.raw.is_empty()) {
                let whole = [b"\x1b", typed].concat();
                match (held, fux::key(&whole, false)) {
                    (true, Some((_, name, true))) if name == "dot" => return Some(0),
                    (false, Some((length, name, true))) if name == "C-]" => {
                        self.prefix = whole.get(1..length).map(<[u8]>::to_vec);
                        at = length - 1;
                    }
                    _ => {}
                }
            }
        }
        let raw = [std::mem::take(&mut self.raw).as_slice(), typed].concat();
        while let Some(rest) = raw.get(at..).filter(|rest| !rest.is_empty()) {
            if self.pasting {
                let end = rest.windows(END.len()).position(|mark| mark == END);
                // (The start of the mark at the very end waits for the rest of it.)
                let begun = |n: &usize| END.get(..*n).is_some_and(|start| rest.ends_with(start));
                let begun = (1..END.len()).rev().find(begun).unwrap_or(0);
                let text = end.map_or(rest.len() - begun, |end| end + END.len());
                self.send(rest.get(..text).unwrap_or_default());
                (self.pasting, at) = (end.is_none(), at + text);
                if end.is_none() {
                    break;
                }
                continue;
            }
            let Some((length, name, down)) = fux::key(rest, whole) else {
                break;
            };
            let key = rest.get(..length).unwrap_or_default();
            at += length;
            // (A key let go, Ctrl by itself, the mouse and the window's focus are the session's
            // to hear of, and no key that follows another: behind a Ctrl-] that waits they
            // wait too, for a key let go before it went down is none to a viewer.)
            if !down || name.starts_with("mouse:") || name.starts_with("focus:") {
                let room = |held: &&mut Vec<u8>| held.len() + key.len() <= 4096;
                match self.prefix.as_mut().filter(room) {
                    Some(held) => held.extend_from_slice(key),
                    None => {
                        let held = self.prefix.take().unwrap_or_default();
                        self.send(&[held.as_slice(), key].concat());
                    }
                }
                continue;
            }
            let held = self.prefix.take();
            self.cut = (whole && key == b"\x1b").then_some(held.is_some());
            match (held, name.as_str()) {
                (None, "C-]") => self.prefix = Some(key.to_vec()),
                (Some(_), "dot") => return Some(0),
                (Some(held), "C-]") => self.send(&held),
                (Some(held), _) => self.send(&[held.as_slice(), key].concat()),
                (None, "C-c") if first => return Some(130),
                (None, _) => self.send(key),
            }
            self.pasting = name == "paste-start";
        }
        self.raw = raw.get(at..).unwrap_or_default().to_vec();
        None
    }

    /// Adds to what is to be sent: to the last message while it has room, and nothing past
    /// `MAX_HELD` (what is typed beyond that while there is no link is lost).
    fn send(&mut self, bytes: &[u8]) {
        if self.held + bytes.len() > MAX_HELD {
            return;
        }
        self.held += bytes.len();
        for piece in bytes.chunks(VIEW_FRAME - 16) {
            match self.ready.back_mut() {
                Some(last) if last.len() + piece.len() <= VIEW_FRAME - 16 => last.extend(piece),
                _ => self.ready.push_back(piece.to_vec()),
            }
        }
    }

    /// The next message of what was typed: read of the terminal when none waits. What is no
    /// whole key waits for its rest, 10 ms from the last read. Or the code koh ends with: its
    /// own key's, or 0 when the terminal is closed.
    async fn next(
        &mut self,
        typed: &mut mpsc::Receiver<Vec<u8>>,
    ) -> std::result::Result<Vec<u8>, i32> {
        loop {
            if let Some(message) = self.ready.pop_front() {
                self.held -= message.len();
                return Ok(message);
            }
            let due = self.last.map(|last| last + Duration::from_millis(10));
            let ends = tokio::select! {
                more = typed.recv() => self.take(&more.ok_or(0)?, false, false),
                () = async { tokio::time::sleep_until(due.unwrap_or_else(Timer::now)).await }, if due.is_some() => {
                    self.last = None;
                    self.take(&[], true, false)
                }
            };
            if let Some(code) = ends {
                return Err(code);
            }
        }
    }
}

fn reconnect_delay(attempt: u32) -> Duration {
    match attempt {
        0 | 1 => Duration::from_millis(200),
        2 => Duration::from_millis(500),
        3 => Duration::from_secs(1),
        4 => Duration::from_secs(2),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_terminals_answers_end_with_what_it_is_and_what_comes_after_is_typed_to_the_byte() {
        // A terminal that takes the keyboard's flags 1 and 4 and tells its colours, one ended
        // by BEL, one of parts whose two bytes differ; then what it is, and what was typed.
        let said: &[u8] = b"\x1b[?5u\x1b]10;rgb:d0d0/d0d0/d0d0\x1b\\\x1b]11;rgb:1234/abcd/00ff\x07\x1b]12;rgb:ff/00/7f\x1b\\\x1b[?62;4c\x1b[Als\r";
        let end = what_it_is(said).unwrap();
        assert_eq!(said.get(end..).unwrap(), b"\x1b[Als\r");
        let terminal = Terminal::said(said.get(..end).unwrap());
        assert_eq!(terminal.keyboard, 5);
        assert_eq!(
            terminal.colours,
            "foreground #d0d0d0\nbackground #12ab00\ncursor #ff007f\n"
        );
        // Its last answer in pieces is none until it is whole, wherever it is cut.
        for cut in 0..end {
            assert_eq!(what_it_is(said.get(..cut).unwrap()), None, "{cut}");
        }
        // One that knows neither says what it is, and no more: no colours, the plain keyboard.
        // What is no colour is none (a number that was not asked, a part that is no number),
        // and flags that are no number of eight bits are none.
        for (said, colours) in [
            (b"\x1b[?6c".as_slice(), ""),
            (
                b"\x1b]10;rgb:+f/00/00\x1b\\\x1b]13;rgb:ff/00/00\x1b\\\x1b[?999u\x1b[?6c",
                "",
            ),
            (
                b"\x1b]11;rgb:1c1c/1c1c\x1b\\\x1b]10;rgb:f/0/8\x1b\\\x1b[?1;2c",
                "",
            ),
        ] {
            let terminal = Terminal::said(said.get(..what_it_is(said).unwrap()).unwrap());
            assert_eq!(
                (terminal.keyboard, terminal.colours.as_str()),
                (0, colours),
                "{said:?}"
            );
        }
        // One that says nothing of what it is has said nothing: all it sent was typed. And
        // what is typed is typed whole, the bytes that have an answer's form too, cut anywhere.
        let typed: &[u8] = b"\x1b[?5u\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\x\x1b[?62c\x1b]1hello\x07y";
        assert_eq!(
            what_it_is(b"\x1b[?5u\x1b]11;rgb:1c1c/1c1c/1c1c\x1b\\x\x1b[?62"),
            None
        );
        for cut in 0..typed.len() {
            let mut keys = Keys::default();
            let reads = [typed.get(..cut).unwrap(), typed.get(cut..).unwrap()];
            assert_eq!(
                self::typed(&mut keys, &reads, false),
                (typed.to_vec(), None),
                "{cut}"
            );
        }
        // What puts the terminal back takes the keyboard's flags back if the viewer set them
        // aside, and not if it did not: they would be the shell's.
        let back = |flags| String::from_utf8(reset(flags)).unwrap();
        assert!(
            back(true).starts_with("\x18\x1b\\\x1b[?2026l\x1b[r")
                && back(true).contains("\x1b[<u\x1b[?1049l")
        );
        assert_eq!(back(false), back(true).replace("\x1b[<u", ""));
    }

    /// What `keys` would send of what was typed in these reads, and the code it ends koh with.
    fn typed(keys: &mut Keys, reads: &[&[u8]], first: bool) -> (Vec<u8>, Option<i32>) {
        let ends = reads.iter().find_map(|read| keys.take(read, false, first));
        let sent: Vec<u8> = std::mem::take(&mut keys.ready)
            .into_iter()
            .flatten()
            .collect();
        keys.held = 0;
        (sent, ends)
    }

    #[test]
    fn kohs_key_leaves_in_whatever_form_a_terminal_sends_it_and_nothing_else_does() {
        // `Ctrl-] .` leaves: in one read or two, in the old form of keys and in the kitty
        // protocol's, with the key's release, Ctrl's own press and a mouse report between the two.
        let leaves: [&[&[u8]]; 5] = [
            &[b"ab\x1d."],
            &[b"ab\x1d", b"."],
            &[b"ab\x1b[93;5u\x1b[46u"],
            &[
                b"ab\x1b[57442;5u\x1b[93;5u",
                b"\x1b[93;5:3u\x1b[57442;1:3u",
                b"\x1b[<35;1;1M\x1b[46;1:1u",
            ],
            &[b"ab\x1b[93;", b"5u."],
        ];
        for reads in leaves {
            let (sent, ends) = typed(&mut Keys::default(), reads, false);
            assert_eq!(ends, Some(0), "{reads:?}");
            assert!(
                sent.starts_with(b"ab") && !sent.contains(&0x1d) && !sent.contains(&b'.'),
                "{reads:?}"
            );
        }
        // Ctrl-] twice is one, typed; any other key after it is typed after it; a dot by itself
        // is a dot. And what a terminal marks as pasted is text, whatever is in it.
        for (reads, sent) in [
            (&[b"\x1d\x1d.".as_slice()][..], b"\x1d.".as_slice()),
            (&[b"\x1d", b"x."], b"\x1dx."),
            (&[b"a.b"], b"a.b"),
            (
                &[b"\x1b[200~\x1d.\x1b[2", b"01~."],
                b"\x1b[200~\x1d.\x1b[201~.",
            ),
            (&[b"\x1b[93;5u\x1b[93;5u"], b"\x1b[93;5u"),
            // (With the kitty keyboard a key is let go too: what comes while Ctrl-] waits is
            // behind it, in its order. Let go before it went down, a key is none to a viewer.)
            (
                &[b"\x1b[93;5:1u", b"\x1b[93;5:3u", b"X"],
                b"\x1b[93;5:1u\x1b[93;5:3uX",
            ),
            (
                &[b"\x1b[93;5u\x1b[<35;1;1M\x1b[I\x1b[57442;1:3ux"],
                b"\x1b[93;5u\x1b[<35;1;1M\x1b[I\x1b[57442;1:3ux",
            ),
            (
                &[b"\x1b[93;5:1u\x1b[93;5:3u\x1b[93;5:1u\x1b[93;5:3u"],
                b"\x1b[93;5:1u\x1b[93;5:3u\x1b[93;5:3u",
            ),
        ] {
            assert_eq!(
                typed(&mut Keys::default(), reads, false),
                (sent.to_vec(), None),
                "{reads:?}"
            );
        }
        // What waits behind Ctrl-] is 4 KiB at most: past that Ctrl-] waits no longer, all of
        // it is typed in its order, and a dot is a dot.
        let moved = b"\x1b[<35;10;10M".repeat(400);
        let all = [b"\x1b[93;5u", moved.as_slice(), b"."].concat();
        assert_eq!(
            typed(&mut Keys::default(), &[&all], false),
            (all.clone(), None)
        );
        // Ctrl-C ends koh while no screen was ever drawn, and is a key after that.
        assert_eq!(
            typed(&mut Keys::default(), &[b"a\x03"], true),
            (b"a".to_vec(), Some(130))
        );
        assert_eq!(
            typed(&mut Keys::default(), &[b"a\x03"], false),
            (b"a\x03".to_vec(), None)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_key_that_comes_in_two_reads_is_one_message_and_what_is_held_is_bounded() {
        let (terminal, mut reads) = mpsc::channel(8);
        let mut keys = Keys::default();
        // An arrow key in two reads, 5 ms apart: one message. An Escape that nothing follows
        // for 10 ms is a key, and is sent then; so is a character in two reads.
        terminal.send(b"x\x1b[".to_vec()).await.unwrap();
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"x");
        let later = terminal.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            later.send(b"A\xc3".to_vec()).await.unwrap();
            later.send(b"\xa9".to_vec()).await.unwrap();
        });
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"\x1b[A");
        assert_eq!(keys.next(&mut reads).await.unwrap(), "é".as_bytes());
        let began = Timer::now();
        terminal.send(b"\x1b".to_vec()).await.unwrap();
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"\x1b");
        assert_eq!(began.elapsed(), Duration::from_millis(10));
        // And so is one that was read while there was no link, or none yet.
        assert_eq!(keys.take(b"\x1b", false, false), None);
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"\x1b");
        // A key a slow path cut after its first byte, the rest 35 ms later: the Escape was
        // typed by then, and the rest is typed after it, as it came.
        let cut = |rest: &'static [u8]| {
            let later = terminal.clone();
            tokio::spawn(async move {
                later.send(b"\x1b".to_vec()).await.unwrap();
                tokio::time::sleep(Duration::from_millis(35)).await;
                later.send(rest.to_vec()).await.unwrap();
            });
        };
        cut(b"[A");
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"\x1b");
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"[A");
        // But koh's own key is koh's, cut so too: either of its two keys.
        cut(b"[93;5u\x1b[46u");
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"\x1b");
        assert_eq!(keys.next(&mut reads).await, Err(0));
        let mut keys = Keys::default();
        terminal.send(b"\x1b[93;5u".to_vec()).await.unwrap();
        cut(b"[46u");
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"\x1b[93;5u\x1b");
        assert_eq!(keys.next(&mut reads).await, Err(0));
        // (An Escape that was one, and then koh's key: it leaves, and a dot does not.)
        let mut keys = Keys::default();
        cut(b".");
        assert_eq!(keys.next(&mut reads).await.unwrap(), b"\x1b");
        assert_eq!(keys.next(&mut reads).await.unwrap(), b".");
        terminal.send(b"\x1d.".to_vec()).await.unwrap();
        assert_eq!(keys.next(&mut reads).await, Err(0));
        let mut keys = Keys::default();
        // With no link what is typed is held up to 64 KiB, and no more; it goes out in pieces
        // no message is too long for. The terminal closed ends it, with 0.
        for _ in 0..40 {
            assert_eq!(keys.take(&[b'a'; 4096], false, false), None);
        }
        assert_eq!(keys.held, MAX_HELD);
        let piece = keys.next(&mut reads).await.unwrap();
        assert!(piece.len() == VIEW_FRAME - 16 && send_fits(&piece));
        (keys.ready, keys.held) = (VecDeque::new(), 0);
        drop(terminal);
        assert_eq!(keys.next(&mut reads).await, Err(0));
    }

    fn send_fits(piece: &[u8]) -> bool {
        crate::proto::encode(&ViewInput::Bytes(piece.to_vec()), VIEW_FRAME).is_ok()
    }
}
