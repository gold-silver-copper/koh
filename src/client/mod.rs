//! The koh client: `koh connect`'s loop, and the commands that dial a server ([`cli`]).
//!
//! The loop relays the program's output to the user's terminal ([`display`]) and what is typed to
//! the server ([`input`]), across reconnects: one display and one input machine live for the
//! whole run, and only what belongs to a connection is made anew.

pub mod backend;
pub mod cli;
mod copy;
pub mod display;
mod exec;
pub mod input;
mod io;
mod probe;

pub use backend::{DefaultBackend, KohBackend};
pub use cli::{connect, sessions, BellHook, ConnectConfig, Remote};
pub use copy::{copy, sync, CopyJob, SyncTree, Synced};
pub use exec::exec;

use std::ops::ControlFlow::{self, Break, Continue};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use crate::events::InputEvent;
use crate::log::Peer;
use crate::proto::{
    encode_client, ClientMsg, Close, InputSeq, Shown, ShownDecoder, HEARTBEAT, SHOWN_TAG,
};
use crate::request::{Argv, Attached, Pick, RemotePath, Request, Resume, MAX_REPLY, MAX_REQUEST};
use crate::terminal::Size;
use crate::transport_iroh::{closed_because, ALPN, PROTOCOL};
use display::Display;
use input::{Keys, Read};
use iroh::endpoint::{Connection, SendStream, TransportErrorCode};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

/// How long a single reconnect dial may run before it is abandoned and retried.
const RECONNECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Reconnect backoff: `BASE << min(attempt, 4)`, capped at `MAX`; attempts from 1 wait 1, 2, 4, 8 s.
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_millis(500);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(8);
/// How long a connection must last to reset the reconnect backoff. One that drops sooner counts as
/// a failed dial, so a server that accepts and at once closes cannot drive a tight redial loop.
const MIN_CONNECTION_DWELL: Duration = Duration::from_secs(5);

/// A wall-clock gap between two loop iterations (which run at least every 50 ms) this long means
/// the process was frozen, as Android does at screen-off. The connection is then almost surely
/// dead, but iroh's idle timer runs on the monotonic clock, which pauses too, so it would hold it
/// for up to five minutes; reconnecting at once reattaches in a second or two.
const STALE_AFTER_FREEZE: Duration = Duration::from_secs(20);

/// How long the server may go unheard before the "link down" banner: three heartbeats.
const LINK_DOWN_GRACE: Duration = HEARTBEAT.saturating_mul(3);

/// More keys in one read than anyone types come from a paste or a program writing to the user's
/// terminal: what they do is not predicted.
const TYPED_KEYS: usize = 32;

/// How long after the cursor went to a fresh row a key typed is held from showing until echoed:
/// the PTY's modes may not be known yet (a password prompt).
const PROMPT_HOLD: Duration = crate::proto::TTY_TICK.saturating_mul(2);

/// How long the notice of a paste too long to send stays on the status line.
const NOTICE_FOR: Duration = Duration::from_secs(3);

/// Dials the server and makes the opening request ([`crate::request`]).
///
/// It makes a shell's first connection and every reconnect, which reattaches to the session the
/// first reached, and the one connection of a command, a copy or a listing.
pub struct IrohConnector {
    endpoint: Endpoint,
    target: EndpointAddr,
    /// The key the server allows, proven on each connection: not `endpoint`'s own, which is this
    /// process's alone ([`crate::request::KeyProof`]).
    key: SecretKey,
}

impl IrohConnector {
    /// A connector dialing `target` from `endpoint`, as `key`.
    pub const fn new(endpoint: Endpoint, target: EndpointAddr, key: SecretKey) -> Self {
        Self {
            endpoint,
            target,
            key,
        }
    }

    /// Connect, prove the key, and make `request`, on the client's first stream, left open for
    /// what follows it.
    pub async fn open(&self, request: &Request) -> anyhow::Result<(Connection, SendStream)> {
        let conn = match self.endpoint.connect(self.target.clone(), ALPN).await {
            Ok(conn) => conn,
            // The TLS handshake ended with alert 120 (`no_application_protocol`), QUIC's crypto
            // error `0x178`: the server does not serve [`ALPN`].
            Err(e) if failed_with(&e, TransportErrorCode::crypto(120)) => {
                return Err(Refused::OtherProtocol.into())
            }
            // The server had no room for the handshake.
            Err(e) if failed_with(&e, TransportErrorCode::CONNECTION_REFUSED) => {
                return Err(Close::Busy.into())
            }
            Err(e) => anyhow::bail!("connecting to server: {}", Peer(e)),
        };
        let opened = async {
            let mut control = conn.open_uni().await?;
            // The control stream's bytes go before input's.
            let _ = control.set_priority(1);
            let mut opening = crate::transport_iroh::prove(&conn, &self.key)?;
            opening.extend(crate::request::encode(request, MAX_REQUEST)?);
            control.write_all(&opening).await?;
            anyhow::Ok(control)
        };
        match opened.await {
            Ok(control) => Ok((conn, control)),
            Err(e) => Err(refusal(&conn, &e)),
        }
    }

    /// Connect to the session `pick` names (a new one running `program` in `cwd`, if given), for a
    /// terminal of `size`, and await the server's first stream, which admits the client and says
    /// which session it reached. A server that will not have us for good closes the connection
    /// instead, a [`Refused`] error; one that cannot have us now (at capacity, say) closes it
    /// saying so, an error that is its [`Close`].
    pub async fn connect(
        &self,
        pick: Pick,
        size: Size,
        program: Option<Argv>,
        cwd: Option<RemotePath>,
    ) -> anyhow::Result<Admitted> {
        let request = Request::Shell {
            pick,
            size,
            program,
            cwd,
        };
        let (conn, control) = self.open(&request).await?;
        let attached = async {
            let mut first = conn.accept_uni().await?;
            let bytes = first.read_to_end(MAX_REPLY.saturating_add(4)).await?;
            anyhow::Ok(crate::request::decode_framed::<Attached>(
                &bytes, MAX_REPLY,
            )?)
        };
        match attached.await {
            Ok(Attached { at }) => Ok(Admitted { conn, control, at }),
            Err(e) => Err(refusal(&conn, &e)),
        }
    }
}

/// Why the server did not answer on `conn`, which failed with `error`: its close code, a
/// [`Refused`] if it is for good.
pub(crate) fn refusal(conn: &Connection, error: &anyhow::Error) -> anyhow::Error {
    match closed_because(conn) {
        Some(why) => Refused::of(why).map_or_else(|| why.into(), Into::into),
        None => anyhow::anyhow!("the server did not answer: {}", Peer(format!("{error:#}"))),
    }
}

/// A shell connection the server admitted: its control stream, open, and the session it reached.
pub struct Admitted {
    pub conn: Connection,
    control: SendStream,
    pub at: Resume,
}

/// The server refused us for good: redialing cannot help, so the client exits saying why.
#[derive(Debug, thiserror::Error)]
pub enum Refused {
    #[error("server rejected the connection: {}", Close::NotAuthorized)]
    NotAuthorized,
    #[error("{}", Close::NoSuchSession)]
    NoSuchSession,
    #[error("{}", Close::OutOfScope)]
    OutOfScope,
    #[error(
        "this koh speaks protocol {PROTOCOL} and the server speaks another; upgrade koh on \
         whichever end is older"
    )]
    OtherProtocol,
}

impl Refused {
    /// The refusal a close for `why` is, if it is for good.
    const fn of(why: Close) -> Option<Self> {
        match why {
            Close::NotAuthorized => Some(Self::NotAuthorized),
            Close::NoSuchSession => Some(Self::NoSuchSession),
            Close::OutOfScope => Some(Self::OutOfScope),
            Close::ProtocolError
            | Close::SessionEnded
            | Close::AtCapacity
            | Close::CouldNotStart
            | Close::Busy
            | Close::NoSuchDir => None,
        }
    }

    /// Its kind, as `--json` says it.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::NotAuthorized => "not_authorized",
            Self::NoSuchSession => "no_such_session",
            Self::OutOfScope => "out_of_scope",
            Self::OtherProtocol => "other_protocol",
        }
    }
}

/// Whether a dial failed with the transport error `code`.
fn failed_with(
    error: &(dyn std::error::Error + 'static),
    code: iroh::endpoint::TransportErrorCode,
) -> bool {
    use iroh::endpoint::ConnectionError;
    let mut next = Some(error);
    while let Some(e) = next {
        match e.downcast_ref::<ConnectionError>() {
            Some(ConnectionError::ConnectionClosed(close)) if close.error_code == code => {
                return true;
            }
            Some(ConnectionError::TransportError(t)) if t.code == code => return true,
            _ => {}
        }
        next = e.source();
    }
    false
}

/// The wait before redialing after `attempt` (from 1) failures.
fn backoff(attempt: u32) -> Duration {
    RECONNECT_BACKOFF_BASE
        .saturating_mul(1u32 << attempt.min(4))
        .min(RECONNECT_BACKOFF_MAX)
}

/// The attempt counter after a connection that lasted `dwell` dropped: reset if it lasted
/// [`MIN_CONNECTION_DWELL`], else counted as a failed dial.
const fn next_attempt_after_drop(attempt: u32, dwell: Duration) -> u32 {
    if dwell.as_millis() >= MIN_CONNECTION_DWELL.as_millis() {
        0
    } else {
        attempt.saturating_add(1)
    }
}

/// This process's pid, as the signal calls take it.
fn own_pid() -> std::io::Result<fuxix::process::Pid> {
    i32::try_from(std::process::id())
        .ok()
        .and_then(fuxix::process::Pid::from_raw)
        .ok_or_else(|| std::io::Error::other("this process's pid is not a valid pid"))
}

/// What one turn of the loop woke for.
enum Step {
    Typed(Option<Vec<u8>>),
    Timeout,
    Quit,
    Resize,
    Server(Option<FromServer>),
    Dialed(Dialed),
    Tick,
}

/// What a connection's reader hands the loop.
enum FromServer {
    /// What the program shows, on epoch `epoch`.
    Shown { epoch: u32, msg: Shown },
    /// So many bytes of epoch `epoch` were read.
    Read { epoch: u32, bytes: u64 },
}

/// A live connection: its stream writers and its reader, which end with it.
struct Wire {
    conn: Connection,
    input_tx: mpsc::Sender<Vec<u8>>,
    control_tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<FromServer>,
    _tasks: [AbortOnDropHandle<()>; 3],
    started: Instant,
    /// The epoch the display shows.
    epoch: u32,
    /// When the server was last heard.
    heard: Instant,
    /// The bytes of input sent and not yet written to the stream: the server has not taken them.
    queued: Arc<AtomicUsize>,
    /// Input was dropped since the queue was last empty: nothing more is sent until it is, and the
    /// status line says so.
    paused: bool,
    /// The newest input sent on it: a report made before the server wrote it is held.
    sent: InputSeq,
}

/// The most input bytes waiting while the server takes no input; past it, typing is dropped and
/// the status line says so. An empty queue takes any input, a whole paste included.
const MAX_QUEUED_INPUT: usize = 1024 * 1024;

/// The most messages of input waiting, however small.
const QUEUED_MESSAGES: usize = 4096;

/// How many control messages may wait for their writer, and decoded ones for the loop.
const CONTROL_QUEUE: usize = 64;
const READER_QUEUE: usize = 64;

impl Wire {
    fn open(Admitted { conn, control, .. }: Admitted) -> Self {
        let (input_tx, input_rx) = mpsc::channel(QUEUED_MESSAGES);
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);
        let (tx, rx) = mpsc::channel(READER_QUEUE);
        let queued = Arc::new(AtomicUsize::new(0));
        let input = {
            let (conn, queued) = (conn.clone(), queued.clone());
            async move {
                if let Ok(stream) = conn.open_uni().await {
                    write_stream(stream, input_rx, Some(&queued)).await;
                }
            }
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "two writers and a reader a connection"
        )]
        let tasks = [
            AbortOnDropHandle::new(tokio::spawn(input)),
            AbortOnDropHandle::new(tokio::spawn(write_stream(control, control_rx, None))),
            AbortOnDropHandle::new(tokio::spawn(read_epochs(conn.clone(), tx))),
        ];
        let now = Instant::now();
        Self {
            conn,
            input_tx,
            control_tx,
            rx,
            _tasks: tasks,
            started: now,
            epoch: 0,
            heard: now,
            queued,
            paused: false,
            sent: InputSeq::default(),
        }
    }

    /// Whether input is being dropped: some was, and the server has yet to take what waits.
    fn paused(&self) -> bool {
        self.paused && self.queued.load(Ordering::Relaxed) > 0
    }

    /// Queue `msg` on its stream; whether there was room. Input waits in order behind what the
    /// server has not taken, up to [`MAX_QUEUED_INPUT`] (an empty queue takes any message); past
    /// it, it is dropped, and so is what follows until the queue is empty.
    fn send(&mut self, msg: &ClientMsg) -> bool {
        let bytes = match encode_client(msg) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "dropping an unencodable message");
                return true;
            }
        };
        if msg.stream() == crate::proto::Stream::Control {
            return self.control_tx.try_send(bytes).is_ok();
        }
        let (len, queued) = (bytes.len(), self.queued.load(Ordering::Relaxed));
        self.paused &= queued > 0;
        if self.paused || (queued > 0 && queued.saturating_add(len) > MAX_QUEUED_INPUT) {
            self.paused = true;
            return false;
        }
        self.queued.fetch_add(len, Ordering::Relaxed);
        if self.input_tx.try_send(bytes).is_err() {
            self.queued.fetch_sub(len, Ordering::Relaxed);
            self.paused = true;
            return false;
        }
        true
    }

    /// Send the window's `size`, its `n`th resize, on both streams: the control one waits for no
    /// input, and among the input nothing typed after it overtakes it.
    fn resize(&mut self, n: u32, size: Size) {
        let msg = ClientMsg::Resize { n, size };
        self.send(&msg);
        if let Ok(bytes) = encode_client(&msg) {
            let _ = self.control_tx.try_send(bytes);
        }
    }
}

impl Drop for Wire {
    /// The run, or this connection, is over: the server is told at once, not at the idle timeout.
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"client exit");
    }
}

/// Write queued messages to one of the client's streams until the queue or the stream closes,
/// taking each off `queued` once written.
async fn write_stream(
    mut send: SendStream,
    mut queue: mpsc::Receiver<Vec<u8>>,
    queued: Option<&AtomicUsize>,
) {
    while let Some(bytes) = queue.recv().await {
        if send.write_all(&bytes).await.is_err() {
            return;
        }
        if let Some(queued) = queued {
            queued.fetch_sub(bytes.len(), Ordering::Relaxed);
        }
    }
    let _ = send.finish();
}

/// Accept the server's epoch streams, reading the newest: a newer one ends the reading of the
/// one before. Ends when the connection does.
async fn read_epochs(conn: Connection, tx: mpsc::Sender<FromServer>) {
    let mut reading: Option<(u32, AbortOnDropHandle<()>)> = None;
    loop {
        let Ok(mut recv) = conn.accept_uni().await else {
            return;
        };
        let mut header = [0u8; 5];
        if recv.read_exact(&mut header).await.is_err() {
            continue;
        }
        let [tag, epoch @ ..] = header;
        let epoch = u32::from_be_bytes(epoch);
        if tag != SHOWN_TAG || reading.as_ref().is_some_and(|(n, _)| *n >= epoch) {
            let _ = recv.stop(0u32.into());
            continue;
        }
        let tx = tx.clone();
        #[expect(
            clippy::disallowed_methods,
            reason = "one epoch's reader at a time: the one before is aborted"
        )]
        let task = tokio::spawn(async move {
            let mut decoder = ShownDecoder::default();
            let mut bytes: u64 = 5;
            while let Ok(Some(chunk)) = recv.read_chunk(64 * 1024).await {
                bytes = bytes.saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                decoder.push(&chunk);
                loop {
                    match decoder.next_shown() {
                        Ok(Some(msg)) => {
                            if tx.send(FromServer::Shown { epoch, msg }).await.is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::debug!(error = %e, "the server's stream broke the protocol");
                            return;
                        }
                    }
                }
                if tx.send(FromServer::Read { epoch, bytes }).await.is_err() {
                    return;
                }
            }
        });
        reading = Some((epoch, AbortOnDropHandle::new(task)));
    }
}

/// The client's link to the server: a live connection, or a redial under way, and whether typing
/// was dropped since the link went down.
enum Net<'c> {
    Up(Box<Wire>),
    Down { dial: Dial<'c>, dropped: bool },
}

/// A redial: the backoff, then one dial, abandoned after [`RECONNECT_CONNECT_TIMEOUT`].
type Dial<'c> = std::pin::Pin<Box<dyn std::future::Future<Output = Dialed> + Send + 'c>>;

/// A redial's result: connected, refused, or timed out.
type Dialed = Result<anyhow::Result<Admitted>, tokio::time::error::Elapsed>;

/// What `future` gives, or never without one: a select arm for a state that may not be.
async fn when<F: std::future::Future>(future: Option<F>) -> F::Output {
    match future {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// The window's resize ticks: waited for, and for ever once the channel closed.
struct Resizes(Option<mpsc::Receiver<()>>);

impl Resizes {
    async fn next(&mut self) {
        while let Some(rx) = self.0.as_mut() {
            if rx.recv().await.is_some() {
                return;
            }
            self.0 = None;
        }
        std::future::pending::<()>().await;
    }
}

/// What the user's terminal and the run hold beside the connection.
pub struct Run<B: KohBackend> {
    pub backend: B,
    pub size: Size,
    pub colours: bool,
    pub clipboard: bool,
    pub links: bool,
    pub bell: Option<BellHook>,
    /// What is typed, a read at a time; its closing ends the run.
    pub input: mpsc::Receiver<Vec<u8>>,
    /// A tick for each change of the window's size.
    pub resizes: mpsc::Receiver<()>,
}

/// Run a shell client on `initial`, redialing through `connector` whenever the link drops; the
/// remote program's exit status if it exited, `None` on a detach.
///
/// Each redial reattaches to the same server session, by its number in that server's run; a
/// session gone meanwhile ends the run. Cancelling `shutdown` (a fatal signal) detaches.
pub async fn run_client<B: KohBackend>(
    initial: Admitted,
    dialed_at: SystemTime,
    connector: IrohConnector,
    run: Run<B>,
    shutdown: CancellationToken,
) -> anyhow::Result<Option<u32>> {
    let Run {
        backend,
        size,
        colours,
        clipboard,
        links,
        bell,
        mut input,
        resizes,
    } = run;
    let mut client = Client {
        backend,
        display: Display::new(size, clipboard, links)?,
        keys: Keys::new(Instant::now(), colours),
        size,
        bell,
        connector: &connector,
        // Every redial goes back to the session the first connection reached, never to another.
        back: Pick::Resume(initial.at),
        net: Net::Up(Box::new(Wire::open(initial))),
        attempt: 0,
        seq: InputSeq::default(),
        resized: 0,
        title: String::new(),
        last_wall: dialed_at,
        paste_dropped: None,
    };
    let ended = client.drive(&mut input, resizes, &shutdown).await;
    let left = client.display.leave(&mut client.backend);
    let flushed = client.backend.flush();
    let ended = ended?;
    left?;
    flushed?;
    Ok(ended)
}

/// The run's state beside the link's.
struct Client<'c, B: KohBackend> {
    backend: B,
    display: Display,
    keys: Keys,
    size: Size,
    bell: Option<BellHook>,
    connector: &'c IrohConnector,
    back: Pick,
    net: Net<'c>,
    attempt: u32,
    seq: InputSeq,
    /// How many times the window was resized.
    resized: u32,
    title: String,
    /// The wall clock at the last turn of the loop, to tell a freeze by.
    last_wall: SystemTime,
    /// When a paste too long to send was dropped.
    paste_dropped: Option<Instant>,
}

/// What a turn of the loop comes to: on, or the run's end, the remote program's status if it
/// exited.
type Flow = anyhow::Result<ControlFlow<Option<u32>>>;

impl<B: KohBackend> Client<'_, B> {
    async fn drive(
        &mut self,
        input: &mut mpsc::Receiver<Vec<u8>>,
        resizes: mpsc::Receiver<()>,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<Option<u32>> {
        self.backend.write_bytes(&self.keys.take_questions())?;
        let mut resizes = Resizes(Some(resizes));
        let mut tick = tokio::time::interval(Duration::from_millis(50));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            // Painted once what the server sent so far is written.
            if !matches!(&self.net, Net::Up(wire) if !wire.rx.is_empty()) {
                let status = self.status(Instant::now());
                self.display.set_status(status);
                self.display.paint(&mut self.backend)?;
                self.backend.flush()?;
            }
            let deadline = self.keys.deadline();
            let (from_server, dialing) = match &mut self.net {
                Net::Up(wire) => (Some(&mut wire.rx), None),
                Net::Down { dial, .. } => (None, Some(dial)),
            };
            let others = async {
                tokio::select! {
                    typed = input.recv() => Step::Typed(typed),
                    () = when(deadline.map(|at| tokio::time::sleep_until(at.into()))) => Step::Timeout,
                    () = shutdown.cancelled() => Step::Quit,
                    msg = when(from_server.map(mpsc::Receiver::recv)) => Step::Server(msg),
                    dialed = when(dialing) => Step::Dialed(dialed),
                    _ = tick.tick() => Step::Tick,
                }
            };
            // A resize first: keys typed after it must not reach the program before it does.
            let step = tokio::select! {
                biased;
                () = resizes.next() => Step::Resize,
                step = others => step,
            };
            let flow = match step {
                Step::Typed(None) | Step::Quit => Ok(Break(None)),
                Step::Typed(Some(bytes)) => {
                    let read = self.keys.bytes(Instant::now(), &bytes);
                    self.typed(read, input, shutdown).await
                }
                Step::Timeout => {
                    let read = self.keys.timeout(Instant::now());
                    self.typed(read, input, shutdown).await
                }
                Step::Resize => {
                    self.resize();
                    Ok(Continue(()))
                }
                Step::Server(Some(from)) => self.heard(from),
                Step::Server(None) => self.lost(),
                Step::Dialed(dialed) => self.dialed(dialed).map(Continue),
                Step::Tick => {
                    self.tick();
                    Ok(Continue(()))
                }
            };
            if let Break(end) = flow? {
                return Ok(end);
            }
        }
    }

    /// What the status line says now.
    fn status(&self, now: Instant) -> Option<&'static str> {
        match &self.net {
            Net::Down { dropped: true, .. } => {
                Some("[koh] reconnecting… · typing during the outage not sent · Ctrl-^ . to quit")
            }
            Net::Down { .. } => Some("[koh] reconnecting… · Ctrl-^ . to quit"),
            Net::Up(wire) if now.saturating_duration_since(wire.heard) > LINK_DOWN_GRACE => {
                Some("[koh] link down… · Ctrl-^ . to quit")
            }
            Net::Up(wire) if wire.paused() => {
                Some("[koh] input paused — the server is not taking input")
            }
            Net::Up(_) => self
                .paste_dropped
                .filter(|at| now.saturating_duration_since(*at) < NOTICE_FOR)
                .map(|_| "[koh] paste over 1 MiB — not sent"),
        }
    }

    /// Redial after `attempt` failures; `dropped` if typing was dropped since the link went down.
    fn redial(&mut self, attempt: u32, dropped: bool) {
        let (connector, pick, size) = (self.connector, self.back, self.size);
        let wait = if attempt > 0 {
            backoff(attempt)
        } else {
            Duration::ZERO
        };
        let dial = Box::pin(async move {
            tokio::time::sleep(wait).await;
            tokio::time::timeout(
                RECONNECT_CONNECT_TIMEOUT,
                connector.connect(pick, size, None, None),
            )
            .await
        });
        self.net = Net::Down { dial, dropped };
    }

    /// The window was resized: the size it is now goes to the server.
    fn resize(&mut self) {
        if let Ok(size) = self.backend.size() {
            self.size = size;
            self.display.resize(size);
            self.send_size();
        }
    }

    /// Tell the server the window's size, if the link is up.
    fn send_size(&mut self) {
        if let Net::Up(wire) = &mut self.net {
            self.resized = self.resized.saturating_add(1);
            wire.resize(self.resized, self.size);
        }
    }

    /// Take what was read from the user's terminal: questions for it answered, and input sent and
    /// predicted while the link is up.
    async fn typed(
        &mut self,
        read: Read,
        input: &mut mpsc::Receiver<Vec<u8>>,
        shutdown: &CancellationToken,
    ) -> Flow {
        self.backend.write_bytes(&self.keys.take_questions())?;
        if read.quit {
            return Ok(Break(None));
        }
        if read.paste_too_long {
            self.paste_dropped = Some(Instant::now());
        }
        match &mut self.net {
            Net::Up(wire) => {
                if let Some(colours) = read.colours {
                    wire.send(&ClientMsg::Colours(colours));
                }
                // At most a message's events at a time, each its own input; one dropped is not
                // predicted, nor is what follows it sent.
                for events in read.events.chunks(crate::events::MAX_EVENTS) {
                    let seq = self.seq.next();
                    let msg = ClientMsg::Keys {
                        seq,
                        events: events.to_vec(),
                    };
                    if !wire.send(&msg) {
                        break;
                    }
                    self.seq = seq;
                    wire.sent = seq;
                    predict(&mut self.display, events, seq);
                }
            }
            // Not sent, nor predicted: the end of a line whose start was lost must not run alone.
            Net::Down { dropped, .. } => {
                *dropped |= read
                    .events
                    .iter()
                    .any(|e| matches!(e, InputEvent::Key(_) | InputEvent::Paste(_)));
            }
        }
        if read.suspend {
            suspend(&mut self.backend, &mut self.display, shutdown, input).await?;
            self.resize();
            if let Net::Up(wire) = &mut self.net {
                wire.send(&ClientMsg::Redraw);
            }
            self.last_wall = SystemTime::now();
        }
        Ok(Continue(()))
    }

    /// Take what the server's reader read.
    fn heard(&mut self, from: FromServer) -> Flow {
        let Net::Up(wire) = &mut self.net else {
            return Ok(Continue(()));
        };
        wire.heard = Instant::now();
        let (epoch, msg) = match from {
            FromServer::Read { epoch, bytes } => {
                if epoch == wire.epoch {
                    wire.send(&ClientMsg::Read { epoch, bytes });
                }
                return Ok(Continue(()));
            }
            FromServer::Shown { epoch, msg } => (epoch, msg),
        };
        if epoch < wire.epoch {
            return Ok(Continue(()));
        }
        if epoch > wire.epoch {
            // A new epoch: its redraw resets the terminal, and the mirror with it.
            wire.epoch = epoch;
            self.display.new_epoch(self.size)?;
        }
        let backend = &mut self.backend;
        match msg {
            Shown::Out(bytes) => self.display.output(backend, &bytes)?,
            Shown::Mark(mark) => self.display.mark(backend, mark.as_bytes())?,
            // Made before the server wrote all this connection sent, it may say `reading` of a
            // program that has yet to take those keys: held.
            Shown::Report { activity, input } => {
                if input >= wire.sent {
                    self.display.report(backend, activity)?;
                }
            }
            Shown::Tty(tty) => self.display.predictor.set_tty(Some(tty)),
            Shown::Echo(acked) => {
                self.display.predictor.set_local_frame_late_acked(acked.0);
                self.display.reconcile();
            }
            Shown::Bell(count) => {
                if let Some(hook) = self.bell.as_mut() {
                    if hook.observe(count, Instant::now()) {
                        hook.fire(count, &self.title);
                    }
                }
            }
            Shown::Title(title) => self.title = title,
            Shown::Exit { code, read } => {
                // Its program read every key this connection sent: said to a terminal that reads
                // reports, which then knows they reached it.
                if read.is_some_and(|read| read >= wire.sent) {
                    self.display.ended(backend)?;
                }
                // The end is here, which this close tells the server: it waits for nothing
                // more, and neither does the client.
                wire.conn.close(Close::SessionEnded.code().into(), b"");
                return Ok(Break(Some(code)));
            }
            Shown::Beat => {}
        }
        Ok(Continue(()))
    }

    /// The connection ended: the run ends with its session, or for good, or the link is redialed.
    fn lost(&mut self) -> Flow {
        let Net::Up(wire) = &self.net else {
            return Ok(Continue(()));
        };
        match closed_because(&wire.conn) {
            Some(Close::SessionEnded) => return Ok(Break(None)),
            Some(why) => {
                if let Some(refused) = Refused::of(why) {
                    return Err(refused.into());
                }
            }
            None => {}
        }
        tracing::info!(reason = ?wire.conn.close_reason(), "link lost; will reconnect");
        self.attempt = next_attempt_after_drop(self.attempt, wire.started.elapsed());
        self.display.predictor = self.display.predictor.reattached();
        self.redial(self.attempt, false);
        Ok(Continue(()))
    }

    /// A redial ended: connected, the colours and the window's size told again; refused for
    /// good; or to be tried again.
    fn dialed(&mut self, dialed: Dialed) -> anyhow::Result<()> {
        match dialed {
            Ok(Ok(admitted)) => {
                let mut wire = Wire::open(admitted);
                if let Some(colours) = self.keys.colours() {
                    wire.send(&ClientMsg::Colours(colours.clone()));
                }
                self.net = Net::Up(Box::new(wire));
                // The window may have changed since the dial began.
                self.send_size();
            }
            Ok(Err(e)) if e.is::<Refused>() => return Err(e),
            failed => {
                if let Ok(Err(e)) = failed {
                    tracing::info!(reason = %e, attempt = self.attempt, "reconnect dial failed");
                }
                self.attempt = self.attempt.saturating_add(1);
                let dropped = matches!(self.net, Net::Down { dropped: true, .. });
                self.redial(self.attempt, dropped);
            }
        }
        Ok(())
    }

    /// The loop's tick: a freeze since the last ends the connection, which is dead by now.
    fn tick(&mut self) {
        // A clock stepped backwards reads as no gap.
        let wall = SystemTime::now();
        let gap = wall
            .duration_since(self.last_wall)
            .unwrap_or(Duration::ZERO);
        self.last_wall = wall;
        if matches!(self.net, Net::Up(_)) && gap >= STALE_AFTER_FREEZE {
            tracing::info!(
                frozen_secs = gap.as_secs(),
                "resumed from a freeze; reconnecting"
            );
            self.redial(0, false);
        }
    }
}

/// Tell the predictor of `events`, sent as input `seq`.
fn predict(display: &mut Display, events: &[InputEvent], seq: InputSeq) {
    // Predictions made now expire with the input that carries them.
    display
        .predictor
        .set_local_frame_sent(seq.0.saturating_sub(1));
    let burst = events.len() > TYPED_KEYS;
    let fresh = display
        .new_row_at
        .is_some_and(|at| at.elapsed() < PROMPT_HOLD);
    for (n, event) in events.iter().enumerate() {
        match event {
            _ if burst && n > 0 => {}
            InputEvent::Key(key) if !burst => {
                if fresh {
                    display.predictor.hold();
                }
                let press = key.stroke().press;
                display.predict_key(press);
            }
            InputEvent::Key(_) | InputEvent::Mouse(_) | InputEvent::Paste(_) => {
                display.predict_other();
            }
            InputEvent::Focus(_) => {}
        }
    }
}

/// Suspend the client: the terminal left as the user's shell expects it, the process stopped
/// with SIGTSTP; once continued, the terminal taken back. The stop may never come (no job
/// control): then a key typed, or a fatal signal, ends the wait.
async fn suspend<B: KohBackend>(
    backend: &mut B,
    display: &mut Display,
    shutdown: &CancellationToken,
    input: &mut mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut continued = signal(SignalKind::from_raw(fuxix::process::Signal::Cont.raw()))?;
    display.leave(backend)?;
    backend.leave_raw_mode()?;
    backend.write_bytes(b"[koh suspended: run `fg` to resume]\r\n")?;
    backend.flush()?;
    fuxix::process::kill(own_pid()?, fuxix::process::Signal::Tstp)?;
    tokio::select! {
        _ = continued.recv() => {}
        _ = input.recv() => {}
        () = shutdown.cancelled() => {}
    }
    backend.enter_raw_mode()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_backoff_grows_then_caps() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(3), Duration::from_secs(4));
        assert_eq!(backoff(4), Duration::from_secs(8));
        assert_eq!(backoff(9), Duration::from_secs(8));
    }

    #[test]
    fn dwell_gate_resets_on_proven_connection_and_climbs_on_flap() {
        assert_eq!(next_attempt_after_drop(3, MIN_CONNECTION_DWELL), 0);
        assert_eq!(next_attempt_after_drop(3, Duration::from_millis(100)), 4);
    }
}
