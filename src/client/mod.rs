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
pub(crate) use io::spawn_client_io;

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
use input::Keys;
use iroh::endpoint::{Connection, SendStream, TransportErrorCode};
use iroh::{Endpoint, EndpointAddr};
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

/// How long notices stay on the status line.
const NOTICE_FOR: Duration = Duration::from_secs(3);

/// Dials the server and makes the opening request ([`crate::request`]).
///
/// It makes a shell's first connection and every reconnect, which reattaches to the session the
/// first reached, and the one connection of a command, a copy or a listing.
pub struct IrohConnector {
    endpoint: Endpoint,
    target: EndpointAddr,
}

impl IrohConnector {
    /// A connector dialing `target` from `endpoint`.
    pub const fn new(endpoint: Endpoint, target: EndpointAddr) -> Self {
        Self { endpoint, target }
    }

    /// Connect and make `request`, on the client's first stream, left open for what follows it.
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
            control
                .write_all(&crate::request::encode(request, MAX_REQUEST)?)
                .await?;
            anyhow::Ok(control)
        };
        match opened.await {
            Ok(control) => Ok((conn, control)),
            Err(e) => Err(refusal(&conn, &e)),
        }
    }

    /// Connect to the session `pick` names (a new one running `program` in `cwd`, if given), for a
    /// terminal of `size`, and await the server's first stream, which admits the client and says which session it reached. A server that
    /// will not have us for good closes the connection instead, a [`Refused`] error; one that
    /// cannot have us now (at capacity, say) closes it saying so, an error that is its [`Close`].
    pub async fn connect(
        &self,
        pick: Pick,
        size: Size,
        (program, cwd): (Option<Argv>, Option<RemotePath>),
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
        Some(Close::NotAuthorized) => Refused::NotAuthorized.into(),
        Some(Close::NoSuchSession) => Refused::NoSuchSession.into(),
        Some(Close::OutOfScope) => Refused::OutOfScope.into(),
        Some(why) => why.into(),
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
    /// The input writer has room for what is held.
    Room,
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
    /// Input waiting for its writer, which waits for the server to take it, and its bytes.
    queued: crate::bounded::Bounded<Vec<u8>, QUEUED_MESSAGES>,
    queued_bytes: usize,
    /// Typing was dropped since the queue was last empty: the status line says so.
    paused: bool,
    /// The newest input sent on it: a report made before the server wrote it is held.
    sent: InputSeq,
}

/// The most typed bytes held while the server takes no input; past it, typing is dropped and the
/// status line says so. An empty queue takes any input, a whole paste included.
const MAX_QUEUED_INPUT: usize = 1024 * 1024;

/// The most messages of input held, however small.
const QUEUED_MESSAGES: usize = 4096;

/// How many encoded messages may wait for a writer, and decoded ones for the loop.
const WRITER_QUEUE: usize = 64;
const READER_QUEUE: usize = 64;

impl Wire {
    fn open(Admitted { conn, control, .. }: Admitted) -> Self {
        let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
        let (control_tx, control_rx) = mpsc::channel::<Vec<u8>>(WRITER_QUEUE);
        let (tx, rx) = mpsc::channel(READER_QUEUE);
        let input = {
            let conn = conn.clone();
            async move {
                if let Ok(stream) = conn.open_uni().await {
                    write_client_stream(stream, input_rx).await;
                }
            }
        };
        #[expect(
            clippy::disallowed_methods,
            reason = "two writers and a reader a connection"
        )]
        let tasks = [
            AbortOnDropHandle::new(tokio::spawn(input)),
            AbortOnDropHandle::new(tokio::spawn(write_client_stream(control, control_rx))),
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
            queued: crate::bounded::Bounded::new(),
            queued_bytes: 0,
            paused: false,
            sent: InputSeq::default(),
        }
    }

    /// Queue `msg` on its stream; whether there was room. Input waits in order behind what the
    /// server has not taken, up to [`MAX_QUEUED_INPUT`]; past it, it is dropped (an empty queue
    /// takes any message).
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
        if self.queued.is_empty() {
            match self.input_tx.try_send(bytes) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Closed(_)) => return false,
                Err(mpsc::error::TrySendError::Full(bytes)) => return self.hold(bytes),
            }
        }
        self.hold(bytes)
    }

    /// Hold `bytes` of input for the writer, if there is room.
    fn hold(&mut self, bytes: Vec<u8>) -> bool {
        let len = bytes.len();
        if self.queued_bytes > 0 && self.queued_bytes.saturating_add(len) > MAX_QUEUED_INPUT {
            self.paused = true;
            return false;
        }
        if self.queued.push_back(bytes).is_err() {
            self.paused = true;
            return false;
        }
        self.queued_bytes = self.queued_bytes.saturating_add(len);
        true
    }

    /// The writer has room: the oldest input held goes.
    fn release(&mut self, permit: mpsc::OwnedPermit<Vec<u8>>) {
        if let Some(bytes) = self.queued.pop_front() {
            self.queued_bytes = self.queued_bytes.saturating_sub(bytes.len());
            let _ = permit.send(bytes);
        }
        if self.queued.is_empty() {
            self.paused = false;
        }
    }
}

impl Drop for Wire {
    /// The run, or this connection, is over: the server is told at once, not at the idle timeout.
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"client exit");
    }
}

/// Write queued messages to one of the client's streams until the queue or the stream closes.
async fn write_client_stream(mut send: SendStream, mut queue: mpsc::Receiver<Vec<u8>>) {
    while let Some(bytes) = queue.recv().await {
        if send.write_all(&bytes).await.is_err() {
            return;
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

/// The client's link to the server: a live connection, or a redial under way.
enum Net<'c> {
    Up(Box<Wire>),
    Down(Dial<'c>),
}

/// A redial: the backoff, then one dial, abandoned after [`RECONNECT_CONNECT_TIMEOUT`].
type Dial<'c> = std::pin::Pin<Box<dyn std::future::Future<Output = Dialed> + Send + 'c>>;

/// A redial's result: connected, refused, or timed out.
type Dialed = Result<anyhow::Result<Admitted>, tokio::time::error::Elapsed>;

/// Dial `pick` again, for a terminal of `size`: at once after a proven connection's drop
/// (`attempt` 0), else after a backoff.
fn dial(connector: &IrohConnector, attempt: u32, pick: Pick, size: Size) -> Dial<'_> {
    let wait = if attempt > 0 {
        backoff(attempt)
    } else {
        Duration::ZERO
    };
    Box::pin(async move {
        tokio::time::sleep(wait).await;
        tokio::time::timeout(
            RECONNECT_CONNECT_TIMEOUT,
            connector.connect(pick, size, (None, None)),
        )
        .await
    })
}

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

/// What the status line says, a notice at a time, for a while.
#[derive(Default)]
struct Notices {
    shown: Option<(&'static str, Instant)>,
}

impl Notices {
    fn give(&mut self, text: &'static str, now: Instant) {
        self.shown = Some((text, now));
    }

    fn say(&self, now: Instant) -> Option<&'static str> {
        self.shown
            .filter(|(_, at)| now.saturating_duration_since(*at) < NOTICE_FOR)
            .map(|(text, _)| text)
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
}

/// Run a shell client on `initial`, redialing through `connector` whenever the link drops; the
/// remote program's exit status if it exited, `None` on a detach.
///
/// Each redial reattaches to the same server session, by its number in that server's run; a
/// session gone meanwhile ends the run. `input_rx` carries typed bytes (its closing ends the run),
/// `resize_rx` resize ticks. Cancelling `shutdown` (a fatal signal) detaches.
pub async fn run_client<B: KohBackend>(
    initial: Admitted,
    dialed_at: SystemTime,
    connector: IrohConnector,
    run: Run<B>,
    (mut input_rx, resize_rx): (mpsc::Receiver<Vec<u8>>, mpsc::Receiver<()>),
    shutdown: CancellationToken,
) -> anyhow::Result<Option<u32>> {
    let Run {
        mut backend,
        mut size,
        colours,
        clipboard,
        links,
        mut bell,
    } = run;
    let mut display = Display::new(size, clipboard, links)?;
    let mut keys = Keys::new(Instant::now(), colours);
    backend.write_bytes(&keys.take_questions())?;
    backend.flush()?;
    // Every redial goes back to the session the first connection reached, never to another.
    let back = Pick::Resume(initial.at);
    let mut resizes = Resizes(Some(resize_rx));
    let mut attempt: u32 = 0;
    let mut net = Net::Up(Box::new(Wire::open(initial)));
    let mut seq = InputSeq::default();
    let mut resized: u32 = 0;
    let mut notices = Notices::default();
    // Since when the link is down, and whether typing was dropped in the outage.
    let mut outage: Option<(Instant, bool)> = None;
    let mut bells: Option<u64> = None;
    let mut title = String::new();
    let mut last_wall = dialed_at;
    let mut status: Option<String> = None;
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let now = Instant::now();
        // The status line, painted again only when it changes.
        let said = match (&net, outage) {
            (Net::Down(_), Some((_, dropped))) => Some(if dropped {
                "[koh] reconnecting… · typing during the outage not sent · Ctrl-^ . to quit"
            } else {
                "[koh] reconnecting… · Ctrl-^ . to quit"
            }),
            (Net::Up(wire), _) if now.saturating_duration_since(wire.heard) > LINK_DOWN_GRACE => {
                Some("[koh] link down… · Ctrl-^ . to quit")
            }
            (Net::Up(wire), _) if wire.paused => {
                Some("[koh] input paused — the server is not taking input")
            }
            _ => notices.say(now),
        }
        .map(str::to_owned);
        if said != status {
            status = said;
            display.set_status(status.clone());
        }
        display.paint(&mut backend)?;
        backend.flush()?;

        let (from_server, dialing, room) = match &mut net {
            Net::Up(wire) => {
                let room = (!wire.queued.is_empty()).then(|| wire.input_tx.clone());
                (Some(&mut wire.rx), None, room)
            }
            Net::Down(dial) => (None, Some(dial), None),
        };
        let others = async {
            tokio::select! {
                typed = input_rx.recv() => Step::Typed(typed),
                () = when(keys.deadline().map(|at| tokio::time::sleep_until(at.into()))) => Step::Timeout,
                () = shutdown.cancelled() => Step::Quit,
                msg = when(from_server.map(mpsc::Receiver::recv)) => Step::Server(msg),
                dialed = when(dialing) => Step::Dialed(dialed),
                _ = tick.tick() => Step::Tick,
                permit = when(room.as_ref().map(mpsc::Sender::reserve)) => match permit {
                    Ok(permit) => {
                        // Taken at once: the permit is the room, and it goes with the held input.
                        drop(permit);
                        Step::Room
                    }
                    Err(_) => Step::Server(None),
                },
            }
        };
        // A resize first: keys typed after it must not reach the program before it does.
        let step = tokio::select! {
            biased;
            () = resizes.next() => Step::Resize,
            step = others => step,
        };
        let read = match step {
            Step::Typed(None) | Step::Quit => {
                display.leave(&mut backend)?;
                backend.flush()?;
                return Ok(None);
            }
            Step::Typed(Some(bytes)) => Some(keys.bytes(Instant::now(), &bytes)),
            Step::Timeout => Some(keys.timeout(Instant::now())),
            Step::Resize => {
                if let Ok(now_size) = backend.size() {
                    size = now_size;
                    display.resize(size);
                    resized = resized.saturating_add(1);
                    if let Net::Up(wire) = &mut net {
                        // On both streams: the control one waits for no input, and among the
                        // input nothing typed after it overtakes it.
                        let msg = ClientMsg::Resize { n: resized, size };
                        wire.send(&msg);
                        if let Ok(bytes) = encode_client(&msg) {
                            let _ = wire.control_tx.try_send(bytes);
                        }
                    }
                }
                None
            }
            Step::Server(Some(from)) => {
                let Net::Up(wire) = &mut net else { continue };
                wire.heard = Instant::now();
                match from {
                    FromServer::Read { epoch, bytes } => {
                        if epoch == wire.epoch {
                            wire.send(&ClientMsg::Read { epoch, bytes });
                        }
                    }
                    FromServer::Shown { epoch, msg } => {
                        if epoch < wire.epoch {
                            continue;
                        }
                        if epoch > wire.epoch {
                            // A new epoch: its redraw resets the terminal, and the mirror with it.
                            wire.epoch = epoch;
                            display.new_epoch(size)?;
                            outage = None;
                        }
                        match msg {
                            Shown::Out(bytes) => display.output(&mut backend, &bytes)?,
                            Shown::Mark(mark) => display.mark(&mut backend, mark.as_bytes())?,
                            // Made before the server wrote all this connection sent, it may say
                            // `reading` of a program that has yet to take those keys: held.
                            Shown::Report { activity, input } => {
                                if input >= wire.sent {
                                    display.report(&mut backend, activity)?;
                                }
                            }
                            Shown::Tty(tty) => display.predictor.set_tty(Some(tty)),
                            Shown::Echo(acked) => {
                                display.predictor.set_local_frame_late_acked(acked.0);
                                display.reconcile();
                            }
                            // The first count the run hears is from before it: it rings nothing.
                            Shown::Bell(count) => {
                                let first = bells.replace(count).is_none();
                                if let Some(hook) = bell.as_mut() {
                                    if first {
                                        hook.prime(count);
                                    } else if hook.observe(count, std::time::Instant::now()) {
                                        hook.fire(count, &title);
                                    }
                                }
                            }
                            Shown::Title(now_title) => title = now_title,
                            Shown::Exit { code, read } => {
                                // Its program read every key this connection sent: said to a
                                // terminal that reads reports, which then knows they reached it.
                                if read.is_some_and(|read| read >= wire.sent) {
                                    display.ended(&mut backend)?;
                                }
                                display.leave(&mut backend)?;
                                backend.flush()?;
                                // The end is here, which this close tells the server: it waits
                                // for nothing more, and neither does the client.
                                wire.conn.close(Close::SessionEnded.code().into(), b"");
                                return Ok(Some(code));
                            }
                            Shown::Beat => {}
                        }
                    }
                }
                None
            }
            Step::Server(None) => {
                let Net::Up(wire) = &net else { continue };
                if closed_because(&wire.conn) == Some(Close::SessionEnded) {
                    display.leave(&mut backend)?;
                    backend.flush()?;
                    return Ok(None);
                }
                if let Some(refused) = closed_because(&wire.conn).filter(|c| {
                    matches!(
                        c,
                        Close::NotAuthorized | Close::NoSuchSession | Close::OutOfScope
                    )
                }) {
                    display.leave(&mut backend)?;
                    backend.flush()?;
                    return Err(refusal(&wire.conn, &anyhow::Error::from(refused)));
                }
                tracing::info!(reason = ?wire.conn.close_reason(), "link lost; will reconnect");
                attempt = next_attempt_after_drop(attempt, wire.started.elapsed());
                outage = Some((Instant::now(), false));
                display.predictor = display.predictor.reattached();
                net = Net::Down(dial(&connector, attempt, back, size));
                None
            }
            Step::Dialed(Ok(Ok(admitted))) => {
                let mut wire = Wire::open(admitted);
                if let Some(colours) = keys.colours() {
                    wire.send(&ClientMsg::Colours(colours.clone()));
                }
                net = Net::Up(Box::new(wire));
                None
            }
            Step::Dialed(failed) => {
                if let Ok(Err(e)) = failed {
                    if e.is::<Refused>() {
                        display.leave(&mut backend)?;
                        backend.flush()?;
                        return Err(e);
                    }
                    tracing::info!(reason = %e, attempt, "reconnect dial failed");
                }
                attempt = attempt.saturating_add(1);
                net = Net::Down(dial(&connector, attempt, back, size));
                None
            }
            Step::Room => {
                if let Net::Up(wire) = &mut net {
                    if let Ok(permit) = wire.input_tx.clone().try_reserve_owned() {
                        wire.release(permit);
                    }
                }
                None
            }
            Step::Tick => {
                // A clock stepped backwards reads as no gap.
                let wall = SystemTime::now();
                let gap = wall.duration_since(last_wall).unwrap_or(Duration::ZERO);
                last_wall = wall;
                if let (Net::Up(wire), true) = (&net, gap >= STALE_AFTER_FREEZE) {
                    tracing::info!(
                        frozen_secs = gap.as_secs(),
                        "resumed from a freeze; reconnecting"
                    );
                    wire.conn.close(0u32.into(), b"reconnecting");
                    outage = Some((Instant::now(), false));
                    net = Net::Down(dial(&connector, 0, back, size));
                }
                None
            }
        };
        let Some(read) = read else { continue };
        backend.write_bytes(&keys.take_questions())?;
        if read.quit {
            display.leave(&mut backend)?;
            backend.flush()?;
            return Ok(None);
        }
        if read.paste_too_long {
            notices.give("[koh] paste over 1 MiB — not sent", Instant::now());
        }
        match &mut net {
            Net::Up(wire) => {
                if let Some(colours) = read.colours {
                    wire.send(&ClientMsg::Colours(colours));
                }
                // At most a message's events at a time, each its own input; one dropped past the
                // queue is said on the status line while it drains.
                for events in read.events.chunks(crate::events::MAX_EVENTS) {
                    seq = seq.next();
                    predict(&mut display, events, seq);
                    let msg = ClientMsg::Keys {
                        seq,
                        events: events.to_vec(),
                    };
                    if wire.send(&msg) {
                        wire.sent = seq;
                    }
                }
            }
            // Not sent, nor predicted: the end of a line whose start was lost must not run alone.
            Net::Down(_) => {
                if read
                    .events
                    .iter()
                    .any(|e| matches!(e, InputEvent::Key(_) | InputEvent::Paste(_)))
                {
                    if let Some((_, dropped)) = outage.as_mut() {
                        *dropped = true;
                    }
                }
            }
        }
        if read.suspend {
            suspend(&mut backend, &mut display, &shutdown, &mut input_rx).await?;
            if let (Net::Up(wire), Ok(now_size)) = (&mut net, backend.size()) {
                size = now_size;
                display.resize(size);
                resized = resized.saturating_add(1);
                wire.send(&ClientMsg::Resize { n: resized, size });
                wire.send(&ClientMsg::Redraw);
            }
            last_wall = SystemTime::now();
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
