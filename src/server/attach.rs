//! One connection to a session: the client's input to the session, and what the program shows
//! to the client, as a stream of [`Shown`] messages per epoch.
//!
//! An epoch begins with the screen as it is ([`Start`]) and goes on with the session's events.
//! The client says how much of the epoch it has read ([`ClientMsg::Read`]), and no more is
//! written than the link carries in about a round trip past that, so what is written is never
//! more than that behind the program. A client that falls behind further than the session keeps
//! events for is sent a new epoch: the old stream is reset, so QUIC stops sending what it
//! missed, and the new one begins with the screen as it is now, and above it what scrolled off
//! since the top row of what the client read ([`Event::Top`]), into its terminal's scrollback.

use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::info;

use super::session::{Event, Input, SessionClient, Start, ToSession, Window};
use crate::bounded::Bounded;
use crate::log::Peer;
use crate::proto::{encode_shown, ClientDecoder, ClientMsg, Close, ProtoError, Shown, HEARTBEAT};
use crate::transport_iroh::close;

/// How many messages may wait for an epoch's stream beside its redraw: the bytes waiting are
/// bounded by the budget, this only by how many small messages may make them up.
const WRITER_QUEUE: usize = 4096;

/// The bytes in flight past what the client read, before its rate is known.
const FIRST_BUDGET: u64 = 256 * 1024;

/// Most tops of the primary screen kept ahead of what the client read ([`Event::Top`]).
const MAX_TOPS: usize = 1024;

/// The least and the most bytes in flight past what the client read.
const LEAST_BUDGET: u64 = 64 * 1024;
const MOST_BUDGET: u64 = 4 << 20;

/// How long the client has to take the program's end, at least.
const FINAL_WAIT: Duration = Duration::from_secs(2);

/// How far apart two readings of the client's progress are taken to judge its rate.
const RATE_SPAN: Duration = Duration::from_millis(250);

/// How much the client may have in flight past what it read: about what it reads in a round trip,
/// and a margin.
#[derive(Debug)]
struct Pace {
    /// Bytes of the epoch written, and read by the client.
    written: u64,
    read: u64,
    /// The last reading of the client's progress, to judge its rate from.
    since: (Instant, u64),
    budget: u64,
}

impl Pace {
    fn new(now: Instant) -> Self {
        Self {
            written: 0,
            read: 0,
            since: (now, 0),
            budget: FIRST_BUDGET,
        }
    }

    /// The client read `bytes` of the epoch by `now`, the round trip being `rtt`.
    fn read(&mut self, bytes: u64, now: Instant, rtt: Duration) {
        self.read = self.read.max(bytes.min(self.written));
        let (at, then) = self.since;
        let span = now.saturating_duration_since(at);
        if span >= RATE_SPAN {
            let rate = u128::from(self.read.saturating_sub(then))
                .saturating_mul(1_000_000_000)
                .checked_div(span.as_nanos())
                .unwrap_or(0);
            let window = rtt.saturating_add(Duration::from_millis(100)).as_nanos();
            let carried = rate
                .saturating_mul(window)
                .checked_div(1_000_000_000)
                .unwrap_or(0);
            let carried = u64::try_from(carried).unwrap_or(u64::MAX).saturating_mul(2);
            // A link that went quiet says nothing of its rate: the budget stays.
            if self.read > then {
                self.budget = carried.clamp(LEAST_BUDGET, MOST_BUDGET);
            }
            self.since = (now, self.read);
        }
    }

    /// Whether more may be written now.
    const fn room(&self) -> bool {
        self.written.saturating_sub(self.read) < self.budget
    }
}

impl Epoch {
    /// Whether more may be queued now: within the budget, and the queue has room.
    fn room(&self) -> bool {
        self.pace.room() && self.queue.capacity() > 0
    }
}

/// One epoch's stream, written by a task of its own.
struct Epoch {
    n: u32,
    queue: mpsc::Sender<Vec<u8>>,
    /// Resets the stream: the client is sent a new epoch.
    reset: CancellationToken,
    /// Whether all of it was delivered, once it was finished.
    delivered: oneshot::Receiver<bool>,
    pace: Pace,
    last_write: Instant,
}

impl Epoch {
    /// Open epoch `n` on `conn`, beginning with `shown`.
    fn open(conn: &Connection, n: u32, shown: Vec<Shown>) -> Self {
        let (queue, rx) = mpsc::channel(WRITER_QUEUE.saturating_add(shown.len()));
        let reset = CancellationToken::new();
        let (done, delivered) = oneshot::channel();
        #[expect(
            clippy::disallowed_methods,
            reason = "an epoch's writer, one a connection at a time: the last is reset first"
        )]
        tokio::spawn(write_epoch(conn.clone(), n, rx, reset.clone(), done));
        let now = Instant::now();
        let mut epoch = Self {
            n,
            queue,
            reset,
            delivered,
            pace: Pace::new(now),
            last_write: now,
        };
        // The redraw is sent whatever the budget.
        for shown in shown {
            epoch.send(&shown);
        }
        epoch
    }

    /// Queue `shown`; `false` if the stream is gone.
    fn send(&mut self, shown: &Shown) -> bool {
        let Ok(bytes) = encode_shown(shown) else {
            tracing::error!("a message for the client did not encode");
            return true;
        };
        self.pace.written = self
            .pace
            .written
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        self.last_write = Instant::now();
        // Nothing is queued but when there is room (`room`), but a redraw, which has its own.
        self.queue.try_send(bytes).is_ok()
    }
}

impl Drop for Epoch {
    fn drop(&mut self) {
        self.reset.cancel();
    }
}

/// Write epoch `n`'s messages from `rx` on a stream of `conn`'s until they end, then say on `done`
/// whether the client had all of it; reset the stream when `reset` is cancelled first.
async fn write_epoch(
    conn: Connection,
    n: u32,
    mut rx: mpsc::Receiver<Vec<u8>>,
    reset: CancellationToken,
    done: oneshot::Sender<bool>,
) {
    let wrote = async {
        let mut send: SendStream = conn.open_uni().await.ok()?;
        let mut header = vec![crate::proto::SHOWN_TAG];
        header.extend_from_slice(&n.to_be_bytes());
        let written = async {
            send.write_all(&header).await.ok()?;
            while let Some(bytes) = rx.recv().await {
                send.write_all(&bytes).await.ok()?;
            }
            send.finish().ok()
        };
        tokio::select! {
            written = written => written?,
            () = reset.cancelled() => {
                let _ = send.reset(0u32.into());
                return None;
            }
        }
        tokio::select! {
            stopped = send.stopped() => Some(matches!(stopped, Ok(None))),
            () = reset.cancelled() => None,
        }
    };
    // A client closes saying the session ended only once it has its end, which may be before
    // the stream's last bytes were acknowledged.
    let delivered = wrote.await.unwrap_or(false)
        || crate::transport_iroh::closed_because(&conn) == Some(Close::SessionEnded);
    let _ = done.send(delivered);
}

/// One of the client's streams as the server reads it.
#[derive(Default)]
struct FromClient {
    decoder: ClientDecoder,
    /// Input decoded when the session had no room for it: the stream is read no further until it
    /// has.
    waiting: Option<ToSession>,
}

/// Serve the session `client` to `conn`, from `start`; `control` is the client's first stream,
/// after its request. Returning (or panicking) detaches.
pub(super) async fn serve(
    conn: &Connection,
    client: SessionClient,
    start: Start,
    control: RecvStream,
) {
    let Start {
        shown,
        top,
        mut events,
    } = start;
    let mut epoch = Epoch::open(conn, 1, shown);
    // Where the client's terminal stands: the top row it has read up to, and the tops further on
    // in what was written, by the bytes of the epoch they follow.
    let mut seen = None;
    let mut tops: Bounded<(u64, fux_vt::RowId), MAX_TOPS> = Bounded::default();
    if let Some(top) = top {
        tops.push_evicting((epoch.pace.written, top));
    }
    let input = client.input.clone();
    let mut streams: [Option<RecvStream>; 2] = [Some(control), None];
    let mut from: [FromClient; 2] = Default::default();
    let mut bufs = [vec![0u8; 16 * 1024], vec![0u8; 16 * 1024]];
    // The newest resize taken: one no newer is a copy or out of date.
    let mut resized = 0;
    let mut window: Option<Window> = None;
    let mut exited = false;
    // The session was told the client has its end.
    let mut told = false;
    // The client is owed a new epoch, redrawn: it fell behind, or asked.
    let mut redraw = false;
    let how = loop {
        while let Some(&(_, top)) = tops.front().filter(|(at, _)| *at <= epoch.pace.read) {
            seen = Some(top);
            tops.pop_front();
        }
        if std::mem::take(&mut redraw) && !exited {
            let Some(start) = client.redraw(seen).await else {
                break "the session was ended (revoked, or the server is stopping)";
            };
            events = start.events;
            let n = epoch.n.wrapping_add(1);
            epoch = Epoch::open(conn, n, start.shown);
            tops.clear();
            if let Some(top) = start.top {
                tops.push_evicting((epoch.pace.written, top));
            }
        }
        if let Some(w) = window.take() {
            // Taken at the next pass if the session's asks are full.
            window = (!client.resize(w)).then_some(w);
        }
        let waiting = from.iter().position(|f| f.waiting.is_some());
        let wants = [0, 1].map(|at| {
            streams.get(at).is_some_and(Option::is_some)
                && from.get(at).is_some_and(|f| f.waiting.is_none())
        });
        let beat = epoch.last_write.checked_add(HEARTBEAT);
        let rtt = crate::transport_iroh::rtt(conn).unwrap_or(Duration::from_millis(100));
        let broke: Result<(), ProtoError> = tokio::select! {
            event = events.recv(), if !exited && epoch.room() => match event {
                Ok(Event::Show(shown)) => {
                    exited = matches!(*shown, Shown::Exit { .. });
                    if !epoch.send(&shown) {
                        break "client detached (session retained)";
                    }
                    if exited {
                        // The end is the epoch's last: the writer finishes the stream, and says
                        // whether the client had it.
                        let (queue, _) = mpsc::channel(1);
                        drop(std::mem::replace(&mut epoch.queue, queue));
                    }
                    Ok(())
                }
                Ok(Event::Top(top)) => {
                    // Kept within a bound: past it the oldest goes, and the client is taken to
                    // stand no further on than it did, which repeats history rather than lose it.
                    tops.push_evicting((epoch.pace.written, top));
                    Ok(())
                }
                Ok(Event::Echo { attach, seq }) => {
                    if attach == client.attach && !epoch.send(&Shown::Echo(seq)) {
                        break "client detached (session retained)";
                    }
                    Ok(())
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    tracing::debug!(missed, "the client fell behind: a new epoch, redrawn");
                    redraw = true;
                    Ok(())
                }
                // The session ended without an end to tell: revoked, or the server stopping.
                Err(broadcast::error::RecvError::Closed) => {
                    break "the session was ended (revoked, or the server is stopping)";
                }
            },
            delivered = &mut epoch.delivered, if exited => {
                if delivered.unwrap_or(false) {
                    // The client has the program's end: the session need keep it no longer.
                    client.ended().await;
                    told = true;
                    let _ = tokio::time::timeout(FINAL_WAIT, conn.closed()).await;
                    close(conn, Close::SessionEnded);
                    break "shell exited";
                }
                // The client may not have the end: the session keeps it, and this close, as a
                // lost link, has the client redial for it.
                conn.close(0u32.into(), b"");
                break "the end went undelivered (session kept)";
            }
            () = tokio::time::sleep(FINAL_WAIT.saturating_mul(4)), if exited => {
                conn.close(0u32.into(), b"");
                break "the end went undelivered (session kept)";
            }
            () = async {
                match beat {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            }, if !exited && epoch.room() => {
                if !epoch.send(&Shown::Beat) {
                    break "client detached (session retained)";
                }
                Ok(())
            }
            permit = input.reserve(), if waiting.is_some() => match permit {
                Ok(permit) => match waiting.and_then(|at| from.get_mut(at)) {
                    Some(f) => {
                        if let Some(input) = f.waiting.take() {
                            permit.send(Input { attach: client.attach, input });
                        }
                        // What the stream already brought behind it is taken now: no more may
                        // come to wake the read.
                        take(f, &mut epoch, (&mut resized, &mut window, &mut redraw), rtt)
                    }
                    None => Ok(()),
                },
                Err(_) => break "the session was ended (revoked, or the server is stopping)",
            },
            stream = conn.accept_uni() => match stream {
                Ok(stream) => match streams.get_mut(1) {
                    Some(slot @ None) => {
                        *slot = Some(stream);
                        Ok(())
                    }
                    Some(Some(_)) | None => Err(ProtoError::UnknownStream),
                },
                Err(e) => {
                    info!(reason = %Peer(e), "connection closed by peer (detaching)");
                    break "client detached (session retained)";
                }
            },
            (at, read) = read_client(&mut streams, &mut bufs, wants), if wants.contains(&true) => match read {
                Ok(Some(n)) => {
                    let bytes = bufs.get(at).and_then(|buf| buf.get(..n)).unwrap_or_default();
                    match from.get_mut(at) {
                        Some(f) => {
                            f.decoder.push(bytes);
                            take(f, &mut epoch, (&mut resized, &mut window, &mut redraw), rtt)
                        }
                        None => Ok(()),
                    }
                }
                Ok(None) => {
                    streams.get_mut(at).map(Option::take);
                    from.get(at).map_or(Ok(()), |f| f.decoder.finish())
                }
                Err(e) => {
                    info!(reason = %Peer(e), "client stream failed (detaching)");
                    break "client detached (session retained)";
                }
            },
        };
        if let Err(e) = broke {
            tracing::warn!(error = %e, "client broke the protocol; closing");
            close(conn, Close::ProtocolError);
            break "client detached (session retained)";
        }
    };
    // A client that has the end closes saying so, at once: whichever arm saw the connection go,
    // the end was delivered.
    if exited && !told && crate::transport_iroh::closed_because(conn) == Some(Close::SessionEnded) {
        client.ended().await;
    }
    info!(peer = %conn.remote_id(), "{how}");
}

/// Take the messages `from` decoded: progress for the epoch's pace, a window, and input for the
/// session, which waits in `from` once one does.
fn take(
    from: &mut FromClient,
    epoch: &mut Epoch,
    (resized, window, redraw): (&mut u32, &mut Option<Window>, &mut bool),
    rtt: Duration,
) -> Result<(), ProtoError> {
    while from.waiting.is_none() {
        let Some(msg) = from.decoder.next_msg()? else {
            return Ok(());
        };
        match msg {
            ClientMsg::Read { epoch: n, bytes } => {
                if n == epoch.n {
                    epoch.pace.read(bytes, Instant::now(), rtt);
                }
            }
            ClientMsg::Resize { n, size } => {
                // Both streams carry it: the first copy counts.
                if n > *resized {
                    *resized = n;
                    let size = crate::terminal::clamp_dims(size);
                    *window = Some(Window { n, size });
                    from.waiting = Some(ToSession::Resize(Window { n, size }));
                }
            }
            ClientMsg::Redraw => *redraw = true,
            ClientMsg::Keys { seq, events } => {
                from.waiting = Some(ToSession::Events { seq, events });
            }
            ClientMsg::Colours(colours) => from.waiting = Some(ToSession::Colours(colours)),
        }
    }
    Ok(())
}

/// Read from whichever of the client's streams `wants` reads first: which, and what it read.
async fn read_client(
    [first, second]: &mut [Option<RecvStream>; 2],
    [first_buf, second_buf]: &mut [Vec<u8>; 2],
    wants: [bool; 2],
) -> (usize, Result<Option<usize>, iroh::endpoint::ReadError>) {
    async fn read(
        stream: Option<&mut RecvStream>,
        buf: &mut [u8],
    ) -> Result<Option<usize>, iroh::endpoint::ReadError> {
        match stream {
            Some(stream) => stream.read(buf).await,
            None => std::future::pending().await,
        }
    }
    let [want_first, want_second] = wants;
    tokio::select! {
        read = read(first.as_mut(), first_buf), if want_first => (0, read),
        read = read(second.as_mut(), second_buf), if want_second => (1, read),
        else => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_follows_what_the_client_reads_in_a_round_trip() {
        let t0 = Instant::now();
        let mut pace = Pace::new(t0);
        assert!(pace.room());
        pace.written = FIRST_BUDGET;
        assert!(!pace.room(), "a full budget in flight");
        // A slow link: 100 KB a second, 50 ms round trips: about 30 KB in flight, so the least.
        pace.written = 10 << 20;
        pace.read(25_000, t0 + RATE_SPAN, Duration::from_millis(50));
        assert_eq!(pace.budget, LEAST_BUDGET);
        // A fast one: 100 MB a second.
        let read = 25_000 + 25_000_000;
        pace.read(read, t0 + RATE_SPAN * 2, Duration::from_millis(50));
        assert_eq!(pace.budget, MOST_BUDGET);
        // Quiet: it stays.
        let budget = pace.budget;
        pace.read(read, t0 + RATE_SPAN * 3, Duration::from_millis(50));
        assert_eq!(pace.budget, budget);
    }
}
