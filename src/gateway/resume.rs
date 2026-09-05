//! Bounded, acknowledged byte forwarding. A Session survives replacement of its remote link.
//! Sequence numbers count frames, including EOF. Application writes happen before acknowledgement;
//! a replayed frame is acknowledged again without repeating its application write.
use std::{collections::VecDeque, io, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

const CHUNK: usize = 16 * 1024;
const WINDOW: usize = 32;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq)]
enum Frame {
    Data(u64, Vec<u8>),
    End(u64),
    Ack(u64),
}
impl Frame {
    fn sequence(&self) -> u64 {
        match self {
            Self::Data(n, _) | Self::End(n) | Self::Ack(n) => *n,
        }
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Frame> {
    // Idle is allowed, but a partially delivered frame has an absolute deadline.
    let kind = reader.read_u8().await?;
    tokio::time::timeout(DEADLINE, async {
        let sequence = reader.read_u64().await?;
        match kind {
            0 => {
                let length = usize::from(reader.read_u16().await?);
                if length == 0 || length > CHUNK {
                    return Err(invalid("invalid gateway chunk"));
                }
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).await?;
                Ok(Frame::Data(sequence, bytes))
            }
            1 => Ok(Frame::End(sequence)),
            2 => Ok(Frame::Ack(sequence)),
            _ => Err(invalid("invalid gateway frame type")),
        }
    })
    .await
    .map_err(io::Error::other)?
}
async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> io::Result<()> {
    tokio::time::timeout(DEADLINE, async {
        writer
            .write_u8(match frame {
                Frame::Data(..) => 0,
                Frame::End(_) => 1,
                Frame::Ack(_) => 2,
            })
            .await?;
        writer.write_u64(frame.sequence()).await?;
        if let Frame::Data(_, bytes) = frame {
            let length =
                u16::try_from(bytes.len()).map_err(|_| invalid("invalid gateway chunk"))?;
            writer.write_u16(length).await?;
            writer.write_all(bytes).await?;
        }
        writer.flush().await
    })
    .await
    .map_err(io::Error::other)?
}

/// Remote-link errors permit a retry; application errors and invalid protocol end the session.
#[derive(Debug)]
pub(super) enum Failure {
    Link(io::Error),
    Session(io::Error),
}
impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Session(error)
    }
}

enum Event {
    Received(io::Result<Frame>),
    Written(Option<u64>),
    Broken(io::Error),
}

pub(super) struct Session {
    local_read: tokio::net::unix::OwnedReadHalf,
    local_write: tokio::net::unix::OwnedWriteHalf,
    received: VecDeque<Frame>,
    write_offset: usize,
    write_deadline: Option<tokio::time::Instant>,
    pending: VecDeque<Frame>,
    next_send: u64,
    acknowledged: u64,
    next_receive: u64,
    local_ended: bool,
    remote_ended: bool,
}
impl Session {
    pub(super) fn new(local: UnixStream) -> Self {
        let (local_read, local_write) = local.into_split();
        Self {
            local_read,
            local_write,
            received: VecDeque::new(),
            write_offset: 0,
            write_deadline: None,
            pending: VecDeque::new(),
            next_send: 0,
            acknowledged: 0,
            next_receive: 0,
            local_ended: false,
            remote_ended: false,
        }
    }
    pub(super) fn committed(&self) -> u64 {
        self.next_receive
    }
    pub(super) fn is_complete(&self) -> bool {
        self.local_ended && self.remote_ended && self.pending.is_empty()
    }
    pub(super) fn confirm_complete(&mut self, next: u64) -> io::Result<()> {
        self.acknowledge(next)?;
        if !self.is_complete() {
            return Err(invalid("premature gateway completion"));
        }
        Ok(())
    }
    fn acknowledge(&mut self, next: u64) -> io::Result<()> {
        if next > self.next_send {
            return Err(invalid("gateway acknowledges unsent frames"));
        }
        if next <= self.acknowledged {
            return Ok(());
        }
        self.acknowledged = next;
        while self
            .pending
            .front()
            .is_some_and(|frame| frame.sequence() < next)
        {
            self.pending.pop_front();
        }
        Ok(())
    }
    fn receive(&mut self, frame: Frame) -> io::Result<()> {
        if let Frame::Ack(next) = frame {
            return self.acknowledge(next);
        }
        let expected = self
            .next_receive
            .checked_add(
                u64::try_from(self.received.len()).map_err(|_| invalid("sequence exhausted"))?,
            )
            .ok_or_else(|| invalid("sequence exhausted"))?;
        if frame.sequence() < expected {
            return Ok(());
        }
        if frame.sequence() != expected
            || self.remote_ended
            || self
                .received
                .back()
                .is_some_and(|frame| matches!(frame, Frame::End(_)))
        {
            return Err(invalid("gateway frame gap or data after EOF"));
        }
        if self.received.len() >= WINDOW {
            return Err(invalid("gateway receive window exceeded"));
        }
        if self.received.is_empty() {
            self.write_deadline = Some(tokio::time::Instant::now() + DEADLINE);
        }
        self.received.push_back(frame);
        Ok(())
    }
    fn written(&mut self, length: usize) -> io::Result<()> {
        let done = match self.received.front() {
            Some(Frame::Data(_, bytes)) => {
                if length == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "application write returned zero",
                    ));
                }
                self.write_offset += length;
                self.write_offset == bytes.len()
            }
            Some(Frame::End(_)) => {
                self.remote_ended = true;
                true
            }
            _ => return Err(invalid("unexpected application write completion")),
        };
        if done {
            self.received.pop_front();
            self.write_offset = 0;
            self.next_receive = self
                .next_receive
                .checked_add(1)
                .ok_or_else(|| invalid("sequence exhausted"))?;
            self.write_deadline =
                (!self.received.is_empty()).then(|| tokio::time::Instant::now() + DEADLINE);
        }
        Ok(())
    }
    async fn exchange_events(
        &mut self,
        outgoing: &mpsc::Sender<Frame>,
        incoming: &mut mpsc::Receiver<Event>,
    ) -> Result<(), Failure> {
        let mut cursor = self.acknowledged;
        let mut ack_queued = None;
        let mut ack_written = None;
        let mut buffer = vec![0; CHUNK];
        loop {
            if self.local_ended
                && self.remote_ended
                && self.pending.is_empty()
                && ack_written == Some(self.next_receive)
            {
                return Ok(());
            }
            let next = if ack_queued == Some(self.next_receive) {
                self.pending
                    .iter()
                    .find(|frame| frame.sequence() >= cursor)
                    .cloned()
            } else {
                Some(Frame::Ack(self.next_receive))
            };
            tokio::select! {
                event = incoming.recv() => {
                    match event {
                        Some(Event::Received(Ok(frame))) => {
                            // A duplicate data frame must elicit another ACK even if no new
                            // application bytes were written (the previous ACK may be lost).
                            if !matches!(frame, Frame::Ack(_)) { ack_queued = None; }
                            self.receive(frame)?;
                        }
                        Some(Event::Received(Err(error))) if error.kind() == io::ErrorKind::InvalidData => return Err(Failure::Session(error)),
                        Some(Event::Received(Err(error)) | Event::Broken(error)) => return Err(Failure::Link(error)),
                        Some(Event::Written(Some(ack))) => ack_written = Some(ack),
                        Some(Event::Written(None)) => {},
                        None => return Err(Failure::Link(io::Error::other("gateway link ended"))),
                    }
                }
                permit = outgoing.reserve(), if next.is_some() => {
                    let permit = permit.map_err(|_| Failure::Link(io::Error::other("gateway writer ended")))?;
                    if let Some(frame) = next {
                        if let Frame::Ack(ack) = frame { ack_queued = Some(ack); }
                        else { cursor = frame.sequence().checked_add(1).ok_or_else(|| invalid("sequence exhausted"))?; }
                        permit.send(frame);
                    }
                }
                length = async {
                    match self.received.front() {
                        Some(Frame::Data(_, bytes)) => self.local_write.write(bytes.get(self.write_offset..).ok_or_else(|| invalid("invalid write offset"))?).await,
                        Some(Frame::End(_)) => { self.local_write.shutdown().await?; Ok(0) },
                        _ => std::future::pending().await,
                    }
                }, if !self.received.is_empty() => {
                    self.written(length?)?;
                }
                () = async {
                    if let Some(deadline) = self.write_deadline { tokio::time::sleep_until(deadline).await; }
                    else { std::future::pending().await }
                } => return Err(Failure::Session(io::Error::new(io::ErrorKind::TimedOut, "local application stalled"))),
                length = self.local_read.read(&mut buffer), if !self.local_ended && self.pending.len() < WINDOW => {
                    let length = length?;
                    let sequence = self.next_send;
                    self.next_send = sequence.checked_add(1).ok_or_else(|| invalid("sequence exhausted"))?;
                    let frame = if length == 0 {
                        self.local_ended = true;
                        Frame::End(sequence)
                    } else { Frame::Data(sequence, buffer.get(..length).ok_or_else(|| invalid("invalid read length"))?.to_vec()) };
                    self.pending.push_back(frame);
                }
            }
        }
    }
    /// Exchange over one remote connection. Retain this Session on Failure::Link, and use a
    /// fresh reader/writer pair for retry. Cancellation of this future ends the whole session.
    pub(super) async fn exchange<R, W>(&mut self, reader: R, writer: W) -> Result<(), Failure>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (events, mut incoming) = mpsc::channel(2);
        let (outgoing, mut queued) = mpsc::channel::<Frame>(1);
        let mut tasks = tokio::task::JoinSet::new();
        let received = events.clone();
        tasks.spawn(async move {
            let mut reader = reader;
            loop {
                let frame = read_frame(&mut reader).await;
                let failed = frame.is_err();
                if received.send(Event::Received(frame)).await.is_err() || failed {
                    break;
                }
            }
        });
        tasks.spawn(async move {
            let mut writer = writer;
            while let Some(frame) = queued.recv().await {
                match write_frame(&mut writer, &frame).await {
                    Ok(()) => {
                        let ack = if let Frame::Ack(n) = frame {
                            Some(n)
                        } else {
                            None
                        };
                        if events.send(Event::Written(ack)).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = events.send(Event::Broken(error)).await;
                        break;
                    }
                }
            }
        });
        let result = self.exchange_events(&outgoing, &mut incoming).await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test assertions retain operation context"
)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lost_ack_reconnect_replays_no_application_bytes() {
        let (local, mut app) = UnixStream::pair().expect("application pair");
        let session = Session::new(local);
        let (wire, mut peer) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            let (read, write) = tokio::io::split(wire);
            let mut session = session;
            let result = session.exchange(read, write).await;
            (session, result)
        });
        write_frame(&mut peer, &Frame::Data(0, b"once".to_vec()))
            .await
            .expect("first input");
        let mut bytes = [0; 4];
        app.read_exact(&mut bytes).await.expect("applied input");
        assert_eq!(&bytes, b"once");
        // Drop without consuming any ACK. The application has committed the operation.
        drop(peer);
        let (mut session, result) = task.await.expect("first exchange");
        assert!(matches!(result, Err(Failure::Link(_))));
        assert_eq!(session.next_receive, 1);
        let (wire, mut peer) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            let (read, write) = tokio::io::split(wire);
            let result = session.exchange(read, write).await;
            (session, result)
        });
        write_frame(&mut peer, &Frame::Data(0, b"once".to_vec()))
            .await
            .expect("replayed input");
        write_frame(&mut peer, &Frame::Data(1, b"next".to_vec()))
            .await
            .expect("new input");
        app.read_exact(&mut bytes).await.expect("only new bytes");
        assert_eq!(&bytes, b"next");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), app.read_u8())
                .await
                .is_err()
        );
        drop(peer);
        let (session, _) = task.await.expect("second exchange");
        assert_eq!(session.next_receive, 2);
    }

    #[tokio::test]
    async fn reconnect_replays_pending_output_and_validates_acknowledgements() {
        let (local, mut app) = UnixStream::pair().expect("application pair");
        let mut session = Session::new(local);
        let (wire, mut peer) = tokio::io::duplex(CHUNK * 2);
        let task = tokio::spawn(async move {
            let (read, write) = tokio::io::split(wire);
            let result = session.exchange(read, write).await;
            (session, result)
        });
        app.write_all(b"persist").await.expect("app output");
        let output = loop {
            let frame = read_frame(&mut peer).await.expect("remote output");
            if matches!(frame, Frame::Data(..)) {
                break frame;
            }
        };
        assert_eq!(output, Frame::Data(0, b"persist".to_vec()));
        drop(peer);
        let (mut session, _) = task.await.expect("first exchange");
        assert_eq!(session.pending.front(), Some(&output));
        assert!(session.acknowledge(2).is_err());
        assert_eq!(session.pending.len(), 1);
        let (wire, mut peer) = tokio::io::duplex(CHUNK * 2);
        let task = tokio::spawn(async move {
            let (read, write) = tokio::io::split(wire);
            let result = session.exchange(read, write).await;
            (session, result)
        });
        loop {
            let frame = read_frame(&mut peer).await.expect("replayed output");
            if matches!(frame, Frame::Data(..)) {
                assert_eq!(frame, output);
                break;
            }
        }
        write_frame(&mut peer, &Frame::Ack(1))
            .await
            .expect("ack output");
        // A subsequent input roundtrip proves that the ordered ACK was processed.
        write_frame(&mut peer, &Frame::Data(0, b"x".to_vec()))
            .await
            .expect("barrier");
        assert_eq!(app.read_u8().await.expect("barrier applied"), b'x');
        drop(peer);
        let (session, _) = task.await.expect("second exchange");
        assert!(session.pending.is_empty());
    }

    #[tokio::test]
    async fn partial_application_write_resumes_at_its_exact_offset() {
        let (local, mut app) = UnixStream::pair().expect("application pair");
        let mut session = Session::new(local);
        session
            .receive(Frame::Data(0, b"abcdef".to_vec()))
            .expect("queued input");
        session
            .local_write
            .write_all(b"abc")
            .await
            .expect("partial application progress");
        session.written(3).expect("record exact progress");
        assert_eq!(
            session.next_receive, 0,
            "partial writes must not be acknowledged"
        );
        let (wire, mut peer) = tokio::io::duplex(64);
        let task = tokio::spawn(async move {
            let (read, write) = tokio::io::split(wire);
            let result = session.exchange(read, write).await;
            (session, result)
        });
        write_frame(&mut peer, &Frame::Data(0, b"abcdef".to_vec()))
            .await
            .expect("replay whole frame");
        let mut bytes = [0; 6];
        app.read_exact(&mut bytes)
            .await
            .expect("complete application bytes");
        assert_eq!(&bytes, b"abcdef");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), app.read_u8())
                .await
                .is_err()
        );
        drop(peer);
        let (session, _) = task.await.expect("exchange");
        assert_eq!(session.next_receive, 1);
        assert!(session.received.is_empty());
    }

    #[tokio::test]
    async fn receive_window_and_wire_chunk_are_bounded() {
        let (local, _app) = UnixStream::pair().expect("application pair");
        let mut session = Session::new(local);
        for sequence in 0..WINDOW {
            session
                .receive(Frame::Data(
                    u64::try_from(sequence).expect("sequence"),
                    vec![0; CHUNK],
                ))
                .expect("within window");
        }
        assert!(session
            .receive(Frame::End(u64::try_from(WINDOW).expect("window")))
            .is_err());
        assert_eq!(session.received.len(), WINDOW);
        let mut oversized: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255];
        assert_eq!(
            read_frame(&mut oversized)
                .await
                .expect_err("reject before payload allocation")
                .kind(),
            io::ErrorKind::InvalidData
        );
        let mut invalid_kind: &[u8] = &[99, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(read_frame(&mut invalid_kind).await.is_err());
    }

    #[tokio::test]
    async fn completed_session_recovers_a_lost_final_ack_and_rejects_premature_completion() {
        let (local, mut app) = UnixStream::pair().expect("application pair");
        let mut session = Session::new(local);
        let (wire, mut peer) = tokio::io::duplex(128);
        let task = tokio::spawn(async move {
            let (read, write) = tokio::io::split(wire);
            let result = session.exchange(read, write).await;
            (session, result)
        });
        // The application emits final output and half-closes. Its peer has also sent EOF.
        app.write_all(b"tail").await.expect("final output");
        app.shutdown().await.expect("application EOF");
        write_frame(&mut peer, &Frame::End(0))
            .await
            .expect("input EOF");
        let mut output = Vec::new();
        loop {
            match read_frame(&mut peer).await.expect("final output frames") {
                Frame::Data(sequence, bytes) => {
                    output.extend_from_slice(&bytes);
                    write_frame(&mut peer, &Frame::Ack(sequence + 1))
                        .await
                        .expect("output ack");
                }
                Frame::End(sequence) => {
                    write_frame(&mut peer, &Frame::Ack(sequence + 1))
                        .await
                        .expect("output EOF ack");
                    break;
                }
                Frame::Ack(_) => {} // Model losing the acknowledgement of our input EOF.
            }
        }
        assert_eq!(output, b"tail");
        let (completed, result) = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .expect("completion deadline")
            .expect("exchange task");
        result.expect("server completed");
        assert!(completed.is_complete());
        assert_eq!(completed.committed(), 1);
        // The reconnecting client has consumed all remote output, but still retains its EOF.
        let (local, _app) = UnixStream::pair().expect("client application pair");
        let mut client = Session::new(local);
        assert!(
            client.confirm_complete(0).is_err(),
            "a server cannot complete a live client"
        );
        client.local_ended = true;
        client.remote_ended = true;
        client.next_send = 1;
        client.pending.push_back(Frame::End(0));
        assert!(
            client.confirm_complete(2).is_err(),
            "completion cannot acknowledge unsent input"
        );
        client
            .confirm_complete(completed.committed())
            .expect("retained completion acknowledges EOF");
        assert!(client.is_complete());
        assert!(client.pending.is_empty());
    }

    #[tokio::test]
    async fn sequence_gaps_and_data_after_eof_end_the_session() {
        let (local, _app) = UnixStream::pair().expect("application pair");
        let mut session = Session::new(local);
        assert!(session.receive(Frame::Data(1, vec![1])).is_err());
        assert_eq!(session.next_receive, 0);
        session.receive(Frame::End(0)).expect("EOF");
        session.receive(Frame::End(0)).expect("replayed EOF");
        session.written(0).expect("EOF committed");
        assert!(session.receive(Frame::Data(1, vec![1])).is_err());
        assert_eq!(session.next_receive, 1);
    }
}
