//! How a connection begins and ends: the admission ack, and every close koh sends and reads.
//!
//! Once the allowlist admits a peer and its session is attached, the server opens a bi-stream and
//! writes one byte. It is not authentication (the handshake did that); it lets the client tell
//! "admitted" from a [`Refusal`], which closes the connection instead, so a refused client fails
//! fast rather than redialing. The server opens the stream and the client accepts it: the other way
//! round both would wait.
//!
//! An admitted connection is a [`Link`], which closes only with a [`Close`]; a refusal ends only a
//! connection not yet admitted, so it never follows the ack. The client reads either end as a
//! [`Disconnect`]: the session ended, a verdict to stop on, or a lost link to redial.

use std::time::Duration;

use anyhow::anyhow;
use iroh::endpoint::{
    ApplicationClose, Connection, ConnectionError, PathId, RecvStream, SendStream,
    TransportErrorCode,
};
use iroh::{Endpoint, EndpointAddr};

use super::ALPN;

/// The single byte the server writes once a peer is authorized.
const ADMIT: u8 = 1;

/// The close codes: an end the client takes as it comes, a refusal, and a broken protocol.
const BYE: u32 = 0;
const REFUSED: u32 = 1;
const BROKE: u32 = 2;

/// How long one dial, the first or a redial, may run before it is abandoned.
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Why the server turns a peer away before admitting it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The peer is not on the allowlist.
    NotAuthorized,
    /// The peer has no session and the server holds as many as it may.
    AtCapacity,
}

impl Refusal {
    const fn reason(self) -> &'static [u8] {
        match self {
            Self::NotAuthorized => b"not authorized",
            Self::AtCapacity => b"server at session capacity",
        }
    }
}

/// Why an end closes an admitted connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// The server: the hosted program exited and the client has the final frame.
    SessionEnded,
    /// The client: the user quit.
    ClientExit,
    /// The client: the link looked lost, and it dials again.
    Reconnecting,
    /// The server: the client opened a second stream.
    SecondStream,
    /// The server: the client's stream broke the protocol.
    ProtocolError,
}

impl Close {
    const fn wire(self) -> (u32, &'static [u8]) {
        match self {
            Self::SessionEnded => (BYE, b"session ended"),
            Self::ClientExit => (BYE, b"client exit"),
            Self::Reconnecting => (BYE, b"reconnecting"),
            Self::SecondStream => (BROKE, b"a second client stream"),
            Self::ProtocolError => (BROKE, b"protocol error"),
        }
    }
}

/// How a connection, or a dial, ended for the client.
#[derive(Debug)]
pub enum Disconnect {
    /// The server ended the session: its program exited.
    Ended,
    /// The server's verdict, which a redial would only meet again.
    Fatal(anyhow::Error),
    /// The link was lost, or the dial failed on the way: worth dialing again.
    Transient(anyhow::Error),
}

impl From<Disconnect> for anyhow::Error {
    fn from(disconnect: Disconnect) -> Self {
        match disconnect {
            Disconnect::Ended => anyhow!("session ended"),
            Disconnect::Fatal(e) | Disconnect::Transient(e) => e,
        }
    }
}

/// An admitted connection.
#[derive(Clone, Debug)]
pub struct Link(Connection);

impl Link {
    pub async fn open_uni(&self) -> Result<SendStream, ConnectionError> {
        self.0.open_uni().await
    }

    pub async fn accept_uni(&self) -> Result<RecvStream, ConnectionError> {
        self.0.accept_uni().await
    }

    /// The smoothed round-trip time of the selected path, or `None` before any path exists.
    pub fn rtt(&self) -> Option<Duration> {
        let paths = self.0.paths();
        paths
            .iter()
            .find(iroh::endpoint::Path::is_selected)
            .or_else(|| paths.iter().next())
            .map(|p| p.rtt())
            .or_else(|| self.0.rtt(PathId::ZERO))
    }

    pub fn close(&self, why: Close) {
        let (code, reason) = why.wire();
        self.0.close(code.into(), reason);
    }

    /// How the connection ended: a lost link if it has not.
    pub fn ended(&self) -> Disconnect {
        self.0.close_reason().map_or_else(
            || Disconnect::Transient(anyhow!("the link was lost")),
            |e| verdict(e.into()),
        )
    }

    /// Wait for the connection to close, and say how it ended.
    pub async fn closed(&self) -> Disconnect {
        verdict(self.0.closed().await.into())
    }
}

/// Server side: turn the peer away, before admitting it ([`admit`] takes the connection).
pub fn refuse(conn: &Connection, why: Refusal) {
    conn.close(REFUSED.into(), why.reason());
}

/// Server side: admit the peer. Opening the stream can wait on the client, so the caller bounds it.
pub async fn admit(conn: Connection) -> std::io::Result<Link> {
    let (mut send, _recv) = conn.open_bi().await.map_err(std::io::Error::other)?;
    send.write_all(&[ADMIT])
        .await
        .map_err(std::io::Error::other)?;
    let _ = send.finish();
    Ok(Link(conn))
}

/// Client side: dial `target` and await the admission ack, within [`DIAL_TIMEOUT`].
pub async fn dial(endpoint: &Endpoint, target: EndpointAddr) -> Result<Link, Disconnect> {
    let dialed = async {
        let conn = endpoint
            .connect(target, ALPN)
            .await
            .map_err(|e| verdict(anyhow::Error::new(e).context("connecting to server")))?;
        await_admission(conn).await
    };
    match tokio::time::timeout(DIAL_TIMEOUT, dialed).await {
        Ok(dialed) => dialed,
        Err(elapsed) => Err(Disconnect::Transient(
            anyhow::Error::new(elapsed)
                .context("timed out connecting (server unreachable or not responding)"),
        )),
    }
}

/// Client side: await the admission ack on `conn`.
async fn await_admission(conn: Connection) -> Result<Link, Disconnect> {
    let ack = async {
        let (_send, mut recv) = conn.accept_bi().await?;
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte).await?;
        anyhow::Ok(byte)
    };
    match ack.await {
        Ok([ADMIT]) => Ok(Link(conn)),
        Ok(_) => Err(Disconnect::Fatal(anyhow!(
            "server did not admit the connection"
        ))),
        // The server's close says why, if it closed.
        Err(e) => Err(verdict(conn.close_reason().map_or(e, |reason| {
            anyhow::Error::new(reason).context("server did not admit the connection")
        }))),
    }
}

/// How the connection that ended with `error` ended, from the [`ConnectionError`] in its chain.
fn verdict(error: anyhow::Error) -> Disconnect {
    use ConnectionError::{ApplicationClosed, ConnectionClosed, TransportError};
    let cause = error
        .chain()
        .find_map(|e| e.downcast_ref::<ConnectionError>())
        .cloned();
    // The TLS handshake ended with alert 120 (`no_application_protocol`): the server is on another
    // koh protocol version, and pointing at the network would mislead.
    let no_alpn = TransportErrorCode::crypto(120);
    let fatal = match cause {
        Some(ApplicationClosed(ApplicationClose { error_code, reason })) => {
            let code = error_code.into_inner();
            let said = peer_reason(&reason);
            if code == u64::from(REFUSED) {
                format!("server rejected the connection: {said}")
            } else if code == u64::from(BROKE) {
                format!("server closed the connection: {said} (does it run the same koh version?)")
            } else if code == u64::from(BYE) && reason.as_ref() == Close::SessionEnded.wire().1 {
                return Disconnect::Ended;
            } else {
                return Disconnect::Transient(error);
            }
        }
        Some(ConnectionClosed(close)) if close.error_code == no_alpn => alpn_mismatch(),
        Some(TransportError(t)) if t.code == no_alpn => alpn_mismatch(),
        Some(ConnectionClosed(close))
            if close.error_code == TransportErrorCode::CONNECTION_REFUSED =>
        {
            return Disconnect::Transient(
                error.context("server refused the connection: at its connection limit"),
            );
        }
        _ => return Disconnect::Transient(error),
    };
    Disconnect::Fatal(error.context(fatal))
}

fn alpn_mismatch() -> String {
    format!(
        "the server does not speak this koh protocol ({}); upgrade koh on both ends",
        String::from_utf8_lossy(ALPN)
    )
}

/// A close reason, which the peer controls: stripped of control characters and capped before it
/// can reach the user's terminal.
fn peer_reason(reason: &[u8]) -> String {
    String::from_utf8_lossy(reason)
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closed(code: u32, reason: &[u8]) -> Disconnect {
        verdict(anyhow::Error::new(ApplicationClosed(ApplicationClose {
            error_code: code.into(),
            reason: reason.to_vec().into(),
        })))
    }
    use ConnectionError::ApplicationClosed;

    fn fatal(d: &Disconnect) -> Option<String> {
        match d {
            Disconnect::Fatal(e) => Some(format!("{e:#}")),
            Disconnect::Ended | Disconnect::Transient(_) => None,
        }
    }

    #[test]
    fn every_close_reads_back_as_the_verdict_it_carries() {
        for why in [
            Close::SessionEnded,
            Close::ClientExit,
            Close::Reconnecting,
            Close::SecondStream,
            Close::ProtocolError,
        ] {
            let (code, reason) = why.wire();
            let read = closed(code, reason);
            match why {
                Close::SessionEnded => assert!(matches!(read, Disconnect::Ended), "{why:?}"),
                Close::ClientExit | Close::Reconnecting => {
                    assert!(matches!(read, Disconnect::Transient(_)), "{why:?}");
                }
                Close::SecondStream | Close::ProtocolError => {
                    let e = fatal(&read).unwrap();
                    assert!(e.contains("same koh version"), "{e}");
                }
            }
        }
        for why in [Refusal::NotAuthorized, Refusal::AtCapacity] {
            let e = fatal(&closed(REFUSED, why.reason())).unwrap();
            let said = String::from_utf8_lossy(why.reason()).into_owned();
            assert!(
                e.contains(&format!("server rejected the connection: {said}")),
                "{e}"
            );
        }
        // Another code, or code 0 with another reason, is a lost link; a peer's reason is cleaned.
        assert!(matches!(closed(7, b"x"), Disconnect::Transient(_)));
        assert!(matches!(closed(BYE, b"bye"), Disconnect::Transient(_)));
        let e = fatal(&closed(REFUSED, b"\x1b]2;owned\x07go")).unwrap();
        assert!(e.contains("rejected the connection: ]2;ownedgo"), "{e}");
    }

    #[test]
    fn the_wire_is_what_old_peers_know() {
        assert_eq!(Close::SessionEnded.wire(), (0, &b"session ended"[..]));
        assert_eq!(Close::ClientExit.wire(), (0, &b"client exit"[..]));
        assert_eq!(Close::Reconnecting.wire(), (0, &b"reconnecting"[..]));
        assert_eq!(
            Close::SecondStream.wire(),
            (2, &b"a second client stream"[..])
        );
        assert_eq!(Close::ProtocolError.wire(), (2, &b"protocol error"[..]));
        assert_eq!(REFUSED, 1);
        assert_eq!(Refusal::NotAuthorized.reason(), b"not authorized");
        assert_eq!(Refusal::AtCapacity.reason(), b"server at session capacity");
    }
}
