//! What a connection is for: the opening request the client makes on its first stream, and the
//! server's replies to it.
//!
//! After the handshake and the allowlist, the client opens a uni stream and writes one
//! [`Request`] on it, a 4-byte big-endian length then its postcard encoding; the server attaches
//! or starts nothing before it. What the stream carries after the request is the request's:
//! a shell's control messages ([`crate::proto::ClientMsg`]), a command's stdin, or the items of a
//! copy ([`crate::copy`]). The server answers on uni streams of its own: a shell's first one
//! carries [`Attached`] (then frames follow, [`crate::proto`]), a listing's [`SessionList`], a
//! command's a tag ([`ExecStream`]) then its output or its [`ExitStatus`].
//!
//! Everything here is pure: each type refuses, as it is decoded, what is past its bound or names
//! nothing (a path holding a NUL byte, no sources), so a value holds only what may be acted on.

use serde::de::{self, DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};

use crate::bounded::at_most;
use crate::proto::ProtoError;
use crate::terminal::Size;

/// Most bytes of an opening request.
pub const MAX_REQUEST: usize = 1 << 20;

/// Most bytes of a reply sent whole ([`Attached`], [`SessionList`], a copy's outcome).
pub const MAX_REPLY: usize = 1 << 20;

/// Most bytes of a path named on the other end: Linux's `PATH_MAX`.
pub const MAX_PATH: usize = 4096;

/// Most bytes of a command line `koh exec` runs.
pub const MAX_COMMAND: usize = 256 * 1024;

/// Most sources one copy names.
pub const MAX_SOURCES: usize = 1024;

/// Most sessions a listing holds.
pub const MAX_LISTED: usize = 1024;

/// Most characters of a title a listing carries.
pub const MAX_TITLE: usize = 256;

/// A session's number, server-wide: each new session takes the next, from 1, for the server's
/// run.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct SessionNum(pub u64);

impl std::fmt::Display for SessionNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// One run of a server, random: session numbers start again at 1 when a server restarts, so a
/// number alone could name another session after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunId(pub u64);

impl RunId {
    /// A new one, from the OS's randomness.
    pub fn random() -> std::io::Result<Self> {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes)?;
        Ok(Self(u64::from_le_bytes(bytes)))
    }
}

/// A session of one server run: what a client attached to, and redials to after a drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resume {
    pub run: RunId,
    pub session: SessionNum,
}

/// Which of the peer's sessions a shell attaches to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pick {
    /// The one most recently attached, else a new one.
    Latest,
    /// Always a new one.
    New,
    /// That one, if it is the peer's, else [`Close::NoSuchSession`](crate::proto::Close).
    Id(SessionNum),
    /// That one of that run: the client's redial to the session it was on. A server run since
    /// restarted has no such session, whatever its numbers.
    Resume(Resume),
}

/// What the connection is for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// A detachable shell session: the stream goes on as the shell's control stream.
    Shell(Pick),
    /// The peer's sessions, answered as one [`SessionList`]; then the connection closes.
    Sessions,
    /// Run a command with no terminal: the stream goes on as its stdin.
    Exec(CommandLine),
    /// Copy files to or from the server.
    Copy(Copy),
}

/// A copy, as the client asks it: exactly one side is the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Copy {
    /// The server sends these paths, as items on a stream of its own; the client says where they
    /// land.
    Get(Sources),
    /// The items the stream carries after the request land at `dest` on the server: inside it if
    /// it is a directory, else as it, if there is one item.
    Put { dest: RemotePath, arity: Arity },
}

/// How many items a copy brings: one may land as the destination's own name, several only
/// inside a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arity {
    One,
    Several,
}

impl Arity {
    pub const fn of(count: usize) -> Self {
        if count > 1 {
            Self::Several
        } else {
            Self::One
        }
    }
}

/// A path on the server as the client wrote it: at most [`MAX_PATH`] bytes, no NUL.
///
/// Empty, `~` and `~/…` are the server user's home and what is in it, and a relative path is
/// relative to it, as that user's shell would take them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemotePath(Vec<u8>);

impl RemotePath {
    /// `bytes`, if a path may hold them.
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.len() > MAX_PATH {
            return Err("a path over 4096 bytes");
        }
        if bytes.contains(&0) {
            return Err("a path holding a NUL byte");
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RemotePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = at_most::<MAX_PATH, D, u8>(deserializer)?;
        Self::new(bytes).map_err(de::Error::custom)
    }
}

/// The sources of a copy from the server: at least one, at most [`MAX_SOURCES`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sources(Vec<RemotePath>);

impl Sources {
    pub fn new(paths: Vec<RemotePath>) -> Result<Self, &'static str> {
        match paths.len() {
            0 => Err("no sources"),
            n if n > MAX_SOURCES => Err("more than 1024 sources"),
            _ => Ok(Self(paths)),
        }
    }

    pub fn paths(&self) -> &[RemotePath] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Sources {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let paths = at_most::<MAX_SOURCES, D, RemotePath>(deserializer)?;
        Self::new(paths).map_err(de::Error::custom)
    }
}

/// A command line for the server user's shell (`$SHELL -c`): at least a byte, at most
/// [`MAX_COMMAND`], no NUL, which no argument can hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandLine(Vec<u8>);

impl CommandLine {
    pub fn new(bytes: Vec<u8>) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Err("an empty command");
        }
        if bytes.len() > MAX_COMMAND {
            return Err("a command over 256 KiB");
        }
        if bytes.contains(&0) {
            return Err("a command holding a NUL byte");
        }
        Ok(Self(bytes))
    }

    /// The words of a command, joined with spaces, as ssh joins them: the shell splits them
    /// again, so quoting means what it means to that shell.
    pub fn join<W: AsRef<[u8]>>(words: &[W]) -> Result<Self, &'static str> {
        let mut line = Vec::new();
        for (n, word) in words.iter().enumerate() {
            if n > 0 {
                line.push(b' ');
            }
            line.extend_from_slice(word.as_ref());
        }
        Self::new(line)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CommandLine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = at_most::<MAX_COMMAND, D, u8>(deserializer)?;
        Self::new(bytes).map_err(de::Error::custom)
    }
}

/// A shell's admission, on the server's first stream: the session it attached, which the client
/// redials to after a drop.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attached {
    pub at: Resume,
}

/// Whether a client is attached to a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    Attached,
    /// No client for these seconds.
    Detached {
        secs: u64,
    },
}

/// One of the peer's sessions, as listed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session: SessionNum,
    /// Seconds since it started.
    pub age_secs: u64,
    pub presence: Presence,
    pub size: Size,
    /// Its window title, at most [`MAX_TITLE`] characters.
    pub title: String,
    /// Its program's exit status, once it exited: the session is kept until a client sees it.
    pub exited: Option<u32>,
}

/// The peer's sessions, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionList(
    #[serde(deserialize_with = "at_most::<MAX_LISTED, _, _>")] pub Vec<SessionInfo>,
);

/// What a stream the server opens for `koh exec` carries, its first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExecStream {
    /// The command's stdout, to its end.
    Stdout = 0,
    /// Its stderr, to its end.
    Stderr = 1,
    /// Its [`ExitStatus`], once both have ended.
    Status = 2,
}

impl ExecStream {
    pub const fn tag(self) -> u8 {
        self as u8
    }

    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0 => Self::Stdout,
            1 => Self::Stderr,
            2 => Self::Status,
            _ => return None,
        })
    }
}

/// How a command ended, as a shell reports it: its exit code, or 128 plus the signal that killed
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitStatus(pub u32);

/// `msg` with its 4-byte big-endian length before it, refused past `max` bytes.
pub fn encode<T: Serialize>(msg: &T, max: usize) -> Result<Vec<u8>, ProtoError> {
    let mut out = postcard::to_extend(msg, vec![0; 4])?;
    let body = out.len().saturating_sub(4);
    if body > max {
        return Err(ProtoError::TooLarge { len: body, max });
    }
    if let Some(prefix) = out.first_chunk_mut::<4>() {
        *prefix = u32::try_from(body).unwrap_or(u32::MAX).to_be_bytes();
    }
    Ok(out)
}

/// The length a 4-byte big-endian prefix announces, refused past `max`.
pub fn body_len(prefix: [u8; 4], max: usize) -> Result<usize, ProtoError> {
    let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
    if len > max {
        return Err(ProtoError::TooLarge { len, max });
    }
    Ok(len)
}

/// Decode a message's body (its length prefix read already), all of it.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, ProtoError> {
    Ok(postcard::from_bytes(body)?)
}

/// Decode a whole framed message, prefix and body, as a reply stream carries it.
pub fn decode_framed<T: DeserializeOwned>(bytes: &[u8], max: usize) -> Result<T, ProtoError> {
    let (prefix, body) = bytes
        .split_first_chunk::<4>()
        .ok_or(ProtoError::Truncated)?;
    if body_len(*prefix, max)? != body.len() {
        return Err(ProtoError::Truncated);
    }
    decode(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(request: &Request) -> Request {
        let bytes = encode(request, MAX_REQUEST).unwrap();
        decode_framed(&bytes, MAX_REQUEST).unwrap()
    }

    #[test]
    fn requests_round_trip_and_what_names_nothing_is_refused_as_it_is_decoded() {
        // Built by hand past the constructors: refused on the way in.
        #[derive(Serialize)]
        enum Raw {
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Shell,
            #[expect(dead_code, reason = "a variant's place, as Request numbers them")]
            Sessions,
            Exec(Vec<u8>),
            Copy(RawCopy),
        }
        #[derive(Serialize)]
        enum RawCopy {
            Get(Vec<Vec<u8>>),
        }
        let path = |p: &[u8]| RemotePath::new(p.to_vec()).unwrap();
        for request in [
            Request::Shell(Pick::Latest),
            Request::Shell(Pick::Resume(Resume {
                run: RunId(7),
                session: SessionNum(3),
            })),
            Request::Sessions,
            Request::Exec(CommandLine::join(&["echo", "a b"]).unwrap()),
            Request::Copy(Copy::Get(
                Sources::new(vec![path(b"~/x"), path(b"")]).unwrap(),
            )),
            Request::Copy(Copy::Put {
                dest: path(b"/tmp/y"),
                arity: Arity::Several,
            }),
        ] {
            assert_eq!(round_trip(&request), request);
        }
        for raw in [
            Raw::Exec(Vec::new()),
            Raw::Exec(b"a\0b".to_vec()),
            Raw::Exec(vec![b'x'; MAX_COMMAND + 1]),
            Raw::Copy(RawCopy::Get(Vec::new())),
            Raw::Copy(RawCopy::Get(vec![b"a\0".to_vec()])),
            Raw::Copy(RawCopy::Get(vec![vec![b'a'; MAX_PATH + 1]])),
            Raw::Copy(RawCopy::Get(vec![Vec::new(); MAX_SOURCES + 1])),
        ] {
            let bytes = encode(&raw, usize::MAX).unwrap();
            assert!(decode_framed::<Request>(&bytes, usize::MAX).is_err());
        }
        // A prefix announcing more than the bound is refused before the body is read.
        assert!(body_len(u32::MAX.to_be_bytes(), MAX_REQUEST).is_err());
    }
}
