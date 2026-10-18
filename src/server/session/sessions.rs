//! The registry's live sessions, by number, each a peer's. A session is forgotten only when its
//! task has ended, which closes its control channel, or when its peer's sessions are ended:
//! nothing outside this module can add or remove one.

use std::collections::BTreeMap;

use iroh::EndpointId;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::{start, Ask, Attach, Handles, SessionSpec, Status};
use crate::proto::Close;
use crate::request::{Pick, RunId, SessionNum};

/// A live session.
struct Live {
    peer: EndpointId,
    /// Its control sender (closed once its task ends), its asks and its status.
    handles: Handles,
    started: Instant,
    /// When an attach last went to it, as the registry counts them: the latest is the highest.
    attached: u64,
}

/// One of a peer's sessions, for a listing to ask how it stands.
pub(in crate::server) struct Listed {
    pub(in crate::server) session: SessionNum,
    pub(in crate::server) started: Instant,
    pub(in crate::server) asks: mpsc::Sender<Ask>,
    pub(in crate::server) status: tokio::sync::watch::Receiver<Status>,
}

/// Every session task the registry started, and the ones still live, by number.
pub(super) struct Sessions {
    live: BTreeMap<SessionNum, Live>,
    /// The number the last session took.
    last: SessionNum,
    /// How many attaches went to a session.
    attaches: u64,
    tasks: JoinSet<()>,
    spec: SessionSpec,
    run: RunId,
    reaper: crate::pty::Reaper,
    /// Whether a peer may attach, asked as its attach is taken.
    allows: Box<dyn Fn(&EndpointId) -> bool + Send>,
}

impl Sessions {
    pub(super) fn new(
        spec: SessionSpec,
        run: RunId,
        reaper: crate::pty::Reaper,
        allows: Box<dyn Fn(&EndpointId) -> bool + Send>,
    ) -> Self {
        Self {
            live: BTreeMap::new(),
            last: SessionNum::default(),
            attaches: 0,
            tasks: JoinSet::new(),
            spec,
            run,
            reaper,
            allows,
        }
    }

    /// Hand `attach` to the session of `peer`'s that `pick` names, which answers it, or start one.
    /// Refused a peer no longer allowed (the end of its sessions is then on its way, or done), a
    /// number not the peer's, a new session at the cap, or a session with too many attaches
    /// waiting.
    pub(super) fn attach(&mut self, peer: EndpointId, pick: Pick, attach: Attach) {
        if !(self.allows)(&peer) {
            let _ = attach.reply.send(Err(Close::NotAuthorized));
            return;
        }
        self.live
            .retain(|_, live| !live.handles.control.is_closed());
        let named = match pick {
            _ if attach.program.is_some() => None,
            Pick::Latest => self
                .live
                .iter()
                .filter(|(_, live)| live.peer == peer)
                .max_by_key(|(_, live)| live.attached)
                .map(|(&session, _)| session),
            Pick::New => None,
            Pick::Resume(at) if at.run != self.run => {
                let _ = attach.reply.send(Err(Close::NoSuchSession));
                return;
            }
            Pick::Id(session) | Pick::Resume(crate::request::Resume { session, .. }) => {
                if self.live.get(&session).is_none_or(|live| live.peer != peer) {
                    let _ = attach.reply.send(Err(Close::NoSuchSession));
                    return;
                }
                Some(session)
            }
        };
        let attach = match named.and_then(|session| self.live.get_mut(&session)) {
            Some(live) => match live.handles.control.try_send(attach) {
                Ok(()) => {
                    self.attaches = self.attaches.saturating_add(1);
                    live.attached = self.attaches;
                    return;
                }
                Err(TrySendError::Full(attach)) => {
                    let _ = attach.reply.send(Err(Close::AtCapacity));
                    return;
                }
                // It ended a moment ago: the latest gets a new one in its place; one asked for
                // by number is gone.
                Err(TrySendError::Closed(attach)) if pick == Pick::Latest => attach,
                Err(TrySendError::Closed(attach)) => {
                    let _ = attach.reply.send(Err(Close::NoSuchSession));
                    return;
                }
            },
            None => attach,
        };
        if self.live.len() >= self.spec.max_sessions {
            let _ = attach.reply.send(Err(Close::AtCapacity));
            return;
        }
        let session = SessionNum(self.last.0.saturating_add(1));
        self.last = session;
        self.attaches = self.attaches.saturating_add(1);
        let (handles, task) = start(session, &self.spec, &self.reaper, attach);
        self.tasks.spawn(task);
        self.live.insert(
            session,
            Live {
                peer,
                handles,
                started: Instant::now(),
                attached: self.attaches,
            },
        );
    }

    /// `peer`'s live sessions, oldest first.
    pub(super) fn list(&mut self, peer: EndpointId) -> Vec<Listed> {
        self.live
            .retain(|_, live| !live.handles.control.is_closed());
        self.live
            .iter()
            .filter(|(_, live)| live.peer == peer)
            .map(|(&session, live)| Listed {
                session,
                started: live.started,
                asks: live.handles.asks.clone(),
                status: live.handles.status.clone(),
            })
            .collect()
    }

    /// Wait for a session task to end, and forget its control channel: an attach that reached it
    /// as it ended is dropped with the channel, so its requester tries again, not waits for the
    /// next attach to drop it. Never while no session runs.
    pub(super) async fn ended(&mut self) {
        let Some(ended) = self.tasks.join_next().await else {
            return std::future::pending().await;
        };
        log_panic(ended);
        self.live
            .retain(|_, live| !live.handles.control.is_closed());
    }

    /// End `peer`'s sessions: their control channels close, and they end.
    pub(super) fn end(&mut self, peer: EndpointId) {
        self.live.retain(|_, live| live.peer != peer);
    }

    /// End every session, attached or not, and wait for their tasks.
    pub(super) async fn shutdown(self) {
        let Self {
            live, mut tasks, ..
        } = self;
        // The control channels close, and each session task ends.
        drop(live);
        while let Some(ended) = tasks.join_next().await {
            log_panic(ended);
        }
    }
}

/// A session task that panicked is said, not reaped in silence.
fn log_panic(ended: Result<(), tokio::task::JoinError>) {
    if let Err(e) = ended {
        tracing::error!(error = %e, "a session task failed");
    }
}
