//! The registry's live sessions, one per peer. A session is forgotten only when its task has
//! ended, which closes its control channel: nothing outside this module can add or remove one.

use std::collections::HashMap;

use iroh::EndpointId;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::JoinSet;

use super::{start, Attach, SessionSpec};
use crate::proto::Close;

/// Every session task the registry started, and the ones still live, by peer.
pub(super) struct Sessions {
    /// Each session's control sender, by peer; closed once its task ends.
    live: HashMap<EndpointId, mpsc::Sender<Attach>>,
    tasks: JoinSet<()>,
    spec: SessionSpec,
    reaper: crate::pty::Reaper,
    /// Whether a peer may attach, asked as its attach is taken.
    allows: Box<dyn Fn(&EndpointId) -> bool + Send>,
}

impl Sessions {
    pub(super) fn new(
        spec: SessionSpec,
        reaper: crate::pty::Reaper,
        allows: Box<dyn Fn(&EndpointId) -> bool + Send>,
    ) -> Self {
        Self {
            live: HashMap::new(),
            tasks: JoinSet::new(),
            spec,
            reaper,
            allows,
        }
    }

    /// Hand `attach` to `peer`'s session, which answers it, starting one if it has none. Refused
    /// a peer no longer allowed (the end of its session is then on its way, or done), at the
    /// session cap, or when its session has too many attaches waiting.
    pub(super) fn attach(&mut self, peer: EndpointId, attach: Attach) {
        if !(self.allows)(&peer) {
            let _ = attach.0.send(Err(Close::NotAuthorized));
            return;
        }
        self.live.retain(|_, control| !control.is_closed());
        let attach = match self.live.get(&peer) {
            Some(control) => match control.try_send(attach) {
                Ok(()) => return,
                Err(TrySendError::Full(Attach(reply))) => {
                    let _ = reply.send(Err(Close::AtCapacity));
                    return;
                }
                // It ended a moment ago: a new one takes its place.
                Err(TrySendError::Closed(attach)) => attach,
            },
            None if self.live.len() >= self.spec.max_sessions => {
                let _ = attach.0.send(Err(Close::AtCapacity));
                return;
            }
            None => attach,
        };
        let (control, task) = start(&self.spec, &self.reaper, attach);
        self.tasks.spawn(task);
        self.live.insert(peer, control);
    }

    /// Wait for a session task to end, and forget its control channel: an attach that reached it
    /// as it ended is dropped with the channel, so its requester tries again, not waits for the
    /// next attach to drop it. Never while no session runs.
    pub(super) async fn ended(&mut self) {
        let Some(ended) = self.tasks.join_next().await else {
            return std::future::pending().await;
        };
        log_panic(ended);
        self.live.retain(|_, control| !control.is_closed());
    }

    /// End `peer`'s session, if it has one: its control channel closes, and it ends.
    pub(super) fn end(&mut self, peer: EndpointId) {
        self.live.remove(&peer);
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
