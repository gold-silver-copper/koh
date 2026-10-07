//! The registry's live sessions, one per peer. A session is forgotten only when its task has
//! ended, which closes its control channel: nothing outside this module can add or remove one.

use std::collections::HashMap;
use std::time::Duration;

use iroh::EndpointId;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;

use super::{start, Attach, AttachKind, SessionClient, SessionSpec};

/// Every session task the registry started, and the ones still live, by peer.
pub(super) struct Sessions {
    /// Each session's control sender, by peer; closed once its task ends.
    live: HashMap<EndpointId, mpsc::Sender<Attach>>,
    tasks: JoinSet<()>,
    spec: SessionSpec,
}

impl Sessions {
    pub(super) fn new(spec: SessionSpec) -> Self {
        Self {
            live: HashMap::new(),
            tasks: JoinSet::new(),
            spec,
        }
    }

    /// Attach `peer` to its session, starting one if it has none. `None` at the session cap, or if
    /// starting one failed.
    pub(super) async fn attach(&mut self, peer: EndpointId) -> Option<(SessionClient, AttachKind)> {
        self.live.retain(|_, control| !control.is_closed());
        while let Some(ended) = self.tasks.try_join_next() {
            log_panic(ended);
        }
        if let Some(control) = self.live.get(&peer) {
            if let Some((client, detached_for)) = attach_to(control).await {
                return Some((client, AttachKind::Reattached { detached_for }));
            }
            // It ended a moment ago: a new one takes its place.
        } else if self.live.len() >= self.spec.max_sessions {
            return None;
        }
        let (control, client, task) = start(&self.spec)
            .map_err(|e| tracing::error!(error = %e, "spawning a session failed"))
            .ok()?;
        self.tasks.spawn(task);
        self.live.insert(peer, control);
        Some((client, AttachKind::Created))
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

/// Attach to the session `control` reaches: a client and how long it was detached, or `None` if
/// its task has ended.
async fn attach_to(control: &mpsc::Sender<Attach>) -> Option<(SessionClient, Option<Duration>)> {
    let (reply, mut rx) = oneshot::channel();
    control.send(Attach(reply)).await.ok()?;
    // A request sent as the session ends can land after its receiver dropped what was queued, and
    // then waits, unanswered, for the last sender, which is in `live`: the end itself answers it.
    // A reply comes first, sent before the receiver is dropped.
    tokio::select! {
        biased;
        attached = &mut rx => attached.ok(),
        () = control.closed() => None,
    }
}
