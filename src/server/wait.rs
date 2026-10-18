//! `koh wait`: wait on the server for a job's end or its text, a session's command to end, its
//! program to read its terminal or its screen to show a text, or a file to appear, and say which
//! came. The wait ends with the connection: a client that gave up is not waited for.

use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::EndpointId;

use super::jobs::Jobs;
use super::place::{Place, Resolved};
use super::session::{Registry, Status};
use crate::request::{Answer, On, Problem, ProblemKind, Until, Wait, Waited};
use crate::terminal::Activity;

/// How often a file is looked for, and a session's screen read again for a text.
const LOOK: Duration = Duration::from_millis(100);

/// Wait as `wait` asks, for `peer`, and answer on `conn` what came.
pub(super) async fn serve(
    conn: &Connection,
    peer: EndpointId,
    wait: &Wait,
    (registry, jobs): (&Registry, &Jobs),
    place: &Place,
) {
    let waited = tokio::select! {
        waited = waited(peer, wait, (registry, jobs), place) => waited,
        _ = conn.closed() => return,
    };
    super::answer(conn, &waited).await;
}

async fn waited(
    peer: EndpointId,
    wait: &Wait,
    (registry, jobs): (&Registry, &Jobs),
    place: &Place,
) -> Answer<Waited> {
    let file = match &wait.until {
        Until::File(path) => Some(place.resolve(path)?),
        Until::End | Until::Text(_) | Until::Reading => None,
    };
    // A scoped key's file is looked for beneath its directory, through no symlink.
    let there = |file: &Resolved| match file {
        Resolved::Path(path) => std::fs::symlink_metadata(path).is_ok(),
        Resolved::Beneath { root, path } => crate::sync::exists_beneath(root, path),
    };
    match &wait.on {
        None => {
            let Some(file) = file else {
                return Err(Problem::new(ProblemKind::Failed, "nothing to wait for"));
            };
            while !there(&file) {
                tokio::time::sleep(LOOK).await;
            }
            Ok(Waited::File)
        }
        Some(On::Job(name)) => {
            let job = jobs
                .get(peer, name)
                .ok_or_else(|| Problem::new(ProblemKind::NoSuchJob, name))?;
            let mut status = job.watch();
            loop {
                let now = *status.borrow_and_update();
                match &wait.until {
                    Until::Text(text) if job.found(text.as_str(), 0) => return Ok(Waited::Text),
                    Until::File(_) if file.as_ref().is_some_and(there) => return Ok(Waited::File),
                    Until::End | Until::Text(_) | Until::File(_) | Until::Reading => {}
                }
                if let Some(code) = now.exit {
                    return Ok(Waited::Ended(Some(i64::from(code))));
                }
                // A file is looked for again at least every `LOOK`.
                let _ = tokio::time::timeout(LOOK, status.changed()).await;
            }
        }
        Some(On::Session(session)) => {
            let found = registry
                .find(peer, *session)
                .await
                .ok_or_else(|| Problem::new(ProblemKind::NoSuchSession, session))?;
            let mut status = found.status();
            let start: Status = status.borrow_and_update().clone();
            let mut screen = None;
            loop {
                let now = status.borrow_and_update().clone();
                if let Some(code) = now.exited {
                    return Ok(Waited::Ended(Some(i64::from(code))));
                }
                match &wait.until {
                    // Ended: the command that ran as the wait began, or at once if none did.
                    Until::End
                        if !start.state.running || now.state.finished > start.state.finished =>
                    {
                        return Ok(Waited::Ended(now.state.last_status.map(i64::from)));
                    }
                    Until::Reading if now.state.activity == Some(Activity::Reading) => {
                        return Ok(Waited::Reading)
                    }
                    Until::File(_) if file.as_ref().is_some_and(there) => return Ok(Waited::File),
                    // The screen is read again once it changed, at most every `LOOK`.
                    Until::Text(text) if screen != Some(now.screen) => {
                        screen = Some(now.screen);
                        let shown = found.text(false).await.unwrap_or_default();
                        if shown.contains(text.as_str()) {
                            return Ok(Waited::Text);
                        }
                        tokio::time::sleep(LOOK).await;
                    }
                    Until::End | Until::Reading | Until::File(_) | Until::Text(_) => {}
                }
                if tokio::time::timeout(LOOK, status.changed())
                    .await
                    .is_ok_and(|c| c.is_err())
                {
                    return Err(Problem::new(ProblemKind::NoSuchSession, session));
                }
            }
        }
    }
}
