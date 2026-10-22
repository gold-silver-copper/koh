//! The client's stdin reader and SIGWINCH ticks, stopped when dropped so they never hold up the
//! process's end.

use anyhow::Context;
use fuxix::poll::{poll, Events, PollFd};
use std::os::fd::{AsFd, OwnedFd};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

/// Most bytes of one read of what is typed: a terminal writes a keystroke, or a paste, at a time.
pub const TYPED: usize = 1024;

/// Most bytes of one read of `koh exec`'s stdin, which may be a large file piped in.
pub const PIPED: usize = 64 * 1024;

/// The stdin reader's thread, stopped when this is dropped: it looks every 100 ms, and blocks on
/// nothing else once the receiver is gone.
pub struct Reading(CancellationToken);

impl Drop for Reading {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Stdin, read `N` bytes at most at a time on a thread of its own until it ends: what it reads, at
/// most `queue` reads waiting, which ends with it (at once if there is no stdin).
pub fn spawn_stdin<const N: usize>(
    queue: usize,
) -> anyhow::Result<(mpsc::Receiver<Vec<u8>>, Reading)> {
    let (tx, rx) = mpsc::channel(queue);
    let cancel = CancellationToken::new();
    // The descriptor itself, not `std::io::stdin()`: that reads through a buffer of its own, and
    // what it took past a read's end would wait unseen by `poll` until more was typed.
    let Ok(stdin) = std::io::stdin().as_fd().try_clone_to_owned() else {
        return Ok((rx, Reading(cancel)));
    };
    let stopping = cancel.clone();
    std::thread::Builder::new()
        .name("koh-stdin".into())
        .spawn(move || read_input::<N>(&stdin, &tx, &stopping))
        .context("spawning the stdin reader")?;
    Ok((rx, Reading(cancel)))
}

/// A tick for each SIGWINCH, while the handle lives; ticks the loop has yet to take are one.
pub fn spawn_resizes() -> anyhow::Result<(mpsc::Receiver<()>, AbortOnDropHandle<()>)> {
    let mut sigwinch =
        signal(SignalKind::window_change()).context("installing the SIGWINCH handler")?;
    let (tx, rx) = mpsc::channel(1);
    #[expect(clippy::disallowed_methods, reason = "one for the run")]
    let task = tokio::spawn(async move {
        while sigwinch.recv().await.is_some() {
            if tx.try_send(()) == Err(mpsc::error::TrySendError::Closed(())) {
                return;
            }
        }
    });
    Ok((rx, AbortOnDropHandle::new(task)))
}

/// Read `fd` until it ends, `N` bytes at most at a time, sending what it reads, until `cancel`.
fn read_input<const N: usize>(
    fd: &OwnedFd,
    sender: &mpsc::Sender<Vec<u8>>,
    cancel: &CancellationToken,
) {
    let mut buffer = vec![0_u8; N];
    while !cancel.is_cancelled() {
        let ready = {
            let mut descriptors = [PollFd::new(fd, Events::IN)];
            poll(
                &mut descriptors,
                Some(std::time::Duration::from_millis(100)),
            )
        };
        match ready {
            Ok(0) => {}
            Err(errno) if errno == fuxix::Errno::INTR => {}
            Ok(_) => match fuxix::io::read(fd, &mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let Some(chunk) = buffer.get(..count) else {
                        break;
                    };
                    // Blocks while the loop is behind; ends when it is gone (the run is over).
                    if sender.blocking_send(chunk.to_vec()).is_err() {
                        break;
                    }
                }
            },
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    #[test]
    fn input_is_forwarded_exactly_and_an_idle_reader_stops_when_cancelled() {
        crate::test_runtime::current_thread().block_on(async {
            let (reader, mut writer) = UnixStream::pair().expect("socket pair");
            let (sender, mut receiver) = mpsc::channel(8);
            let cancel = CancellationToken::new();
            let thread_cancel = cancel.clone();
            let input = std::thread::spawn(move || {
                read_input::<TYPED>(&OwnedFd::from(reader), &sender, &thread_cancel);
            });
            // Longer than one read, and nothing typed after: every byte goes on as it is.
            let line = [b"a\0\x1bZ".as_slice(), &[b'y'; 2000], b"\r"].concat();
            writer.write_all(&line).expect("write input");
            let mut got = Vec::new();
            while got.len() < line.len() {
                got.extend(receiver.recv().await.expect("producer gone"));
            }
            assert_eq!(got, line);
            cancel.cancel();
            let start = Instant::now();
            input.join().expect("join producer");
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(receiver.recv().await.is_none());
        });
    }
}
