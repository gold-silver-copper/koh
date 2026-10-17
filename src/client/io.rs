//! The client's stdin and SIGWINCH producers, cancellable so teardown never blocks on input.

use anyhow::Context;
use fuxix::poll::{poll, Events, PollFd};
use std::os::fd::{AsFd, OwnedFd};
use std::thread::JoinHandle;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::task::JoinHandle as TokioJoinHandle;
use tokio_util::sync::CancellationToken;

/// The receiving ends that `connect` hands to [`run_client`](super::run_client).
pub struct ClientIoChannels {
    pub input_rx: mpsc::Receiver<Vec<u8>>,
    pub resize_rx: mpsc::Receiver<()>,
}

/// The producer tasks. Call [`shutdown`](Self::shutdown) after the session returns.
pub struct ClientIoTasks {
    cancel: CancellationToken,
    input: Option<JoinHandle<()>>,
    resize: Option<TokioJoinHandle<()>>,
}

/// The message of a `panic!` payload, which is a `&str` or `String` unless a custom payload was used.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic payload")
}

impl ClientIoTasks {
    /// Cancel both producers and join them; the input poll sees that within 100 ms.
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.cancel.cancel();
        let resize_result = match self.resize.take() {
            Some(resize) => resize.await.context("joining SIGWINCH producer"),
            None => Ok(()),
        };
        let input = self.input.take();
        let input_result = tokio::task::spawn_blocking(move || {
            if let Some(input) = input {
                input.join().map_err(|payload| {
                    anyhow::anyhow!("stdin producer panicked: {}", panic_message(&*payload))
                })?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("joining stdin producer task")
        .and_then(|result| result);
        first_error(resize_result, input_result)
    }
}

/// `result`, or `cleanup`'s error if only the cleanup failed. A cleanup error behind a failed
/// `result` is logged rather than lost.
pub(super) fn first_error<T>(
    result: anyhow::Result<T>,
    cleanup: anyhow::Result<()>,
) -> anyhow::Result<T> {
    match (result, cleanup) {
        (Ok(value), cleanup) => cleanup.map(|()| value),
        (Err(primary), Err(cleanup)) => {
            tracing::warn!(error = ?cleanup, "cleanup also failed");
            Err(primary)
        }
        (Err(primary), Ok(())) => Err(primary),
    }
}

impl Drop for ClientIoTasks {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Start the byte-exact stdin and SIGWINCH producers.
pub fn spawn_client_io() -> anyhow::Result<(ClientIoChannels, ClientIoTasks)> {
    let runtime = tokio::runtime::Handle::try_current()
        .context("starting client I/O requires a Tokio runtime")?;
    let mut sigwinch =
        signal(SignalKind::window_change()).context("installing SIGWINCH handler")?;
    let cancel = CancellationToken::new();
    let (input_tx, input_rx) = mpsc::channel(64);
    let input_cancel = cancel.clone();
    // The descriptor itself, not `std::io::stdin()`: that reads through a buffer of its own, and
    // what it took past a read's end would wait unseen by `poll` until more was typed.
    let stdin = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context("duplicating stdin")?;
    let input = std::thread::Builder::new()
        .name("koh-stdin".into())
        .spawn(move || read_input(&stdin, &input_tx, &input_cancel))
        .context("spawning stdin producer")?;
    let (resize_tx, resize_rx) = mpsc::channel(8);
    let resize_cancel = cancel.clone();
    let resize = runtime.spawn(async move {
        loop {
            tokio::select! {
                () = resize_cancel.cancelled() => break,
                received = sigwinch.recv() => {
                    if received.is_none()
                        || !send_resize(&resize_tx, &resize_cancel).await
                    {
                        break;
                    }
                }
            }
        }
    });
    Ok((
        ClientIoChannels {
            input_rx,
            resize_rx,
        },
        ClientIoTasks {
            cancel,
            input: Some(input),
            resize: Some(resize),
        },
    ))
}

async fn send_resize(sender: &mpsc::Sender<()>, cancel: &CancellationToken) -> bool {
    tokio::select! {
        biased;
        () = cancel.cancelled() => false,
        result = sender.send(()) => result.is_ok(),
    }
}

fn read_input(fd: &OwnedFd, sender: &mpsc::Sender<Vec<u8>>, cancel: &CancellationToken) {
    let mut buffer = [0_u8; 1024];
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
    use tokio::time::timeout;

    #[test]
    fn public_spawn_requires_an_entered_tokio_runtime() {
        let error = spawn_client_io()
            .err()
            .expect("spawn outside a runtime must return an error");
        assert!(
            format!("{error:#}").contains("requires a Tokio runtime"),
            "unexpected error: {error:#}"
        );
    }

    #[test]
    fn public_spawn_reports_resize_and_shuts_down() {
        crate::test_runtime::current_thread().block_on(async {
            let (channels, tasks) = spawn_client_io().expect("spawn public client I/O");
            let ClientIoChannels {
                mut input_rx,
                mut resize_rx,
            } = channels;

            let own = crate::client::own_pid().expect("own pid");
            fuxix::process::kill(own, fuxix::process::Signal::Winch).expect("signal SIGWINCH");
            assert_eq!(
                timeout(Duration::from_secs(1), resize_rx.recv())
                    .await
                    .expect("resize producer stalled"),
                Some(())
            );
            timeout(Duration::from_secs(1), tasks.shutdown())
                .await
                .expect("shutdown stalled")
                .expect("shutdown failed");
            assert!(resize_rx.recv().await.is_none());
            while input_rx.recv().await.is_some() {}
        });
    }

    #[test]
    fn dropping_public_tasks_cancels_both_producers() {
        crate::test_runtime::current_thread().block_on(async {
            let (channels, tasks) = spawn_client_io().expect("spawn public client I/O");
            let ClientIoChannels {
                mut input_rx,
                mut resize_rx,
            } = channels;
            drop(tasks);

            timeout(Duration::from_secs(1), async {
                while input_rx.recv().await.is_some() {}
            })
            .await
            .expect("stdin producer remained alive after task owner was dropped");
            timeout(Duration::from_secs(1), async {
                while resize_rx.recv().await.is_some() {}
            })
            .await
            .expect("resize producer remained alive after task owner was dropped");
        });
    }

    #[test]
    fn input_producer_forwards_bytes_exactly_and_an_idle_one_cancels_without_a_byte() {
        crate::test_runtime::current_thread().block_on(async {
            // Producer framing does not transform terminal input; client teardown owns and joins
            // every producer, idle in its poll.
            let (reader, mut writer) = UnixStream::pair().expect("socket pair");
            let (sender, mut receiver) = mpsc::channel(1);
            let cancel = CancellationToken::new();
            let thread_cancel = cancel.clone();
            let input = std::thread::spawn(move || {
                read_input(&OwnedFd::from(reader), &sender, &thread_cancel);
            });
            writer.write_all(b"a\0\x1bZ").expect("write input");
            assert_eq!(
                receiver.recv().await.as_deref(),
                Some(b"a\0\x1bZ".as_slice())
            );
            cancel.cancel();
            let start = Instant::now();
            input.join().expect("join producer");
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(receiver.recv().await.is_none());
        });
    }

    #[test]
    fn input_longer_than_one_read_is_forwarded_whole_with_nothing_typed_after() {
        // A terminal writes a long typed line in one go: every byte goes on as it is, without
        // waiting for the next key.
        crate::test_runtime::current_thread().block_on(async {
            let (reader, mut writer) = UnixStream::pair().expect("socket pair");
            let (sender, mut receiver) = mpsc::channel(8);
            let cancel = CancellationToken::new();
            let thread_cancel = cancel.clone();
            let input = std::thread::spawn(move || {
                read_input(&OwnedFd::from(reader), &sender, &thread_cancel);
            });
            let line = [vec![b'y'; 2000].as_slice(), b"\r"].concat();
            writer.write_all(&line).expect("write input");
            let mut got = Vec::new();
            while got.len() < line.len() {
                let chunk = timeout(Duration::from_secs(1), receiver.recv())
                    .await
                    .expect("the line's end waits for more input")
                    .expect("producer gone");
                got.extend(chunk);
            }
            assert_eq!(got, line);
            cancel.cancel();
            input.join().expect("join producer");
        });
    }

    #[test]
    fn shutdown_ends_input_blocked_by_a_full_channel_once_the_loop_is_gone() {
        // Shutdown follows the loop's return, which drops the receiving end.
        crate::test_runtime::current_thread().block_on(async {
            let (reader, mut writer) = UnixStream::pair().expect("socket pair");
            let (sender, receiver) = mpsc::channel(1);
            sender.try_send(vec![0]).expect("fill input channel");
            let cancel = CancellationToken::new();
            let thread_cancel = cancel.clone();
            let input = std::thread::spawn(move || {
                read_input(&OwnedFd::from(reader), &sender, &thread_cancel);
            });
            let resize_cancel = cancel.clone();
            let resize = koh_testkit::spawn(async move { resize_cancel.cancelled().await });
            let tasks = ClientIoTasks {
                cancel,
                input: Some(input),
                resize: Some(resize),
            };

            writer.write_all(b"blocked").expect("write blocked input");
            drop(receiver);
            timeout(Duration::from_secs(1), tasks.shutdown())
                .await
                .expect("shutdown stalled on the full channel")
                .expect("shutdown failed");
        });
    }

    #[test]
    fn shutdown_cancels_resize_blocked_by_a_full_channel() {
        crate::test_runtime::current_thread().block_on(async {
            let (sender, _receiver) = mpsc::channel(1);
            sender.try_send(()).expect("fill resize channel");
            let cancel = CancellationToken::new();
            let resize_cancel = cancel.clone();
            let resize = koh_testkit::spawn(async move {
                assert!(!send_resize(&sender, &resize_cancel).await);
            });
            let tasks = ClientIoTasks {
                cancel,
                input: None,
                resize: Some(resize),
            };

            timeout(Duration::from_secs(1), tasks.shutdown())
                .await
                .expect("shutdown stalled on the full resize channel")
                .expect("shutdown failed");
        });
    }
}
