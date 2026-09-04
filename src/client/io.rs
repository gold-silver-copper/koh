//! Cancellation-aware terminal input and resize producers for embedded clients.

use anyhow::Context;
use nix::poll::{poll, PollFd, PollFlags};
use std::io::Read;
use std::os::fd::AsFd;
use std::thread::JoinHandle;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle as TokioJoinHandle;
use tokio_util::sync::CancellationToken;

/// Receivers passed directly to [`super::connect_with`].
pub struct ClientIoChannels {
    pub input_rx: mpsc::Receiver<Vec<u8>>,
    pub resize_rx: mpsc::Receiver<()>,
}

/// Owned producer tasks. Call [`shutdown`](Self::shutdown) after `connect_with` returns.
pub struct ClientIoTasks {
    cancel: CancellationToken,
    input: Option<JoinHandle<()>>,
    resize: Option<TokioJoinHandle<()>>,
}

impl ClientIoTasks {
    /// Cancels both producers and joins them. The input poll checks cancellation at least every
    /// 100 ms, so teardown never waits for another byte on stdin.
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.cancel.cancel();
        let resize_result = match self.resize.take() {
            Some(resize) => resize.await.context("joining SIGWINCH producer"),
            None => Ok(()),
        };
        let input = self.input.take();
        let input_result = tokio::task::spawn_blocking(move || {
            if let Some(input) = input {
                input
                    .join()
                    .map_err(|_| anyhow::anyhow!("stdin producer panicked"))?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("joining stdin producer task")
        .and_then(|result| result);
        match (resize_result, input_result) {
            (Err(primary), Err(cleanup)) => {
                tracing::warn!(error = ?cleanup, "stdin producer cleanup also failed");
                Err(primary)
            }
            (Err(primary), Ok(())) => Err(primary),
            (Ok(()), Err(cleanup)) => Err(cleanup),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl Drop for ClientIoTasks {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Starts byte-exact stdin and SIGWINCH producers for an embedded `connect_with` client.
pub fn spawn_client_io() -> anyhow::Result<(ClientIoChannels, ClientIoTasks)> {
    let runtime = tokio::runtime::Handle::try_current()
        .context("starting client I/O requires a Tokio runtime")?;
    let mut sigwinch =
        signal(SignalKind::window_change()).context("installing SIGWINCH handler")?;
    let cancel = CancellationToken::new();
    let (input_tx, input_rx) = mpsc::channel(64);
    let input_cancel = cancel.clone();
    let input = std::thread::Builder::new()
        .name("koh-stdin".into())
        .spawn(move || read_input(std::io::stdin(), &input_tx, &input_cancel))
        .context("spawning stdin producer")?;
    let (resize_tx, resize_rx) = mpsc::channel(8);
    let resize_cancel = cancel.clone();
    let resize = runtime.spawn(async move {
        loop {
            tokio::select! {
                () = resize_cancel.cancelled() => break,
                received = sigwinch.recv() => {
                    if received.is_none() || resize_tx.send(()).await.is_err() { break; }
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

fn read_input<R: Read + AsFd>(
    mut reader: R,
    sender: &mpsc::Sender<Vec<u8>>,
    cancel: &CancellationToken,
) {
    let mut buffer = [0_u8; 1024];
    while !cancel.is_cancelled() {
        let ready = {
            let mut descriptors = [PollFd::new(reader.as_fd(), PollFlags::POLLIN)];
            poll(&mut descriptors, 100_u16)
        };
        match ready {
            Ok(0) | Err(nix::errno::Errno::EINTR) => {}
            Ok(_) => match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let Some(chunk) = buffer.get(..count) else {
                        break;
                    };
                    if !send_chunk(sender, cancel, chunk.to_vec()) {
                        break;
                    }
                }
            },
            Err(_) => break,
        }
    }
}

fn send_chunk(
    sender: &mpsc::Sender<Vec<u8>>,
    cancel: &CancellationToken,
    mut chunk: Vec<u8>,
) -> bool {
    loop {
        if cancel.is_cancelled() {
            return false;
        }
        match sender.try_send(chunk) {
            Ok(()) => return true,
            Err(TrySendError::Closed(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                chunk = returned;
                std::thread::park_timeout(std::time::Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{raise, Signal};
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

    #[tokio::test]
    async fn public_spawn_reports_resize_and_shuts_down() {
        let (channels, tasks) = spawn_client_io().expect("spawn public client I/O");
        let ClientIoChannels {
            mut input_rx,
            mut resize_rx,
        } = channels;

        raise(Signal::SIGWINCH).expect("raise SIGWINCH");
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
    }

    #[tokio::test]
    async fn dropping_public_tasks_cancels_both_producers() {
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
        assert_eq!(
            timeout(Duration::from_secs(1), resize_rx.recv())
                .await
                .expect("resize producer remained alive after task owner was dropped"),
            None
        );
    }

    #[tokio::test]
    async fn idle_input_poll_cancels_and_joins_without_waiting_for_a_byte() {
        // KC-IO-01: embedded client teardown owns and joins every producer.
        let (reader, _writer) = UnixStream::pair().expect("socket pair");
        let (sender, mut receiver) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let thread_cancel = cancel.clone();
        let input = std::thread::spawn(move || read_input(reader, &sender, &thread_cancel));
        cancel.cancel();
        let start = Instant::now();
        input.join().expect("join producer");
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(receiver.recv().await.is_none());
    }

    #[tokio::test]
    async fn input_producer_forwards_bytes_exactly() {
        // KC-IO-02: producer framing does not transform terminal input.
        let (reader, mut writer) = UnixStream::pair().expect("socket pair");
        let (sender, mut receiver) = mpsc::channel(1);
        let cancel = CancellationToken::new();
        let thread_cancel = cancel.clone();
        let input = std::thread::spawn(move || read_input(reader, &sender, &thread_cancel));
        writer.write_all(b"a\0\x1bZ").expect("write input");
        assert_eq!(
            receiver.recv().await.as_deref(),
            Some(b"a\0\x1bZ".as_slice())
        );
        cancel.cancel();
        input.join().expect("join producer");
    }

    #[tokio::test]
    async fn shutdown_cancels_input_blocked_by_a_full_channel() {
        let (reader, mut writer) = UnixStream::pair().expect("socket pair");
        let (sender, mut receiver) = mpsc::channel(1);
        sender.try_send(vec![0]).expect("fill input channel");
        let cancel = CancellationToken::new();
        let thread_cancel = cancel.clone();
        let input = std::thread::spawn(move || read_input(reader, &sender, &thread_cancel));
        let resize_cancel = cancel.clone();
        let resize = tokio::spawn(async move { resize_cancel.cancelled().await });
        let tasks = ClientIoTasks {
            cancel,
            input: Some(input),
            resize: Some(resize),
        };

        writer.write_all(b"blocked").expect("write blocked input");
        tokio::time::sleep(Duration::from_millis(30)).await;
        timeout(Duration::from_secs(1), tasks.shutdown())
            .await
            .expect("shutdown stalled on the full channel")
            .expect("shutdown failed");
        assert_eq!(receiver.recv().await, Some(vec![0]));
        assert!(receiver.recv().await.is_none());
    }
}
