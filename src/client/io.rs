//! Cancellation-aware terminal input and resize producers for embedded clients.

use anyhow::Context;
use nix::poll::{poll, PollFd, PollFlags};
use std::io::Read;
use std::os::fd::AsFd;
use std::thread::JoinHandle;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
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
    resize: TokioJoinHandle<()>,
}

impl ClientIoTasks {
    /// Cancels both producers and joins them. The input poll checks cancellation at least every
    /// 100 ms, so teardown never waits for another byte on stdin.
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        self.cancel.cancel();
        self.resize.await.context("joining SIGWINCH producer")?;
        let input = self.input.take();
        tokio::task::spawn_blocking(move || {
            if let Some(input) = input {
                input
                    .join()
                    .map_err(|_| anyhow::anyhow!("stdin producer panicked"))?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("joining stdin producer task")??;
        Ok(())
    }
}

/// Starts byte-exact stdin and SIGWINCH producers for an embedded `connect_with` client.
pub fn spawn_client_io() -> anyhow::Result<(ClientIoChannels, ClientIoTasks)> {
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
    let resize = tokio::spawn(async move {
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
            resize,
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
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

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
        std::io::Write::write_all(&mut writer, b"a\0\x1bZ").expect("write input");
        assert_eq!(
            receiver.recv().await.as_deref(),
            Some(b"a\0\x1bZ".as_slice())
        );
        cancel.cancel();
        input.join().expect("join producer");
    }
}
