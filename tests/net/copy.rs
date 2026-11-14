//! Copy workers must stop when their transport pumps stop, including under backpressure.

use std::time::Duration;

use anyhow::Context as _;
use koh::sync::{self, Dest, FileHeader, FileId, Item, Mode, Name, Opts};
use koh::transport_iroh::{generate_secret_key, ALPN};

use crate::link::{FaultNet, Profile};

#[test]
fn disconnected_copy_sender_releases_its_channels() -> anyhow::Result<()> {
    disconnected_copy(true)
}

#[test]
fn disconnected_copy_receiver_releases_its_channels() -> anyhow::Result<()> {
    disconnected_copy(false)
}

fn disconnected_copy(sender: bool) -> anyhow::Result<()> {
    let runtime = koh_testkit::multi_thread(2)?;
    let result = runtime.block_on(async {
        let net = FaultNet::new(Profile::default(), 1);
        let server = net.endpoint(generate_secret_key()?, true).await?;
        let client = net.endpoint(generate_secret_key()?, false).await?;
        let (dialed, accepted) =
            tokio::join!(client.connect(FaultNet::addr(server.id()), ALPN), async {
                server
                    .accept()
                    .await
                    .context("incoming copy connection")?
                    .await
                    .context("accept copy connection")
            });
        let (client_conn, server_conn) = (dialed?, accepted?);

        if sender {
            // No reply stream: the sender must see its reply channel close, rather than wait for
            // a sender retained by an already completed transport pump.
            let mut output = server_conn.open_uni().await?;
            let sent = tokio::time::timeout(
                Duration::from_secs(3),
                sync::send_on(Ok(vec![]), Opts::default(), &mut output, async { None }),
            )
            .await
            .context("copy sender stayed alive after its reply stream disappeared")?;
            anyhow::ensure!(sent.is_err(), "a copy without a receiver cannot succeed");
            return Ok(());
        }

        // Fill the receiver's reply queue before stopping its output. An end reply must not
        // wait forever on a full queue whose transport pump has already returned.
        let mut input = client_conn.open_uni().await?;
        let mut bytes = Vec::new();
        for id in 0..256 {
            for item in [
                Item::File(FileHeader {
                    id: FileId(id),
                    name: Name::new(format!("file-{id}").into_bytes())
                        .map_err(anyhow::Error::msg)?,
                    mode: Mode::new(0o600).context("file mode")?,
                    mtime: None,
                    size: 0,
                }),
                Item::Differs {
                    id: FileId(id),
                    from: 0,
                },
            ] {
                bytes.extend(koh::request::encode(&item, sync::MAX_ITEM)?);
            }
        }
        bytes.extend(koh::request::encode(&Item::Done, sync::MAX_ITEM)?);
        input.write_all(&bytes).await?;
        input.finish()?;
        let control = server_conn.accept_uni().await?;
        let mut replies = server_conn.open_uni().await?;
        // Make the stream visible before starting the receiver, then stop it explicitly.
        replies.write_all(b"reply").await?;
        let mut stopped = client_conn.accept_uni().await?;
        stopped.stop(0u32.into())?;
        replies.stopped().await?;
        let dest = koh_testkit::home!();
        tokio::time::timeout(
            Duration::from_secs(3),
            sync::receive_on(
                (Ok(Dest::Path(dest.to_path_buf())), 256),
                Opts {
                    dry_run: true,
                    ..Opts::default()
                },
                async { Some(control) },
                &mut replies,
            ),
        )
        .await
        .context("copy receiver stayed alive after its reply stream stopped")??;
        Ok(())
    });
    // A regression must report a failed deadline, not hang while the runtime waits for the
    // very blocking worker whose channel lifetime is under test.
    runtime.shutdown_timeout(Duration::from_millis(100));
    result
}
