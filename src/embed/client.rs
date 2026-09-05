use crate::client::{ConnectConfig, IrohConnector};
use crate::transport_iroh::{
    bind_endpoint, bind_endpoint_local, bind_endpoint_with_relay, direct_addr, parse_endpoint_id,
    parse_relay_url, relay_addr, IrohChannel,
};
use anyhow::Context as _;

/// An authenticated, admitted connection with owned reconnect state. Establish it before starting
/// application input readers. No terminal is opened and no signal handlers are installed here.
pub struct Connection {
    endpoint: iroh::Endpoint,
    escape_keys: bool,
    _identity: crate::identity::Identity,
    connector: IrohConnector,
    channel: IrohChannel,
}

impl Connection {
    pub async fn connect(
        config: &ConnectConfig,
        protocol: &'static [u8],
        identity: &crate::identity::Identity,
    ) -> anyhow::Result<Self> {
        let secret = identity.secret.clone();
        let server = parse_endpoint_id(&config.server).context("parsing server endpoint id")?;
        let (endpoint, target) = if let Some(addr) = config.direct {
            let endpoint = bind_endpoint_local(secret, false).await?;
            (endpoint, direct_addr(server, addr))
        } else if let Some(url) = &config.relay_url {
            let relay = parse_relay_url(url)?;
            let endpoint = bind_endpoint_with_relay(secret, false, relay.clone()).await?;
            (endpoint, relay_addr(server, relay))
        } else {
            (bind_endpoint(secret, false).await?, server.into())
        };
        let connector = IrohConnector::with_alpn(endpoint.clone(), target, protocol);
        let channel = tokio::time::timeout(std::time::Duration::from_secs(15), connector.connect())
            .await
            .context(
                "timed out connecting to workspace (server unreachable or not responding)",
            )??;
        Ok(Self {
            escape_keys: false,
            _identity: identity.clone(),
            endpoint,
            connector,
            channel,
        })
    }

    /// Opt into koh's standalone Ctrl-^ detach/suspend keys. Embedders default to byte-exact
    /// input and own their shortcuts through the cancellation token.
    #[must_use]
    pub const fn with_koh_escape_keys(mut self) -> Self {
        self.escape_keys = true;
        self
    }

    /// Runs the transport session using application-owned terminal and input sources. Dropping this
    /// future drops its terminal and all owned connection handles; normal exit awaits bounded close.
    #[expect(
        clippy::future_not_send,
        reason = "the application terminal may be thread-local"
    )]
    pub async fn run<S: crate::client::ClientState, T: crate::client::ClientTerminal<S>>(
        self,
        terminal: T,
        input: tokio::sync::mpsc::Receiver<Vec<u8>>,
        resize: tokio::sync::mpsc::Receiver<()>,
        shutdown: tokio_util::sync::CancellationToken,
        bell: Option<crate::client::BellHook>,
    ) -> anyhow::Result<Option<u32>> {
        let size = terminal.size().unwrap_or((24, 80));
        let result = crate::client::run_client_configured(
            self.channel,
            self.connector,
            crate::predict::DisplayPreference::Always,
            size,
            input,
            resize,
            terminal,
            shutdown,
            bell,
            self.escape_keys,
        )
        .await;
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(2), self.endpoint.close()).await;
        result
    }

    /// Close a prepared connection without running an application session.
    pub async fn close(self) {
        self.channel.close(0, b"client closed");
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(2), self.endpoint.close()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redial_reuses_the_supplied_identity_without_a_key_file() -> anyhow::Result<()> {
        use crate::transport_iroh::{admission, bind_endpoint_local_alpns, generate_secret_key};
        let server =
            bind_endpoint_local_alpns(generate_secret_key(), vec![b"embed-test/1".to_vec()])
                .await?;
        let identity = crate::identity::Identity::generate();
        let expected = identity.secret.public();
        let socket = server
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .context("server IPv4 socket")?;
        let config = ConnectConfig {
            server: server.id().to_string(),
            // Any attempt to reload instead of reusing `secret` would fail here.
            key_file: Some("/nonexistent/fux-redial-test.key".into()),
            direct: Some(([127, 0, 0, 1], socket.port()).into()),
            relay_url: None,
            clipboard: false,
            bell_command: None,
        };
        let peer = server.clone();
        let accept = async move {
            for _ in 0..2 {
                let connection = peer.accept().await.context("accept connection")?.await?;
                anyhow::ensure!(
                    connection.remote_id() == expected,
                    "client identity changed"
                );
                admission::admit(&connection).await?;
                connection.closed().await;
            }
            Ok::<_, anyhow::Error>(())
        };
        let client = async {
            let prepared = Connection::connect(&config, b"embed-test/1", &identity).await?;
            prepared.channel.close(0, b"test reconnect");
            // This is the same connector run_client_with owns across link losses.
            let channel = prepared.connector.connect().await?;
            channel.close(0, b"test done");
            prepared.endpoint.close().await;
            Ok::<_, anyhow::Error>(())
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            Box::pin(async { tokio::try_join!(accept, client) }),
        )
        .await??;
        server.close().await;
        Ok(())
    }
}
