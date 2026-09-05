use clap::{Args, Subcommand};
use std::path::PathBuf;
use tokio::signal::unix::{signal, SignalKind};

#[derive(Debug, Args)]
pub struct GatewayArgs {
    #[command(subcommand)]
    action: Action,
}
#[derive(Debug, Subcommand)]
enum Action {
    /// Expose one local Unix service to explicitly authorized remote peers.
    Serve {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long, required = true)]
        allow: Vec<String>,
        #[arg(long, conflicts_with = "relay_url")]
        local: bool,
        #[arg(long)]
        relay_url: Option<String>,
    },
    /// Expose an authenticated remote service through a private local Unix socket.
    Connect {
        server: String,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "relay_url")]
        direct: Option<std::net::SocketAddr>,
        #[arg(long)]
        relay_url: Option<String>,
    },
}
pub async fn run(args: GatewayArgs) -> anyhow::Result<()> {
    let mut service = match args.action {
        Action::Serve {
            socket,
            key_file,
            allow,
            local,
            relay_url,
        } => {
            let key = key_file.map_or_else(|| crate::identity::default_path("gateway"), Ok)?;
            let identity = crate::identity::load(&key)?;
            let profile = if local {
                crate::embed::NetworkProfile::Local
            } else if let Some(url) = relay_url {
                crate::embed::NetworkProfile::Relay(url)
            } else {
                crate::embed::NetworkProfile::Default
            };
            let service =
                super::serve(identity, allow.into_iter().collect(), profile, socket).await?;
            println!(
                "{}",
                serde_json::json!({"endpoint_id":service.endpoint_id(), "direct_addr":service.direct_addr()})
            );
            service
        }
        Action::Connect {
            server,
            socket,
            key_file,
            direct,
            relay_url,
        } => {
            let identity = crate::identity::load_client(key_file.as_deref())?;
            let service = super::connect(
                identity,
                super::ConnectConfig {
                    server,
                    socket: socket.clone(),
                    direct,
                    relay_url,
                },
            )
            .await?;
            println!("{}", serde_json::json!({"socket":socket}));
            service
        }
    };
    // Close the owned endpoint on every signal-registration or shutdown path.
    let signals = (
        signal(SignalKind::interrupt()),
        signal(SignalKind::terminate()),
    );
    let result = match signals {
        (Ok(mut interrupt), Ok(mut terminate)) => {
            tokio::select! { _ = interrupt.recv() => {}, _ = terminate.recv() => {} }
            Ok(())
        }
        (Err(error), _) | (_, Err(error)) => Err(error.into()),
    };
    service.close().await;
    result
}
