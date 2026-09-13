//! Identity display independent of shell hosting and rendering.
#[cfg(feature = "cli")]
use clap::Args;
use std::path::PathBuf;

/// Configuration for [`run_id`] — the clap-free form of `koh id`'s arguments.
#[derive(Debug, Clone, Default)]
pub struct IdConfig {
    /// Path to the client's persistent secret key. `None` = the platform default client key path.
    pub key_file: Option<PathBuf>,
}

/// Arguments for `koh id` (the clap adapter over [`IdConfig`]; `cli` only).
#[cfg(feature = "cli")]
#[derive(Args, Debug)]
pub struct IdArgs {
    /// Path to the client's persistent secret key.
    #[arg(long)]
    key_file: Option<PathBuf>,
}

#[cfg(feature = "cli")]
impl From<IdArgs> for IdConfig {
    fn from(a: IdArgs) -> Self {
        Self {
            key_file: a.key_file,
        }
    }
}

/// `koh id` — print this machine's koh id (to add to a server's `--allow` list) and exit.
/// Accepts an [`IdConfig`] or anything convertible into one (`IdArgs` under `cli`).
pub fn run_id(config: impl Into<IdConfig>) -> anyhow::Result<()> {
    let args: IdConfig = config.into();
    let key_file = match args.key_file {
        Some(p) => p,
        None => crate::transport_iroh::default_key_path("client")?,
    };
    let identity = crate::identity::load(&key_file)?;
    println!("{}", identity.endpoint_id());
    Ok(())
}
