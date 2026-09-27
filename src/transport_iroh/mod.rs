//! The iroh glue: endpoint setup, the identity key file, dial addresses and a connection's path
//! RTT. Everything QUIC-shaped (encryption, NAT traversal, relays, roaming, loss recovery) is
//! iroh's.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use iroh::endpoint::{
    presets, BindOpts, Connection, IdleTimeout, PathId, QuicTransportConfig, VarInt,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};

pub mod admission;

/// The connection idle timeout is 5 minutes, not iroh's ~30 s, so a short suspend (Android
/// freezing the process, so keepalives stop) is ridden out on the same connection; the client
/// redials after a longer one.
///
/// The server accepts only the client's one message stream; the client, the admission bi-stream
/// and a few frame streams (superseded ones are reset, so few are ever open).
fn koh_transport_config(accept: bool) -> QuicTransportConfig {
    // From a `u32` of milliseconds, unlike from a `Duration`, it cannot fail.
    const IDLE_TIMEOUT_MS: u32 = 300_000;
    let (uni, bidi) = if accept { (1, 0) } else { (8, 1) };
    QuicTransportConfig::builder()
        .keep_alive_interval(Duration::from_secs(5))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(IDLE_TIMEOUT_MS))))
        .max_concurrent_uni_streams(VarInt::from_u32(uni))
        .max_concurrent_bidi_streams(VarInt::from_u32(bidi))
        .build()
}

/// The ALPN, which is the protocol version ([`crate::proto`]): a peer on another fails the TLS
/// handshake instead of misparsing mid-session.
pub const ALPN: &[u8] = b"koh/3";

/// Errors from endpoint/identity setup.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("secret key file is invalid, a symlink, or not a regular file")]
    BadKeyFile,
    #[error(
        "{0} is not a koh identity key (expected exactly {KEY_LEN} bytes); remove it with \
         `koh key reset --key-file {0} --yes`, which creates a new identity on next use"
    )]
    NotAKey(String),
    #[error("could not parse endpoint id: {0}")]
    BadEndpointId(String),
    #[error("UDP port {0} is already in use (another koh serve?); stop it or pick another --port")]
    PortInUse(u16),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// The length of a key file: an iroh secret key's raw bytes, and nothing else.
pub const KEY_LEN: usize = 32;

/// Load the [`SecretKey`] at `path`, creating it if absent. The file is the key's raw bytes,
/// protected by its permissions (0600) like an SSH host key.
pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey, SetupError> {
    // Not `Path::exists`, which follows links: a dangling symlink must reach the checked open.
    let entry_exists = match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.into()),
    };
    if entry_exists {
        // First: in a dir another user can write, they could swap the key for their own.
        if let Some(parent) = path.parent() {
            ensure_state_dir_secure(parent)?;
        }
        load_secret_key(path)
    } else {
        let sk = generate_secret_key()?;
        if let Some(parent) = path.parent() {
            create_dir_private(parent)?;
            ensure_state_dir_secure(parent)?;
        }
        if create_secret_file(path, &sk.to_bytes())? {
            Ok(sk)
        } else {
            // Another process created it first; its key is the identity.
            load_secret_key(path)
        }
    }
}

/// Read a key file: exactly [`KEY_LEN`] bytes, opened and checked on one file descriptor.
fn load_secret_key(path: &Path) -> Result<SecretKey, SetupError> {
    let bytes = read_key_file_secure(path)?;
    let Ok(raw) = <[u8; KEY_LEN]>::try_from(bytes.as_slice()) else {
        return Err(SetupError::NotAKey(path.display().to_string()));
    };
    Ok(SecretKey::from_bytes(&raw))
}

/// Publish `contents` at `path` without replacing a file another process published first: with the
/// containing directory locked, check `path` is still free, write a born-private (0600) temporary
/// file and rename it into place. Returns whether this call published it.
///
/// Not a hard link, which would need no lock: Android's SELinux policy denies `link` to the shell
/// and to apps.
fn create_secret_file(path: &Path, contents: &[u8]) -> std::io::Result<bool> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    // Held until this returns: creators take turns, so only the first finds `path` free, and a
    // reader sees no key or a whole one.
    let directory = std::fs::File::open(parent)?;
    directory.lock()?;
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let (tmp, mut file) = loop {
        let tmp = path.with_extension(format!(
            "tmp.{}.{:016x}",
            std::process::id(),
            getrandom::u64()?
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => break (tmp, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    };
    let result = (|| {
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result.map(|()| true)
}

/// Create `dir` and its missing parents with mode 0700; an existing dir is left as it is.
pub(crate) fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

/// Read the key file at `path`: opened with `O_NOFOLLOW`, then checked, tightened and read through
/// that one descriptor, so a swapped-in symlink can neither redirect the chmod or the read nor race
/// a gap between a check and an act.
fn read_key_file_secure(path: &Path) -> Result<Vec<u8>, SetupError> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(fuxix::file::NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        // The open refused a symlink (ELOOP); asking afterwards only names the refusal.
        Err(_) if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) => {
            tracing::warn!(path = %path.display(), "secret key path is a symlink; refusing to load it");
            return Err(SetupError::BadKeyFile);
        }
        Err(e) => return Err(SetupError::Io(e)),
    };
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        tracing::warn!(path = %path.display(), "secret key path is not a regular file; refusing to load it");
        return Err(SetupError::BadKeyFile);
    }
    tighten_key_perms_via_fd(&file, path, &meta);
    // Read one byte past a key, so an oversized file is detected without reading all of it.
    let mut bytes = Vec::with_capacity(KEY_LEN.saturating_add(1));
    let limit = u64::try_from(KEY_LEN.saturating_add(1)).unwrap_or(u64::MAX);
    file.take(limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Tighten a group/other-accessible key file to 0600 through its descriptor (`fchmod`): a loosened
/// key, say from a permissive backup, lets a local user impersonate its owner.
fn tighten_key_perms_via_fd(file: &std::fs::File, path: &Path, meta: &std::fs::Metadata) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        match file.set_permissions(std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => tracing::warn!(
                path = %path.display(),
                prev_mode = format!("{:o}", mode & 0o777),
                "secret key file was group/other-accessible; tightened to 0600 (via fd)"
            ),
            Err(e) => tracing::warn!(
                path = %path.display(),
                mode = format!("{:o}", mode & 0o777),
                error = %e,
                "secret key file is group/other-accessible and could not be tightened; fix it with `chmod 600`"
            ),
        }
    }
}

/// Refuse a state dir another user could replace the key in, and warn about a merely loose one.
pub(crate) fn ensure_state_dir_secure(dir: &Path) -> Result<(), SetupError> {
    use std::os::unix::fs::PermissionsExt;
    if dir.as_os_str().is_empty() {
        return Ok(()); // a relative "id.key" has an empty parent (the CWD); nothing to stat
    }
    let Ok(meta) = std::fs::metadata(dir) else {
        return Ok(());
    };
    let mode = meta.permissions().mode();
    // Only other-writable without the sticky bit (which limits unlink to owners, as in /tmp's 1777)
    // lets another user replace the key. Group-writable is allowed: Android's /data/local/tmp is
    // 0771, and a single-user device has no co-tenant.
    let other_writable = mode & 0o002 != 0;
    let sticky = mode & 0o1000 != 0;
    if other_writable && !sticky {
        return Err(SetupError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "state dir {} is world-writable without the sticky bit (mode {:o}); any user \
                 could replace the secret key — chmod 700 it, add the sticky bit, or pass \
                 --key-file pointing at a private path",
                dir.display(),
                mode & 0o7777
            ),
        )));
    }
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %dir.display(),
            mode = format!("{:o}", mode & 0o7777),
            "state dir is group/other-accessible; the key is still 0600, but prefer chmod 700"
        );
    }
    Ok(())
}

/// koh's config directory, the one place it keeps files: `$XDG_CONFIG_HOME/koh`, else
/// `$HOME/.config/koh`, with no platform-specific or temporary fallback. `None` if neither is set.
fn config_dir_from(
    xdg_config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<std::path::PathBuf> {
    let nonempty = |o: Option<std::ffi::OsString>| o.filter(|v| !v.is_empty());
    if let Some(x) = nonempty(xdg_config_home) {
        return Some(std::path::PathBuf::from(x).join("koh"));
    }
    nonempty(home).map(|h| std::path::PathBuf::from(h).join(".config").join("koh"))
}

/// The default key path for `role` (`"client"` or `"server"`): `<config dir>/<role>.key`. An
/// error, not a fallback, if there is no config dir.
pub fn default_key_path(role: &str) -> Result<std::path::PathBuf, SetupError> {
    config_dir_from(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    )
    .map(|d| d.join(format!("{role}.key")))
    .ok_or_else(|| {
        SetupError::Other(anyhow::anyhow!(
            "cannot locate ~/.config (neither $XDG_CONFIG_HOME nor $HOME is set); pass --key-file"
        ))
    })
}

/// A new secret key from the OS's randomness, with no fallback: a predictable key is no key.
pub fn generate_secret_key() -> std::io::Result<SecretKey> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(SecretKey::from_bytes(&bytes))
}

/// Parse an [`EndpointId`] from its canonical (hex) string form, or the n0 base32 form.
pub fn parse_endpoint_id(s: &str) -> Result<EndpointId, SetupError> {
    s.trim()
        .parse::<EndpointId>()
        .map_err(|e| SetupError::BadEndpointId(e.to_string()))
}

/// A `$KOH_DNS` value: `IP:PORT`, or an `IP` on port 53.
fn parse_dns_spec(spec: &str) -> Option<SocketAddr> {
    let spec = spec.trim();
    spec.parse::<SocketAddr>().ok().or_else(|| {
        spec.parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// The nameserver `$KOH_DNS` names, else Google's on Android, else `None` for the system's.
///
/// iroh builds a default resolver for every endpoint, which reads the system config; on Android
/// that goes through a JNI context a bare CLI (Termux) lacks, and panics. An explicit nameserver
/// never reads it.
#[cfg_attr(
    target_os = "android",
    expect(
        clippy::unnecessary_wraps,
        reason = "Android always pins a nameserver (Some); the None arm is desktop-only"
    )
)]
fn discovery_dns_resolver() -> Option<iroh::dns::DnsResolver> {
    use iroh::dns::DnsResolver;
    if let Some(addr) = std::env::var("KOH_DNS")
        .ok()
        .as_deref()
        .and_then(parse_dns_spec)
    {
        return Some(DnsResolver::with_nameserver(addr));
    }
    #[cfg(target_os = "android")]
    {
        Some(DnsResolver::with_nameserver(SocketAddr::from((
            [8, 8, 8, 8],
            53,
        ))))
    }
    #[cfg(not(target_os = "android"))]
    {
        None
    }
}

/// Where an endpoint finds its peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    /// n0's relays and DNS discovery, so a bare endpoint id is dialable.
    N0,
    /// No relay and no discovery: dialed by id and socket address (LAN, loopback, tests).
    Local,
    /// Only this self-hosted relay, and no discovery.
    Relay(RelayUrl),
}

/// Bind an endpoint on `network`, [`configure`]d, on UDP `port` for IPv4 and, where the host has
/// it, IPv6; `None` binds ephemeral ports. `accept` lets it accept connections (the server).
///
/// A fixed port lets a client dialing an address find a restarted server where it was. A port in
/// use is [`SetupError::PortInUse`].
pub async fn bind_on(
    secret: SecretKey,
    accept: bool,
    network: &Network,
    port: Option<u16>,
) -> Result<Endpoint, SetupError> {
    let builder = match network {
        Network::N0 => Endpoint::builder(presets::N0),
        Network::Local => Endpoint::builder(presets::Minimal),
        Network::Relay(relay) => {
            Endpoint::builder(presets::Minimal).relay_mode(RelayMode::custom([relay.clone()]))
        }
    };
    let builder = match port {
        // IPv6 as iroh binds it by default: skipped where the host has none.
        Some(port) => builder
            .clear_ip_transports()
            .bind_addr((Ipv4Addr::UNSPECIFIED, port))
            .and_then(|builder| {
                builder.bind_addr_with_opts(
                    (Ipv6Addr::UNSPECIFIED, port),
                    BindOpts::default().set_is_required(false),
                )
            })
            .map_err(|e| SetupError::Other(anyhow::Error::new(e)))?,
        None => builder,
    };
    configure(builder, secret, accept)
        .bind()
        .await
        .map_err(|e| {
            let error = anyhow::Error::new(e);
            let in_use = error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AddrInUse)
            });
            match port {
                Some(port) if in_use => SetupError::PortInUse(port),
                _ => SetupError::Other(error),
            }
        })
}

/// Apply koh's identity, transport config, DNS resolver and (when `accept`ing) ALPN to `builder`.
/// Every endpoint koh binds goes through this, tests' included.
pub fn configure(
    builder: iroh::endpoint::Builder,
    secret: SecretKey,
    accept: bool,
) -> iroh::endpoint::Builder {
    let mut builder = builder
        .secret_key(secret)
        .transport_config(koh_transport_config(accept));
    if let Some(resolver) = discovery_dns_resolver() {
        builder = builder.dns_resolver(resolver);
    }
    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    builder
}

/// Bind an endpoint with n0's relays and DNS discovery, so a bare endpoint id is dialable. `accept`
/// lets it accept connections (the server).
pub async fn bind_endpoint(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    bind_on(secret, accept, &Network::N0, None).await
}

/// Bind an endpoint with no relay and no discovery, dialed by id and socket address (LAN,
/// loopback, tests).
pub async fn bind_endpoint_local(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    bind_on(secret, accept, &Network::Local, None).await
}

/// `ep`'s address on the IPv4 loopback interface.
pub fn loopback_addr(ep: &Endpoint) -> EndpointAddr {
    let mut addr = EndpointAddr::new(ep.id());
    if let Some(port) = ep
        .bound_sockets()
        .iter()
        .find(|s| s.is_ipv4())
        .map(std::net::SocketAddr::port)
    {
        addr = addr.with_ip_addr(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    addr
}

/// How long closing an endpoint waits for its peers to see the close.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Close `endpoint`, waiting at most [`CLOSE_WAIT`] for its peers to see it; whether they did.
/// iroh waits three probe timeouts of the slowest path, over ten seconds for a vanished peer.
pub(crate) async fn close_endpoint(endpoint: &Endpoint) -> bool {
    tokio::time::timeout(CLOSE_WAIT, endpoint.close())
        .await
        .is_ok()
}

/// A peer's address from its id and a direct socket address.
pub fn direct_addr(id: EndpointId, addr: SocketAddr) -> EndpointAddr {
    EndpointAddr::new(id).with_ip_addr(addr)
}

/// A peer's address from its id and the relay it uses.
pub fn relay_addr(id: EndpointId, relay: RelayUrl) -> EndpointAddr {
    EndpointAddr::new(id).with_relay_url(relay)
}

/// Bind an endpoint whose only relay is `relay` (self-hosted), with no discovery.
pub async fn bind_endpoint_with_relay(
    secret: SecretKey,
    accept: bool,
    relay: RelayUrl,
) -> Result<Endpoint, SetupError> {
    bind_on(secret, accept, &Network::Relay(relay), None).await
}

/// Parse a relay URL string (e.g. `https://relay.example:3340`).
pub fn parse_relay_url(s: &str) -> Result<RelayUrl, SetupError> {
    s.trim()
        .parse::<RelayUrl>()
        .map_err(|e| SetupError::Other(anyhow::anyhow!("bad relay url: {e}")))
}

/// The smoothed round-trip time of `conn`'s selected path, or `None` before any path exists.
pub fn rtt(conn: &Connection) -> Option<Duration> {
    let paths = conn.paths();
    paths
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .or_else(|| paths.iter().next())
        .map(|p| p.rtt())
        .or_else(|| conn.rtt(PathId::ZERO))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir_is_xdg_then_home_and_never_elsewhere() {
        use std::ffi::OsString;
        use std::path::PathBuf;
        let s = |x: &str| Some(OsString::from(x));
        // $XDG_CONFIG_HOME wins outright.
        assert_eq!(
            config_dir_from(s("/x"), s("/home/u")),
            Some(PathBuf::from("/x/koh"))
        );
        // Else $HOME/.config/koh.
        assert_eq!(
            config_dir_from(None, s("/home/u")),
            Some(PathBuf::from("/home/u/.config/koh"))
        );
        // Empty values are skipped, not used.
        assert_eq!(
            config_dir_from(Some(OsString::new()), s("/home/u")),
            Some(PathBuf::from("/home/u/.config/koh"))
        );
        // No XDG and no HOME: NO default (the caller must pass --key-file) — koh never falls back to
        // a CWD/tmp/platform path. ~/.config is the only location koh ever picks on its own.
        assert_eq!(config_dir_from(None, None), None);
        assert_eq!(
            config_dir_from(Some(OsString::new()), Some(OsString::new())),
            None
        );
    }

    #[test]
    fn a_created_key_is_its_raw_bytes_and_loads_back_to_the_same_identity() {
        let dir = std::env::temp_dir().join(format!("koh-key-test-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();

        let sk1 = load_or_create_secret_key(&path).expect("create a key");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            sk1.to_bytes(),
            "the file is the raw key"
        );
        let sk2 = load_or_create_secret_key(&path).expect("load it back");
        assert_eq!(sk1.to_bytes(), sk2.to_bytes(), "round-trips through disk");

        // The endpoint id is stable and round-trips through its string form.
        let id = sk1.public();
        let s = id.to_string();
        assert_eq!(parse_endpoint_id(&s).unwrap(), id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_first_key_creation_publishes_exactly_one_identity() {
        let dir = std::env::temp_dir().join(format!("koh-key-create-race-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).expect("private directory");
        let keys = [
            generate_secret_key().expect("OS randomness"),
            generate_secret_key().expect("OS randomness"),
        ];
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for key in keys {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let created =
                    create_secret_file(&path, &key.to_bytes()).expect("atomic key create");
                (created, key.to_bytes())
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().expect("creator thread"))
            .collect();
        assert_eq!(outcomes.iter().filter(|(created, _)| *created).count(), 1);
        let published = std::fs::read(&path).expect("published key");
        let winner = outcomes
            .iter()
            .find_map(|(created, bytes)| created.then_some(bytes))
            .expect("one winner");
        assert_eq!(published.as_slice(), winner.as_slice());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn preplanted_predictable_temporary_name_cannot_block_key_creation() {
        let dir = std::env::temp_dir().join(format!("koh-key-preplant-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).expect("private directory");
        let predictable = path.with_extension(format!("tmp.{}.1", std::process::id()));
        std::fs::write(&predictable, b"attacker-owned").expect("preplant old temporary name");
        let key = generate_secret_key().expect("OS randomness");
        assert!(
            create_secret_file(&path, &key.to_bytes()).expect("create identity"),
            "the identity is published despite the preplanted predictable name"
        );
        assert_eq!(
            std::fs::read(&predictable).expect("preplant remains untouched"),
            b"attacker-owned"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn created_key_file_is_owner_only() {
        // A written secret key must be 0600 (no group/other bits) and its parent dir must not
        // be group/other-writable — the key is the node identity, so a world-readable key is a
        // local-impersonation risk.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-key-perm-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();

        load_or_create_secret_key(&path).expect("create a key");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "key file must not be group/other-accessible, got {mode:o}"
        );
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(
            dmode & 0o077,
            0,
            "state dir must not be group/other-accessible, got {dmode:o}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_state_dir_secure_refuses_only_nonsticky_world_writable() {
        // Only a dir where ANOTHER user can replace the key must be refused — that is
        // a non-sticky *other*-writable dir. A merely group-writable dir (Android's /data/local/tmp
        // is 0771, NOT other-writable) and a sticky world-writable dir (Linux /tmp is 1777; sticky
        // restricts unlink to file owners) must be ALLOWED, else koh can't start in those standard
        // locations.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-ww-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let set =
            |m: u32| std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(m)).unwrap();

        set(0o777); // other-writable, no sticky: anyone can replace the key
        assert!(
            ensure_state_dir_secure(&dir).is_err(),
            "a non-sticky world-writable dir must be refused"
        );
        set(0o700);
        assert!(
            ensure_state_dir_secure(&dir).is_ok(),
            "a private 0700 dir is accepted"
        );
        set(0o771); // Android /data/local/tmp shape: group-writable, NOT other-writable
        assert!(
            ensure_state_dir_secure(&dir).is_ok(),
            "a group-writable but not-other-writable dir (0771) must be allowed"
        );
        set(0o1777); // Linux /tmp shape: world-writable but sticky
        assert!(
            ensure_state_dir_secure(&dir).is_ok(),
            "a sticky world-writable dir (1777) must be allowed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fd_key_read_does_not_follow_a_symlinked_key() {
        // The fd-based load (`O_NOFOLLOW`) must refuse a symlinked key path and never
        // chmod or read its target — so an attacker-planted symlink to a victim file is inert (the
        // target's perms and the load both reflect a refusal, not a follow).
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("victim");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let link = dir.join("server.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        // The open itself fails on the symlink (ELOOP), surfaced as BadKeyFile — no follow.
        assert!(
            matches!(read_key_file_secure(&link), Err(SetupError::BadKeyFile)),
            "a symlinked key must be refused at open, not followed"
        );
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o644,
            "a symlinked key's target must not be re-permissioned"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fd_key_read_tightens_a_loose_real_key_via_the_fd() {
        // A loose (group/other-accessible) real key is tightened to 0600 through the fd, and
        // its contents still read back. Proves the fd path both fstats and fchmods the same inode.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-loose-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();
        let key = dir.join("server.key");
        std::fs::write(&key, b"deadbeef\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let text = read_key_file_secure(&key).expect("a loose real key still reads");
        assert_eq!(text, b"deadbeef\n", "contents read back through the fd");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a loose key is tightened to 0600 via the fd");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_refuses_a_symlinked_key() {
        // A symlinked key path must be refused before the key is read (following it would make
        // the load a read-oracle on the target). The parent dir is 0700 so the dir check passes and we
        // reach the symlink guard.
        let dir = std::env::temp_dir().join(format!("koh-keylink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap(); // 0700
        let target = dir.join("secret");
        std::fs::write(&target, b"deadbeef").unwrap();
        let link = dir.join("server.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let result = load_or_create_secret_key(&link);
        assert!(
            matches!(result, Err(SetupError::BadKeyFile)),
            "a symlinked key path must be refused, got {result:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_refuses_a_dangling_symlink_instead_of_creating_a_key() {
        let dir = std::env::temp_dir().join(format!("koh-dangling-keylink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();
        let link = dir.join("server.key");
        std::os::unix::fs::symlink(dir.join("missing"), &link).unwrap();

        let result = load_or_create_secret_key(&link);
        assert!(
            matches!(result, Err(SetupError::BadKeyFile)),
            "a dangling symlink must be rejected before key creation, got {result:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_that_is_not_exactly_a_key_is_refused_with_the_reset_hint() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-notakey-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();
        let path = dir.join("id.key");
        let old_format = format!("koh-key-v1\n{}\n", "A".repeat(120));
        for contents in [
            Vec::new(),
            vec![7u8; KEY_LEN - 1],
            vec![7u8; KEY_LEN + 1],
            old_format.into_bytes(),
        ] {
            std::fs::write(&path, &contents).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let error = load_or_create_secret_key(&path).expect_err("refused");
            assert!(matches!(error, SetupError::NotAKey(_)), "{error:?}");
            let message = error.to_string();
            assert!(message.contains("koh key reset"), "{message}");
            assert!(message.contains(&path.display().to_string()), "{message}");
            assert!(
                !message.contains("koh-key-v1"),
                "the old format is not named: {message}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_endpoint_id("not-a-real-endpoint-id").is_err());
    }

    #[test]
    fn dns_spec_accepts_ip_and_ip_port_rejects_junk() {
        // Bare IPv4 defaults to :53; explicit port is honored.
        assert_eq!(
            parse_dns_spec("1.1.1.1"),
            Some(SocketAddr::from(([1, 1, 1, 1], 53)))
        );
        assert_eq!(
            parse_dns_spec("8.8.8.8:5353"),
            Some(SocketAddr::from(([8, 8, 8, 8], 5353)))
        );
        // IPv6 in both bare and bracketed-with-port forms.
        assert_eq!(
            parse_dns_spec("2001:4860:4860::8888").map(|a| a.port()),
            Some(53)
        );
        assert_eq!(
            parse_dns_spec("[2001:4860:4860::8888]:53").map(|a| a.port()),
            Some(53)
        );
        // Whitespace is tolerated; junk is rejected (no panic, no partial parse).
        assert_eq!(
            parse_dns_spec("  9.9.9.9  "),
            Some(SocketAddr::from(([9, 9, 9, 9], 53)))
        );
        assert_eq!(parse_dns_spec(""), None);
        assert_eq!(parse_dns_spec("not-an-ip"), None);
        assert_eq!(parse_dns_spec("8.8.8.8:"), None);
        assert_eq!(parse_dns_spec("8.8.8.8:99999"), None);
    }

    /// The exact iroh call the Android bare-id fix depends on: building a resolver from an
    /// explicit nameserver must succeed without reading (or panicking on) the host system DNS.
    /// Running this on the host verifies the API we can't compile-check on the Android target.
    #[test]
    fn explicit_nameserver_resolver_builds() {
        let _resolver =
            iroh::dns::DnsResolver::with_nameserver(SocketAddr::from(([8, 8, 8, 8], 53)));
    }

    /// Two real iroh endpoints on loopback connect and exchange a stream each way, under the
    /// per-role stream limits: no relay, no second machine, fully hermetic.
    #[test]
    fn two_endpoints_exchange_streams_over_loopback() {
        crate::test_runtime::current_thread().block_on(async {
            let server = bind_endpoint_local(generate_secret_key().expect("OS randomness"), true)
                .await
                .expect("bind server");
            let client = bind_endpoint_local(generate_secret_key().expect("OS randomness"), false)
                .await
                .expect("bind client");
            let server_addr = loopback_addr(&server);

            let srv = tokio::spawn(async move {
                let incoming = server.accept().await.expect("accept");
                let conn = incoming.await.expect("handshake");
                let mut recv = conn.accept_uni().await.expect("the client's stream");
                let ping = recv.read_to_end(64).await.expect("read ping");
                let mut send = conn.open_uni().await.expect("a server stream");
                send.write_all(&ping).await.expect("echo");
                send.finish().expect("finish");
                conn.closed().await;
            });

            let conn = client
                .connect(server_addr, ALPN)
                .await
                .expect("connect over loopback");
            let mut send = conn.open_uni().await.expect("open a stream");
            send.write_all(b"ping-over-real-iroh").await.expect("write");
            send.finish().expect("finish");
            let mut recv = conn.accept_uni().await.expect("the echo stream");
            let echoed = recv.read_to_end(64).await.expect("read the echo");
            assert_eq!(echoed, b"ping-over-real-iroh");

            conn.close(0u32.into(), b"done");
            let _ = srv.await;
        });
    }

    #[test]
    fn a_fixed_port_is_bound_and_a_taken_one_is_reported() {
        crate::test_runtime::current_thread().block_on(async {
            // A port the OS just handed out, so almost surely free.
            let port = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .and_then(|socket| socket.local_addr())
                .expect("a free port")
                .port();
            let secret = generate_secret_key().expect("OS randomness");
            let first = bind_on(secret.clone(), true, &Network::Local, Some(port))
                .await
                .expect("bind the port");
            let bound = first.bound_sockets();
            assert!(
                bound.iter().any(|s| s.is_ipv4() && s.port() == port),
                "{bound:?}"
            );
            assert!(
                bound
                    .iter()
                    .filter(|s| s.is_ipv6())
                    .all(|s| s.port() == port),
                "{bound:?}"
            );
            // The same port again, as a second server would: a clear error, not a random port.
            match bind_on(secret, true, &Network::Local, Some(port)).await {
                Err(SetupError::PortInUse(p)) => assert_eq!(p, port),
                Err(e) => panic!("expected PortInUse, got {e}"),
                Ok(_) => panic!("a taken port must not bind"),
            }
            assert_eq!(
                SetupError::PortInUse(port).to_string(),
                format!(
                    "UDP port {port} is already in use (another koh serve?); stop it or pick \
                     another --port"
                )
            );
            first.close().await;
        });
    }

    #[test]
    fn the_alpn_names_the_stream_protocol() {
        // `koh/3` is the stream protocol; a peer on another version (e.g. `koh/iroh/2`) fails the
        // TLS handshake instead of misparsing.
        assert_eq!(ALPN, b"koh/3");
    }
}
