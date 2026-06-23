//! # koh-transport-iroh
//!
//! The iroh glue: endpoint setup, a persistent node identity, dial-by-endpoint-id, and a
//! thin [`IrohChannel`] over a `Connection` that the SSP driver uses to ship datagrams and
//! read the path RTT. Everything QUIC-shaped (encryption, key exchange, NAT traversal,
//! relay fallback, roaming/migration, RTT measurement) is iroh's job; this crate just
//! exposes the few primitives the protocol above it needs.
//!
//! ## Datagrams, not streams
//!
//! The steady SSP flow rides QUIC **unreliable datagrams** ([`IrohChannel::send`] /
//! [`IrohChannel::recv`]). Oversized instructions are handled upstream by the
//! [`koh_wire`] fragmenter (each fragment fits [`IrohChannel::max_datagram_size`]), so we
//! never put the steady flow on a reliable stream — that would reintroduce the
//! head-of-line blocking mosh exists to avoid.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use crate::wire::DEFAULT_MAX_DATAGRAM;
use bytes::Bytes;
use iroh::endpoint::{
    presets, Connection, ConnectionError, IdleTimeout, PathId, QuicTransportConfig, VarInt,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey};

pub mod auth;
pub mod ratelimit;

/// Keepalive + connection idle-timeout tuned so a phone screen-off doesn't drop the connection.
/// iroh's defaults already PING every 5s and drop a *path* after 15s, but the *connection* idle
/// timeout defaults to ~30s; we raise it to 300s (5 min) so a short suspend (Android freezing the
/// process, so keepalives stop) is ridden out on the *same* connection with no visible reconnect.
/// Longer outages are handled above this layer: the client transparently re-dials and reattaches
/// to the detachable server session (see `crate::client::run_client`), so we don't need to hold a
/// dead connection open indefinitely here.
#[expect(
    clippy::expect_used,
    reason = "300s is far below IdleTimeout's varint ceiling; the conversion is statically infallible"
)]
#[allow(
    clippy::duration_suboptimal_units,
    reason = "`from_secs(300)` is the intended, readable idle timeout"
)]
fn koh_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .keep_alive_interval(Duration::from_secs(5))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(300)).expect("300s fits in IdleTimeout"),
        ))
        .build()
}

/// The ALPN that identifies the koh protocol on the wire.
pub const ALPN: &[u8] = b"koh/iroh/1";

/// Errors from endpoint/identity setup.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("secret key file is not 32 bytes of hex")]
    BadKeyFile,
    #[error("could not parse endpoint id: {0}")]
    BadEndpointId(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Load a persistent [`SecretKey`] from `path`, or generate + persist one if absent.
///
/// The file holds the 32-byte secret as lowercase hex. A stable key gives the server a
/// stable [`EndpointId`], mirroring iroh-ssh's `--persist`.
pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey, SetupError> {
    if path.exists() {
        // Tighten an existing group/other-accessible key to 0600 (it is the node's whole identity,
        // so a loose key is a local-impersonation risk), and refuse a world-writable containing dir
        // where a co-tenant could swap the key out (KOH-16 / KOH-06).
        tighten_or_warn_key_perms(path);
        if let Some(parent) = path.parent() {
            ensure_state_dir_secure(parent)?;
        }
        let text = std::fs::read_to_string(path)?;
        let bytes = data_encoding::HEXLOWER_PERMISSIVE
            .decode(text.trim().as_bytes())
            .map_err(|_| SetupError::BadKeyFile)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| SetupError::BadKeyFile)?;
        Ok(SecretKey::from_bytes(&arr))
    } else {
        let sk = generate_secret_key();
        if let Some(parent) = path.parent() {
            create_dir_private(parent)?;
            // Reject a world-writable state dir before writing the identity key into it (KOH-06).
            ensure_state_dir_secure(parent)?;
        }
        // The key is the node identity (M-1): write it owner-only (0600) and never leave a
        // world-readable window. On unix, create the file with `create_new` + mode 0600 (so it is
        // born private — no chmod race) and rename it into place atomically; elsewhere, fall back to
        // a plain write (best effort — the platform's own ACLs apply).
        write_secret_file(
            path,
            data_encoding::HEXLOWER.encode(&sk.to_bytes()).as_bytes(),
        )?;
        Ok(sk)
    }
}

/// Create `dir` (recursively) restricted to the owner (mode 0700 on unix) so a freshly-created
/// state dir doesn't expose its contents. Off-unix this is a plain recursive create.
fn create_dir_private(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // `recursive(true)` is idempotent if the dir already exists; the mode applies to the
        // components it creates.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `contents` to `path` as an owner-only (0600) file, atomically and without ever exposing a
/// world-readable window. On unix: create a sibling temp file with `create_new` + mode 0600, write,
/// fsync, then rename over `path`. Off-unix: a plain write (the platform's default ACLs apply).
fn write_secret_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        // Clean up any stale temp from a previous crashed run so `create_new` can succeed.
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        drop(f);
        // Atomic publish; if the rename fails, don't leave the temp behind.
        std::fs::rename(&tmp, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

/// On unix, if `path` is group/other-accessible (mode & 0o077 != 0), proactively tighten it to
/// 0600; only warn if that fails. The key IS the node identity, so a loose key is a local-
/// impersonation risk — and an upgrade-in-place from a pre-0.3.1 build (created via a plain write,
/// umask → typically 0644) lands here. Unlike the original warn-only behavior this re-permissions
/// the key (tightening can only ever help) rather than leaving it exposed (KOH-16). No-op elsewhere.
fn tighten_or_warn_key_perms(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode();
            if mode & 0o077 != 0 {
                match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
                    Ok(()) => tracing::warn!(
                        path = %path.display(),
                        prev_mode = format!("{:o}", mode & 0o777),
                        "secret key file was group/other-accessible; tightened to 0600"
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
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Refuse a state dir a co-tenant could tamper with, and flag a merely-loose one (KOH-06 / KOH-12).
///
/// On unix: a group/other-**writable** dir lets another user unlink/replace the secret key even
/// though the key file itself is 0600, so this hard-errors (pointing at `--key-file` /
/// `$KOH_STATE_DIR`). A group/other-**readable** (but not writable) dir only grants traverse, so it
/// just warns — `create_dir_private` already makes koh-created dirs 0700, so this only fires on a
/// pre-existing loosened dir or a shared fallback location. No-op off-unix / for the CWD.
fn ensure_state_dir_secure(dir: &Path) -> Result<(), SetupError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if dir.as_os_str().is_empty() {
            return Ok(()); // a relative "id.key" has an empty parent (the CWD); nothing to stat
        }
        if let Ok(meta) = std::fs::metadata(dir) {
            let mode = meta.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(SetupError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "state dir {} is group/other-writable (mode {:o}); a co-located user could \
                         replace the secret key — tighten it (chmod 700) or pass --key-file / set \
                         $KOH_STATE_DIR to a private path",
                        dir.display(),
                        mode & 0o777
                    ),
                )));
            }
            if mode & 0o077 != 0 {
                tracing::warn!(
                    path = %dir.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "state dir is group/other-accessible; tighten with `chmod 700`"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// The default persistent key path when `--key-file` isn't given, for `role` (`"client"`/`"server"`).
///
/// Prefers the platform config dir via `ProjectDirs` (desktop unchanged). On Android that yields
/// nothing, so rather than a relative `koh-<role>.key` in the (often read-only / nondeterministic)
/// CWD, resolve a **stable, writable** base — see [`state_dir_from`]. The parent dir is created when
/// the key is first written (`load_or_create_secret_key`); a non-writable location surfaces as a
/// clear error there (the caller names the path and can suggest `--key-file`).
pub fn default_key_path(role: &str) -> std::path::PathBuf {
    if let Some(dirs) = directories::ProjectDirs::from("", "", "koh") {
        return dirs.config_dir().join(format!("{role}.key"));
    }
    state_dir_from(
        std::env::var_os("KOH_STATE_DIR"),
        std::env::var_os("HOME"),
        std::env::var_os("TMPDIR"),
    )
    .join(format!("{role}.key"))
}

/// Resolve koh's state dir from explicit env values (pure, so it's unit-testable): `$KOH_STATE_DIR`,
/// else `$HOME/.config/koh` (Termux sets `$HOME`), else `$TMPDIR/koh`, else `/data/local/tmp/koh`.
fn state_dir_from(
    koh_state: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
    tmpdir: Option<std::ffi::OsString>,
) -> std::path::PathBuf {
    let nonempty = |o: Option<std::ffi::OsString>| o.filter(|v| !v.is_empty());
    if let Some(d) = nonempty(koh_state) {
        return std::path::PathBuf::from(d);
    }
    if let Some(h) = nonempty(home) {
        return std::path::PathBuf::from(h).join(".config").join("koh");
    }
    if let Some(t) = nonempty(tmpdir) {
        return std::path::PathBuf::from(t).join("koh");
    }
    std::path::PathBuf::from("/data/local/tmp/koh")
}

/// Generate a fresh random secret key (uses the OS RNG so it's independent of iroh's rand version).
pub fn generate_secret_key() -> SecretKey {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    SecretKey::from_bytes(&bytes)
}

/// Parse an [`EndpointId`] from its canonical (hex) string form, or the n0 base32 form.
pub fn parse_endpoint_id(s: &str) -> Result<EndpointId, SetupError> {
    s.trim()
        .parse::<EndpointId>()
        .map_err(|e| SetupError::BadEndpointId(e.to_string()))
}

/// The canonical (hex) string form of an [`EndpointId`], suitable for copy/paste.
pub fn format_endpoint_id(id: &EndpointId) -> String {
    id.to_string()
}

/// Parse a `$KOH_DNS` value: either `IP:PORT` (e.g. `8.8.8.8:53`) or a bare `IP`
/// (e.g. `1.1.1.1`, defaulting to port 53). Returns `None` for anything unparseable.
fn parse_dns_spec(spec: &str) -> Option<SocketAddr> {
    let spec = spec.trim();
    spec.parse::<SocketAddr>().ok().or_else(|| {
        spec.parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, 53))
    })
}

/// An explicit DNS resolver for iroh's discovery, or `None` to keep iroh's default
/// (the host's system DNS).
///
/// iroh builds `DnsResolver::default()` for **every** endpoint it binds (see
/// `Endpoint::builder(...).dns_resolver` / the `unwrap_or_default()` at bind time), and that
/// default reads the host's resolver config. On Android that read goes through the app's JNI
/// context, which a bare CLI (e.g. a Termux build) does not have — so it **panics**
/// (`ndk-context: android context was not initialized`) instead of returning an error iroh could
/// fall back from. We sidestep it by pinning an explicit public nameserver, which never touches
/// the system config (`DnsResolver::with_nameserver`).
///
/// - `$KOH_DNS` (any platform): override the nameserver, as `IP` or `IP:PORT`. Lets a desktop
///   opt in / pick a reachable resolver, and makes this path testable off-Android.
/// - On Android, default to Google Public DNS (`8.8.8.8:53`) even when unset.
/// - Elsewhere, `None`: keep iroh's system-DNS default (honors split-horizon / corporate DNS).
// On Android every branch returns `Some`, so clippy flags the wrapper there; the `Option` exists
// for the desktop `None` branch (which that target can't see), so scope the expectation to Android.
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

/// Build an iroh [`Endpoint`] with the `presets::N0` profile (relay + DNS discovery, so a
/// bare endpoint id is dialable).
///
/// `accept` registers our ALPN so the endpoint can accept incoming connections (server side).
pub async fn bind_endpoint(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .transport_config(koh_transport_config());
    if let Some(resolver) = discovery_dns_resolver() {
        builder = builder.dns_resolver(resolver);
    }
    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    let ep = builder
        .bind()
        .await
        .map_err(|e| SetupError::Other(e.into()))?;
    Ok(ep)
}

/// Build an iroh [`Endpoint`] with **no relay and no discovery** (`presets::Minimal`).
///
/// Use this for same-host / same-LAN sessions and for tests: peers must be dialed by a full
/// [`EndpointAddr`] (id + direct socket address), e.g. via [`loopback_addr`]. It avoids any
/// dependency on n0's public relay/DNS, so it is fully hermetic.
pub async fn bind_endpoint_local(secret: SecretKey, accept: bool) -> Result<Endpoint, SetupError> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .transport_config(koh_transport_config());
    // Even with no discovery, iroh constructs a default `DnsResolver` at bind time, which panics
    // on a bare-CLI Android build; pin an explicit resolver there. See `discovery_dns_resolver`.
    if let Some(resolver) = discovery_dns_resolver() {
        builder = builder.dns_resolver(resolver);
    }
    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    let ep = builder
        .bind()
        .await
        .map_err(|e| SetupError::Other(e.into()))?;
    Ok(ep)
}

/// A dial-able [`EndpointAddr`] for `ep` over the IPv4 loopback interface (id + 127.0.0.1:port).
/// Pair with [`bind_endpoint_local`] to connect two endpoints on one host without a relay.
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

/// A dial-able [`EndpointAddr`] from a peer's id + a known direct socket address (LAN / loopback,
/// no relay/discovery needed). Use with [`bind_endpoint_local`].
pub fn direct_addr(id: EndpointId, addr: SocketAddr) -> EndpointAddr {
    EndpointAddr::new(id).with_ip_addr(addr)
}

/// A dial-able [`EndpointAddr`] from a peer's id + a relay URL (relay-assisted, incl. NAT
/// traversal). Use with [`bind_endpoint_with_relay`] pointed at the same relay.
pub fn relay_addr(id: EndpointId, relay: RelayUrl) -> EndpointAddr {
    EndpointAddr::new(id).with_relay_url(relay)
}

/// Build an iroh [`Endpoint`] whose only relay is `relay` (no n0 relays, no DNS discovery).
///
/// Used for self-hosted relays (private deployments): peers dial by id + this same relay URL
/// ([`relay_addr`]). Covers NAT traversal / roaming via the local relay.
pub async fn bind_endpoint_with_relay(
    secret: SecretKey,
    accept: bool,
    relay: RelayUrl,
) -> Result<Endpoint, SetupError> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(RelayMode::custom([relay]))
        .transport_config(koh_transport_config());
    // iroh builds a default `DnsResolver` at bind time even here, which panics on a bare-CLI
    // Android build; pin an explicit resolver there. See `discovery_dns_resolver`.
    if let Some(resolver) = discovery_dns_resolver() {
        builder = builder.dns_resolver(resolver);
    }
    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    let ep = builder
        .bind()
        .await
        .map_err(|e| SetupError::Other(e.into()))?;
    Ok(ep)
}

/// Parse a relay URL string (e.g. `https://relay.example:3340`).
pub fn parse_relay_url(s: &str) -> Result<RelayUrl, SetupError> {
    s.trim()
        .parse::<RelayUrl>()
        .map_err(|e| SetupError::Other(anyhow::anyhow!("bad relay url: {e}")))
}

/// A datagram channel over a single iroh [`Connection`].
///
/// Oversized state is split by the [`koh_wire`] fragmenter across datagrams — never a reliable
/// stream (which would reintroduce the head-of-line blocking the protocol exists to avoid).
#[derive(Clone)]
pub struct IrohChannel {
    conn: Connection,
}

impl IrohChannel {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }

    /// The peer's stable identity.
    pub fn remote_id(&self) -> EndpointId {
        self.conn.remote_id()
    }

    /// Borrow the underlying connection (for advanced use / lifecycle).
    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Send one datagram. Failures (peer congestion, too-large, unsupported) are *dropped* on
    /// purpose: the SSP resends the current state on the next tick, so a lost datagram is a
    /// non-event. Returns whether it was handed to the transport.
    pub fn send(&self, datagram: &[u8]) -> bool {
        match self.conn.send_datagram(Bytes::copy_from_slice(datagram)) {
            Ok(()) => true,
            Err(e) => {
                tracing::trace!(error = %e, len = datagram.len(), "datagram send dropped");
                false
            }
        }
    }

    /// Await the next inbound datagram.
    pub async fn recv(&self) -> Result<Bytes, ConnectionError> {
        self.conn.read_datagram().await
    }

    /// The current datagram payload budget (path-MTU dependent; can change over the
    /// connection's life). Falls back to a conservative default if datagrams report no size.
    pub fn max_datagram_size(&self) -> usize {
        self.conn
            .max_datagram_size()
            .unwrap_or(DEFAULT_MAX_DATAGRAM)
            .max(64)
    }

    /// The smoothed path RTT in milliseconds, preferring the currently-selected path. `None`
    /// before any path is established (e.g. mid-holepunch).
    pub fn rtt_ms(&self) -> Option<f64> {
        let to_ms = |d: Duration| d.as_secs_f64() * 1000.0;
        if let Some(p) = self
            .conn
            .paths()
            .iter()
            .find(iroh::endpoint::Path::is_selected)
        {
            return Some(to_ms(p.rtt()));
        }
        if let Some(p) = self.conn.paths().iter().next() {
            return Some(to_ms(p.rtt()));
        }
        self.conn.rtt(PathId::ZERO).map(to_ms)
    }

    /// Immediately close the connection with an application code + reason.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(VarInt::from_u32(code), reason);
    }

    /// Resolve when the connection closes, yielding the reason.
    pub async fn closed(&self) -> ConnectionError {
        self.conn.closed().await
    }
}

/// A monotonic millisecond clock for driving the SSP scheduler, anchored at a base instant.
#[derive(Debug, Clone, Copy)]
pub struct MonoClock {
    base: tokio::time::Instant,
}

impl Default for MonoClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonoClock {
    pub fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
        }
    }

    /// Milliseconds since this clock was created.
    pub fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    /// The base instant, for computing absolute sleep deadlines from ms offsets.
    pub fn base(&self) -> tokio::time::Instant {
        self.base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_resolves_in_priority_order() {
        use std::ffi::OsString;
        use std::path::PathBuf;
        let s = |x: &str| Some(OsString::from(x));
        // KOH_STATE_DIR wins outright.
        assert_eq!(
            state_dir_from(s("/x"), s("/home/u"), s("/tmp")),
            PathBuf::from("/x")
        );
        // Else $HOME/.config/koh (the Termux case).
        assert_eq!(
            state_dir_from(None, s("/home/u"), s("/tmp")),
            PathBuf::from("/home/u/.config/koh")
        );
        // Empty values are skipped, not used.
        assert_eq!(
            state_dir_from(Some(OsString::new()), Some(OsString::new()), s("/tmp")),
            PathBuf::from("/tmp/koh")
        );
        // Last resort: a writable Android scratch dir, never a relative CWD path.
        let last = state_dir_from(None, None, None);
        assert_eq!(last, PathBuf::from("/data/local/tmp/koh"));
        assert!(
            last.is_absolute(),
            "the default must be absolute, not CWD-relative"
        );
    }

    #[test]
    fn secret_key_roundtrips_through_disk() {
        let dir = std::env::temp_dir().join(format!("koh-key-test-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);

        let sk1 = load_or_create_secret_key(&path).unwrap();
        let sk2 = load_or_create_secret_key(&path).unwrap();
        assert_eq!(
            sk1.to_bytes(),
            sk2.to_bytes(),
            "second load must reuse the key"
        );

        // The endpoint id is stable and round-trips through its string form.
        let id = sk1.public();
        let s = format_endpoint_id(&id);
        assert_eq!(parse_endpoint_id(&s).unwrap(), id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn created_key_file_is_owner_only() {
        // M-1: a freshly-created secret key must be 0600 (no group/other bits) and its parent dir
        // must not be group/other-writable — the key is the node identity, so a world-readable key
        // is a local-impersonation risk.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-key-perm-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);

        let _ = load_or_create_secret_key(&path).unwrap();
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

    /// Tier-1 foundation: two real iroh endpoints on loopback establish a connection and
    /// exchange a datagram both ways over the genuine accept/connect/datagram API — no relay,
    /// no second machine, fully hermetic.
    #[tokio::test]
    async fn two_endpoints_exchange_datagram_over_loopback() {
        let server = bind_endpoint_local(generate_secret_key(), true)
            .await
            .expect("bind server");
        let client = bind_endpoint_local(generate_secret_key(), false)
            .await
            .expect("bind client");
        let server_addr = loopback_addr(&server);

        let srv = tokio::spawn(async move {
            let incoming = server.accept().await.expect("accept");
            let conn = incoming.await.expect("handshake");
            let dg = conn.read_datagram().await.expect("read datagram");
            conn.send_datagram(dg).expect("echo datagram"); // echo it back
            conn.closed().await;
        });

        let conn = client
            .connect(server_addr, ALPN)
            .await
            .expect("connect over loopback");
        let chan = IrohChannel::new(conn);
        assert!(
            chan.send(b"ping-over-real-iroh"),
            "datagram send should succeed"
        );
        let echoed = chan.recv().await.expect("recv echo");
        assert_eq!(&echoed[..], b"ping-over-real-iroh");

        chan.close(0, b"done");
        let _ = srv.await;
    }
}
