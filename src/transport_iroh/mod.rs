//! # koh-transport-iroh
//!
//! The iroh glue: endpoint setup, a persistent node identity, dial-by-endpoint-id, and a
//! thin [`IrohChannel`] over a `Connection` that the SSP driver uses to ship datagrams and
//! read the path RTT. Everything QUIC-shaped (encryption, key exchange, NAT traversal,
//! relay fallback, roaming/migration, RTT measurement) is iroh's job; this module just
//! exposes the few primitives the protocol above it needs.
//!
//! ## Datagrams, not streams
//!
//! The steady SSP flow rides QUIC **unreliable datagrams** ([`IrohChannel::send`] /
//! [`IrohChannel::recv`]). Oversized instructions are handled upstream by the
//! [`wire`](crate::wire) fragmenter (each fragment fits [`IrohChannel::max_datagram_size`]), so we
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
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

pub mod admission;
mod keyfile;
pub mod sk_auth;

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
    #[error("secret key file is invalid, a symlink, or not a regular file")]
    BadKeyFile,
    #[error("could not parse endpoint id: {0}")]
    BadEndpointId(String),
    #[error("encrypted identity key: {0}")]
    Keyfile(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Load a persistent [`SecretKey`] from `path`, or generate + persist one if absent.
///
/// The key is always stored in the passphrase-encrypted `koh-key-v1` format (there is no plaintext
/// format). A stable key gives the server a stable [`EndpointId`], mirroring iroh-ssh's `--persist`.
pub fn load_or_create_secret_key(path: &Path) -> Result<SecretKey, SetupError> {
    if path.exists() {
        // Refuse a dangerous containing dir FIRST (KOH-06/KR-06): the load below tightens the key's
        // perms and reads it, and in a dir where another user can unlink/replace entries they could
        // swap `id.key` for their own. (v0.4.2 narrowed this to a non-sticky *other*-writable dir so
        // Android's group-writable /data/local/tmp still works — see `ensure_state_dir_secure`.)
        if let Some(parent) = path.parent() {
            ensure_state_dir_secure(parent)?;
        }
        // Open the key ONCE and do every subsequent step (fstat, perm-tighten, read) on that file
        // descriptor (K-01). The previous flow was check-then-act — `symlink_metadata`, then a path
        // `chmod`, then a path `read` — each re-resolving the path string, leaving a TOCTOU window
        // in a group-writable dir where a co-tenant could swap `id.key` for a symlink *between* the
        // checks. `read_key_file_secure` opens with `O_NOFOLLOW` (a symlinked key is refused at
        // open) and operates only on the held fd, so there is no second path resolution to race.
        let mut text = read_key_file_secure(path)?;
        // The identity key is ALWAYS the `koh-key-v1` encrypted format (koh has no plaintext key
        // path). Decrypt under the resolved passphrase; secret material stays in `Zeroizing` and the
        // raw file text is wiped before returning.
        let pass = resolve_key_passphrase(path)?;
        let secret = keyfile::decrypt_key(&text, pass.expose_secret())
            .map_err(|e| SetupError::Keyfile(e.to_string()))?;
        let sk = SecretKey::from_bytes(&secret);
        text.zeroize();
        Ok(sk)
    } else {
        let sk = generate_secret_key();
        if let Some(parent) = path.parent() {
            create_dir_private(parent)?;
            // Reject a world-writable state dir before writing the identity key into it (KOH-06).
            ensure_state_dir_secure(parent)?;
        }
        // The key is the node identity (M-1): write it owner-only (0600) AND encrypted at rest
        // (`koh-key-v1`) — encryption is mandatory, so a fresh key requires a passphrase up front
        // (a no-echo confirmed TTY prompt, or `$KOH_KEY_NEW_PASSPHRASE` when headless).
        let pass = resolve_new_key_passphrase(path)?;
        write_identity_key(path, &sk, pass.expose_secret())?;
        Ok(sk)
    }
}

/// Resolve the passphrase for an encrypted identity key: `$KOH_KEY_PASSPHRASE` if set (non-empty),
/// else a no-echo TTY prompt, else a clear error (so an unattended `koh serve` with an encrypted key
/// fails loudly with the fix rather than hanging).
fn resolve_key_passphrase(path: &Path) -> Result<SecretString, SetupError> {
    use std::io::IsTerminal as _;
    if let Ok(p) = std::env::var("KOH_KEY_PASSPHRASE") {
        if !p.is_empty() {
            return Ok(SecretString::from(p));
        }
    }
    if std::io::stdin().is_terminal() {
        let p = rpassword::prompt_password(format!("Passphrase for {}: ", path.display()))
            .map_err(SetupError::Io)?;
        return Ok(SecretString::from(p));
    }
    Err(SetupError::Other(anyhow::anyhow!(
        "identity key {} is encrypted; set $KOH_KEY_PASSPHRASE (no TTY available for a prompt)",
        path.display()
    )))
}

/// Resolve a passphrase to encrypt a freshly-created identity key: `$KOH_KEY_NEW_PASSPHRASE` if set,
/// else a confirmed no-echo TTY prompt, else a clear error. An empty passphrase is rejected —
/// encryption is mandatory, so there is no plaintext fallback.
fn resolve_new_key_passphrase(path: &Path) -> Result<SecretString, SetupError> {
    use std::io::IsTerminal as _;
    if let Ok(p) = std::env::var("KOH_KEY_NEW_PASSPHRASE") {
        if p.is_empty() {
            return Err(SetupError::Other(anyhow::anyhow!(
                "$KOH_KEY_NEW_PASSPHRASE is empty; identity keys are always encrypted (set a non-empty passphrase)"
            )));
        }
        enforce_passphrase_strength(&p)?;
        return Ok(SecretString::from(p));
    }
    if std::io::stdin().is_terminal() {
        let p1 = rpassword::prompt_password(format!(
            "Set a passphrase to encrypt the new identity key {}: ",
            path.display()
        ))
        .map_err(SetupError::Io)?;
        if p1.is_empty() {
            return Err(SetupError::Other(anyhow::anyhow!(
                "an empty passphrase is not allowed; identity keys are always encrypted"
            )));
        }
        let p2 = rpassword::prompt_password("Confirm passphrase: ").map_err(SetupError::Io)?;
        if p1 != p2 {
            return Err(SetupError::Other(anyhow::anyhow!(
                "passphrases did not match"
            )));
        }
        enforce_passphrase_strength(&p1)?;
        return Ok(SecretString::from(p1));
    }
    Err(SetupError::Other(anyhow::anyhow!(
        "no identity key at {} and no TTY to prompt; set $KOH_KEY_NEW_PASSPHRASE to create an encrypted key",
        path.display()
    )))
}

/// The minimum identity-key passphrase length koh accepts. A passphrase shorter than this would make
/// the at-rest encryption (Argon2id + AES-256-GCM) effectively defeatable by an offline attacker who
/// already holds the key file — i.e. an *effectively unencrypted* key. koh has no plaintext key
/// format and, by the same logic, no weak-passphrase escape from real encryption.
const MIN_PASSPHRASE_CHARS: usize = 12;

/// Reject an identity-key passphrase weaker than [`MIN_PASSPHRASE_CHARS`]. Enforced as a HARD floor
/// (not an advisory) on every key-creation / re-encryption path — the TTY prompt AND
/// `$KOH_KEY_NEW_PASSPHRASE` alike — so there is no way to land an effectively-unencrypted key on
/// disk. Shared by key creation and `koh key`.
pub(crate) fn enforce_passphrase_strength(passphrase: &str) -> Result<(), SetupError> {
    if passphrase.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(SetupError::Other(anyhow::anyhow!(
            "identity-key passphrase is too short (< {MIN_PASSPHRASE_CHARS} chars); identity keys are \
             always strongly encrypted — choose a longer, higher-entropy passphrase"
        )));
    }
    Ok(())
}

/// Persist `sk` to `path` atomically (born-private 0600) in the `koh-key-v1` encrypted format. The
/// shared key-write path for `koh key`. The owned secret bytes are zeroized after use. `passphrase`
/// must be non-empty — koh has no plaintext key format.
pub(crate) fn write_identity_key(
    path: &Path,
    sk: &SecretKey,
    passphrase: &str,
) -> Result<(), SetupError> {
    let secret = Zeroizing::new(sk.to_bytes());
    let text = keyfile::encrypt_key(&secret, passphrase)
        .map_err(|e| SetupError::Keyfile(e.to_string()))?;
    write_secret_file(path, text.as_bytes())?;
    Ok(())
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

/// Read the hex key text from `path`, doing every step on a single opened file descriptor so there
/// is no path-based recheck window (K-01).
///
/// On unix: open with `O_NOFOLLOW` (a symlinked final component is refused at open — `ELOOP`),
/// confirm via the fd that it is a regular file, tighten group/other-accessible perms to 0600 via
/// the fd (`fchmod`, never a second path `chmod`), then read the contents from the same fd. A
/// co-tenant who swaps `id.key` for a symlink can therefore neither redirect the `chmod`/read to
/// another file nor race a gap between a check and an act — there is only the one open. On other
/// platforms, fall back to a plain read (the platform's own ACLs apply, matching the key-write path).
fn read_key_file_secure(path: &Path) -> Result<String, SetupError> {
    #[cfg(unix)]
    {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        // `O_NOFOLLOW`: refuse to follow a symlink planted as the key path — otherwise the load
        // could be turned into a chmod/read oracle on an arbitrary file koh can reach.
        let mut file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(nix::libc::ELOOP) => {
                tracing::warn!(path = %path.display(), "secret key path is a symlink; refusing to load it");
                return Err(SetupError::BadKeyFile);
            }
            Err(e) => return Err(SetupError::Io(e)),
        };
        let meta = file.metadata().map_err(SetupError::Io)?;
        if !meta.file_type().is_file() {
            tracing::warn!(path = %path.display(), "secret key path is not a regular file; refusing to load it");
            return Err(SetupError::BadKeyFile);
        }
        tighten_key_perms_via_fd(&file, path, &meta);
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(SetupError::Io)?;
        Ok(text)
    }
    #[cfg(not(unix))]
    {
        Ok(std::fs::read_to_string(path)?)
    }
}

/// On unix, tighten an existing group/other-accessible key file to 0600 — operating on the held
/// **fd** (`File::set_permissions` is `fchmod`), so it can't be redirected to a different inode by a
/// path swap (K-01). The key IS the node identity (KOH-16), so a loose key is a local-impersonation
/// risk; a key file whose perms were loosened out-of-band (manual `chmod`, a restore from a
/// permissive backup/umask) is re-tightened here on load.
#[cfg(unix)]
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

/// Refuse a state dir a co-tenant could tamper with, and flag a merely-loose one (KOH-06 / KOH-12).
///
/// On unix: a group/other-**writable** dir lets another user unlink/replace the secret key even
/// though the key file itself is 0600, so this hard-errors (pointing at `--key-file`). A
/// group/other-**readable** (but not writable) dir only grants traverse, so it
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
            // The real threat (KOH-06) is a dir where *another user* can unlink/replace the key.
            // That is precisely an **other-writable, non-sticky** dir: the sticky bit (e.g. /tmp's
            // 1777) restricts unlink to file owners, and an other-writable bit is what lets an
            // unrelated uid write. We must NOT hard-refuse merely group-writable dirs: Android's
            // standard scratch /data/local/tmp is 0771 (group `shell`, NOT other-writable), and a
            // single-user device has no co-tenant — refusing it broke koh on Android. So refuse
            // only a non-sticky other-writable dir; warn (don't refuse) on anything looser than 0700.
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
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// koh's config directory — the SINGLE place koh ever keeps files it owns. XDG-style and always
/// under `~/.config`: `$XDG_CONFIG_HOME/koh` when set, else `$HOME/.config/koh`. There is
/// deliberately no platform-specific dir (no macOS `Application Support`), no `$TMPDIR` /
/// `/data/local/tmp` / CWD fallback, and no `$KOH_STATE_DIR` override — one canonical location.
/// `None` only when neither `$XDG_CONFIG_HOME` nor `$HOME` is set (a daemon with no environment),
/// in which case the caller must pass an explicit `--key-file`. Pure over its inputs (unit-testable).
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

/// The default persistent key path for `role` (`"client"`/`"server"`) when `--key-file` isn't given.
///
/// `<config-dir>/<role>.key` under `~/.config/koh` (see [`config_dir_from`]). The dir is created 0700
/// when the key is first written (`load_or_create_secret_key`). Errors (rather than scattering a key
/// into the CWD/tmp) when `~/.config` can't be located — pass `--key-file` in that case.
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
/// Oversized state is split by the [`wire`](crate::wire) fragmenter across datagrams — never a reliable
/// stream (which would reintroduce the head-of-line blocking the protocol exists to avoid).
///
/// Architectural note (AR-04): the driver loops (`server::run_attached`, `client::drive_connection`)
/// take `&IrohChannel` **concretely**, not behind a `DatagramChannel` trait. This is deliberate: koh
/// is architected around exactly one real transport (iroh subsumes crypto/NAT/roaming/RTT/MTU), and
/// the pure `ssp::Transport` state machine — which `SimHarness` drives directly — already carries the
/// transport-agnostic protocol logic. A trait here would buy only a deterministic *loop* test double
/// (the loops are otherwise covered by real-iroh loopback e2e); it would also have to preserve the
/// typed close-reason path (`client::server_close_reason`) and could not type-enforce the
/// `read_datagram` cancel-safety the loops rely on. Extract the trait only if a second transport or
/// that loop double genuinely earns its keep — until then the concrete type is the right call.
#[derive(Clone)]
pub struct IrohChannel {
    conn: Connection,
}

impl IrohChannel {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passphrase_floor_rejects_weak_accepts_strong() {
        // The "no effectively-unencrypted key" guard: a passphrase below the minimum is a hard error
        // on every creation path, so a weak passphrase can't stand in for real encryption.
        assert!(
            enforce_passphrase_strength("").is_err(),
            "empty is rejected"
        );
        assert!(
            enforce_passphrase_strength(&"a".repeat(MIN_PASSPHRASE_CHARS - 1)).is_err(),
            "one below the floor is rejected"
        );
        assert!(
            enforce_passphrase_strength(&"a".repeat(MIN_PASSPHRASE_CHARS)).is_ok(),
            "exactly the {MIN_PASSPHRASE_CHARS}-char minimum is accepted"
        );
        assert!(enforce_passphrase_strength("correct horse battery staple").is_ok());
        // Counts characters, not bytes: (floor-1) two-byte chars is still below the floor.
        assert!(
            enforce_passphrase_strength(&"é".repeat(MIN_PASSPHRASE_CHARS - 1)).is_err(),
            "the floor counts chars, not bytes"
        );
        assert!(enforce_passphrase_strength(&"é".repeat(MIN_PASSPHRASE_CHARS)).is_ok());
    }

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
    fn secret_key_roundtrips_through_disk() {
        // Write an encrypted key and read it back through the keyfile codec. Avoids the env/TTY
        // passphrase resolution of `load_or_create_secret_key` (which would need a racy env var).
        let dir = std::env::temp_dir().join(format!("koh-key-test-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();

        let sk1 = generate_secret_key();
        write_identity_key(&path, &sk1, "test-pass").expect("write encrypted key");
        let text = std::fs::read_to_string(&path).unwrap();
        let bytes = keyfile::decrypt_key(&text, "test-pass").expect("decrypts back");
        let sk2 = SecretKey::from_bytes(&bytes);
        assert_eq!(sk1.to_bytes(), sk2.to_bytes(), "round-trips through disk");

        // The endpoint id is stable and round-trips through its string form.
        let id = sk1.public();
        let s = format_endpoint_id(&id);
        assert_eq!(parse_endpoint_id(&s).unwrap(), id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn created_key_file_is_owner_only() {
        // M-1: a written secret key must be 0600 (no group/other bits) and its parent dir must not
        // be group/other-writable — the key is the node identity, so a world-readable key is a
        // local-impersonation risk.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-key-perm-{}", std::process::id()));
        let path = dir.join("id.key");
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();

        write_identity_key(&path, &generate_secret_key(), "test-pass")
            .expect("write encrypted key");
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

    #[cfg(unix)]
    #[test]
    fn ensure_state_dir_secure_refuses_only_nonsticky_world_writable() {
        // KOH-06/KR-06: only a dir where ANOTHER user can replace the key must be refused — that is
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

    #[cfg(unix)]
    #[test]
    fn fd_key_read_does_not_follow_a_symlinked_key() {
        // K-01 / KR-06: the fd-based load (`O_NOFOLLOW`) must refuse a symlinked key path and never
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

    #[cfg(unix)]
    #[test]
    fn fd_key_read_tightens_a_loose_real_key_via_the_fd() {
        // K-01: a loose (group/other-accessible) real key is tightened to 0600 through the fd, and
        // its contents still read back. Proves the fd path both fstats and fchmods the same inode.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("koh-loose-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();
        let key = dir.join("server.key");
        std::fs::write(&key, b"deadbeef\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

        let text = read_key_file_secure(&key).expect("a loose real key still reads");
        assert_eq!(text.trim(), "deadbeef", "contents read back through the fd");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a loose key is tightened to 0600 via the fd");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_a_symlinked_key() {
        // KR-06: a symlinked key path must be refused before `read_to_string` (which would follow it
        // as a read-oracle on the target). The parent dir is 0700 so the dir check passes and we
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
    fn write_identity_key_encrypted_roundtrips_and_rejects_wrong_passphrase() {
        // The koh-key-v1 write path: storing with a passphrase produces an encrypted file that the
        // keyfile codec decrypts back to the SAME secret (endpoint id preserved), and a wrong
        // passphrase is rejected — end-to-end of the flagship without the env/TTY resolution layer.
        let dir = std::env::temp_dir().join(format!("koh-enc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_dir_private(&dir).unwrap();
        let key = dir.join("id.key");
        let sk = generate_secret_key();
        write_identity_key(&key, &sk, "correct horse").expect("write encrypted");

        let text = std::fs::read_to_string(&key).unwrap();
        assert!(
            text.starts_with("koh-key-v1"),
            "stored in the encrypted format"
        );
        let got = keyfile::decrypt_key(&text, "correct horse").expect("decrypts");
        assert_eq!(*got, sk.to_bytes(), "round-trips to the same secret");
        assert!(
            keyfile::decrypt_key(&text, "wrong").is_err(),
            "a wrong passphrase is rejected"
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
