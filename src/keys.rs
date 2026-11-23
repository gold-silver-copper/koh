//! Identity keys, peer lists (`servers` and `clients`), scoped authorization,
//! and QR rendering — compatible with existing `~/.config/koh/` files.

use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::net::SocketAddr;
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Component, Path, PathBuf};

use iroh::{EndpointId, RelayUrl, SecretKey};
use qrcode::{QrCode, render::unicode};

use crate::{Exit, KohError, Result, atomic_write, is_safe_name};

const KEY_LEN: usize = 32;

/// Role of an identity key (`client.key` or `server.key`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub fn file(self) -> &'static str {
        match self {
            Self::Client => "client.key",
            Self::Server => "server.key",
        }
    }

    pub fn list_file(self) -> &'static str {
        match self {
            Self::Client => "servers",
            Self::Server => "clients",
        }
    }
}

/// Optional route attached to a saved server in `servers`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    Direct(SocketAddr),
    Relay(RelayUrl),
}

/// Optional scope restricting an allowed client key in `clients`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Full,
    Cp(PathBuf),
    Exec(PathBuf),
}

impl Scope {
    /// Checks whether a path is allowed for copy operations under this scope.
    pub fn check_cp(&self, target: &Path) -> Result<()> {
        match self {
            Self::Full => Ok(()),
            Self::Cp(root) | Self::Exec(root) => check_beneath(root, target),
        }
    }

    /// Checks whether a working directory is allowed for exec/run under this scope.
    pub fn check_exec(&self, cwd: &Path) -> Result<()> {
        match self {
            Self::Full => Ok(()),
            Self::Exec(root) => check_beneath(root, cwd),
            Self::Cp(_) => Err(KohError::refused("key scope allows only cp")),
        }
    }

    /// Interactive sessions and arbitrary jobs require Full scope.
    pub fn check_full(&self) -> Result<()> {
        match self {
            Self::Full => Ok(()),
            _ => Err(KohError::refused("key scope does not allow this operation")),
        }
    }
}

/// Whether `target` says, by its text, that it is beneath the scope's directory `root`: it
/// starts with that directory's path (as the `clients` file has it, or resolved) and goes on
/// with plain names, none of them `..`. Nothing of `target` is resolved: a symlink beneath
/// `root` leads where it leads.
fn check_beneath(root: &Path, target: &Path) -> Result<()> {
    let root = expand_home(root)?;
    let base = root
        .canonicalize()
        .map_err(|e| KohError::refused(format!("scope root {}: {e}", root.display())))?;
    let beneath = |dir: &Path| {
        target
            .strip_prefix(dir)
            .is_ok_and(|rest| rest.components().all(|c| matches!(c, Component::Normal(_))))
    };
    if beneath(&root) || beneath(&base) {
        Ok(())
    } else {
        Err(KohError::refused(format!(
            "path {} is outside allowed scope {}",
            target.display(),
            base.display()
        )))
    }
}

#[derive(Clone, Debug)]
pub struct ServerEntry {
    pub name: String,
    pub id: EndpointId,
    pub route: Option<Route>,
}

#[derive(Clone, Debug)]
pub struct ClientEntry {
    pub name: String,
    pub id: EndpointId,
    pub scope: Scope,
}

/// Default config directory (`$KOH_CONFIG_DIR`, else `$XDG_CONFIG_HOME/koh`, else `$HOME/.config/koh`).
pub fn config_dir(key_file: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = key_file {
        return p
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .ok_or_else(|| KohError::usage("invalid --key-file path"));
    }
    if let Ok(dir) = std::env::var("KOH_CONFIG_DIR")
        && !dir.is_empty()
    {
        return Ok(PathBuf::from(dir));
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return Ok(PathBuf::from(xdg).join("koh"));
    }
    Ok(home_dir()?.join(".config").join("koh"))
}

pub fn home_dir() -> Result<PathBuf> {
    std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| KohError::failed("HOME is not set"))
}

pub fn expand_home(path: &Path) -> Result<PathBuf> {
    let s = path.to_string_lossy();
    if s == "~" {
        return home_dir();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        return Ok(home_dir()?.join(rest));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(home_dir()?.join(path))
    }
}

pub fn key_path(role: Role, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    Ok(config_dir(None)?.join(role.file()))
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| KohError::failed(format!("cannot create {}: {e}", dir.display())))?;
    let meta =
        fs::metadata(dir).map_err(|e| KohError::failed(format!("stat {}: {e}", dir.display())))?;
    let uid = rustix::process::geteuid().as_raw();
    if meta.uid() != uid {
        return Err(KohError::refused(format!(
            "{} is owned by another user",
            dir.display()
        )));
    }
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(KohError::refused(format!(
            "{} is writable by group or others; run chmod 700",
            dir.display()
        )));
    }
    Ok(())
}

/// Loads or creates a 32-byte Ed25519 identity key with `0600` permissions (refusing symlinks).
pub fn load_or_create_key(role: Role, explicit: Option<&Path>) -> Result<SecretKey> {
    let path = key_path(role, explicit)?;
    let parent = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| KohError::usage("invalid key path"))?;
    ensure_private_dir(parent)?;

    match open_nofollow(&path) {
        Ok(file) => {
            let meta = file
                .metadata()
                .map_err(|e| KohError::failed(format!("stat key: {e}")))?;
            if !meta.is_file() {
                return Err(KohError::refused("key path is not a regular file"));
            }
            if meta.permissions().mode() & 0o077 != 0 {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
            let mut buf = Vec::with_capacity(KEY_LEN + 1);
            file.take((KEY_LEN + 1) as u64)
                .read_to_end(&mut buf)
                .map_err(|e| KohError::failed(format!("read key: {e}")))?;
            let raw: [u8; KEY_LEN] = buf.try_into().map_err(|_| {
                KohError::failed(format!("{} is not a 32-byte key", path.display()))
            })?;
            Ok(SecretKey::from_bytes(&raw))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut raw = [0u8; KEY_LEN];
            File::open("/dev/urandom")
                .and_then(|mut f| f.read_exact(&mut raw))
                .map_err(|e| KohError::failed(format!("read /dev/urandom: {e}")))?;
            let key = SecretKey::from_bytes(&raw);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(|e| KohError::failed(format!("create {}: {e}", path.display())))?;
            std::io::Write::write_all(&mut f, &key.to_bytes())
                .map_err(|e| KohError::failed(format!("write {}: {e}", path.display())))?;
            Ok(key)
        }
        Err(e) => Err(KohError::failed(format!("open {}: {e}", path.display()))),
    }
}

/// Holds the server key for one server, until the file this returns is dropped (or its process
/// ends, however it ends). A second server on the key is refused: it would have the same
/// endpoint id, and each client connection would reach one or the other, each with its own jobs
/// and sessions. The lock is on a file beside the key, which stays: its being there says nothing.
pub fn hold_for_serving(explicit: Option<&Path>) -> Result<File> {
    let key = key_path(Role::Server, explicit)?;
    let name = key
        .file_name()
        .ok_or_else(|| KohError::usage("invalid key path"))?
        .to_string_lossy();
    let path = key.with_file_name(format!("{name}.serving"));
    let failed = |e: std::io::Error| KohError::failed(format!("lock {}: {e}", path.display()));
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(failed)?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(fs::TryLockError::WouldBlock) => Err(KohError::new(
            Exit::BUSY,
            "busy",
            format!(
                "another koh server is serving with the key {}: stop that one, or give this one \
                 a key of its own (--key-file)",
                key.display()
            ),
        )),
        Err(fs::TryLockError::Error(e)) => Err(failed(e)),
    }
}

pub fn reset_key(role: Role, explicit: Option<&Path>) -> Result<()> {
    let path = key_path(role, explicit)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(KohError::failed(format!("remove {}: {e}", path.display()))),
    }
}

fn open_nofollow(path: &Path) -> std::io::Result<File> {
    #[cfg(target_os = "linux")]
    const O_NOFOLLOW: i32 = 0o400_000;
    #[cfg(target_os = "macos")]
    const O_NOFOLLOW: i32 = 0x0100;
    OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
}

pub fn parse_endpoint_id(s: &str) -> Result<EndpointId> {
    s.parse::<EndpointId>()
        .map_err(|e| KohError::usage(format!("invalid endpoint id {s:?}: {e}")))
}

pub fn parse_relay_url(s: &str) -> Result<RelayUrl> {
    s.parse::<RelayUrl>()
        .map_err(|e| KohError::usage(format!("invalid relay url {s:?}: {e}")))
}

/// Loads saved `servers` list beside `client.key`.
pub fn load_servers(key_file: Option<&Path>) -> Result<Vec<ServerEntry>> {
    let path = config_dir(key_file)?.join(Role::Client.list_file());
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(KohError::failed(format!("read {}: {e}", path.display()))),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let (Some(name), Some(id_str)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(id) = id_str.parse::<EndpointId>() else {
            continue;
        };
        let route = parts.next().and_then(|w| match w.split_once('=') {
            Some(("direct", addr)) => addr.parse().ok().map(Route::Direct),
            Some(("relay", url)) => url.parse().ok().map(Route::Relay),
            _ => None,
        });
        out.push(ServerEntry {
            name: name.to_string(),
            id,
            route,
        });
    }
    Ok(out)
}

pub fn save_servers(key_file: Option<&Path>, entries: &[ServerEntry]) -> Result<()> {
    let dir = config_dir(key_file)?;
    ensure_private_dir(&dir)?;
    let mut text = String::new();
    for e in entries {
        text.push_str(&e.name);
        text.push(' ');
        text.push_str(&e.id.to_string());
        match &e.route {
            Some(Route::Direct(addr)) => text.push_str(&format!(" direct={addr}")),
            Some(Route::Relay(url)) => text.push_str(&format!(" relay={url}")),
            None => {}
        }
        text.push('\n');
    }
    atomic_write(&dir.join(Role::Client.list_file()), text.as_bytes())
        .map_err(|e| KohError::failed(format!("write servers: {e}")))
}

/// Loads allowed `clients` list beside `server.key`.
pub fn load_clients(key_file: Option<&Path>) -> Result<Vec<ClientEntry>> {
    let path = config_dir(key_file)?.join(Role::Server.list_file());
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(KohError::failed(format!("read {}: {e}", path.display()))),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let (Some(name), Some(id_str)) = (parts.next(), parts.next()) else {
            continue;
        };
        let Ok(id) = id_str.parse::<EndpointId>() else {
            continue;
        };
        let scope = match parts.next().and_then(|w| w.split_once('=')) {
            Some(("cp", dir)) => Scope::Cp(PathBuf::from(dir)),
            Some(("exec", dir)) => Scope::Exec(PathBuf::from(dir)),
            _ => Scope::Full,
        };
        out.push(ClientEntry {
            name: name.to_string(),
            id,
            scope,
        });
    }
    Ok(out)
}

pub fn save_clients(key_file: Option<&Path>, entries: &[ClientEntry]) -> Result<()> {
    let dir = config_dir(key_file)?;
    ensure_private_dir(&dir)?;
    let mut text = String::new();
    for e in entries {
        text.push_str(&e.name);
        text.push(' ');
        text.push_str(&e.id.to_string());
        match &e.scope {
            Scope::Full => {}
            Scope::Cp(dir) => text.push_str(&format!(" cp={}", dir.display())),
            Scope::Exec(dir) => text.push_str(&format!(" exec={}", dir.display())),
        }
        text.push('\n');
    }
    atomic_write(&dir.join(Role::Server.list_file()), text.as_bytes())
        .map_err(|e| KohError::failed(format!("write clients: {e}")))
}

/// Resolves a server target (`<saved-name>` or raw `<endpoint-id>`) and merges CLI route overrides.
pub fn resolve_server(
    target: &str,
    key_file: Option<&Path>,
    direct: Option<SocketAddr>,
    relay: Option<RelayUrl>,
) -> Result<(EndpointId, Option<Route>)> {
    let saved = load_servers(key_file)?;
    let (id, saved_route) = if let Some(entry) = saved.into_iter().find(|e| e.name == target) {
        (entry.id, entry.route)
    } else {
        (parse_endpoint_id(target)?, None)
    };
    let route = direct
        .map(Route::Direct)
        .or(relay.map(Route::Relay))
        .or(saved_route);
    Ok((id, route))
}

pub fn validate_peer_name(name: &str) -> Result<()> {
    if is_safe_name(name) && name.len() <= 32 {
        Ok(())
    } else {
        Err(KohError::usage(format!("invalid name {name:?}")))
    }
}

/// Renders an endpoint ID as a compact Unicode half-block QR code for terminal display.
pub fn render_qr(id: &EndpointId) -> String {
    QrCode::new(id.to_string().as_bytes())
        .map(|code| {
            code.render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build()
        })
        .unwrap_or_default()
}
