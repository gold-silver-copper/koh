//! Names for endpoint ids, kept beside the keys.
//!
//! `servers`, the servers this machine connects to, sits beside the client key; `clients`, the
//! clients allowed to connect to it, beside the server key. Each line is `name id`, and a server's
//! may end with how to dial it, `direct=IP:PORT` or `relay=URL`, a client's with its scope
//! (`cp=DIR`, `exec=DIR`, [`Scope`]); `#` lines and blank lines are kept as they are. Both files
//! go through [`KeyFile`]'s rules, as the key does: `clients` decides who may open a shell here.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use iroh::{EndpointId, RelayUrl};

use crate::identity::KeyFile;
use crate::transport_iroh::{parse_endpoint_id, parse_relay_url};

/// Most bytes in a name.
pub const MAX_NAME: usize = 32;

/// Which list of names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum List {
    /// The servers this machine connects to (`koh connect <name>`).
    Servers,
    /// The clients allowed to connect to this machine (`koh serve`).
    Clients,
}

impl List {
    /// The list's file, beside its key.
    pub fn file(self) -> &'static str {
        match self {
            Self::Servers => "servers",
            Self::Clients => "clients",
        }
    }

    /// The key the list sits beside: a machine's servers are its client key's, its clients its
    /// server key's.
    pub fn role(self) -> &'static str {
        match self {
            Self::Servers => "client",
            Self::Clients => "server",
        }
    }

    /// One entry of the list, for messages.
    pub fn noun(self) -> &'static str {
        match self {
            Self::Servers => "server",
            Self::Clients => "client",
        }
    }
}

/// Where this machine's keys are, and so its lists.
#[derive(Debug, Clone)]
pub struct Places {
    pub client_key: PathBuf,
    pub server_key: PathBuf,
}

impl Places {
    /// The given key paths, or the default ones. With one given and no default place (no `$HOME`,
    /// as for a system service), the other is beside it, so `--key-file` alone is enough.
    pub fn new(client_key: Option<PathBuf>, server_key: Option<PathBuf>) -> anyhow::Result<Self> {
        let beside = |given: &Option<PathBuf>, role: &str| {
            given
                .as_ref()
                .map(|path| path.with_file_name(format!("{role}.key")))
        };
        let (client_beside, server_beside) =
            (beside(&server_key, "client"), beside(&client_key, "server"));
        let resolve = |key: Option<PathBuf>, beside: Option<PathBuf>, role: &str| {
            KeyFile::path_for(key, role).or_else(|error| beside.ok_or(error))
        };
        Ok(Self {
            client_key: resolve(client_key, client_beside, "client")?,
            server_key: resolve(server_key, server_beside, "server")?,
        })
    }

    /// The key path for `role` (`"client"` or `"server"`).
    pub fn key(&self, role: &str) -> &Path {
        if role == "server" {
            &self.server_key
        } else {
            &self.client_key
        }
    }

    fn key_file(&self, list: List) -> anyhow::Result<KeyFile> {
        KeyFile::open(self.key(list.role()))
    }
}

/// A list of names, with the comments and blank lines it was read with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Names {
    lines: Vec<Line>,
}

/// How a saved server is dialed, when not through iroh's discovery and n0's relays: what
/// `--direct` or `--relay-url` would say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    Direct(SocketAddr),
    Relay(RelayUrl),
}

impl Route {
    /// A route as its file holds it: `direct=IP:PORT` or `relay=URL`.
    fn parse(word: &str) -> anyhow::Result<Self> {
        match word.split_once('=') {
            Some(("direct", addr)) => addr
                .parse()
                .map(Self::Direct)
                .with_context(|| format!("bad direct address {addr:?}")),
            Some(("relay", url)) => Ok(Self::Relay(parse_relay_url(url)?)),
            _ => anyhow::bail!("expected `direct=IP:PORT` or `relay=URL`, found {word:?}"),
        }
    }
}

impl std::fmt::Display for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct(addr) => write!(f, "direct={addr}"),
            Self::Relay(url) => write!(f, "relay={url}"),
        }
    }
}

/// What a client may do on the server: everything, or only what its words name.
///
/// - `cp=DIR`: copies to and from DIR and what is in it, and nowhere else: a path is taken from
///   DIR, and none reaches out of it, by `..`, `~` or a symlink.
/// - `exec=DIR`: commands and jobs (`koh exec`, `run`, `jobs`, `logs`, `kill`, `wait` on a job or
///   for a file in DIR), started in DIR or a directory in it. A command is no sandbox: it can do
///   whatever the server user can.
///
/// A scoped client gets no shell session, no session list and no session's text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    pub cp: Option<PathBuf>,
    pub exec: Option<PathBuf>,
}

impl Scope {
    /// Whether the client may do everything.
    pub const fn is_full(&self) -> bool {
        self.cp.is_none() && self.exec.is_none()
    }

    /// A directory a scope names: absolute, holding no whitespace or `..`.
    pub fn dir(text: &str) -> anyhow::Result<PathBuf> {
        let path = PathBuf::from(text);
        anyhow::ensure!(
            path.is_absolute()
                && !text.contains(char::is_whitespace)
                && !path
                    .components()
                    .any(|c| c == std::path::Component::ParentDir),
            "a scope's directory is an absolute path with no spaces or `..`, not {text:?}"
        );
        Ok(path)
    }

    /// Add the word `word` (`cp=DIR` or `exec=DIR`), refused if it is another or said twice.
    fn take(&mut self, word: &str) -> anyhow::Result<()> {
        let (slot, dir) = match word.split_once('=') {
            Some(("cp", dir)) => (&mut self.cp, dir),
            Some(("exec", dir)) => (&mut self.exec, dir),
            _ => anyhow::bail!("expected `cp=DIR` or `exec=DIR`, found {word:?}"),
        };
        anyhow::ensure!(slot.is_none(), "{word:?} is said twice");
        *slot = Some(Self::dir(dir)?);
        Ok(())
    }
}

impl std::fmt::Display for Scope {
    /// The scope as the file holds it, each word after a space.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(dir) = &self.cp {
            write!(f, " cp={}", dir.display())?;
        }
        if let Some(dir) = &self.exec {
            write!(f, " exec={}", dir.display())?;
        }
        Ok(())
    }
}

/// A saved name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub id: EndpointId,
    /// How to dial it, for a server saved with one.
    pub route: Option<Route>,
    /// What it may do, for a client.
    pub scope: Scope,
}

impl std::fmt::Display for Entry {
    /// The entry as its file holds it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.name, self.id)?;
        if let Some(route) = &self.route {
            write!(f, " {route}")?;
        }
        write!(f, "{}", self.scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Line {
    Entry(Entry),
    /// A comment or a blank line, kept as written.
    Other(String),
}

impl Names {
    /// Parse `text`, the contents of `file` (for errors), a `list`. A line that is neither a
    /// comment, blank, nor `name id` with a good name and id (and for a server, perhaps a route)
    /// is an error naming the file and the line.
    pub fn parse(text: &str, file: &str, list: List) -> anyhow::Result<Self> {
        let mut names = Self::default();
        for (number, line) in (1_usize..).zip(text.lines()) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                names.lines.push(Line::Other(line.to_owned()));
                continue;
            }
            let at = || format!("{file}, line {number}");
            let mut words = trimmed.split_whitespace();
            let expected = match list {
                List::Servers => "`name id`, or `name id direct=IP:PORT` or `name id relay=URL`",
                List::Clients => "`name id`, then perhaps `cp=DIR` and `exec=DIR`",
            };
            let (Some(name), Some(id)) = (words.next(), words.next()) else {
                anyhow::bail!("{}: expected {expected}, found {trimmed:?}", at());
            };
            check_name(name).with_context(at)?;
            let id = parse_endpoint_id(id).with_context(at)?;
            let (mut route, mut scope) = (None, Scope::default());
            for word in words {
                match list {
                    List::Servers if route.is_none() => {
                        route = Some(Route::parse(word).with_context(at)?);
                    }
                    List::Servers => {
                        anyhow::bail!("{}: expected {expected}, found {trimmed:?}", at())
                    }
                    List::Clients => scope.take(word).with_context(at)?,
                }
            }
            if names.get(name).is_some() {
                anyhow::bail!("{}: {name:?} is named twice", at());
            }
            names.lines.push(Line::Entry(Entry {
                name: name.to_owned(),
                id,
                route,
                scope,
            }));
        }
        Ok(names)
    }

    /// The list as its file holds it.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::new();
        for line in &self.lines {
            let _ = match line {
                Line::Entry(entry) => writeln!(text, "{entry}"),
                Line::Other(other) => writeln!(text, "{other}"),
            };
        }
        text
    }

    /// Every entry, in the file's order.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.lines.iter().filter_map(|line| match line {
            Line::Entry(entry) => Some(entry),
            Line::Other(_) => None,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.entries().next().is_none()
    }

    /// The entry saved under `name`.
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries().find(|entry| entry.name == name)
    }

    /// The name `id` is saved under.
    pub fn name_of(&self, id: EndpointId) -> Option<&str> {
        self.entries()
            .find(|entry| entry.id == id)
            .map(|entry| entry.name.as_str())
    }

    /// Save `id` as `name`, dialed by `route` if given, scoped to `scope`: refused if the name is
    /// taken or the id is saved under another name.
    pub fn add(
        &mut self,
        name: &str,
        id: EndpointId,
        route: Option<Route>,
        scope: Scope,
    ) -> anyhow::Result<()> {
        check_name(name)?;
        if self.get(name).is_some() {
            anyhow::bail!("{name:?} is already saved; remove or rename it first");
        }
        if let Some(other) = self.name_of(id) {
            anyhow::bail!("{id} is already saved as {other:?}");
        }
        self.lines.push(Line::Entry(Entry {
            name: name.to_owned(),
            id,
            route,
            scope,
        }));
        Ok(())
    }

    /// Forget `name`, and return its id.
    pub fn remove(&mut self, name: &str) -> anyhow::Result<EndpointId> {
        let id = self.get(name).with_context(|| self.unknown(name))?.id;
        self.lines
            .retain(|line| !matches!(line, Line::Entry(entry) if entry.name == name));
        Ok(id)
    }

    /// Save `old`'s id as `new` instead.
    pub fn rename(&mut self, old: &str, new: &str) -> anyhow::Result<()> {
        check_name(new)?;
        if self.get(new).is_some() {
            anyhow::bail!("{new:?} is already saved");
        }
        let unknown = self.unknown(old);
        let entry = self
            .lines
            .iter_mut()
            .find_map(|line| match line {
                Line::Entry(entry) if entry.name == old => Some(&mut entry.name),
                Line::Entry(_) | Line::Other(_) => None,
            })
            .context(unknown)?;
        new.clone_into(entry);
        Ok(())
    }

    /// The error for a name that is not saved, listing those that are.
    fn unknown(&self, name: &str) -> String {
        let saved: Vec<&str> = self.entries().map(|entry| entry.name.as_str()).collect();
        if saved.is_empty() {
            format!("{name:?} is not saved, and nothing is")
        } else {
            format!("{name:?} is not saved; saved: {}", saved.join(", "))
        }
    }
}

/// A name: 1 to [`MAX_NAME`] letters, digits, `-`, `_` or `.`, not starting with `-` (it would read
/// as a flag), and never something that reads as an endpoint id.
pub fn check_name(name: &str) -> anyhow::Result<()> {
    let good = !name.is_empty()
        && name.len() <= MAX_NAME
        && !name.starts_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
    anyhow::ensure!(
        good,
        "{name:?} is not a name: use 1 to {MAX_NAME} letters, digits, '-', '_' or '.', not \
         starting with '-'"
    );
    anyhow::ensure!(
        parse_endpoint_id(name).is_err(),
        "{name:?} reads as an endpoint id, so it cannot be a name"
    );
    Ok(())
}

/// `id` shortened for a list: its first and last four characters.
pub fn short(id: EndpointId) -> String {
    // Hex, so every character is a byte.
    let id = id.to_string();
    let tail = id.len().saturating_sub(4);
    format!(
        "{}…{}",
        id.get(..4).unwrap_or(""),
        id.get(tail..).unwrap_or("")
    )
}

/// The list `list`, empty if its file does not exist.
pub fn load(places: &Places, list: List) -> anyhow::Result<Names> {
    read(&places.key_file(list)?, list, &shown(places, list))
}

/// The list `list` beside `key`, empty if its file does not exist; `shown` names it in errors.
pub fn read(key: &KeyFile, list: List, shown: &str) -> anyhow::Result<Names> {
    let text = key.read_beside(list.file())?;
    Names::parse(text.as_deref().unwrap_or(""), shown, list)
}

/// Change the list `list` with `change`, which sees it as it is on disk now; another koh's change
/// made meanwhile is never lost, as the directory is locked throughout. What `change` returns is
/// returned.
pub fn update<T>(
    places: &Places,
    list: List,
    change: impl FnOnce(&mut Names) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let key = places.key_file(list)?;
    let file = shown(places, list);
    let mut out = None;
    key.update_beside(list.file(), |text| {
        let mut names = Names::parse(text.as_deref().unwrap_or(""), &file, list)?;
        out = Some(change(&mut names)?);
        Ok(Some(names.render()))
    })?;
    out.context("internal error: the list was not changed")
}

/// What `koh servers` or `koh clients` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Print the list, one entry a line, as the file holds it.
    List,
    Add {
        name: String,
        id: EndpointId,
        /// How to dial it: only a server has one.
        route: Option<Route>,
        /// What it may do: only a client has one.
        scope: Scope,
    },
    Remove {
        name: String,
    },
    Rename {
        old: String,
        new: String,
    },
}

/// Run `koh servers` or `koh clients`, saying what was done to `out`.
pub fn run(
    places: &Places,
    list: List,
    op: Op,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let file = shown(places, list);
    match op {
        Op::List => {
            let names = load(places, list)?;
            if names.is_empty() {
                writeln!(
                    out,
                    "no {}s saved in {file}; add one with `koh {} add <name> <id>`",
                    list.noun(),
                    list.file()
                )?;
            }
            for entry in names.entries() {
                writeln!(out, "{entry}")?;
            }
        }
        Op::Add {
            name,
            id,
            route,
            scope,
        } => {
            let dialed = route
                .as_ref()
                .map_or_else(String::new, |route| format!(", {route}"));
            let scoped = scope.to_string();
            let scoped = if scoped.is_empty() {
                String::new()
            } else {
                format!(", scoped to{scoped}")
            };
            let dialed = format!("{dialed}{scoped}");
            update(places, list, |names| names.add(&name, id, route, scope))?;
            writeln!(
                out,
                "saved {} {name} ({}{dialed}) in {file}",
                list.noun(),
                short(id)
            )?;
        }
        Op::Remove { name } => {
            let id = update(places, list, |names| names.remove(&name))?;
            writeln!(
                out,
                "removed {} {name} ({}) from {file}",
                list.noun(),
                short(id)
            )?;
        }
        Op::Rename { old, new } => {
            update(places, list, |names| names.rename(&old, &new))?;
            writeln!(out, "renamed {} {old} to {new} in {file}", list.noun())?;
        }
    }
    Ok(())
}

/// The list's path, for messages.
pub fn shown(places: &Places, list: List) -> String {
    places
        .key(list.role())
        .with_file_name(list.file())
        .display()
        .to_string()
}

#[cfg(test)]
pub(crate) mod tests;
