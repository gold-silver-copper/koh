//! Delta file sync using blake3 hashes: manifest diff, chunked transfer,
//! `--delete`, `--exclude` globs, `-p` mtime preservation, and `--dry-run`.
//!
//! A path a peer names is plain names beneath the tree: that is told by its text, and it is all
//! that is told. The tree is what the file system says it is. A symlink in a tree that is read
//! is not sent, and `--delete` leaves it; one in the tree a copy lands in is a directory like
//! any other, and a file that lands where one is takes its place.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use iroh::endpoint::{RecvStream, SendStream};
use serde::Serialize;

use crate::proto::{MAX_CHUNK, MAX_CTRL, SyncEntry, SyncMsg, SyncSummary, recv_msg, send_msg};
use crate::{KohError, Result};

/// Most entries a tree may hold, on either end.
pub const MAX_FILES: usize = 100_000;
/// Most directories an entry may be beneath its tree: its path there has that many names and its own.
/// (Both ends count the names of the path as it is sent, so they agree on what is too deep.)
const MAX_DEPTH: usize = 128;
const CHUNK_SIZE: usize = 64 << 10;

/// Simple glob matcher supporting `*`, `?`, and `**` against relative paths and basenames.
pub fn matches_exclude(rel: &str, patterns: &[String]) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    patterns.iter().any(|pat| {
        let pat = pat.trim_end_matches('/');
        if pat.contains('/') {
            glob_match(pat.as_bytes(), rel.as_bytes())
        } else {
            glob_match(pat.as_bytes(), base.as_bytes())
                || rel
                    .split('/')
                    .any(|seg| glob_match(pat.as_bytes(), seg.as_bytes()))
        }
    })
}

fn glob_match(pat: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star_p, mut star_t) = (None::<usize>, 0usize);
    while t < text.len() {
        match pat.get(p).copied() {
            Some(b'*') => {
                star_p = Some(p);
                star_t = t;
                p += 1;
            }
            Some(b'?') => {
                p += 1;
                t += 1;
            }
            Some(c) if Some(c) == text.get(t).copied() => {
                p += 1;
                t += 1;
            }
            _ => {
                if let Some(sp) = star_p {
                    p = sp + 1;
                    star_t += 1;
                    t = star_t;
                } else {
                    return false;
                }
            }
        }
    }
    while pat.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pat.len()
}

/// Whether `name` is one plain name: not empty, `.` or `..`, with no `/` or NUL.
fn plain(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\0'])
}

/// The names of the wire path `rel`: a path beneath a tree, and nothing else. Each is one plain
/// name, and there are at most 129: an entry's own, and those of the 128 directories it may be
/// beneath.
pub fn wire_names(rel: &str) -> Result<Vec<&str>> {
    let names: Vec<&str> = rel.split('/').collect();
    if names.len() > MAX_DEPTH + 1 || !names.iter().all(|name| plain(name)) {
        return Err(KohError::refused(format!("unsafe relative path {rel:?}")));
    }
    Ok(names)
}

/// Where the wire path `rel` is beneath `root`.
fn beneath(root: &Path, rel: &str) -> Result<PathBuf> {
    wire_names(rel)?;
    Ok(root.join(rel))
}

/// A file written under a name of its own beside where it lands: removed unless it lands.
struct Temp {
    path: PathBuf,
    landed: bool,
}

impl Temp {
    /// A file beside `target`, under a name no other copy writes to.
    fn create(target: &Path) -> Result<(File, Self)> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nth = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = target.with_file_name(format!(".koh-{:x}-{nth:x}.tmp", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| KohError::failed(format!("create {}: {e}", path.display())))?;
        let temp = Self {
            path,
            landed: false,
        };
        Ok((file, temp))
    }

    /// Give it the name it lands under: whatever was there goes.
    fn land(mut self, target: &Path) -> Result<()> {
        fs::rename(&self.path, target)
            .map_err(|e| KohError::failed(format!("rename {}: {e}", target.display())))?;
        self.landed = true;
        Ok(())
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        if !self.landed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn entry(path: String, meta: &fs::Metadata, hash: [u8; 32]) -> SyncEntry {
    SyncEntry {
        path,
        size: if meta.is_dir() { 0 } else { meta.len() },
        mtime_secs: meta.mtime(),
        mode: meta.permissions().mode() & 0o777,
        hash,
        is_dir: meta.is_dir(),
    }
}

fn open(path: &Path) -> Result<File> {
    File::open(path).map_err(|e| KohError::failed(format!("open {}: {e}", path.display())))
}

fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 32 << 10];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| KohError::failed(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        if let Some(slice) = buf.get(..n) {
            hasher.update(slice);
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

/// The directories and regular files beneath `rel` of `root`, into `out`: an entry that is
/// neither (a symlink, to whatever) is not one and is not entered. With `hash`, each file's
/// blake3. `depth` is how many names the path of the directory has as it is sent: an entry in a
/// directory that is itself as deep as an entry may be is too deep, and the tree is not read
/// further.
fn scan(
    root: &Path,
    rel: &str,
    prefix: Option<&str>,
    excludes: &[String],
    hash: bool,
    depth: usize,
    out: &mut Vec<SyncEntry>,
) -> Result<()> {
    let dir = root.join(rel);
    let failed = |e| KohError::failed(format!("read_dir {}: {e}", dir.display()));
    let mut names = Vec::new();
    for item in fs::read_dir(&dir).map_err(failed)? {
        if let Ok(name) = item.map_err(failed)?.file_name().into_string() {
            names.push(name);
        }
    }
    names.sort();
    for name in names {
        let child = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        if matches_exclude(&child, excludes) {
            continue;
        }
        let full = root.join(&child);
        let Ok(meta) = fs::symlink_metadata(&full) else {
            continue;
        };
        if !meta.is_dir() && !meta.is_file() {
            continue;
        }
        if depth > MAX_DEPTH {
            return Err(KohError::failed(format!(
                "{child}: more than {MAX_DEPTH} directories deep"
            )));
        }
        if out.len() >= MAX_FILES {
            return Err(KohError::failed("tree exceeds maximum file count (100000)"));
        }
        let wire = match prefix {
            Some(p) => format!("{p}/{child}"),
            None => child.clone(),
        };
        let sum = if hash && meta.is_file() {
            hash_file(&full)?
        } else {
            [0u8; 32]
        };
        out.push(entry(wire, &meta, sum));
        if meta.is_dir() {
            scan(root, &child, prefix, excludes, hash, depth + 1, out)?;
        }
    }
    Ok(())
}

/// The sorted blake3 manifest of the file or directory `root` (`meta` is its own), and the name
/// its paths are prefixed with: with `preserve_root` a directory's own, so several directories
/// can share one destination.
fn manifest(
    root: &Path,
    meta: &fs::Metadata,
    excludes: &[String],
    preserve_root: bool,
) -> Result<(Vec<SyncEntry>, Option<String>)> {
    let name = root.file_name().and_then(|n| n.to_str());
    let mut entries = Vec::new();
    if meta.is_file() {
        let name = name.ok_or_else(|| KohError::usage("invalid filename"))?;
        entries.push(entry(name.to_string(), meta, hash_file(root)?));
        return Ok((entries, None));
    }
    if !meta.is_dir() {
        return Err(KohError::usage(format!(
            "{} is neither file nor directory",
            root.display()
        )));
    }
    let prefix = if preserve_root {
        let name = name.ok_or_else(|| KohError::usage("cannot determine the directory's name"))?;
        entries.push(entry(name.to_string(), meta, [0u8; 32]));
        Some(name.to_string())
    } else {
        None
    };
    let depth = usize::from(prefix.is_some());
    scan(
        root,
        "",
        prefix.as_deref(),
        excludes,
        true,
        depth,
        &mut entries,
    )?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((entries, prefix))
}

/// What the peer said went wrong, if that is why sending to it failed.
async fn peer_failure(recv: &mut RecvStream) -> Option<KohError> {
    let said = recv_msg::<SyncMsg>(recv, MAX_CTRL * 4);
    match tokio::time::timeout(Duration::from_secs(2), said).await {
        Ok(Ok(SyncMsg::Failed(err))) => Some(err.into()),
        _ => None,
    }
}

async fn send_file_msg<T: Serialize>(
    send: &mut SendStream,
    recv: &mut RecvStream,
    msg: &T,
    max: usize,
) -> Result<()> {
    match send_msg(send, msg, max).await {
        Ok(()) => Ok(()),
        Err(err) => Err(peer_failure(recv).await.unwrap_or(err)),
    }
}

/// Sender half of delta sync: sends manifest, streams only requested files, receives summary.
pub async fn send_tree(
    root: &Path,
    excludes: &[String],
    preserve_root: bool,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SyncSummary> {
    let meta = fs::metadata(root)
        .map_err(|e| KohError::failed(format!("stat {}: {e}", root.display())))?;
    let (manifest, prefix) = manifest(root, &meta, excludes, preserve_root)?;
    let files: BTreeMap<String, SyncEntry> = manifest
        .iter()
        .filter(|e| !e.is_dir)
        .cloned()
        .map(|e| (e.path.clone(), e))
        .collect();
    send_msg(send, &SyncMsg::Manifest(manifest), MAX_CTRL * 8).await?;

    let needed = match recv_msg(recv, MAX_CTRL * 4).await? {
        SyncMsg::Need(needed) => needed,
        SyncMsg::Failed(err) => return Err(err.into()),
        _ => return Err(KohError::failed("expected Need message from receiver")),
    };
    let mut buf = vec![0u8; CHUNK_SIZE];
    for rel in needed {
        // (Only what the manifest holds is sent: a path this end read from its own tree.)
        let Some(entry) = files.get(&rel) else {
            continue;
        };
        let path = match prefix.as_deref() {
            _ if meta.is_file() => root.to_path_buf(),
            Some(prefix) => root.join(
                rel.strip_prefix(prefix)
                    .and_then(|s| s.strip_prefix('/'))
                    .ok_or_else(|| {
                        KohError::refused(format!("unexpected prefixed path {rel:?}"))
                    })?,
            ),
            None => root.join(&rel),
        };
        let mut file = open(&path)?;
        let start = SyncMsg::FileStart {
            path: rel.clone(),
            size: entry.size,
            mtime_secs: entry.mtime_secs,
            mode: entry.mode,
        };
        send_file_msg(send, recv, &start, MAX_CTRL).await?;
        loop {
            let n = file
                .read(&mut buf)
                .map_err(|e| KohError::failed(format!("read {}: {e}", path.display())))?;
            if n == 0 {
                break;
            }
            if let Some(slice) = buf.get(..n) {
                let chunk = SyncMsg::FileChunk(slice.to_vec());
                send_file_msg(send, recv, &chunk, MAX_CHUNK).await?;
            }
        }
        send_file_msg(send, recv, &SyncMsg::FileEnd, MAX_CTRL).await?;
    }
    match recv_msg(recv, MAX_CTRL * 4).await? {
        SyncMsg::Summary(summary) => Ok(summary),
        SyncMsg::Failed(err) => Err(err.into()),
        _ => Err(KohError::failed("expected Summary from receiver")),
    }
}

/// Receiver half of delta sync: diffs manifest against the tree at `dst`, requests changed
/// files, applies updates.
pub async fn receive_tree(
    dst: &Path,
    excludes: &[String],
    delete: bool,
    preserve_mtime: bool,
    dry_run: bool,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SyncSummary> {
    let src_entries = match recv_msg(recv, MAX_CTRL * 8).await? {
        SyncMsg::Manifest(entries) => entries,
        SyncMsg::Failed(err) => return Err(err.into()),
        _ => return Err(KohError::failed("expected Manifest from sender")),
    };
    if src_entries.len() > MAX_FILES {
        return Err(KohError::refused(format!(
            "manifest exceeds maximum file count ({MAX_FILES})"
        )));
    }
    let mut summary = SyncSummary {
        dry_run,
        ..SyncSummary::default()
    };
    let mut needed = Vec::new();
    let mut src_set = BTreeSet::new();
    let mkdir = |dir: &Path| {
        fs::create_dir_all(dir)
            .map_err(|e| KohError::failed(format!("mkdir {}: {e}", dir.display())))
    };
    // In a dry run nothing is made: a destination that is not there holds nothing.
    if !dry_run {
        mkdir(dst)?;
    }

    for entry in &src_entries {
        let target = beneath(dst, &entry.path)?;
        src_set.insert(entry.path.clone());
        if entry.is_dir {
            if !dry_run {
                mkdir(&target)?;
            }
            continue;
        }
        match fs::metadata(&target).ok().filter(|m| m.is_file()) {
            // (A file of another size differs, and need not be read to know.)
            Some(there) if there.len() == entry.size && hash_file(&target)? == entry.hash => {
                summary.unchanged += 1;
                continue;
            }
            Some(_) => summary.updated.push(entry.path.clone()),
            None => summary.added.push(entry.path.clone()),
        }
        needed.push(entry.path.clone());
    }

    if delete && dst.is_dir() {
        let mut local = Vec::new();
        scan(dst, "", None, excludes, false, 0, &mut local)?;
        local.sort_by(|a, b| a.path.cmp(&b.path));
        for local in local.into_iter().rev() {
            if src_set.contains(&local.path) {
                continue;
            }
            if !dry_run {
                let target = dst.join(&local.path);
                let _ = if local.is_dir {
                    fs::remove_dir(target)
                } else {
                    fs::remove_file(target)
                };
            }
            summary.deleted.push(local.path);
        }
    }

    if dry_run {
        send_msg(send, &SyncMsg::Need(Vec::new()), MAX_CTRL).await?;
        send_msg(send, &SyncMsg::Summary(summary.clone()), MAX_CTRL * 4).await?;
        return Ok(summary);
    }

    send_msg(send, &SyncMsg::Need(needed.clone()), MAX_CTRL * 4).await?;
    let mut wanted: BTreeSet<String> = needed.into_iter().collect();
    while !wanted.is_empty() {
        let (path, size, mtime_secs, mode) = match recv_msg(recv, MAX_CTRL).await? {
            SyncMsg::FileStart {
                path,
                size,
                mtime_secs,
                mode,
            } => (path, size, mtime_secs, mode),
            SyncMsg::Failed(err) => return Err(err.into()),
            _ => return Err(KohError::failed("expected FileStart")),
        };
        if !wanted.remove(&path) {
            return Err(KohError::refused(format!(
                "{path:?} was sent but not asked for"
            )));
        }
        let target = beneath(dst, &path)?;
        if let Some(parent) = target.parent() {
            mkdir(parent)?;
        }
        let (mut out, temp) = Temp::create(&target)?;
        let mut written = 0u64;
        loop {
            match recv_msg(recv, MAX_CHUNK).await? {
                SyncMsg::FileChunk(bytes) => {
                    written += bytes.len() as u64;
                    if written > size {
                        break;
                    }
                    out.write_all(&bytes)
                        .map_err(|e| KohError::failed(format!("write {path}: {e}")))?;
                }
                SyncMsg::FileEnd => break,
                SyncMsg::Failed(err) => return Err(err.into()),
                _ => return Err(KohError::failed("unexpected message during file transfer")),
            }
        }
        if written != size {
            return Err(KohError::failed(format!(
                "size mismatch on {path} ({written} != {size})"
            )));
        }
        let perms = fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o755 } else { 0o644 });
        let _ = out.set_permissions(perms);
        if preserve_mtime {
            let since = Duration::from_secs(mtime_secs.unsigned_abs());
            let at = if mtime_secs < 0 {
                UNIX_EPOCH.checked_sub(since)
            } else {
                UNIX_EPOCH.checked_add(since)
            };
            if let Some(at) = at {
                let _ = out.set_modified(at);
            }
        }
        drop(out);
        temp.land(&target)?;
        summary.bytes_transferred += written;
    }

    send_msg(send, &SyncMsg::Summary(summary.clone()), MAX_CTRL * 4).await?;
    Ok(summary)
}
