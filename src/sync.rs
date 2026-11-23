//! Delta file sync using blake3 hashes: manifest diff, chunked transfer,
//! `--delete`, `--exclude` globs, `-p` mtime preservation, and `--dry-run`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Component, Path, PathBuf};

use iroh::endpoint::{RecvStream, SendStream};

use crate::proto::{MAX_CHUNK, MAX_CTRL, SyncEntry, SyncMsg, SyncSummary, recv_msg, send_msg};
use crate::{KohError, Result};

const MAX_FILES: usize = 100_000;
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

/// Scans a local file or directory tree into a sorted blake3 manifest.
pub fn scan_tree(root: &Path, excludes: &[String]) -> Result<Vec<SyncEntry>> {
    let meta = fs::metadata(root)
        .map_err(|e| KohError::failed(format!("stat {}: {e}", root.display())))?;
    let mut entries = Vec::new();
    if meta.is_file() {
        let name = root
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| KohError::usage("invalid filename"))?;
        entries.push(hash_file(root, name.to_string(), &meta)?);
        return Ok(entries);
    }
    if !meta.is_dir() {
        return Err(KohError::usage(format!(
            "{} is neither file nor directory",
            root.display()
        )));
    }
    walk(root, Path::new(""), excludes, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

fn walk(root: &Path, rel: &Path, excludes: &[String], out: &mut Vec<SyncEntry>) -> Result<()> {
    let dir = if rel.as_os_str().is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel)
    };
    let rd = fs::read_dir(&dir)
        .map_err(|e| KohError::failed(format!("read_dir {}: {e}", dir.display())))?;
    let mut names = Vec::new();
    for item in rd {
        let item = item.map_err(|e| KohError::failed(format!("dir entry: {e}")))?;
        names.push(item.file_name());
    }
    names.sort();
    for name in names {
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let child_rel = if rel.as_os_str().is_empty() {
            PathBuf::from(name_str)
        } else {
            rel.join(name_str)
        };
        let rel_str = child_rel.to_string_lossy().to_string();
        if matches_exclude(&rel_str, excludes) {
            continue;
        }
        let full = root.join(&child_rel);
        let meta = match fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.file_type().is_symlink() {
            continue; // Never follow symlinks across sync boundaries.
        }
        if out.len() >= MAX_FILES {
            return Err(KohError::failed("tree exceeds maximum file count (100000)"));
        }
        if meta.is_dir() {
            out.push(SyncEntry {
                path: rel_str,
                size: 0,
                mtime_secs: meta.mtime(),
                mode: meta.permissions().mode() & 0o777,
                hash: [0u8; 32],
                is_dir: true,
            });
            walk(root, &child_rel, excludes, out)?;
        } else if meta.is_file() {
            out.push(hash_file(&full, rel_str, &meta)?);
        }
    }
    Ok(())
}

fn hash_file(path: &Path, rel: String, meta: &fs::Metadata) -> Result<SyncEntry> {
    let mut f =
        File::open(path).map_err(|e| KohError::failed(format!("open {}: {e}", path.display())))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 32 << 10];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| KohError::failed(format!("read {}: {e}", path.display())))?;
        if n == 0 {
            break;
        }
        if let Some(slice) = buf.get(..n) {
            hasher.update(slice);
        }
    }
    Ok(SyncEntry {
        path: rel,
        size: meta.len(),
        mtime_secs: meta.mtime(),
        mode: meta.permissions().mode() & 0o777,
        hash: *hasher.finalize().as_bytes(),
        is_dir: false,
    })
}

/// Validates a relative wire path so it can never escape `dst_root`.
pub fn safe_join(dst_root: &Path, rel: &str) -> Result<PathBuf> {
    if rel.is_empty() || rel.starts_with('/') {
        return Err(KohError::refused(format!("unsafe relative path {rel:?}")));
    }
    let mut out = dst_root.to_path_buf();
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(part) => out.push(part),
            _ => {
                return Err(KohError::refused(format!(
                    "unsafe path component in {rel:?}"
                )));
            }
        }
    }
    Ok(out)
}

/// Sender half of delta sync: sends manifest, streams only requested files, receives summary.
pub async fn send_tree(
    root: &Path,
    excludes: &[String],
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SyncSummary> {
    let single_file = fs::metadata(root).map(|m| m.is_file()).unwrap_or(false);
    let manifest = scan_tree(root, excludes)?;
    let by_path: BTreeMap<String, SyncEntry> = manifest
        .iter()
        .cloned()
        .map(|e| (e.path.clone(), e))
        .collect();
    send_msg(send, &SyncMsg::Manifest(manifest), MAX_CTRL * 8).await?;

    let SyncMsg::Need(needed) = recv_msg(recv, MAX_CTRL * 4).await? else {
        return Err(KohError::failed("expected Need message from receiver"));
    };
    let mut buf = vec![0u8; CHUNK_SIZE];
    for rel in needed {
        let Some(entry) = by_path.get(&rel) else {
            continue;
        };
        let full = if single_file {
            root.to_path_buf()
        } else {
            safe_join(root, &rel)?
        };
        send_msg(
            send,
            &SyncMsg::FileStart {
                path: rel.clone(),
                size: entry.size,
                mtime_secs: entry.mtime_secs,
                mode: entry.mode,
            },
            MAX_CTRL,
        )
        .await?;
        let mut f = File::open(&full)
            .map_err(|e| KohError::failed(format!("open {}: {e}", full.display())))?;
        loop {
            let n = f
                .read(&mut buf)
                .map_err(|e| KohError::failed(format!("read {}: {e}", full.display())))?;
            if n == 0 {
                break;
            }
            if let Some(slice) = buf.get(..n) {
                send_msg(send, &SyncMsg::FileChunk(slice.to_vec()), MAX_CHUNK).await?;
            }
        }
        send_msg(send, &SyncMsg::FileEnd, MAX_CTRL).await?;
    }
    let SyncMsg::Summary(summary) = recv_msg(recv, MAX_CTRL * 4).await? else {
        return Err(KohError::failed("expected Summary from receiver"));
    };
    Ok(summary)
}

/// Receiver half of delta sync: diffs manifest against `dst_root`, requests changed files, applies updates.
pub async fn receive_tree(
    dst_root: &Path,
    excludes: &[String],
    delete: bool,
    preserve_mtime: bool,
    dry_run: bool,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<SyncSummary> {
    let SyncMsg::Manifest(src_entries) = recv_msg(recv, MAX_CTRL * 8).await? else {
        return Err(KohError::failed("expected Manifest from sender"));
    };
    let mut summary = SyncSummary {
        dry_run,
        ..SyncSummary::default()
    };
    let mut needed = Vec::new();
    let mut src_set = BTreeSet::new();

    if !dry_run {
        fs::create_dir_all(dst_root)
            .map_err(|e| KohError::failed(format!("create_dir_all {}: {e}", dst_root.display())))?;
    }

    for entry in &src_entries {
        let target = safe_join(dst_root, &entry.path)?;
        src_set.insert(entry.path.clone());
        if entry.is_dir {
            if !dry_run {
                fs::create_dir_all(&target)
                    .map_err(|e| KohError::failed(format!("mkdir {}: {e}", target.display())))?;
            }
            continue;
        }
        let existing = fs::metadata(&target).ok().filter(|m| m.is_file());
        match existing {
            Some(meta) if meta.len() == entry.size => {
                let local = hash_file(&target, entry.path.clone(), &meta)?;
                if local.hash == entry.hash {
                    summary.unchanged += 1;
                    continue;
                }
                summary.updated.push(entry.path.clone());
                needed.push(entry.path.clone());
            }
            Some(_) => {
                summary.updated.push(entry.path.clone());
                needed.push(entry.path.clone());
            }
            None => {
                summary.added.push(entry.path.clone());
                needed.push(entry.path.clone());
            }
        }
    }

    if delete && dst_root.is_dir() {
        let local_entries = scan_tree(dst_root, excludes)?;
        for local in local_entries.into_iter().rev() {
            if !src_set.contains(&local.path) {
                summary.deleted.push(local.path.clone());
                if !dry_run {
                    let target = safe_join(dst_root, &local.path)?;
                    if local.is_dir {
                        let _ = fs::remove_dir(&target);
                    } else {
                        let _ = fs::remove_file(&target);
                    }
                }
            }
        }
    }

    if dry_run {
        send_msg(send, &SyncMsg::Need(Vec::new()), MAX_CTRL).await?;
        send_msg(send, &SyncMsg::Summary(summary.clone()), MAX_CTRL * 4).await?;
        return Ok(summary);
    }

    send_msg(send, &SyncMsg::Need(needed.clone()), MAX_CTRL * 4).await?;
    for _ in 0..needed.len() {
        let SyncMsg::FileStart {
            path,
            size,
            mtime_secs,
            mode,
        } = recv_msg(recv, MAX_CTRL).await?
        else {
            return Err(KohError::failed("expected FileStart"));
        };
        let target = safe_join(dst_root, &path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| KohError::failed(format!("mkdir {}: {e}", parent.display())))?;
        }
        let fname = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file");
        let tmp = target.with_file_name(format!(".{fname}.koh-tmp"));
        let mut out = File::create(&tmp)
            .map_err(|e| KohError::failed(format!("create {}: {e}", tmp.display())))?;
        let mut written = 0u64;
        loop {
            match recv_msg(recv, MAX_CHUNK).await? {
                SyncMsg::FileChunk(bytes) => {
                    out.write_all(&bytes)
                        .map_err(|e| KohError::failed(format!("write {}: {e}", tmp.display())))?;
                    written += bytes.len() as u64;
                }
                SyncMsg::FileEnd => break,
                _ => return Err(KohError::failed("unexpected message during file transfer")),
            }
        }
        drop(out);
        if written != size {
            let _ = fs::remove_file(&tmp);
            return Err(KohError::failed(format!(
                "size mismatch on {path} ({written} != {size})"
            )));
        }
        let perms = fs::Permissions::from_mode(if mode & 0o111 != 0 { 0o755 } else { 0o644 });
        let _ = fs::set_permissions(&tmp, perms);
        if preserve_mtime {
            let ts = rustix::fs::Timestamps {
                last_access: rustix::fs::Timespec {
                    tv_sec: mtime_secs,
                    tv_nsec: 0,
                },
                last_modification: rustix::fs::Timespec {
                    tv_sec: mtime_secs,
                    tv_nsec: 0,
                },
            };
            let _ = rustix::fs::utimensat(rustix::fs::CWD, &tmp, &ts, rustix::fs::AtFlags::empty());
        }
        fs::rename(&tmp, &target)
            .map_err(|e| KohError::failed(format!("rename {}: {e}", target.display())))?;
        summary.bytes_transferred += written;
    }

    send_msg(send, &SyncMsg::Summary(summary.clone()), MAX_CTRL * 4).await?;
    Ok(summary)
}
