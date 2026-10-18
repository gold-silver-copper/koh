use super::*;
use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

/// Copy `sources` to `dest` under `opts`, the two ends on threads of their own joined as the
/// streams join them, the sender's bytes cut after `cut` if given: the receiver's outcome.
fn copy_with(
    sources: &[Source],
    dest: &Dest,
    opts: &Opts,
    cut: Option<usize>,
) -> Result<Summary, Failure> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(PIPE_DEPTH);
    let (cut_tx, cut_rx) = mpsc::channel::<Vec<u8>>(PIPE_DEPTH);
    let (reply_tx, mut reply_rx) = mpsc::channel::<Reply>(REPLY_DEPTH);
    let count = sources.len();
    let target = Target::resolve(dest, count);
    let sources = sources.to_vec();
    let send_opts = opts.clone();
    let sender = std::thread::spawn(move || {
        let mut answers = |wait: bool| {
            if wait {
                reply_rx.blocking_recv()
            } else {
                reply_rx.try_recv().ok()
            }
        };
        let _ = send(&sources, &send_opts, ChannelWriter(tx), &mut answers);
    });
    // What the sender writes, cut short if asked.
    let pipe = std::thread::spawn(move || {
        let mut passed = 0_usize;
        while let Some(chunk) = rx.blocking_recv() {
            let room = cut.map_or(chunk.len(), |cut| {
                cut.saturating_sub(passed).min(chunk.len())
            });
            if room > 0 && cut_tx.blocking_send(chunk[..room].to_vec()).is_err() {
                return;
            }
            passed = passed.saturating_add(chunk.len());
            if cut.is_some_and(|cut| passed >= cut) {
                return;
            }
        }
    });
    let outcome = target.and_then(|(target, made)| {
        let mut answer = |reply: Reply| reply_tx.try_send(reply).is_ok();
        let summary = receive(ChannelReader::new(cut_rx), &target, opts, &mut answer);
        let _ = reply_tx.try_send(Reply::End(summary.clone()));
        summary.map(|mut s| {
            s.dirs = s.dirs.saturating_add(made);
            s
        })
    });
    drop(reply_tx);
    let joined = pipe.join().is_ok() && sender.join().is_ok();
    outcome.and_then(|summary| {
        if joined {
            Ok(summary)
        } else {
            Err(Failure::new(
                FailKind::Other,
                Path::new("a copy's thread panicked"),
            ))
        }
    })
}

fn copy(sources: &[&Path], dest: &Path, opts: &Opts) -> Result<Summary, Failure> {
    let sources: Vec<Source> = sources
        .iter()
        .map(|p| Source::Path(p.to_path_buf()))
        .collect();
    copy_with(&sources, &Dest::Path(dest.to_path_buf()), opts, None)
}

/// What is in `dir`, recursively: each entry's relative path, kind, mode and contents (a file's
/// bytes, a symlink's target), sorted.
fn tree(dir: &Path) -> Vec<(PathBuf, char, u32, Vec<u8>)> {
    fn walk(root: &Path, at: &Path, out: &mut Vec<(PathBuf, char, u32, Vec<u8>)>) {
        for entry in fs::read_dir(at).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let meta = fs::symlink_metadata(&path).unwrap();
            let mode = meta.mode() & 0o7777;
            if meta.is_symlink() {
                use std::os::unix::ffi::OsStringExt as _;
                let target = fs::read_link(&path).unwrap().into_os_string().into_vec();
                out.push((rel, 'l', 0, target));
            } else if meta.is_dir() {
                out.push((rel, 'd', mode, Vec::new()));
                walk(root, &path, out);
            } else {
                out.push((rel, 'f', mode, fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

/// A tree with a mode, an odd name, a symlink, an empty file and one past a chunk.
fn sample(root: &Path) -> PathBuf {
    let top = root.join("top dir");
    fs::create_dir_all(top.join("sub")).unwrap();
    let odd = std::ffi::OsStr::from_bytes(if cfg!(target_os = "macos") {
        b"line\nbreak \xc3\xa9 name"
    } else {
        b"line\nbreak \xff name"
    });
    fs::write(top.join(odd), b"odd").unwrap();
    fs::write(top.join("sub/big"), vec![7u8; CHUNK * 2 + 5]).unwrap();
    fs::write(top.join("empty"), b"").unwrap();
    fs::set_permissions(top.join("empty"), fs::Permissions::from_mode(0o751)).unwrap();
    std::os::unix::fs::symlink("sub/big", top.join("link")).unwrap();
    top
}

fn mtime(path: &Path) -> (i64, i64) {
    let meta = fs::metadata(path).unwrap();
    (meta.mtime(), meta.mtime_nsec())
}

#[test]
fn a_tree_lands_then_only_what_changed_is_sent_and_gets_its_arrival_time() {
    let scratch = crate::test_runtime::scratch("sync-again");
    let top = sample(&scratch.join("from"));
    let into = scratch.join("into");
    let first = copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    let landed = into.join("x/top dir");
    assert_eq!(tree(&landed), tree(&top));
    assert_eq!((first.new, first.links, first.dirs), (3, 1, 4), "{first:?}");
    // The source's time was not kept: a copy is new where it lands.
    let old = filetime(&top.join("sub/big"), 1_000_000);
    assert_ne!(mtime(&landed.join("sub/big")), old);
    // Again: nothing is sent, and nothing it did not send is touched.
    let before = mtime(&landed.join("sub/big"));
    let again = copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    assert_eq!(
        (again.written(), again.unchanged, again.bytes),
        (0, 3, 0),
        "{again:?}"
    );
    assert_eq!(mtime(&landed.join("sub/big")), before);
    // A file edited before the last copy landed (an older time than the copy's) is sent, and
    // lands newer than the copy before: a build there sees it changed (K1).
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(top.join("sub/big"), vec![8u8; CHUNK * 2 + 5]).unwrap();
    filetime(&top.join("sub/big"), 1_000_000);
    let edited = copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    assert_eq!((edited.replaced, edited.unchanged), (1, 2), "{edited:?}");
    assert!(mtime(&landed.join("sub/big")) > before);
    // With -p, the source's times, the unchanged files' too.
    let kept = Opts {
        keep_times: true,
        ..Opts::default()
    };
    copy(&[&top], &into.join("x/"), &kept).unwrap();
    assert_eq!(mtime(&landed.join("sub/big")).0, 1_000_000);
    // A setuid or setgid program lands as a plain one.
    fs::set_permissions(top.join("empty"), fs::Permissions::from_mode(0o6755)).unwrap();
    copy(&[&top], &into.join("x/"), &Opts::default()).unwrap();
    let mode = fs::metadata(landed.join("empty")).unwrap().mode() & 0o7777;
    assert_eq!(mode, 0o755);
}

/// Set `path`'s modification time to `secs`, and say it.
fn filetime(path: &Path, secs: u64) -> (i64, i64) {
    let file = fs::File::options().write(true).open(path).unwrap();
    let at = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs));
    file.set_modified(at.unwrap()).unwrap();
    mtime(path)
}

#[test]
fn a_tree_merges_into_one_there_and_delete_and_exclude_say_what_goes() {
    let scratch = crate::test_runtime::scratch("sync-merge");
    let src = scratch.join("src");
    fs::create_dir_all(src.join("a")).unwrap();
    fs::write(src.join("a/one"), b"1").unwrap();
    fs::write(src.join("keep.o"), b"o").unwrap();
    let dest = scratch.join("dest/src");
    fs::create_dir_all(dest.join("a")).unwrap();
    fs::write(dest.join("a/theirs"), b"t").unwrap();
    fs::write(dest.join("cache.o"), b"c").unwrap();
    // Merged: what was there stays, without --delete.
    let merged = copy(&[&src], &scratch.join("dest"), &Opts::default()).unwrap();
    assert_eq!(merged.new, 2);
    assert!(dest.join("a/theirs").exists() && dest.join("a/one").exists());
    // With --delete, what the source lacks goes, but what is excluded stays and is not sent.
    let opts = Opts {
        delete: true,
        excludes: glob::Excludes::new(vec![glob::Pattern::new(b"*.o".to_vec()).unwrap()]).unwrap(),
        ..Opts::default()
    };
    fs::remove_file(src.join("keep.o")).unwrap();
    let pruned = copy(&[&src], &scratch.join("dest"), &opts).unwrap();
    assert_eq!(pruned.deleted, 1, "{pruned:?}");
    assert!(!dest.join("a/theirs").exists());
    assert!(dest.join("cache.o").exists() && dest.join("keep.o").exists());
    // What is in a directory (`dir/.`) lands in the destination itself.
    let flat = scratch.join("flat");
    copy(&[&src.join(".")], &flat, &Opts::default()).unwrap();
    assert!(flat.join("a/one").exists());
    // A file into a missing directory: its parents are made.
    copy(
        &[&src.join("a/one")],
        &scratch.join("p/q/r/one"),
        &Opts::default(),
    )
    .unwrap();
    assert_eq!(fs::read(scratch.join("p/q/r/one")).unwrap(), b"1");
}

#[test]
fn a_copy_cut_anywhere_leaves_whole_files_and_the_next_one_resumes() {
    let scratch = crate::test_runtime::scratch("sync-cut");
    let src = scratch.join("src");
    fs::create_dir_all(&src).unwrap();
    let big: Vec<u8> = (0..CHUNK * 5)
        .map(|n| u8::try_from(n % 251).unwrap())
        .collect();
    fs::write(src.join("big"), &big).unwrap();
    fs::write(src.join("small"), b"small").unwrap();
    let source = [Source::Path(src)];
    for cut in [10, 300, CHUNK, CHUNK * 3 + 77] {
        let dest = scratch.join(format!("cut-{cut}/"));
        let failed = copy_with(
            &source,
            &Dest::Path(dest.clone()),
            &Opts::default(),
            Some(cut),
        );
        assert_eq!(
            failed.unwrap_err().kind,
            FailKind::Truncated,
            "cut at {cut}"
        );
        // Whatever landed is whole.
        for (name, want) in [("big", &big[..]), ("small", &b"small"[..])] {
            if let Ok(got) = fs::read(dest.join("src").join(name)) {
                assert_eq!(got, want, "{name} cut at {cut}");
            }
        }
        // Run again: it all lands, the big file from where the cut left it.
        let resumed =
            copy_with(&source, &Dest::Path(dest.clone()), &Opts::default(), None).unwrap();
        assert_eq!(fs::read(dest.join("src/big")).unwrap(), big, "cut at {cut}");
        let names: Vec<_> = fs::read_dir(dest.join("src"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 2, "no part left: {names:?}");
        if cut > CHUNK * 2 {
            assert_eq!(resumed.resumed, 1, "cut at {cut}: {resumed:?}");
            assert!(
                resumed.bytes < u64::try_from(big.len()).unwrap(),
                "{resumed:?}"
            );
        }
    }
}

#[test]
fn nothing_lands_through_a_symlink_or_outside_a_scoped_directory() {
    let scratch = crate::test_runtime::scratch("sync-symlink");
    let src = scratch.join("src");
    fs::create_dir_all(src.join("d")).unwrap();
    fs::write(src.join("d/f"), b"f").unwrap();
    let outside = scratch.join("outside");
    fs::create_dir_all(&outside).unwrap();
    // Where the source has a directory, the destination has a symlink to elsewhere.
    let dest = scratch.join("dest/src");
    fs::create_dir_all(&dest).unwrap();
    std::os::unix::fs::symlink(&outside, dest.join("d")).unwrap();
    let refused = copy(&[&src], &scratch.join("dest"), &Opts::default()).unwrap_err();
    assert_eq!(refused.kind, FailKind::IsASymlink);
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    // Beneath a scoped directory, a symlinked part of the destination is not followed either.
    let root = scratch.join("root");
    fs::create_dir_all(&root).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
    let name = |n: &str| Name::new(n.as_bytes().to_vec()).unwrap();
    let dest = Dest::Beneath {
        root,
        path: vec![name("link"), name("x")],
        dir: true,
    };
    let refused = copy_with(
        &[Source::Path(src.join("d/f"))],
        &dest,
        &Opts::default(),
        None,
    );
    assert!(refused.is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
    // Built by hand past the constructor, a name that reaches out is refused as it is decoded.
    for bad in [&b""[..], b".", b"..", b"a/b", b"a\0"] {
        assert!(Name::new(bad.to_vec()).is_err(), "{bad:?}");
    }
}
