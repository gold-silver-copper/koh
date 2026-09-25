#![cfg(unix)]

use std::process::{Command, Stdio};

#[test]
fn concurrent_first_uses_publish_one_key_and_one_endpoint_id() {
    let dir = std::env::temp_dir().join(format!(
        "koh-public-key-race-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos()
    ));
    std::fs::create_dir(&dir).expect("create private state directory");
    let key = dir.join("id.key");
    let mut children = Vec::new();
    for _ in 0..4 {
        children.push(
            Command::new(env!("CARGO_BIN_EXE_koh"))
                .args(["id", "--key-file"])
                .arg(&key)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn public koh id command"),
        );
    }
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().expect("wait for koh id"))
        .collect();
    for output in &outputs {
        assert!(
            output.status.success(),
            "koh id failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let first = &outputs[0].stdout;
    assert!(outputs.iter().all(|output| output.stdout == *first));
    assert!(key.is_file(), "one identity key was published");
    std::fs::remove_dir_all(dir).expect("remove test state directory");
}

#[test]
fn reset_removes_an_unreadable_key_by_relative_path_only_after_explicit_confirmation() {
    use std::os::unix::fs::PermissionsExt as _;
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(std::env::temp_dir().join(format!(
        "koh-relative-reset-{}",
        koh_core::identity::Identity::generate().endpoint_id()
    )));
    std::fs::create_dir(&directory.0).expect("private directory");
    std::fs::set_permissions(&directory.0, std::fs::Permissions::from_mode(0o700))
        .expect("private mode");
    let path = directory.0.join("identity.key");
    // An identity in the old encrypted format: not a key koh reads, but reset must remove it.
    std::fs::write(
        &path,
        b"koh-key-v1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
    )
    .expect("disposable identity");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("key mode");
    let run = |confirmed: bool| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_koh"));
        command
            .current_dir(&directory.0)
            .env_clear()
            .args(["key", "reset", "--key-file", "identity.key"])
            .stdin(Stdio::null());
        if confirmed {
            command.arg("--yes");
        }
        command.output().expect("reset command")
    };
    assert!(!run(false).status.success());
    assert!(path.exists(), "unconfirmed reset removed key");
    // `koh id` refuses the old file and points at the reset.
    let id = Command::new(env!("CARGO_BIN_EXE_koh"))
        .current_dir(&directory.0)
        .env_clear()
        .args(["id", "--key-file", "identity.key"])
        .stdin(Stdio::null())
        .output()
        .expect("id command");
    assert!(!id.status.success());
    let stderr = String::from_utf8_lossy(&id.stderr);
    assert!(stderr.contains("koh key reset"), "{stderr}");
    let output = run(true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!path.exists(), "confirmed reset retained key");
}
