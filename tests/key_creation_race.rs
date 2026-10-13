#![cfg(unix)]
#![forbid(clippy::disallowed_methods)]

use std::process::Stdio;

use koh_testkit::command;

#[test]
fn concurrent_first_uses_publish_one_key_and_one_endpoint_id() {
    let dir = koh_testkit::scratch!("public-key-race").expect("a private state directory");
    let key = dir.join("id.key");
    let mut children = Vec::new();
    for _ in 0..4 {
        children.push(
            command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
                .expect("spawn koh")
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
}

#[test]
fn reset_removes_an_unreadable_key_by_relative_path_only_after_explicit_confirmation() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = koh_testkit::scratch!("relative-reset").expect("a private directory");
    let path = directory.join("identity.key");
    // A `koh-key-v1` (passphrase-encrypted) file: not a key koh reads, but reset must remove it.
    std::fs::write(
        &path,
        b"koh-key-v1\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
    )
    .expect("disposable identity");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("key mode");
    let run = |confirmed: bool| {
        let mut command =
            command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!()).expect("spawn koh");
        command
            .current_dir(&directory)
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
    // `koh id` refuses the file and points at the reset.
    let id = command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!())
        .expect("spawn koh")
        .current_dir(&directory)
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

#[test]
fn tests_may_start_koh_but_never_a_program_that_authenticates() {
    assert!(command(env!("CARGO_BIN_EXE_koh"), &koh_testkit::home!()).is_ok());
    for program in ["sudo", "/usr/bin/passwd", "su", "ssh"] {
        assert!(
            command(program, &koh_testkit::home!()).is_err(),
            "{program}"
        );
    }
}
