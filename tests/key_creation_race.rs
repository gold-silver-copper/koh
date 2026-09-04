#![cfg(all(unix, feature = "cli"))]

use std::process::{Command, Stdio};

#[test]
fn concurrent_public_first_create_uses_the_new_passphrase_for_the_loser() {
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
                .env("KOH_KEY_NEW_PASSPHRASE", "concurrent-test-passphrase")
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
