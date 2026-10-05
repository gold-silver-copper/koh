# Where the corpus comes from

The recordings in this directory (`NAME.bin` and `NAME.json`, 113 of them) are copied unchanged
from fux's corpus, `fux-vt/compare/corpus/` in https://github.com/gold-silver-copper/fux at commit
`f6382e6` (fux 0.18.0). fux is MIT-licensed, by the same author as koh.

Each recording is what a real program (bash, zsh, fish, nvim, vim, emacs, helix, htop, btop,
lazygit, fzf, less, man, git, delta, claude and others) wrote to a 40×120 terminal, or the size its
JSON gives, while keys were typed into it. `NAME.json` gives the program and its version, the
size, the replies the recording terminal gave, and each step's keys, resize and where its output
ends. fux's `fux-vt/compare/README.md` ("The corpus") says how they were recorded, and its
`corpus/INVENTORY.md` lists what each program sends.

They are copied rather than fetched so that koh's tests run offline and on CI with no network.
They are 3.6 MB, and `Cargo.toml` excludes `testing/` from the published crate.

`recording.rs` reads them. koh's corpus tests (`tests/corpus.rs`, `tests/net/corpus.rs`) and the
harness crates include it by path.

To update them, copy `fux-vt/compare/corpus/*.bin` and `*.json` from a newer fux commit, name that
commit here, and run `cargo test --test corpus`.
