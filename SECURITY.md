# Security Policy

koh is a young, largely single-maintainer project. It has had several internal security, quality, and
architecture reviews, but **no external/professional audit** — please calibrate trust accordingly (see
the [`THREAT_MODEL.md`](docs/THREAT_MODEL.md)). `forbid(unsafe)` and a denied-panic lint family shrink
the surface that needs auditing, but they do not replace independent eyes.

## Reporting a vulnerability

Please report suspected security issues **privately**, not in a public issue or PR:

- **Preferred:** GitHub private vulnerability reporting — open a draft advisory at
  <https://github.com/gold-silver-copper/koh/security/advisories/new>.
- **Backup:** email the maintainer at `stephen.korzen@gmail.com` with `[koh security]` in the subject.

Helpful to include: a description and impact, the affected version (`koh --version`), and a
reproduction if you have one. We aim to **acknowledge within 7 days** and to coordinate a fix and
disclosure within **90 days** of a confirmed report (sooner for an actively-exploited issue). We'll
credit reporters who want it.

## Scope

**In scope** (code koh authors):

- On-disk identity-key handling and local-attacker hardening (`koh-core/src/transport_iroh/`,
  `koh-core/src/identity.rs`): the key file is the raw 32-byte secret, protected by its
  permissions (0600) like an SSH host key.
- The connection accept gauntlet / node-id allowlist authorization
  (`koh-core/src/server/cli.rs`) and the admission barrier
  (`koh-core/src/transport_iroh/admission.rs`).
- The untrusted wire decoders (`koh-core/src/proto.rs`) and the connection cores
  (`koh-core/src/server/mod.rs`, `koh-core/src/client/session.rs`).
- The terminal apply path (`koh-core/src/terminal/`): decoding and validating the structured screen diff.

**Out of scope — report upstream** (dependencies koh does not author):

- Transport crypto / QUIC / TLS: **iroh** and its QUIC backend, **rustls**, **ring**.
- The server's terminal emulator **`fux-vt`** (a parse/logic bug belongs to the
  [fux](https://github.com/gold-silver-copper/fux) project; the client never runs it on server
  bytes) and the PTY layer **`portable-pty`**.
- Known advisories in the dependency tree are tracked via `cargo deny check advisories` (CI) +
  [`deny.toml`](deny.toml).

## Audit trail

The code's comments state invariants, not finding IDs. This index maps every finding ID from koh's
security audits and reviews to what guards it today: a test (`file::name`; `src/` and `tests/`
paths are in `koh-core/`, `testing/` and `.github/` at the repository root), or, where the mechanism
is gone, what replaced it. The finding reports themselves live in [`docs/audits/`](docs/audits/)
and the git log.

**Security audit v0.3.1 fixes (H-, M-, L-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| H-1 | A peer's resize allocates an unbounded grid (OOM) | `src/terminal/server.rs::server_resize_clamps_oom_and_zero`, `src/terminal/mod.rs::client_apply_clamps_oom_resize`, `clamp_dims_bounds_both_extremes`; `testing/android/scripts/sec-resize-oom-server.sh` |
| M-1 | The identity key is written world-readable | `src/transport_iroh/mod.rs::created_key_file_is_owner_only`; `testing/android/scripts/sec-key-perms.sh` |
| M-2 | A (0, 0) resize panics the emulator | `src/terminal/server.rs::server_resize_clamps_oom_and_zero`, `src/terminal/mod.rs::client_apply_clamps_zero_resize`; `testing/android/scripts/sec-resize-zero-panic.sh` |
| L-1 | A server silently sets the client's clipboard (OSC 52) | `src/client/render.rs::out_of_band_clipboard_off_by_default_emits_nothing`, `out_of_band_rejects_non_base64_clipboard_even_when_opted_in` |
| L-2 | The client trusts the server's title/icon/clipboard sizes | `src/terminal/mod.rs::client_apply_caps_oversized_title_and_clipboard` |
| L-3 | No cap on connections, handshakes or sessions | `src/server/session.rs::max_sessions_refuses_a_new_peer_but_allows_a_reattach`, `tests/net/hostile_peer.rs::a_flood_of_connections_and_garbage_does_not_take_the_server_down` |
| L-4 | `KOH_*` variables leak into the spawned shell | `src/pty.rs::scrub_removes_inherited_koh_vars`; `testing/android/scripts/sec-env-leak.sh` |

**Security audit v0.3.1 findings (KOH-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| KOH-01 | Received states bounded by count, not bytes | Replaced by koh/3's fixed window of 16 frames per end: `src/client/session.rs::only_the_last_frames_are_kept_as_bases`, `src/server/mod.rs::only_the_last_frames_are_kept_so_an_ack_for_an_older_one_is_ignored`, `tests/net/hostile_peer.rs::frames_with_unknown_bases_never_grow_the_client` |
| KOH-02 | Decompression amplification on apply | `src/proto.rs::an_inflate_bomb_is_rejected`, `oversized_client_messages_are_rejected_before_buffering`, `tests/net/hostile_peer.rs::an_oversized_or_bomb_frame_never_grows_the_client`, `an_oversized_client_message_closes_the_connection_only` |
| KOH-03 | Fixed public KDF salt in the passphrase handshake | Removed: there is no over-the-wire passphrase; the node-id allowlist is the only factor |
| KOH-04 | `String::truncate` on the status line panics the client | `src/client/render.rs::status_line_truncation_is_panic_free_across_all_widths` |
| KOH-05, KOH-09 | Unbounded per-frame resize and key events | `src/server/mod.rs::a_read_keeps_only_the_last_resize_and_concatenates_keys`; the resize flood in `testing/android/scripts/stress-evil-peer.sh` |
| KOH-06 | State dir in a world-writable shared location | `src/transport_iroh/mod.rs::ensure_state_dir_secure_refuses_only_nonsticky_world_writable`, `config_dir_is_xdg_then_home_and_never_elsewhere` |
| KOH-07 | Fragment reassembly buffers ~39 MiB | Removed: koh/3 has no fragments; a frame is one stream read under `MAX_FRAME` (see KOH-02) |
| KOH-08 | Stalled handshakes hold connection permits | The pending-handshake cap and the handshake and admission deadlines in `src/server/cli.rs::serve_endpoint`; no automated test (the admission-stall attack in `testing/android/scripts/stress-evil-peer.sh` exercises it on a device) |
| KOH-10 | A SIGHUP-immune child leaks the PTY threads | `Pty`'s `Drop` and `kill_hard` send SIGKILL; `tests/pty.rs::dropping_pty_eofs_child_and_stops_writer`, `shutdown_joins_both_io_threads_without_deadlock` (no SIGHUP-immune child in a test) |
| KOH-11, KOH-13 | Passphrase handshake downgrades | Removed with the passphrase handshake |
| KOH-12 | A pre-existing state dir is not made private | `src/transport_iroh/mod.rs::ensure_state_dir_secure_refuses_only_nonsticky_world_writable`, `created_key_file_is_owner_only` |
| KOH-14 | CLI args holding a passphrase derive `Debug` | Removed: no passphrase or other secret is a CLI argument |
| KOH-15 | The env scrub list misses variables | Scrubbed by prefix: `src/pty.rs::scrub_removes_inherited_koh_vars` |
| KOH-16 | A loose existing key is never re-tightened | `src/transport_iroh/mod.rs::fd_key_read_tightens_a_loose_real_key_via_the_fd` |
| KOH-17 | Unmaintained `atomic-polyfill` via postcard defaults | postcard's default features are off (`koh-core/Cargo.toml`); `cargo deny check advisories` in CI |
| KOH-18 | Unmaintained `paste` via iroh | Accepted, advisory-only: the ignore in [`deny.toml`](deny.toml) |
| KOH-19 | Pre-release `ed25519-dalek` / `curve25519-dalek` | Accepted: iroh 1.0.0 still depends on them; tracked with each iroh bump |

**Review follow-ups (KR-, K-, KB-, KC-, KS-, S-, AR-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| KR-01 | A stalled QUIC handshake pins permits for the idle timeout | `ACCEPT_HANDSHAKE_TIMEOUT` in `src/server/cli.rs`; no automated test |
| KR-02 | Signalling a reaped, possibly recycled PID | `tests/pty.rs::reaped_child_is_not_signaled_again` |
| KR-06 | Key perms touched before the dir check; symlinked key followed | `src/transport_iroh/mod.rs::load_refuses_a_symlinked_key`, `fd_key_read_does_not_follow_a_symlinked_key`, `ensure_state_dir_secure_refuses_only_nonsticky_world_writable` |
| KR-07 | A pre-existing loose `$KOH_LOG` is reused | `connect` in `src/client/cli.rs` fchmods the log to 0600 or disables file logging; no automated test |
| K-01 | Key load races a path swap (TOCTOU) | `src/transport_iroh/mod.rs::fd_key_read_does_not_follow_a_symlinked_key`, `fd_key_read_tightens_a_loose_real_key_via_the_fd` |
| K-03 | An accept-then-close server spins the client's reconnect | `src/client/mod.rs::dwell_gate_resets_on_proven_connection_and_climbs_on_flap`, `reconnect_backoff_grows_then_caps` |
| K-13 | `clamp_dims` is the only bound on one resize's allocation | `src/terminal/mod.rs::clamp_dims_bounds_both_extremes`, `apply_is_panic_free_and_holds_invariants` |
| K-16 | A panicking connection leaks its session | Detach on drop of `SessionClient`: `src/server/session.rs::the_last_detach_starts_the_ttl_a_concurrent_one_does_not`, `tests/net/session.rs::connections_dropped_with_input_in_flight_do_not_hurt_the_session` |
| KB-01 | The bell hook | `src/client/cli.rs::bell_hook_fires_on_a_rise_and_rate_limits_a_burst`, `tests/net/bell.rs::a_remote_bell_runs_the_hook_at_most_once_a_second` |
| KB-02 | The bell hook's environment and first frame | `src/client/cli.rs::bell_hook_command_scrubs_parent_koh_vars_and_exports_its_own`, `bell_hook_prime_swallows_the_count_it_is_seeded_with_but_not_later_rises`, `tests/net/bell.rs::stale_bells_before_attach_do_not_fire_but_bells_after_a_reconnect_do` |
| KC-01 | Predictor over a `ScreenView`; input modes byte-identical | `src/predict.rs::predictor_runs_over_a_plain_screen_view`, `src/client/render.rs::input_modes_formatted_and_diff_match_the_vt100_oracle` |
| KC-IO-01 | Client teardown owns and joins every producer | `src/client/io.rs::idle_input_poll_cancels_and_joins_without_waiting_for_a_byte`, `dropping_public_tasks_cancels_both_producers` |
| KC-IO-02 | The input producer does not transform bytes | `src/client/io.rs::input_producer_forwards_bytes_exactly` |
| KS-01, KS-04 | Shared sessions across peers; their unwind guard | Removed with the generic session host: one PTY per peer, and K-16's detach on drop |
| KS-02 | Echo-ack per connection, not per session | `src/server/mod.rs::echo_ack_is_tracked_per_connection_so_a_second_connection_sees_only_its_own_input`, `echo_ack_trackers_are_independent_per_connection` |
| KS-03 | A screen change wakes every attached connection | The session's `watch` channel: `src/server/mod.rs::echo_ack_is_tracked_per_connection_so_a_second_connection_sees_only_its_own_input` keeps two connections on one session receiving frames |
| S-04 | Per-cell `String` allocation on repaint | Performance only; nothing to guard |
| S-07 | One place states the prediction-cell invariants | `PredictionEngine::place_cell`; the prediction tests in `src/predict.rs` |
| AR-02 | `predict` and `proto` import direction | CI's layering-guard step (`.github/workflows/ci.yml`) |
| AR-06 | The admission pipeline's order | `src/server/cli.rs::serve_endpoint`; `tests/admission.rs`, `tests/net/hostile_peer.rs::a_bad_admission_byte_is_rejected_not_treated_as_admitted` |

## Please do not

Run automated scanning that degrades a third party (relays, the public DNS discovery service), or test
against servers / keys you do not own.
