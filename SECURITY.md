# Security Policy

koh is a young, largely single-maintainer project. It has had several internal security, quality, and
architecture reviews, but **no external/professional audit** — please calibrate trust accordingly (see
the [`THREAT_MODEL.md`](docs/THREAT_MODEL.md)). `forbid(unsafe)` and the forbidden panic lints shrink
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

- On-disk identity-key handling and local-attacker hardening (`src/identity.rs`,
  `src/identity/key_file.rs`): the key file is the raw 32-byte secret, protected by its
  permissions (0600) like an SSH host key.
- The connection accept gauntlet / node-id allowlist authorization
  (`src/server/cli.rs`), and the session registry that attaches only allowed peers
  (`src/server/session/sessions.rs`).
- The untrusted wire decoders (`src/proto.rs`, `src/request.rs`, `src/sync/`) and the connection
  cores (`src/server/attach.rs`, `src/client/mod.rs`).
- The output filter both ends run (`src/stream.rs`): what of a server's output reaches the
  user's terminal.
- What a request may reach on the server: the scopes of client keys (`src/server/cli.rs`,
  `src/server/place.rs`), and where a copy lands (`src/sync/receive.rs`, `src/sync/fsat.rs`).

**Out of scope — report upstream** (dependencies koh does not author):

- Transport crypto / QUIC / TLS: **iroh** and its QUIC backend, **rustls**, **ring**.
- The terminal emulator **`fux-vt`**, which the server runs on its programs' output and the
  client on what it writes to the user's terminal (a parse/logic bug belongs to the
  [fux](https://github.com/gold-silver-copper/fux) project), and the system-call layer **`fuxix`** (PTYs, each session's `setsid` and
  controlling terminal, signals; also fux's).
- Known advisories in the dependency tree are tracked via `cargo deny check advisories` (CI) +
  [`deny.toml`](deny.toml).

## Audit trail

The code's comments state invariants, not finding IDs. This index maps every finding ID from koh's
security audits and reviews to what guards it today: a test (`file::name`, from the repository
root; `tests/doc_limits.rs` checks each still exists), or, where the mechanism is gone, what
replaced it. The finding reports themselves live in [`docs/audits/`](docs/audits/)
and the git log.

**Security audit v0.3.1 fixes (H-, M-, L-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| H-1 | A peer's resize allocates an unbounded grid (OOM) | `tests/sessions.rs::a_session_takes_keys_and_clamped_resizes_then_ends_with_the_server`, every size through `src/terminal/mod.rs::clamp_dims`; `testing/android/scripts/sec-resize-oom-server.sh` |
| M-1 | The identity key is written world-readable | `src/identity/key_file.rs::a_created_key_is_its_raw_bytes_and_loads_back_to_the_same_identity`; `testing/android/scripts/sec-key-perms.sh` |
| M-2 | A (0, 0) resize panics the emulator | `tests/sessions.rs::a_session_takes_keys_and_clamped_resizes_then_ends_with_the_server`, `src/terminal/mod.rs::clamp_dims`; `testing/android/scripts/sec-resize-zero-panic.sh` |
| L-1 | A server silently sets the client's clipboard (OSC 52) | Accepted since 0.13: clipboard writes are on by default, the owner's choice, and off with `--no-clipboard` (`src/args.rs::connect_takes_a_server_a_bell_command_and_turns_features_off`). What bounds them stays, in the client's filter: `src/stream.rs::the_clipboard_and_links_pass_only_if_allowed_and_a_clipboard_read_never` |
| L-2 | The client trusts the server's title/icon/clipboard sizes | The client's filter bounds each: `src/stream.rs::a_title_is_cut_to_its_bound_with_no_control_in_it`, `the_clipboard_and_links_pass_only_if_allowed_and_a_clipboard_read_never`, `a_sequence_past_its_bound_is_dropped_whole_and_what_follows_passes` |
| L-3 | No cap on connections, handshakes or sessions | `tests/sessions.rs::max_sessions_refuses_a_new_peer_but_allows_a_reattach`, `tests/net/hostile_peer.rs::a_flood_of_connections_and_garbage_does_not_take_the_server_down` |
| L-4 | `KOH_*` variables leak into the spawned shell | `src/pty.rs::scrub_removes_inherited_koh_vars`; `testing/android/scripts/sec-env-leak.sh` |

**Security audit v0.3.1 findings (KOH-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| KOH-01 | Received states bounded by count, not bytes | Removed: since koh/8 neither end keeps screens for the other; the client reads one epoch's stream a message at a time (`tests/net/hostile_peer.rs::hostile_streams_leave_the_client_running`), and a session keeps at most 128 events of at most 16 KiB for its slowest client (`EVENTS` in `src/server/session.rs`) |
| KOH-02 | Decompression amplification on apply | Removed: since koh/8 nothing is compressed, and every message is refused past its cap before it is buffered: `src/proto.rs::messages_decode_however_they_are_split_and_oversized_ones_are_refused`, `tests/net/hostile_peer.rs::hostile_streams_leave_the_client_running`, `an_oversized_client_message_closes_the_connection_only` |
| KOH-03 | Fixed public KDF salt in the passphrase handshake | Removed: there is no over-the-wire passphrase; the node-id allowlist is the only factor |
| KOH-04 | `String::truncate` on the status line panics the client | The line is cut by characters and width: `src/client/display.rs::the_status_line_covers_the_last_row_and_is_taken_back_whole` |
| KOH-05, KOH-09 | Unbounded per-frame resize and key events | `src/server/session.rs::replies_wait_behind_input_and_overflow_is_bounded`, `tests/sessions.rs::a_resize_waits_for_no_typing_the_program_has_not_read`, `tests/net/hostile_peer.rs::malformed_keys_and_colours_close_the_connection_only`; the resize flood in `testing/android/scripts/stress-evil-peer.sh` |
| KOH-06 | State dir in a world-writable shared location | `src/identity/key_file.rs::only_a_nonsticky_world_writable_directory_is_refused`, `a_directory_of_another_user_but_root_is_refused`, `src/transport_iroh/mod.rs::config_dir_is_xdg_then_home_and_never_elsewhere` |
| KOH-07 | Fragment reassembly buffers ~39 MiB | Removed: there are no fragments; a message is read under its cap, `MAX_SHOWN` or `MAX_CLIENT_MESSAGE` (see KOH-02) |
| KOH-08 | Stalled handshakes hold connection permits | Handshakes hold none, and have a deadline; the pending-handshake cap, when full, gives up the oldest of the address holding the most for a new one, never refusing it: `src/server/cli.rs::a_burst_is_let_through_and_a_flood_gives_up_only_its_own`, `tests/sessions.rs::an_allowed_client_far_away_gets_in_through_a_flood_of_stalled_handshakes`; the admission-stall attack in `testing/android/scripts/stress-evil-peer.sh` exercises it on a device |
| KOH-10 | A SIGHUP-immune child leaks the PTY threads | `Pty`'s `Drop` hangs the program up and the reaper kills it after a second's grace: `tests/pty.rs::dropping_a_pty_ends_its_program`, `a_hung_up_program_has_time_to_exit_before_it_is_killed`, `shutdown_joins_both_io_threads_without_deadlock` |
| KOH-11, KOH-13 | Passphrase handshake downgrades | Removed with the passphrase handshake |
| KOH-12 | A pre-existing state dir is not made private | `src/identity/key_file.rs::only_a_nonsticky_world_writable_directory_is_refused`, `a_missing_directory_is_created_private` |
| KOH-14 | CLI args holding a passphrase derive `Debug` | Removed: no passphrase or other secret is a CLI argument |
| KOH-15 | The env scrub list misses variables | Scrubbed by prefix: `src/pty.rs::scrub_removes_inherited_koh_vars` |
| KOH-16 | A loose existing key is never re-tightened | `src/identity/key_file.rs::loose_key_and_lock_files_are_tightened_through_the_descriptor` |
| KOH-17 | Unmaintained `atomic-polyfill` via postcard defaults | postcard's default features are off (`Cargo.toml`); `cargo deny check advisories` in CI |
| KOH-18 | Unmaintained `paste` via iroh | Accepted, advisory-only: the ignore in [`deny.toml`](deny.toml) |
| KOH-19 | Pre-release `ed25519-dalek` / `curve25519-dalek` | Resolved: iroh 1.3 depends on their stable releases (`ed25519-dalek` 3, `curve25519-dalek` 5 in `Cargo.lock`) |

**Audit of 2026-10-11 (A-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| A-1 | A full input queue froze a connection, leaking its session attachment and permit | The connection never waits inside its loop (`src/server/attach.rs::serve`): `tests/net/hostile_peer.rs::a_full_session_queue_does_not_stop_the_output` |
| A-2 | Frames a client never takes grew the server's in-flight list | What the server writes waits for the client's reads, and a client too far behind gets a redraw, not a backlog: `src/server/attach.rs::the_budget_follows_what_the_client_reads_in_a_round_trip`, `tests/net/session.rs::a_program_that_stops_reading_input_never_freezes_the_client`; `src/bounded.rs`, and `clippy.toml`'s ban on unbounded queues |
| A-3 | Links left off a frame made the two ends' dictionaries differ | Removed with the frames and their dictionaries |
| A-4 | The allowlist check had no test; `koh clients rm` needed a restart | `tests/names_cli.rs::clients_added_and_removed_take_effect_on_a_running_server` |
| A-5 | Hostile-server tests that could not fail | `tests/net/hostile_peer.rs::hostile_streams_leave_the_client_running` waits for good output after the hostile streams, then quits the client through the escape; the hostile clients' tests check the close is `Close::ProtocolError` |
| A-6 | A hostile frame could allocate before its counts were checked | `src/bounded.rs::a_sequence_past_its_bound_is_refused_before_it_is_read`, the wire's `at_most` bounds |
| A-7 | A flood of input starved the client's frames | The client's loop is unbiased: `tests/net/session.rs::a_flood_of_typing_does_not_starve_the_frames` (the output, since koh/8) |

**Audits of 2026-10-12: server, protocol and shared state (B-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| B-1 | A `clients` file that could not be read disconnected every saved client | One reader keeps the list last read well, and drops a client only when two reads agree (an editor's save leaves it missing or empty a moment): `src/server/cli.rs::only_a_removal_two_reads_agree_on_drops_a_saved_client` |
| B-2 | Removing a client left its session running | `tests/sessions.rs::ending_a_peers_session_ends_it_at_once` |
| B-3 | Log lines could interleave; a peer's text could start a line or reorder one | `src/log.rs::a_log_line_is_written_whole_in_one_write`, `a_peers_text_is_one_line_of_printable_ascii`; close reasons are codes, never text: `src/proto.rs::close_codes_round_trip_and_0_is_none_of_them` |
| B-4 | A refusal after admission was retried for ever; a capacity close could look permanent | A refusal is a close code, for good only as `Refused` (`src/client/mod.rs::refusal`): `src/proto.rs::close_codes_round_trip_and_0_is_none_of_them`, `tests/sessions.rs::a_program_that_cannot_start_is_refused_as_such` |
| B-5 | The final screen could miss the program's last output | `src/server/session.rs::the_program_ends_once_its_exit_is_known_and_its_output_drained` |
| B-6 | A reconnect after the program exited got a fresh shell | `tests/sessions.rs::a_reconnect_after_exit_sees_the_exit_until_a_client_has_it` |
| B-7 | A lost or reordered history reply stalled scrollback | Removed with the scrollback view: history is output, in the user's terminal's own scrollback (`tests/net/session.rs::scrolled_off_output_is_in_the_terminals_scrollback_and_a_fresh_attachs`) |
| B-8 | A search could loop on history rows it fetched and lost | Removed with the scrollback view (see B-7) |
| B-9 | A double SIGHUP skipped the drain | `src/lib.rs::a_double_sighup_still_drains_and_a_later_signal_forces` |
| B-10 | Anyone who reaches the UDP port could block allowed clients' dials | Slowed, not stopped: spoofed addresses must answer a QUIC retry first, a real one that floods gives up only its own. `src/server/cli.rs::a_burst_is_let_through_and_a_flood_gives_up_only_its_own`, `tests/sessions.rs::an_allowed_client_far_away_gets_in_through_a_flood_of_stalled_handshakes` |
| B-11 | The server kept a clipboard of up to 3 times its cap | Removed: the server keeps no clipboard; a write passes the filter as the program wrote it, at most `MAX_CLIPBOARD` (`src/stream.rs::the_clipboard_and_links_pass_only_if_allowed_and_a_clipboard_read_never`) |
| B-12 | A hard-linked key could be truncated through `$KOH_LOG` | `src/identity/key_file.rs::a_hard_linked_key_or_log_is_refused_and_left_whole` |
| B-13 | Queued client messages waited for more bytes; a clean end with some left was an error | `src/proto.rs::messages_decode_however_they_are_split_and_oversized_ones_are_refused`; input decoded behind what was delivered is taken at once (`src/server/attach.rs::take`) |
| B-14 | An old connection's input could interleave with a reconnect's | Input is numbered by attachment, and only the newest's reaches the program: `tests/sessions.rs::echo_ack_is_tracked_per_connection_and_only_the_newest_ones_input_reaches_the_program` |

**Review follow-ups (KR-, K-, KB-, KC-, KS-, S-, AR-).**

| ID | Finding | Guarded by |
|----|---------|------------|
| KR-01 | A stalled QUIC handshake pins permits for the idle timeout | `ACCEPT_HANDSHAKE_TIMEOUT` in `src/server/cli.rs`; no automated test |
| KR-02 | Signalling a reaped, possibly recycled PID | Guarded by its type: `src/pty.rs`'s `Running` owns the pid and is the only way to signal it, and is given up when the program is reaped |
| KR-06 | Key perms touched before the dir check; symlinked key followed | `src/identity/key_file.rs::a_symlinked_key_is_refused_and_its_target_left_alone`, `a_dangling_symlink_is_refused_instead_of_creating_or_missing_a_key`, `only_a_nonsticky_world_writable_directory_is_refused` |
| KR-07 | A pre-existing loose `$KOH_LOG` is reused | `src/identity/key_file.rs::a_symlinked_log_is_refused_before_its_target_is_truncated`, `a_fifo_log_or_key_is_refused_without_waiting_for_a_reader` (`open_private_log` refuses a symlink, FIFO or device before opening, or another user's file, fchmods a loose log to 0600, and truncates only after; `connect` disables file logging on refusal) |
| K-01 | Key load races a path swap (TOCTOU) | `src/identity/key_file.rs::a_symlinked_key_is_refused_and_its_target_left_alone`, `loose_key_and_lock_files_are_tightened_through_the_descriptor` |
| K-03 | An accept-then-close server spins the client's reconnect | `src/client/mod.rs::dwell_gate_resets_on_proven_connection_and_climbs_on_flap`, `reconnect_backoff_grows_then_caps` |
| K-13 | `clamp_dims` is the only bound on one resize's allocation | `src/terminal/mod.rs::host_size`, through which every emulator and PTY size passes; `tests/sessions.rs::a_session_takes_keys_and_clamped_resizes_then_ends_with_the_server` |
| K-16 | A panicking connection leaks its session | Detach on drop of `SessionClient`: `tests/sessions.rs::the_last_detach_starts_the_ttl_a_concurrent_one_does_not`, `tests/net/session.rs::many_connects_in_a_row_reattach_the_same_session` |
| KB-01 | The bell hook | `src/client/cli.rs::bell_hook_fires_on_a_rise_and_rate_limits_a_burst`, `tests/net/bell.rs::a_remote_bell_runs_the_hook_at_most_once_a_second` |
| KB-02 | The bell hook's environment and first frame | `src/client/cli.rs::bell_hook_command_scrubs_parent_koh_vars_and_exports_its_own`, `tests/net/bell.rs::stale_bells_before_attach_do_not_fire_but_bells_after_a_reconnect_do` |
| KC-01 | Predictor over a `ScreenView`; input modes byte-identical | `src/predict.rs::prop_predicting_any_keys_is_panic_free`; the program's input modes reach the user's terminal as it set them, and are put back on leaving: `src/client/display.rs::what_the_program_set_is_put_back_when_the_client_leaves` |
| KC-IO-01 | Client teardown owns and joins every producer | `src/client/io.rs::input_producer_forwards_bytes_exactly_and_an_idle_one_cancels_without_a_byte`, `dropping_public_tasks_cancels_both_producers` |
| KC-IO-02 | The input producer does not transform bytes | `src/client/io.rs::input_producer_forwards_bytes_exactly_and_an_idle_one_cancels_without_a_byte` |
| KS-01, KS-04 | Shared sessions across peers; their unwind guard | Removed with the generic session host: one PTY per peer, and K-16's detach on drop |
| KS-02 | Echo-ack per connection, not per session | `tests/sessions.rs::echo_ack_is_tracked_per_connection_and_only_the_newest_ones_input_reaches_the_program` |
| KS-03 | A screen change wakes every attached connection | The session's broadcast of what is shown: `tests/sessions.rs::echo_ack_is_tracked_per_connection_and_only_the_newest_ones_input_reaches_the_program` keeps two connections on one session receiving output |
| S-04 | Per-cell `String` allocation on repaint | Removed with the client's painter |
| S-07 | One place states the prediction-cell invariants | `PredictionEngine::place`; the prediction tests in `src/predict.rs` |
| AR-02 | `predict` and `proto` import direction | CI's layering-guard step (`.github/workflows/ci.yml`) |
| AR-06 | The admission pipeline's order | `src/server/cli.rs::serve_endpoint`; `tests/names_cli.rs::clients_added_and_removed_take_effect_on_a_running_server`, `tests/sessions.rs::ending_a_peers_session_ends_it_at_once` |

**Audit of koh-next, the rewrite for scripts and agents (N-).** Every bound and check of the koh
before it (156dbe4) was listed and followed to where it lives now; the rows below are what the
rewrite changed or brought.

| ID | Finding | Guarded by |
|----|---------|------------|
| N-1 | The client writes the server's output to the user's terminal (as ssh does), so a hostile server could make the terminal answer it | The client's own filter drops every question a terminal answers, whatever the server sent: `src/stream.rs::questions_are_dropped_and_the_rest_passes_however_it_is_split`, `src/client/display.rs::marks_carry_the_terminals_nonce_and_the_last_report_follows_each` |
| N-2 | Raw output could leave modes, keyboard flags or a palette set in the user's terminal after koh | Put back on leaving and on a suspend: `src/client/display.rs::what_the_program_set_is_put_back_when_the_client_leaves` |
| N-3 | Raw output dropped the old caps on titles and clipboard writes | Restored in the filter: `src/stream.rs::a_title_is_cut_to_its_bound_with_no_control_in_it`, `the_clipboard_and_links_pass_only_if_allowed_and_a_clipboard_read_never` |
| N-4 | The client now runs a terminal parser on server bytes (its mirror, for prediction) | Accepted: fux-vt is panic-free by construction and bounded, and the mirror keeps no history; `fuzz/fuzz_targets/server_process.rs` and the corpus (`tests/corpus.rs::every_recording_shows_through_koh_as_it_does_in_a_terminal_and_redrawn`) feed it real and arbitrary output |
| N-5 | A program's own marks could fake a remote command's end in the user's terminal | Both filters drop marks in the output; only the shell's signed ones are relayed apart: `src/stream.rs::only_the_shells_signed_marks_are_relayed_without_the_nonce`, `tests/sessions.rs::a_sessions_bash_marks_its_commands_after_the_users_bashrc` |
| N-6 | A killed or dropped `koh exec` left its command running | The command connection's idle timeout is 20 s, and a lost connection hangs the command up: `tests/commands.rs::a_command_whose_client_is_stopped_or_killed_is_hung_up` |
| N-7 | A copy could give a landed file setuid or setgid, a program that runs as the receiving user for whoever starts it | No copy lands either bit (`Mode::landed`): `src/sync/tests.rs::a_tree_lands_then_only_what_changed_is_sent_and_gets_its_arrival_time` |
| N-8 | A merging copy (the sync) lands into directories that already exist, which may hold symlinks | Every entry is reached from the one above it by descriptor, following no symlink (`src/sync/fsat.rs::walk`): `src/sync/tests.rs::nothing_lands_through_a_symlink_or_outside_a_scoped_directory` |
| N-9 | A scoped key's paths could leave its directory (`..`, an absolute path, `~`, a symlink) | `src/server/place.rs::a_scoped_keys_paths_stay_in_its_directory`, `src/sync/tests.rs::nothing_lands_through_a_symlink_or_outside_a_scoped_directory`; a scoped wait for a file looks through no symlink (`src/sync/mod.rs::exists_beneath`); a scope changed closes the client's connections (`src/server/cli.rs::only_a_removal_two_reads_agree_on_drops_a_saved_client`) |
| N-10 | A scoped key asking for a shell, a session's text or another scope's request | Closed with `Close::OutOfScope`: `tests/commands.rs::a_scoped_key_copies_only_in_its_directory_and_runs_no_shell` |
| N-11 | Jobs outlive their connection, so a peer could pile up processes and logs | At most 64 jobs kept, all peers', each log bounded by `--job-log-bytes` (at most 64 MiB, held at most twice over), ended ones forgotten after the session TTL, all hung up when the server stops: `src/server/jobs.rs::a_log_keeps_its_newest_bytes_and_says_how_many_went`, `tests/commands.rs::a_job_outlives_its_client_and_is_waited_for_followed_and_killed` |
| N-12 | A peer's job, session or wait reaching another peer's | Each is found by peer and name or number only: `tests/commands.rs::connect_picks_a_session_by_number_or_a_new_one_and_sessions_lists_them`, `tests/sessions.rs::attach_creates_then_reattaches_the_same_peer` |
| N-13 | A client that never reads a session's output makes the server keep it | The session keeps 128 events for its slowest client, then sends it a redraw; the connection writes no more than its budget past what the client read: `src/server/attach.rs::the_budget_follows_what_the_client_reads_in_a_round_trip` |
| N-14 | A sync's bookkeeping grows with the tree | At most 4 million names seen and a million renames or removals deferred (`MAX_SEEN`, `MAX_DEFERRED` in `src/sync/receive.rs`), 64 files unanswered (`WINDOW`), 128 directories deep (`MAX_DEPTH`): `src/sync/tests.rs::a_copy_cut_anywhere_leaves_whole_files_and_the_next_one_resumes` |

## Please do not

Run automated scanning that degrades a third party (relays, the public DNS discovery service), or test
against servers / keys you do not own.
