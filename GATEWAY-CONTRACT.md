# Local service gateway

Koh can expose a local Unix service through authenticated QUIC without owning that application's state or processes. Fux uses this as an optional remote transport; its default build has no koh dependency.

Server:

```sh
koh gateway serve --socket /private/runtime/fux/default.attach.sock --allow CLIENT_ID
```

Client, with a private existing directory for the proxy socket:

```sh
koh gateway connect SERVER_ID --socket /private/runtime/viewer.sock
fux attach --socket /private/runtime/viewer.sock
```

Koh owns both identities and prompts only when starting a gateway process. `--key-file` selects its identity. `--local` on serve and `--direct HOST:PORT` on connect support discovery-free testing; `--relay-url` selects an explicit relay. The gateway carries opaque application bytes and does not parse workspace state or observation reports.

The server's fixed socket target is never supplied by remote clients. The allowlist is checked before opening that socket. Both sides check local peer credentials; socket directories must be private and owned by the effective user. Local listeners are mode 0600 and remove only their own inode on teardown. Each gateway admits at most 64 concurrent connection tasks, including handshakes. The gateway uses versioned framed forwarding with bounded buffers and backpressure. Application bytes are acknowledged after local writes complete.

Verified behavior includes authorized byte-exact forwarding, denied peers never reaching the application, and local shell state surviving gateway shutdown. Forced-QUIC-loss tests perform five automatic reconnects against both a counter service and a real fux shell. The real shell keeps its PID and local attachment, and six commands produce exactly six file effects. These tests use the production resume registry and client loop over real loopback QUIC connections.

## Resume framing foundation

ALPN is now `koh/local-gateway/2`. Data frames carry a monotonically increasing u64 frame sequence and at most 16 KiB of opaque bytes; EOF consumes a sequence number. Cumulative ACKs name the next committed sequence. There are at most 32 unacknowledged outbound frames and 32 queued inbound frames per attachment. A partially delivered remote frame and a stalled local write have 10-second deadlines.

The internal Session retains both journals and the exact offset of a partially applied local write across replacement links. Duplicate committed or queued frames never repeat application bytes. Invalid sequence gaps, acknowledgements beyond sent data, data after EOF, and receive-window violations terminate the session. Application read/write errors are fatal; link errors may be resumed. Cancellation of the entire exchange means ending that session, not an implicit safe reconnect.

Six focused tests verify lost-ACK deduplication, replay of unacknowledged output, exact partial-write continuation, sequencing/EOF rejection, buffer/codec bounds, and final-ACK recovery. Real gateway byte forwarding and the real-fux survival scenario also pass with this framing. Automatic reconnect uses the session protocol described below. Final-completion recovery is implemented with retained completed-session records; a session-layer regression verifies lost final-ACK recovery and rejects premature completion. This does not claim final-packet loss through a real relay.

## Session handshake and retention

After TLS peer authorization and admission, the client opens one bidirectional stream. It sends a mode byte (`0` create, `1` resume) followed by a random 32-byte token. The server scopes the token to the authenticated TLS peer. A resume never creates a missing session or opens another application connection. The server replies with one byte: `0` accepted, `1` rejected, `2` busy, or `3` completed followed by a big-endian u64 committed-frame count. Accepted streams continue with resume frames. Handshake reads and terminal replies have bounded deadlines.

There are at most 64 retained sessions, including live, disconnected, failed, and completed records, in addition to the existing 64-connection-task bound. A session has one exclusive active link. Concurrent resumes receive busy and retry; they cannot interleave application writes. Disconnected sessions expire after 30 seconds, and a periodic reaper releases their sockets. Live sessions are protected from expiry while in use. Completed records retain the final committed count for 30 seconds; repeated completion queries do not extend that deadline.

The client retries a detected link loss every 100 ms for up to 30 seconds, with each connection/admission handshake capped at 10 seconds. A successful resume reuses the original local stream and journals. Explicit rejection, invalid protocol, local application failure, or grace expiry ends the attachment. Neither session expiry nor gateway shutdown terminates the underlying fux panes. A gateway process restart loses its in-memory resume registry and requires a fresh fux attachment.

Tests cover authenticated token scoping, missing/expired resume rejection, registry capacity, exclusive active ownership, expired-socket release, forced real QUIC reconnects, and the framing invariants above. Current real runtime evidence is macOS loopback; relay/NAT and platform-wide runtime claims require additional evidence.
