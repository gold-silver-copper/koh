# Design note: the kitty keyboard protocol

Status: proposed, not built. Phase 4 of `koh-next-prompt.md` asks for this note before any work.

## What happens today

koh forwards the bytes the user's terminal sends for each key, as they come. The server's
terminal has fux-vt's `kitty_keyboard` option off, so a program's `CSI > flags u` (push),
`CSI < u` (pop) and `CSI ? u` (query) are ignored, and the query goes unanswered. Programs that ask
first (nvim, helix, fish, lazygit and claude in the corpus all push or set flags) see no answer
and keep to legacy keys. They cannot tell `Ctrl-I` from `Tab`, `Ctrl-[` from `Escape`, or see key
releases. Turning the option on as it stands would be wrong: a program told it may use the
protocol would get the legacy keys the user's terminal still sends.

## The choice: mirror the flags, or encode on the server

**Mirroring** (what the prompt sketches) sets the user's terminal's flags to the program's (`CSI =
flags ; 1 u`) whenever they change, and keeps forwarding bytes. It is small, but it breaks on
reattach: a session outlives its client, and a client on a terminal without the protocol (Apple's
Terminal, xterm) can reattach to a program that pushed flags. That terminal cannot send what the
program expects, and nothing can fix it from the client side.

**Encoding on the server** (what fux does for each pane) holds whichever terminal attaches. The
client decodes what the user's terminal sends into key events: a key, its modifiers, and press,
repeat or release, as the terminal reported them (legacy bytes, modifyOtherKeys, or kitty's).
The server encodes each event as the program's current mode asks: kitty flags, modifyOtherKeys,
cursor-key and keypad modes. A program that pushed flags gets kitty's encoding from any client,
and a legacy program gets legacy bytes from a kitty terminal.

**Recommendation: encode on the server.** It is the only design that survives reattach, and it
also removes the cursor-key mode the client mirrors today.

## Wire

- `ClientMsg::Input` keeps carrying bytes, for pastes (bracketed paste stays byte-exact) and for
  anything the decoder does not know. A new `ClientMsg::Keys { seq, events }` carries decoded
  keys. Both share the input sequence numbers, so ordering and echo-ack are unchanged.
- An event is a key code (a Unicode scalar or one of kitty's functional keys), a modifier mask,
  and its kind. Decoding refuses unknown codes and masks, as it refuses unknown style bits.
- `WireModes` gains nothing: the server encodes, so the client no longer needs the program's
  keyboard modes.
- The client asks its terminal for the protocol at start-up (`CSI ? u` before DA1, in
  `client::probe`), and pushes disambiguate-and-alternates (`CSI > 5 u`) if it is there, as fux
  does. It pops on exit and on suspend. Without it, the client decodes legacy input.

koh/3 changes in place while it is unreleased; after a release this needs a new ALPN.

## Threat model

- The server learns the same thing it learns today, which keys were pressed, and no more: key
  releases are only asked for if the program pushed that flag.
- The client's decoder reads only the user's terminal, never server bytes. It is bounded: one
  pending escape sequence at most, given back as bytes past a length limit, as `client::probe`
  does.
- What the client sends its terminal (one push at start, one pop at exit) is fixed. Nothing a
  server sends changes the user's terminal's keyboard flags, so none are left set when the client
  exits.

## Prediction

`predict.rs` reads raw bytes today: printables, backspace, CR, the arrow keys in their CSI and SS3
forms, Home and End, and the line editor's keys (`Ctrl-W`, `Ctrl-U`, `Ctrl-A`, `Ctrl-E`,
`Alt-Backspace`, `Alt-B`, `Alt-F`), reading an escape sequence whole, parameters and all. With
events it reads keys instead, which is simpler, because there is one form of each key (`Alt-B` is
`b` with Alt, whatever the terminal sent), and it stops mistaking kitty's encoded keys for unknown
sequences. The PTY's modes, which the client now learns for the predictor (echo and line mode),
do not bear on the encoding. Key releases and pure
modifier presses predict nothing. The predictor's epoch rules do not change.

## How to test it

- **Decoder:** property tests that legacy bytes decode to events and encode back to the same
  bytes; kitty's own encodings for every functional key and modifier; split reads.
- **Encoder:** fux-vt has the program's flag stack (`Screen::kitty_keyboard_flags`,
  `Screen::modify_other_keys`). For each mode, an event encodes as kitty's spec and xterm's
  ctlseqs say. fux's `encode` tests are the reference, and can be ported.
- **Corpus:** fux's recordings were made with keys typed this way (`corpus/keys/*.keys`, encoded
  in the mode the program asked for). Replaying a recording's keys through the decoder and encoder
  must give the bytes the recording's program read.
- **End to end:** nvim (installed here) pushes flags; under koh, `Ctrl-I` and `Tab` must reach it
  as different keys (`:map` them to different commands and look at the screen), from a client
  whose terminal speaks the protocol and from one that does not.
- **The oracle:** exempt keys sent to a program that pushed flags, until the base has this.
