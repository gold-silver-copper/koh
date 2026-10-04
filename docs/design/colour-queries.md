# Design note: answering colour queries

Status: proposed, not built. Phase 4 of `koh-next-prompt.md` asks for this note before any work.

## What happens today

Programs ask the terminal for its colours to pick a light or dark theme: OSC 11 (background) and
OSC 10 (foreground), sometimes OSC 4 for palette entries. In the corpus, bat, delta, emacs, fish,
nvim, tmux, vim and zellij ask (zellij asks all 256 entries). Since this branch the server's
terminal answers OSC 4 with xterm's default palette (fux-vt's `palette` option), and with the
colours a program set. But OSC 10 and 11 for colours nobody set reach koh as
`Event::ColorQuery`, which koh ignores. A program then waits for its own timeout and guesses.
emacs waits up to `xterm-query-timeout` (2 s), but measured under koh it fell back to
asynchronous handling without a visible delay. bat and delta assume dark, so a light terminal
gets a dark theme.

## Design

- **The client asks once.** At start-up, in `client::probe`, before DA1: `OSC 10 ; ?`, `OSC 11 ;
  ?`, and `OSC 4 ; n ; ?` for entries 0 to 15 (the ones themes change). It reads the answers
  (`rgb:RRRR/GGGG/BBBB`, ended by BEL or ST) out of stdin, as it reads the underline-style answers
  now. A terminal that answers none leaves the program's queries unanswered, as today.
- **The client tells the server.** A new `ClientMsg::Colours { foreground, background, palette }`
  goes once after connecting, with each colour optional and 8 bits a channel. Decoding refuses
  more than 16 entries. Every reconnect sends it again, so a client on another terminal that
  reattaches brings its own colours.
- **The server answers from them.** The session keeps the last colours it was told, and
  `ServerTerminal`'s sink answers `Event::ColorQuery { number, bel }` for 10 and 11 from them, in
  the form xterm uses, with the terminator the program used. The answer goes to the program's
  input like every other reply, after anything typed before. Palette entries the program set are
  still answered with those, by fux-vt.
- **Scheme changes.** With fux-vt's `color_scheme_updates` option (mode 2031) on, a program can
  subscribe. The client turns 2031 on in the user's terminal. On its report (`CSI ? 997 ; 1|2 n`)
  the client asks the colours again and sends `Colours` again, and the server sends a subscribed
  program the report. That is a second step and can follow the first.

## Wire

One new client message, bounded: at most 2 + 16 colours of 3 bytes. Nothing changes in frames.
koh/3 changes in place while it is unreleased; after a release this needs a new ALPN.

## Threat model

- **What it tells the server:** the client tells the server the user's terminal colours, which
  is new. It's a small fingerprint (a theme) given to a server the user chose to connect to. It
  could be turned off with a flag (`--no-colours`) if wanted; my proposal is on by default, with
  the flag.
- **No new path into the user's terminal:** the server's answers go to the program, never to the
  user's terminal. Nothing a server or program sends makes the client ask its terminal anything:
  the client asks once, at start-up, and again only when its own terminal reports a scheme
  change.
- **No amplification:** a program that asks a thousand times gets a thousand answers from the
  server's copy. The client's terminal is never asked again for them.

## Prediction

None: colour queries and their answers are not typed input.

## How to test it

- **The probe:** answers in `rgb:R/G/B` with 1 to 4 hex digits a channel, BEL and ST terminators,
  split reads, a terminal that answers only some, and keys typed between answers.
- **The server:** a query for 10 or 11 is answered from the client's colours with the program's
  terminator, and left unanswered with none. A colour the program set wins. A reattaching
  client's colours replace the last.
- **The corpus:** the recordings' `replies` field holds the answers fux gave (a fixed dark
  scheme). Fed the same colours, the server must give the same answers to the recordings'
  queries.
- **End to end:** nvim sets `'background'` from OSC 11. Under koh with a light background
  answered, `:set background?` must show `light`, and with a dark one `dark`. bat's theme
  choice is a second check.
- **The oracle:** exempt OSC 10 and 11 queries (already exempt as palette sequences) until the
  base answers them.
