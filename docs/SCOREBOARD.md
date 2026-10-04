# koh's scoreboard

koh beside mosh and plain ssh, made by `testing/scoreboard.sh` (see `testing/bench/README.md` for how each number is taken). Every number is from one run on the machine below; run it again to compare on yours.

- **Commit:** c07bcf7 testing: the oracle, koh at the working tree beside koh at a commit
- **Machine:** AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, 32 threads; Linux 7.2.5-3-omarchy x86_64
- **Date:** 2026-10-04 19:42 UTC
- **Tools:** mosh-server (mosh 1.4.0) [build mosh-1.4.0-dirty]; OpenSSH_10.5p1, OpenSSL 3.6.4 25 Aug 2026; perf version 7.2.3-1

## Bytes on the wire

Each workload played as the program, on a clean link, one step at a time: the harness types for a step, the program writes it, and the step ends when the link has carried nothing for 300 ms. Payload bytes delivered (UDP payloads for koh and mosh, TCP payloads for ssh; no IP, UDP or TCP headers), after the connection's setup, in KiB: to the client / to the server. koh is counted on the fault link of its own tests, which is its only path; mosh and ssh through a proxy on loopback. ssh is as it ships: OpenSSH 9.5 and later obscure keystroke timing by default, sending chaff packets for a while after each key typed, which the harness's key for each step sets off as a user's typing would.

| Workload | Output KiB | koh | mosh | ssh |
| --- | ---: | ---: | ---: | ---: |
| ascii-flood (1 MiB of lines of text, scrolling) | 1024.1 | 1.8 / 0.2 | 3.4 / 0.1 | 1031.5 / 0.3 |
| cursor-motion (256 KiB of numbers written at random places) | 256.0 | 3.8 / 0.2 | 4.7 / 0.1 | 259.3 / 1.9 |
| scroll-region (256 KiB of lines scrolling between a header and a footer) | 256.1 | 1.8 / 0.2 | 2.3 / 0.1 | 262.1 / 4.4 |
| redraw-30fps (the whole screen redrawn 30 times a second for 5 s, as a dashboard does) | 730.1 | 467.1 / 12.5 | 343.3 / 3.4 | 743.5 / 3.0 |
| **the corpus**, 113 recordings | 2898.8 | 676.9 / 182.1 | 483.6 / 127.4 | 6054.9 / 3145.1 |

<details><summary>Each recording</summary>

| Workload | Output KiB | koh | mosh | ssh |
| --- | ---: | ---: | ---: | ---: |
| bash | 0.9 | 4.1 / 3.6 | 3.4 / 2.4 | 59.5 / 58.6 |
| bash-complete | 0.4 | 2.4 / 1.9 | 1.9 / 1.2 | 39.0 / 38.5 |
| bash-history | 0.8 | 2.6 / 2.1 | 2.3 / 1.4 | 39.3 / 38.5 |
| bash-small | 0.3 | 1.5 / 1.4 | 1.4 / 1.0 | 24.5 / 24.2 |
| bat-diff | 5.5 | 1.5 / 0.6 | 1.1 / 0.4 | 16.1 / 10.6 |
| bat-markdown | 14.3 | 1.5 / 0.3 | 0.9 / 0.1 | 17.7 / 3.3 |
| bat-page | 62.4 | 8.4 / 1.2 | 6.7 / 0.8 | 86.2 / 23.3 |
| btop | 191.8 | 4.3 / 0.6 | 3.7 / 0.4 | 200.0 / 6.9 |
| btop-small | 93.3 | 3.3 / 0.7 | 2.5 / 0.4 | 103.9 / 10.0 |
| cargo-build | 1.5 | 0.5 / 0.2 | 0.4 / 0.1 | 5.7 / 4.2 |
| cargo-errors | 2.2 | 1.4 / 0.2 | 0.7 / 0.2 | 5.8 / 3.6 |
| cargo-test | 3.9 | 0.7 / 0.2 | 0.5 / 0.1 | 6.2 / 2.3 |
| clang-errors | 0.7 | 0.7 / 0.2 | 0.5 / 0.1 | 3.0 / 2.3 |
| claude | 10.5 | 1.6 / 0.5 | 2.4 / 0.4 | 18.6 / 8.1 |
| claude-ghostty | 3.0 | 1.5 / 0.6 | 1.3 / 0.4 | 15.7 / 12.7 |
| claude-main | 3.0 | 1.5 / 0.6 | 1.3 / 0.4 | 15.9 / 13.0 |
| claude-resize | 7.9 | 4.8 / 1.1 | 3.0 / 0.7 | 24.0 / 16.3 |
| claude-small | 3.3 | 1.7 / 0.7 | 1.4 / 0.4 | 15.0 / 11.8 |
| delta-diff | 44.3 | 8.4 / 1.0 | 6.9 / 0.7 | 63.4 / 18.8 |
| delta-log | 33.6 | 7.1 / 1.7 | 5.9 / 1.1 | 64.7 / 30.9 |
| delta-show | 5.8 | 2.0 / 0.7 | 1.4 / 1.2 | 19.4 / 13.7 |
| delta-wide | 12.2 | 2.6 / 0.6 | 1.9 / 0.4 | 23.5 / 11.3 |
| emacs-dired | 24.2 | 5.7 / 1.6 | 4.8 / 1.1 | 50.5 / 26.3 |
| emacs-mx | 19.5 | 7.2 / 2.0 | 6.4 / 1.4 | 50.5 / 31.0 |
| emacs-resize | 44.2 | 17.3 / 1.6 | 9.8 / 1.0 | 72.9 / 28.6 |
| emacs-scroll | 29.8 | 11.1 / 1.9 | 10.4 / 1.3 | 62.5 / 32.7 |
| emacs-split | 18.8 | 7.2 / 1.6 | 5.8 / 1.1 | 45.3 / 26.4 |
| fish | 2.7 | 2.2 / 1.8 | 2.0 / 1.2 | 32.6 / 30.2 |
| fish-complete | 3.7 | 3.4 / 2.0 | 2.7 / 1.4 | 38.2 / 34.6 |
| fish-history | 1.8 | 2.3 / 2.0 | 2.0 / 1.6 | 35.2 / 33.5 |
| fish-small | 2.1 | 1.4 / 1.0 | 1.3 / 0.7 | 26.1 / 24.2 |
| fzf | 28.7 | 5.3 / 1.8 | 4.2 / 1.6 | 65.6 / 36.7 |
| fzf-height | 14.8 | 3.6 / 1.5 | 2.4 / 1.0 | 42.5 / 27.6 |
| fzf-multi | 16.6 | 3.4 / 1.6 | 2.8 / 1.1 | 46.9 / 30.3 |
| fzf-preview | 70.8 | 9.2 / 1.6 | 6.1 / 1.3 | 98.7 / 27.4 |
| fzf-small | 4.4 | 1.8 / 1.0 | 1.4 / 0.9 | 21.3 / 16.9 |
| git-add-p | 1.9 | 3.1 / 1.0 | 2.0 / 0.7 | 23.6 / 21.7 |
| git-diff | 5.6 | 2.6 / 0.8 | 2.0 / 0.5 | 20.9 / 15.4 |
| git-graph | 0.9 | 1.0 / 0.5 | 0.7 / 0.9 | 11.1 / 10.3 |
| gls | 1.9 | 0.5 / 0.2 | 0.3 / 0.1 | 3.8 / 1.9 |
| gls-long | 1.5 | 0.7 / 0.2 | 0.4 / 0.1 | 4.6 / 3.1 |
| gls-wide | 4.9 | 0.9 / 0.2 | 0.5 / 0.1 | 7.5 / 2.5 |
| helix | 62.4 | 10.3 / 3.3 | 7.1 / 2.6 | 113.4 / 50.7 |
| helix-picker | 75.5 | 7.9 / 1.5 | 7.0 / 1.0 | 97.2 / 21.2 |
| helix-resize | 199.7 | 23.8 / 2.0 | 14.7 / 1.1 | 227.2 / 26.4 |
| helix-select | 112.3 | 13.7 / 2.9 | 9.8 / 2.2 | 160.9 / 48.0 |
| helix-small | 31.6 | 4.9 / 1.2 | 4.3 / 0.9 | 53.6 / 21.8 |
| helix-unicode | 29.8 | 6.0 / 2.5 | 4.2 / 1.7 | 76.8 / 46.8 |
| htop | 9.4 | 6.4 / 1.6 | 4.4 / 1.1 | 35.0 / 25.6 |
| htop-small | 2.6 | 1.9 / 0.7 | 1.3 / 0.4 | 11.8 / 9.2 |
| htop-tree | 3.9 | 3.3 / 1.0 | 2.1 / 0.7 | 22.8 / 18.9 |
| lazygit | 32.1 | 21.1 / 2.4 | 12.0 / 1.9 | 72.4 / 40.2 |
| lazygit-small | 14.6 | 8.5 / 1.2 | 5.3 / 0.8 | 35.5 / 20.9 |
| lazygit-stage | 28.5 | 14.2 / 2.3 | 8.5 / 2.1 | 69.8 / 41.2 |
| less | 25.7 | 19.0 / 2.4 | 14.9 / 1.7 | 67.2 / 41.5 |
| less-chop | 11.2 | 6.3 / 1.7 | 4.6 / 1.1 | 39.0 / 27.7 |
| less-color | 17.5 | 8.1 / 1.0 | 5.5 / 0.7 | 32.4 / 14.8 |
| less-small | 1.8 | 3.1 / 1.4 | 2.7 / 1.0 | 26.8 / 25.0 |
| man | 8.2 | 4.7 / 1.7 | 4.2 / 1.1 | 37.8 / 29.5 |
| man-long | 22.1 | 11.4 / 1.8 | 9.4 / 1.4 | 61.2 / 39.1 |
| man-small | 2.2 | 2.6 / 1.5 | 2.1 / 1.0 | 25.6 / 23.4 |
| man-tables | 9.1 | 4.9 / 1.2 | 3.6 / 0.8 | 30.3 / 21.2 |
| man-wide | 19.7 | 6.7 / 1.0 | 6.3 / 0.7 | 39.0 / 19.1 |
| mc | 18.9 | 11.2 / 2.7 | 8.8 / 1.8 | 63.0 / 44.0 |
| mc-small | 4.4 | 3.3 / 1.2 | 2.2 / 0.8 | 24.4 / 20.0 |
| micro-edit | 101.3 | 11.4 / 1.9 | 9.1 / 1.5 | 130.6 / 28.8 |
| micro-small | 14.3 | 4.2 / 1.5 | 3.0 / 1.0 | 39.4 / 25.0 |
| micro-split | 84.1 | 13.6 / 1.8 | 7.4 / 1.2 | 116.9 / 32.3 |
| ncdu | 5.8 | 4.5 / 2.2 | 3.7 / 1.5 | 45.5 / 39.7 |
| nnn | 1.4 | 2.7 / 1.7 | 2.3 / 1.1 | 30.0 / 28.7 |
| nnn-detail | 2.2 | 2.8 / 1.4 | 2.1 / 1.0 | 27.3 / 25.0 |
| npm-install | 0.0 | 0.3 / 0.2 | 0.2 / 0.1 | 4.7 / 4.7 |
| nvim-diagnostics | 57.8 | 9.1 / 1.8 | 6.4 / 1.2 | 88.5 / 30.4 |
| nvim-diff | 48.2 | 4.8 / 1.6 | 3.7 / 1.1 | 78.2 / 30.1 |
| nvim-help | 27.6 | 5.4 / 1.5 | 4.0 / 1.0 | 52.4 / 24.7 |
| nvim-insert | 46.2 | 7.4 / 2.7 | 6.5 / 1.8 | 92.8 / 46.4 |
| nvim-netrw | 17.1 | 3.3 / 1.6 | 2.7 / 1.1 | 42.0 / 24.9 |
| nvim-resize | 111.5 | 15.2 / 2.2 | 8.4 / 1.3 | 144.2 / 32.3 |
| nvim-scroll | 85.6 | 10.0 / 2.1 | 8.9 / 1.4 | 122.2 / 36.3 |
| nvim-search | 59.6 | 8.7 / 2.1 | 5.9 / 1.4 | 94.4 / 34.6 |
| nvim-small | 11.2 | 3.6 / 1.7 | 3.2 / 1.1 | 36.1 / 25.0 |
| nvim-split | 52.6 | 10.6 / 1.8 | 7.1 / 1.3 | 86.8 / 34.0 |
| nvim-tabs | 56.0 | 12.3 / 1.4 | 7.9 / 1.0 | 82.7 / 26.5 |
| nvim-terminal | 28.8 | 4.1 / 1.8 | 3.3 / 1.2 | 60.0 / 31.1 |
| nvim-unicode | 17.6 | 4.2 / 2.4 | 3.5 / 1.7 | 66.2 / 48.6 |
| nvim-visual | 35.8 | 9.8 / 3.7 | 6.3 / 2.5 | 102.4 / 66.5 |
| nvim-wide | 93.4 | 12.9 / 1.2 | 5.4 / 0.8 | 118.3 / 24.3 |
| pico | 7.2 | 5.1 / 1.3 | 3.7 / 0.9 | 29.6 / 22.4 |
| ranger | 5.6 | 5.8 / 2.1 | 3.6 / 1.4 | 42.7 / 37.1 |
| tig | 4.6 | 5.0 / 1.7 | 3.3 / 1.1 | 34.7 / 30.1 |
| tig-blame | 20.2 | 8.4 / 1.4 | 4.9 / 1.0 | 40.1 / 19.8 |
| tig-tree | 3.7 | 4.5 / 1.8 | 3.5 / 1.4 | 36.5 / 32.8 |
| tmux | 15.7 | 7.0 / 4.4 | 5.6 / 3.1 | 86.2 / 70.5 |
| tmux-copy | 5.6 | 2.8 / 2.0 | 2.7 / 1.4 | 38.6 / 33.0 |
| tmux-resize | 11.0 | 5.5 / 2.7 | 4.4 / 1.7 | 52.2 / 41.4 |
| tmux-small | 4.9 | 3.4 / 2.1 | 2.7 / 1.4 | 41.2 / 36.4 |
| tmux-vim | 33.7 | 20.6 / 2.5 | 8.6 / 1.7 | 85.1 / 51.4 |
| top | 1.4 | 2.3 / 0.6 | 1.6 / 0.4 | 13.7 / 12.3 |
| vim | 24.9 | 16.9 / 5.0 | 13.2 / 3.4 | 108.6 / 83.6 |
| vim-diff | 18.2 | 4.8 / 1.6 | 3.6 / 1.1 | 50.4 / 32.1 |
| vim-help | 11.8 | 5.8 / 1.4 | 4.3 / 1.0 | 35.9 / 24.1 |
| vim-insert | 12.3 | 8.0 / 2.5 | 5.3 / 1.7 | 53.7 / 41.3 |
| vim-resize | 24.6 | 15.7 / 2.2 | 8.1 / 1.3 | 56.1 / 31.7 |
| vim-small | 11.1 | 7.0 / 1.4 | 5.7 / 1.0 | 35.5 / 24.4 |
| vim-terminal | 17.3 | 2.3 / 1.3 | 1.9 / 0.8 | 35.4 / 18.1 |
| vim-unicode | 11.2 | 5.1 / 2.5 | 3.7 / 1.7 | 58.5 / 47.3 |
| zellij | 117.2 | 4.0 / 1.7 | 3.5 / 1.1 | 141.2 / 23.3 |
| zellij-small | 25.7 | 1.6 / 0.8 | 1.3 / 0.6 | 43.6 / 17.6 |
| zsh | 1.5 | 4.3 / 3.5 | 3.5 / 2.4 | 61.9 / 60.3 |
| zsh-history | 1.5 | 2.9 / 2.1 | 2.3 / 1.4 | 40.4 / 38.9 |
| zsh-menu | 3.5 | 4.6 / 2.6 | 3.4 / 1.8 | 53.2 / 49.6 |
| zsh-resize | 1.5 | 3.6 / 2.0 | 2.6 / 1.5 | 35.8 / 34.5 |
| zsh-small | 0.9 | 1.9 / 1.5 | 1.7 / 1.0 | 32.1 / 31.1 |

</details>

## Keystroke latency beside a flood

A program floods the top row as fast as `awk` can write (its cursor saved and restored around each write) while `cat` echoes what is typed below it; 100 keys are typed 150–250 ms apart, and each is timed from being typed to showing in the user's terminal (a fux-vt parser reading what the client painted): with prediction, as the user sees it. For koh, *echoed* is the time to show on the screen the server sent, prediction aside. Milliseconds, p50 / p99. The delay is one way, each way; loss is each way, per packet. ssh has no figure with loss: a TCP proxy cannot drop without TCP hiding it, which needs a kernel queueing discipline this harness does not use.

| Link | koh | koh, echoed | mosh | ssh |
| --- | ---: | ---: | ---: | ---: |
| clean | 0.1 / 0.2 | 9.9 / 20.2 | 19.0 / 40.1 | 2.3 / 3.3 |
| 50 ms RTT | 0.1 / 53.6 | 66.1 / 78.3 | 70.7 / 89.4 | 69.9 / 100.9 |
| 50 ms RTT, 5% loss | 0.1 / 60.7 | 67.8 / 139.1 | 72.6 / 182.4 | - |

## Server memory per session

What a session's terminal costs the server: a child process makes server emulators at 40x120 with the scrollback given, fills them (or not) with enough lines of text to fill the scrollback and the screen, takes a snapshot of each as a session holds one, and reports how much its resident memory grew, per session. A session also holds a PTY, two threads and its connection, which this does not count.

| Scrollback | Sessions | Idle | Full |
| ---: | ---: | ---: | ---: |
| 1000 | 16 | 240.5 KiB | 1146.0 KiB |
| 65000 | 2 | 478.0 KiB | 58574.0 KiB |

## Instructions

Counted with `perf stat -e instructions:u`, which does not change with the machine's load: each in a child process of its own, the fewest of three runs less the fewest of three baseline runs (making the same inputs, doing nothing with them). *Emulator*: the output fed to the server's emulator in 4 KiB reads, per byte. *Server*: the same, with the snapshot, diff and encoded frame a session's burst takes after every read, per byte: an interactive program's pace, and more than a flood costs, since a session takes one snapshot per burst of up to 65 reads and sends frames at most once per frame interval. *Client*: those frames decoded, applied and painted, per frame.

| Workload | Emulator, per byte | Server, per byte | Client, per frame |
| --- | ---: | ---: | ---: |
| ascii-flood | 18.4 | 1397.0 | 8390806.4 |
| cursor-motion | 53.1 | 2804.6 | 7495542.7 |
| scroll-region | 17.1 | 1394.4 | 7657596.8 |
| redraw-30fps | 22.4 | 1865.8 | 4112270.9 |
| corpus | 54.0 | 738.5 | 2219404.1 |

Load average at the start: 1.20 2.39 2.45; at the end: 1.86 1.25 0.64.
