# koh's scoreboard

koh beside mosh and plain ssh, made by `testing/scoreboard.sh` (see `testing/bench/README.md` for how each number is taken). Every number is from one run on the machine below; run it again to compare on yours.

- **Commit:** 3c4478d server: finding frames costs the emulator less (this branch)
- **Machine:** AMD RYZEN AI MAX+ 395 w/ Radeon 8060S, 32 threads; Linux 7.2.5-3-omarchy x86_64
- **Date:** 2026-10-04 22:26 UTC
- **Tools:** mosh-server (mosh 1.4.0) [build mosh-1.4.0-dirty]; OpenSSH_10.5p1, OpenSSL 3.6.4 25 Aug 2026; perf version 7.2.3-1

## Bytes on the wire

Each workload played as the program, on a clean link, one step at a time: the harness types for a step, the program writes it, and the step ends when the link has carried nothing for 300 ms. Payload bytes delivered (UDP payloads for koh and mosh, TCP payloads for ssh; no IP, UDP or TCP headers), after the connection's setup, in KiB: to the client / to the server. koh is counted on the fault link of its own tests, which is its only path; mosh and ssh through a proxy on loopback. ssh is as it ships: OpenSSH 9.5 and later obscure keystroke timing by default, sending chaff packets for a while after each key typed, which the harness's key for each step sets off as a user's typing would.

| Workload | Output KiB | koh | mosh | ssh |
| --- | ---: | ---: | ---: | ---: |
| ascii-flood (1 MiB of lines of text, scrolling) | 1024.1 | 1.9 / 0.2 | 3.4 / 0.1 | 1032.1 / 0.3 |
| cursor-motion (256 KiB of numbers written at random places) | 256.0 | 3.9 / 0.2 | 4.7 / 0.1 | 262.5 / 4.4 |
| scroll-region (256 KiB of lines scrolling between a header and a footer) | 256.1 | 1.9 / 0.2 | 2.3 / 0.1 | 263.0 / 5.3 |
| redraw-30fps (the whole screen redrawn 30 times a second for 5 s, as a dashboard does) | 730.1 | 467.4 / 12.7 | 343.5 / 3.4 | 743.1 / 2.7 |
| **the corpus**, 113 recordings | 2898.8 | 688.0 / 182.2 | 483.5 / 127.0 | 6018.8 / 3109.3 |

<details><summary>Each recording</summary>

| Workload | Output KiB | koh | mosh | ssh |
| --- | ---: | ---: | ---: | ---: |
| bash | 0.9 | 4.1 / 3.5 | 3.4 / 2.3 | 67.9 / 67.0 |
| bash-complete | 0.4 | 2.4 / 1.9 | 2.0 / 1.2 | 36.1 / 35.7 |
| bash-history | 0.8 | 2.7 / 2.1 | 2.3 / 1.4 | 38.2 / 37.4 |
| bash-small | 0.3 | 1.6 / 1.4 | 1.4 / 1.0 | 24.3 / 24.0 |
| bat-diff | 5.5 | 1.5 / 0.6 | 1.1 / 0.4 | 17.5 / 12.0 |
| bat-markdown | 14.3 | 1.5 / 0.2 | 0.9 / 0.1 | 18.1 / 3.7 |
| bat-page | 62.4 | 8.5 / 1.2 | 6.6 / 0.8 | 78.6 / 15.8 |
| btop | 191.8 | 4.3 / 0.6 | 3.7 / 0.4 | 203.7 / 10.6 |
| btop-small | 93.3 | 3.4 / 0.7 | 2.5 / 0.4 | 104.0 / 10.2 |
| cargo-build | 1.5 | 0.5 / 0.2 | 0.4 / 0.1 | 6.3 / 4.8 |
| cargo-errors | 2.2 | 1.4 / 0.2 | 0.7 / 0.1 | 6.4 / 4.3 |
| cargo-test | 3.9 | 0.7 / 0.2 | 0.5 / 0.1 | 7.3 / 3.4 |
| clang-errors | 0.7 | 0.7 / 0.2 | 0.5 / 0.1 | 4.7 / 4.0 |
| claude | 10.5 | 1.7 / 0.6 | 2.4 / 0.4 | 19.6 / 9.1 |
| claude-ghostty | 3.0 | 1.7 / 0.6 | 1.3 / 0.4 | 13.9 / 10.9 |
| claude-main | 3.0 | 1.6 / 0.6 | 1.3 / 0.4 | 12.4 / 9.5 |
| claude-resize | 7.9 | 5.1 / 1.1 | 3.0 / 0.7 | 27.0 / 19.3 |
| claude-small | 3.3 | 1.7 / 0.6 | 1.4 / 0.4 | 13.7 / 10.5 |
| delta-diff | 44.3 | 8.8 / 1.0 | 6.9 / 0.7 | 63.0 / 18.4 |
| delta-log | 33.6 | 7.3 / 1.7 | 5.8 / 1.1 | 64.0 / 30.2 |
| delta-show | 5.8 | 2.0 / 0.7 | 1.4 / 1.1 | 22.9 / 17.2 |
| delta-wide | 12.2 | 2.6 / 0.6 | 1.9 / 0.4 | 23.7 / 11.4 |
| emacs-dired | 24.2 | 5.8 / 1.6 | 4.8 / 1.1 | 52.5 / 28.3 |
| emacs-mx | 19.5 | 7.2 / 2.0 | 6.4 / 1.4 | 58.5 / 39.0 |
| emacs-resize | 44.2 | 17.5 / 1.7 | 9.8 / 1.0 | 66.8 / 22.6 |
| emacs-scroll | 29.8 | 11.1 / 1.8 | 10.4 / 1.3 | 59.5 / 29.7 |
| emacs-split | 18.8 | 7.3 / 1.6 | 5.8 / 1.1 | 45.9 / 27.1 |
| fish | 2.7 | 2.2 / 1.8 | 2.0 / 1.3 | 34.2 / 31.8 |
| fish-complete | 3.7 | 3.4 / 2.0 | 2.7 / 1.4 | 35.1 / 31.5 |
| fish-history | 1.8 | 2.3 / 2.0 | 2.0 / 1.5 | 34.9 / 33.2 |
| fish-small | 2.1 | 1.4 / 1.0 | 1.3 / 0.7 | 17.1 / 15.2 |
| fzf | 28.7 | 5.4 / 1.8 | 4.2 / 1.6 | 50.8 / 21.9 |
| fzf-height | 14.8 | 3.6 / 1.5 | 2.4 / 0.9 | 38.1 / 23.3 |
| fzf-multi | 16.6 | 3.6 / 1.7 | 2.8 / 1.1 | 42.8 / 26.1 |
| fzf-preview | 70.8 | 9.4 / 1.6 | 6.1 / 1.3 | 93.5 / 22.2 |
| fzf-small | 4.4 | 1.9 / 1.0 | 1.3 / 0.9 | 23.7 / 19.3 |
| git-add-p | 1.9 | 3.1 / 1.0 | 2.0 / 0.7 | 18.8 / 16.8 |
| git-diff | 5.6 | 2.6 / 0.9 | 2.0 / 0.6 | 19.0 / 13.4 |
| git-graph | 0.9 | 1.0 / 0.5 | 0.6 / 0.9 | 7.4 / 6.6 |
| gls | 1.9 | 0.8 / 0.2 | 0.3 / 0.2 | 4.9 / 3.1 |
| gls-long | 1.5 | 0.8 / 0.2 | 0.4 / 0.1 | 5.5 / 4.0 |
| gls-wide | 4.9 | 1.6 / 0.2 | 0.5 / 0.1 | 9.6 / 4.6 |
| helix | 62.4 | 10.4 / 3.2 | 7.1 / 2.6 | 117.6 / 54.9 |
| helix-picker | 75.5 | 7.9 / 1.4 | 7.1 / 1.0 | 100.3 / 24.2 |
| helix-resize | 199.7 | 24.3 / 2.0 | 14.7 / 1.1 | 234.4 / 33.7 |
| helix-select | 112.3 | 13.7 / 2.8 | 9.8 / 2.2 | 168.0 / 55.1 |
| helix-small | 31.6 | 4.9 / 1.3 | 4.3 / 0.8 | 60.2 / 28.4 |
| helix-unicode | 29.8 | 6.0 / 2.5 | 4.2 / 1.7 | 75.9 / 45.9 |
| htop | 9.4 | 6.5 / 1.6 | 4.4 / 1.1 | 36.6 / 27.2 |
| htop-small | 2.6 | 2.0 / 0.7 | 1.3 / 0.4 | 11.7 / 9.1 |
| htop-tree | 3.9 | 3.4 / 1.0 | 2.1 / 0.7 | 18.1 / 14.2 |
| lazygit | 32.1 | 21.5 / 2.5 | 12.0 / 1.9 | 78.2 / 46.0 |
| lazygit-small | 14.6 | 8.7 / 1.2 | 5.3 / 0.8 | 33.4 / 18.8 |
| lazygit-stage | 28.5 | 14.5 / 2.3 | 8.5 / 2.0 | 75.7 / 47.1 |
| less | 25.7 | 19.6 / 2.4 | 14.9 / 1.6 | 63.9 / 38.2 |
| less-chop | 11.2 | 6.5 / 1.7 | 4.6 / 1.1 | 33.3 / 22.1 |
| less-color | 17.5 | 8.0 / 1.0 | 5.5 / 0.7 | 35.0 / 17.4 |
| less-small | 1.8 | 3.3 / 1.5 | 2.7 / 1.0 | 25.6 / 23.8 |
| man | 8.2 | 4.8 / 1.7 | 4.2 / 1.1 | 40.1 / 31.8 |
| man-long | 22.1 | 11.7 / 1.9 | 9.3 / 1.4 | 50.1 / 27.9 |
| man-small | 2.2 | 2.6 / 1.5 | 2.1 / 1.0 | 26.0 / 23.9 |
| man-tables | 9.1 | 5.0 / 1.3 | 3.6 / 0.8 | 27.5 / 18.3 |
| man-wide | 19.7 | 6.8 / 1.0 | 6.3 / 0.7 | 38.7 / 18.8 |
| mc | 18.9 | 11.2 / 2.7 | 8.8 / 1.8 | 68.9 / 49.9 |
| mc-small | 4.4 | 3.4 / 1.3 | 2.2 / 0.9 | 26.4 / 22.0 |
| micro-edit | 101.3 | 11.4 / 1.8 | 9.1 / 1.5 | 130.9 / 29.1 |
| micro-small | 14.3 | 4.2 / 1.4 | 3.0 / 1.0 | 42.8 / 28.4 |
| micro-split | 84.1 | 13.9 / 1.9 | 7.3 / 1.3 | 111.4 / 26.8 |
| ncdu | 5.8 | 4.5 / 2.3 | 3.7 / 1.6 | 37.6 / 31.9 |
| nnn | 1.4 | 2.8 / 1.7 | 2.3 / 1.1 | 27.4 / 26.1 |
| nnn-detail | 2.2 | 2.9 / 1.5 | 2.0 / 1.0 | 24.9 / 22.6 |
| npm-install | 0.0 | 0.2 / 0.2 | 0.2 / 0.1 | 2.3 / 2.3 |
| nvim-diagnostics | 57.8 | 9.1 / 1.8 | 6.5 / 1.3 | 90.2 / 32.1 |
| nvim-diff | 48.2 | 4.9 / 1.7 | 3.7 / 1.1 | 76.1 / 27.7 |
| nvim-help | 27.6 | 6.2 / 1.5 | 4.0 / 1.0 | 56.3 / 28.6 |
| nvim-insert | 46.2 | 7.5 / 2.7 | 6.5 / 1.8 | 96.2 / 49.9 |
| nvim-netrw | 17.1 | 3.2 / 1.6 | 2.7 / 1.1 | 40.1 / 23.0 |
| nvim-resize | 111.5 | 15.4 / 2.1 | 8.4 / 1.3 | 148.3 / 36.6 |
| nvim-scroll | 85.6 | 10.1 / 2.1 | 8.9 / 1.4 | 119.9 / 33.9 |
| nvim-search | 59.6 | 8.6 / 2.0 | 5.9 / 1.4 | 99.2 / 39.4 |
| nvim-small | 11.2 | 3.5 / 1.6 | 3.2 / 1.1 | 40.8 / 29.7 |
| nvim-split | 52.6 | 10.7 / 1.9 | 7.1 / 1.3 | 80.2 / 27.5 |
| nvim-tabs | 56.0 | 12.5 / 1.5 | 7.9 / 1.0 | 80.2 / 23.9 |
| nvim-terminal | 28.8 | 4.2 / 1.8 | 3.2 / 1.3 | 63.0 / 34.2 |
| nvim-unicode | 17.6 | 4.2 / 2.4 | 3.5 / 1.7 | 62.0 / 44.4 |
| nvim-visual | 35.8 | 10.0 / 3.7 | 6.3 / 2.5 | 102.4 / 66.5 |
| nvim-wide | 93.4 | 13.0 / 1.2 | 5.4 / 0.8 | 114.8 / 20.8 |
| pico | 7.2 | 5.1 / 1.2 | 3.8 / 0.9 | 22.6 / 15.4 |
| ranger | 5.6 | 5.9 / 2.1 | 3.5 / 1.4 | 44.7 / 39.1 |
| tig | 4.6 | 5.0 / 1.6 | 3.4 / 1.1 | 34.2 / 29.5 |
| tig-blame | 20.2 | 8.5 / 1.4 | 4.9 / 1.0 | 51.3 / 30.9 |
| tig-tree | 3.7 | 4.5 / 1.9 | 3.5 / 1.5 | 32.4 / 28.7 |
| tmux | 15.7 | 7.0 / 4.2 | 5.6 / 3.1 | 93.1 / 77.4 |
| tmux-copy | 5.6 | 2.9 / 2.1 | 2.6 / 1.4 | 36.5 / 30.9 |
| tmux-resize | 11.0 | 5.6 / 2.7 | 4.3 / 1.7 | 58.8 / 48.1 |
| tmux-small | 4.9 | 3.5 / 2.1 | 2.7 / 1.4 | 41.1 / 36.3 |
| tmux-vim | 33.7 | 20.9 / 2.4 | 8.6 / 1.7 | 77.6 / 43.9 |
| top | 1.4 | 2.3 / 0.6 | 1.7 / 0.4 | 12.5 / 11.1 |
| vim | 24.9 | 17.0 / 5.0 | 13.2 / 3.3 | 115.1 / 90.1 |
| vim-diff | 18.2 | 4.8 / 1.6 | 3.6 / 1.1 | 45.8 / 27.5 |
| vim-help | 11.8 | 5.9 / 1.4 | 4.3 / 1.0 | 35.9 / 24.0 |
| vim-insert | 12.3 | 8.1 / 2.5 | 5.2 / 1.6 | 55.9 / 43.5 |
| vim-resize | 24.6 | 15.9 / 2.1 | 8.1 / 1.3 | 58.7 / 34.3 |
| vim-small | 11.1 | 7.1 / 1.5 | 5.7 / 1.0 | 36.3 / 25.2 |
| vim-terminal | 17.3 | 2.2 / 1.2 | 1.9 / 0.8 | 34.9 / 17.6 |
| vim-unicode | 11.2 | 5.1 / 2.5 | 3.6 / 1.7 | 54.9 / 43.6 |
| zellij | 117.2 | 4.3 / 1.8 | 3.5 / 1.1 | 150.0 / 32.0 |
| zellij-small | 25.7 | 1.7 / 0.9 | 1.3 / 0.5 | 38.0 / 12.1 |
| zsh | 1.5 | 4.3 / 3.5 | 3.5 / 2.4 | 61.1 / 59.6 |
| zsh-history | 1.5 | 2.9 / 2.1 | 2.3 / 1.4 | 29.3 / 27.7 |
| zsh-menu | 3.5 | 4.5 / 2.6 | 3.3 / 1.8 | 56.2 / 52.6 |
| zsh-resize | 1.5 | 3.7 / 2.0 | 2.6 / 1.5 | 31.2 / 30.0 |
| zsh-small | 0.9 | 1.9 / 1.5 | 1.7 / 1.0 | 26.0 / 25.0 |

</details>

## Keystroke latency beside a flood

A program floods the top row as fast as `awk` can write (its cursor saved and restored around each write) while `cat` echoes what is typed below it; 100 keys are typed 150–250 ms apart, and each is timed from being typed to showing in the user's terminal (a fux-vt parser reading what the client painted): with prediction, as the user sees it. For koh, *echoed* is the time to show on the screen the server sent, prediction aside. Milliseconds, p50 / p99. The delay is one way, each way; loss is each way, per packet. ssh has no figure with loss: a TCP proxy cannot drop without TCP hiding it, which needs a kernel queueing discipline this harness does not use.

| Link | koh | koh, echoed | mosh | ssh |
| --- | ---: | ---: | ---: | ---: |
| clean | 0.1 / 0.2 | 9.9 / 20.1 | 18.0 / 39.6 | 3.3 / 3.5 |
| 50 ms RTT | 0.1 / 61.1 | 66.2 / 79.9 | 72.5 / 88.1 | 69.7 / 107.3 |
| 50 ms RTT, 5% loss | 0.1 / 59.8 | 70.6 / 148.1 | 74.6 / 181.4 | - |

## Server memory per session

What a session's terminal costs the server: a child process makes server emulators at 40x120 with the scrollback given, fills them (or not) with enough lines of text to fill the scrollback and the screen, takes a snapshot of each as a session holds one, and reports how much its resident memory grew, per session. A session also holds a PTY, two threads and its connection, which this does not count.

| Scrollback | Sessions | Idle | Full |
| ---: | ---: | ---: | ---: |
| 1000 | 16 | 241.2 KiB | 1146.2 KiB |
| 65000 | 2 | 542.0 KiB | 58510.0 KiB |

## Instructions

Counted with `perf stat -e instructions:u`, which does not change with the machine's load: each in a child process of its own, the fewest of three runs less the fewest of three baseline runs (making the same inputs, doing nothing with them). *Emulator*: the output fed to the server's emulator in 4 KiB reads, per byte. *Server*: the same, with the snapshot, diff and encoded frame a session's burst takes after every read, per byte: an interactive program's pace, and more than a flood costs, since a session takes one snapshot per burst of up to 65 reads and sends frames at most once per frame interval. *Client*: those frames decoded, applied and painted, per frame.

| Workload | Emulator, per byte | Server, per byte | Client, per frame |
| --- | ---: | ---: | ---: |
| ascii-flood | 24.4 | 1476.5 | 9244402.5 |
| cursor-motion | 70.3 | 2841.7 | 8040012.3 |
| scroll-region | 23.2 | 1473.3 | 8461431.0 |
| redraw-30fps | 31.0 | 1917.0 | 4534889.3 |
| corpus | 97.0 | 784.9 | 2479667.4 |

Load average at the start: 5.85 3.03 2.02; at the end: 1.81 1.10 0.57.
