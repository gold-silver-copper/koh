ssh bench 'cd ~/crates/ringbuf && cargo test --offline -q 2>&1 | sed -n "s/^---- \(.*\) stdout ----$/\1/p"' > answer.txt
ssh bench 'cd ~/crates/ringbuf && sed -i "s/(self.head + i) % self.len\]/(self.head + i) % self.capacity()]/" src/lib.rs && cargo test --offline -q'
