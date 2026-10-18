ssh bench 'cd ~/crates/ringbuf && sed -i "s/self.head = (self.head + 1) % self.len;/self.head = (self.head + 1) % self.capacity();/" src/lib.rs && cargo test --offline -j 2'
