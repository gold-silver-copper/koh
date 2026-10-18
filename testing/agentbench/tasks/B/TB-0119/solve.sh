ssh bench 'set -e; cd ~/crates/stampede; cargo build --release --offline -j 2
  v=$(./target/release/stampede --version | cut -d" " -f2)
  rm -rf ~/stage; mkdir -p ~/stage/stampede-$v/bin ~/dist
  cp target/release/stampede ~/stage/stampede-$v/bin/; cp README.md LICENSE ~/stage/stampede-$v/
  tar -C ~/stage -czf ~/dist/stampede-$v-linux.tar.gz stampede-$v
  cd ~/dist && sha256sum stampede-$v-linux.tar.gz > SHA256SUMS'
mkdir -p dist
scp -q 'bench:dist/*' dist/
