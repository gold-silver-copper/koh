//! Proxies that carry mosh's UDP and ssh's TCP between client and server on loopback, delaying
//! and (UDP only) dropping as a link profile says, and counting what they deliver each way: the
//! same count the fault link keeps for koh, payload bytes and packets (datagrams for UDP, the
//! chunks one read returned for TCP).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Packets and bytes delivered one way.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Count {
    pub packets: u64,
    pub bytes: u64,
}

impl Count {
    fn add(&mut self, bytes: usize) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }
}

/// What a link does to each packet, each way.
#[derive(Clone, Copy, Debug, Default)]
pub struct Profile {
    pub delay: Duration,
    pub loss: f64,
    /// Each direction's bandwidth in bits a second, if limited (a 100 ms buffer).
    pub rate: Option<u64>,
}

/// What the proxy delivered: to the server, to the client.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub to_server: Count,
    pub to_client: Count,
}

#[derive(Default)]
struct State {
    counts: Counts,
    rng: u64,
}

impl State {
    /// True with probability `p`, from a seeded sequence (splitmix64).
    fn chance(&mut self, p: f64) -> bool {
        self.rng = self.rng.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let unit = f64::from(u32::try_from(z >> 32).unwrap_or(u32::MAX)) / 4_294_967_296.0;
        unit < p
    }
}

/// A running proxy: the address clients dial, and its counts.
pub struct Proxy {
    pub addr: SocketAddr,
    state: Arc<Mutex<State>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Proxy {
    pub fn counts(&self) -> Counts {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .counts
    }

    /// Carry UDP between whoever sends to [`Proxy::addr`] and `server`.
    pub async fn udp(server: SocketAddr, profile: Profile, seed: u64) -> std::io::Result<Self> {
        let outer = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let inner = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        inner.connect(server).await?;
        let state = Arc::new(Mutex::new(State {
            rng: seed,
            ..State::default()
        }));
        let client: Arc<Mutex<Option<SocketAddr>>> = Arc::default();
        let up = {
            let (outer, inner, state, client) =
                (outer.clone(), inner.clone(), state.clone(), client.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                while let Ok((len, from)) = outer.recv_from(&mut buf).await {
                    *client.lock().unwrap_or_else(PoisonError::into_inner) = Some(from);
                    let data = buf.get(..len).unwrap_or_default().to_vec();
                    {
                        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
                        if state.chance(profile.loss) {
                            continue;
                        }
                        state.counts.to_server.add(len);
                    }
                    let inner = inner.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(profile.delay).await;
                        let _ = inner.send(&data).await;
                    });
                }
            })
        };
        let down = {
            let (outer, inner, state, client) =
                (outer.clone(), inner.clone(), state.clone(), client);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                while let Ok(len) = inner.recv(&mut buf).await {
                    let Some(to) = *client.lock().unwrap_or_else(PoisonError::into_inner) else {
                        continue;
                    };
                    let data = buf.get(..len).unwrap_or_default().to_vec();
                    {
                        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
                        if state.chance(profile.loss) {
                            continue;
                        }
                        state.counts.to_client.add(len);
                    }
                    let outer = outer.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(profile.delay).await;
                        let _ = outer.send_to(&data, to).await;
                    });
                }
            })
        };
        Ok(Self {
            addr: outer.local_addr()?,
            state,
            tasks: vec![up, down],
        })
    }

    /// Carry TCP connections to [`Proxy::addr`] on to `server`, delayed. TCP's own retransmission
    /// would hide a drop, so a TCP proxy never drops.
    pub async fn tcp(server: SocketAddr, delay: Duration) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let state = Arc::new(Mutex::new(State::default()));
        let accept = {
            let state = state.clone();
            tokio::spawn(async move {
                while let Ok((client, _)) = listener.accept().await {
                    let Ok(upstream) = TcpStream::connect(server).await else {
                        continue;
                    };
                    let _ = client.set_nodelay(true);
                    let _ = upstream.set_nodelay(true);
                    let (cr, cw) = client.into_split();
                    let (ur, uw) = upstream.into_split();
                    tokio::spawn(pump(cr, uw, delay, state.clone(), true));
                    tokio::spawn(pump(ur, cw, delay, state.clone(), false));
                }
            })
        };
        Ok(Self {
            addr,
            state,
            tasks: vec![accept],
        })
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Copy `from` to `to`, each chunk `delay` later, counting it as delivered when it is written.
/// A bounded queue between, so a sender faster than the link is held back, as TCP holds it.
async fn pump(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
    state: Arc<Mutex<State>>,
    to_server: bool,
) {
    let (tx, mut rx) = mpsc::channel::<(Instant, Vec<u8>)>(64);
    let writer = tokio::spawn(async move {
        while let Some((at, data)) = rx.recv().await {
            tokio::time::sleep_until(at).await;
            if to.write_all(&data).await.is_err() {
                break;
            }
            let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
            let count = if to_server {
                &mut state.counts.to_server
            } else {
                &mut state.counts.to_client
            };
            count.add(data.len());
        }
        let _ = to.shutdown().await;
    });
    let mut buf = vec![0u8; 65_536];
    while let Ok(len) = from.read(&mut buf).await {
        if len == 0 {
            break;
        }
        let at = Instant::now()
            .checked_add(delay)
            .unwrap_or_else(Instant::now);
        if tx
            .send((at, buf.get(..len).unwrap_or_default().to_vec()))
            .await
            .is_err()
        {
            break;
        }
    }
    drop(tx);
    let _ = writer.await;
}
