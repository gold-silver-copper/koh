//! A fault-injecting network for iroh endpoints, below QUIC.
//!
//! An endpoint bound with [`FaultNet::endpoint`] has no IP and no relay transport: its only path
//! is this link in the test's own process, so every packet between two of them passes through
//! it and nothing can route around it. The link loses, delays, jitters, duplicates and holds
//! back packets, limits each direction's rate behind a buffer, drops everything for an
//! interval, and counts what it did to the packets for each endpoint.
//!
//! What it does to a packet is decided by a generator seeded for the endpoint the packet goes
//! to: the n-th packet towards an endpoint meets the same fate in every run of one seed.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use iroh::endpoint::presets;
use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use iroh_base::CustomAddr;
use tokio::sync::{Notify, mpsc};
use tokio::time::Instant;

/// This transport's number among iroh's custom addresses ("koh").
const TRANSPORT_ID: u64 = 0x006b_6f68;

/// The packets that wait for an endpoint to read them. A full inbox drops the next packet.
const INBOX: usize = 8192;

/// What the link does to each packet, each way.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    /// How likely a packet is lost.
    pub loss: f64,
    /// How long a packet takes one way, before jitter.
    pub delay: Duration,
    /// The delay varies evenly by up to this much either way. A packet does not overtake the
    /// one before it for that: only one that is held back is overtaken.
    pub jitter: Duration,
    /// How likely a packet arrives twice.
    pub dup: f64,
    /// How likely a packet is held back, by `delay + jitter` more and at least 5 ms, so that
    /// those sent after it arrive before it.
    pub reorder: f64,
    /// Each direction's bits a second, if limited: a packet waits its turn behind those before
    /// it, and is dropped if it would wait longer than `queue`.
    pub rate: Option<u64>,
    /// The longest a packet waits for a limited link before it is dropped: the bottleneck's
    /// buffer.
    pub queue: Duration,
}

impl Profile {
    /// The four links of koh's old scoreboard beside a clean one: 25 ms each way; that with 5%
    /// of the packets lost; and 1 Mbit/s and 256 kbit/s, each 25 ms each way behind a buffer of
    /// 100 ms.
    pub fn named(name: &str) -> Profile {
        let delay = Duration::from_millis(25);
        let slow = |rate| Profile {
            delay,
            rate: Some(rate),
            queue: Duration::from_millis(100),
            ..Profile::default()
        };
        match name {
            "clean" => Profile::default(),
            "25ms" => Profile {
                delay,
                ..Profile::default()
            },
            "25ms-5%" => Profile {
                delay,
                loss: 0.05,
                ..Profile::default()
            },
            "1Mbit" => slow(1_000_000),
            "256kbit" => slow(256_000),
            // A link that delivers some packets twice and some late, behind those sent after.
            "dup-reorder" => Profile {
                delay: Duration::from_millis(10),
                jitter: Duration::from_millis(5),
                dup: 0.10,
                reorder: 0.10,
                ..Profile::default()
            },
            other => panic!("no link profile {other:?}"),
        }
    }
}

/// What became of the packets sent towards one endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Packets handed to the link.
    pub sent: u64,
    /// Lost by the profile's `loss`.
    pub lost: u64,
    /// Dropped while the link was black-holed.
    pub black_holed: u64,
    /// Dropped because the limited link's buffer was full.
    pub overflowed: u64,
    /// Waited their turn on a limited link behind a packet before them, and were carried.
    pub waited: u64,
    /// Delivered a second time.
    pub duplicated: u64,
    /// Held back so that later packets overtook them.
    pub held_back: u64,
    /// Dropped because the endpoint had not read the 8,192 packets before it.
    pub unread: u64,
    /// Packets handed to the endpoint (a duplicate counts twice), and their bytes.
    pub delivered: u64,
    pub bytes: u64,
}

/// Evenly spread numbers from a seed (splitmix64): the same seed, the same numbers.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number in `0..1`.
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Always draws, so that a profile's other faults fall on the same packets whatever this
    /// one's odds are.
    fn chance(&mut self, odds: f64) -> bool {
        self.unit() < odds
    }
}

pub struct Packet {
    from: CustomAddr,
    pub data: Arc<[u8]>,
}

/// One endpoint's side of the link: what is on its way to it.
struct Towards {
    rng: Rng,
    inbox: mpsc::Sender<Packet>,
    counts: Counts,
    /// When the limited link towards it is next free.
    busy_until: Instant,
    /// When the last packet that was not held back arrives: none arrives before that one.
    in_order: Instant,
}

struct State {
    profile: Profile,
    seed: u64,
    /// Everything sent before this is dropped: towards the endpoint named, or towards all.
    outage: Option<(Instant, Option<EndpointId>)>,
    towards: HashMap<EndpointId, Towards>,
    /// Packets on their way, the next to arrive first; one sent earlier before one sent later.
    flying: BinaryHeap<Reverse<(Instant, u64, EndpointId)>>,
    cargo: HashMap<u64, Packet>,
    sent: u64,
    pumping: bool,
}

/// The network. Clone it to hand it to several endpoints.
#[derive(Clone)]
pub struct FaultNet {
    state: Arc<Mutex<State>>,
    wake: Arc<Notify>,
}

impl FaultNet {
    pub fn new(profile: Profile, seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                profile,
                seed,
                outage: None,
                towards: HashMap::new(),
                flying: BinaryHeap::new(),
                cargo: HashMap::new(),
                sent: 0,
                pumping: false,
            })),
            wake: Arc::new(Notify::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A test thread that panicked must not hide the link from the rest of the test.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Another profile from now on. (Packets on their way arrive as they were sent.)
    pub fn set(&self, profile: Profile) {
        self.lock().profile = profile;
    }

    /// Drops every packet sent during the next `duration`.
    pub fn black_hole(&self, duration: Duration) {
        self.lock().outage = Some((Instant::now() + duration, None));
    }

    /// Drops every packet sent towards `id` during the next `duration`: a link that is gone
    /// one way. The other way it carries on.
    pub fn black_hole_towards(&self, id: EndpointId, duration: Duration) {
        self.lock().outage = Some((Instant::now() + duration, Some(id)));
    }

    /// What became of the packets sent towards `id` so far.
    pub fn counts(&self, id: EndpointId) -> Counts {
        let state = self.lock();
        state
            .towards
            .get(&id)
            .map(|to| to.counts)
            .unwrap_or_default()
    }

    /// The address that reaches `id` over this link, and nothing else.
    pub fn addr(id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(id, [TransportAddr::Custom(custom_addr(id))])
    }

    /// Binds an endpoint whose only transport is this link, and which is koh's own in all
    /// else: its key, what koh asks of QUIC for a session, and koh's protocol if it `accept`s.
    pub async fn endpoint(&self, secret: SecretKey, accept: bool) -> Endpoint {
        let id = secret.public();
        let packets = self.join(id);
        let transport = Arc::new(LinkTransport {
            net: self.clone(),
            id,
            packets: Mutex::new(Some(packets)),
        });
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(secret)
            // (A server's endpoint as `koh serve` binds it, and a client's as `koh connect` does.)
            .transport_config(if accept {
                koh::net::transport_config(true)
            } else {
                koh::net::view_transport_config()
            })
            .clear_ip_transports()
            .add_custom_transport(transport);
        if accept {
            builder = builder.alpns(vec![koh::proto::ALPN.to_vec()]);
        }
        builder.bind().await.expect("an endpoint on the fault link")
    }

    /// A place on the link for `id`: where the packets sent towards it arrive.
    pub fn join(&self, id: EndpointId) -> mpsc::Receiver<Packet> {
        let (inbox, packets) = mpsc::channel(INBOX);
        let mut state = self.lock();
        // (Each endpoint's generator by the order the endpoints came in.)
        let nth = state.towards.len() as u64;
        let rng = Rng(state.seed ^ nth.wrapping_mul(0xa076_1d64_78bd_642f));
        let now = Instant::now();
        let towards = Towards {
            rng,
            inbox,
            counts: Counts::default(),
            busy_until: now,
            in_order: now,
        };
        state.towards.insert(id, towards);
        if !state.pumping {
            state.pumping = true;
            tokio::spawn(self.clone().pump());
        }
        packets
    }

    /// Hands each packet on its way to its endpoint when its time has come.
    async fn pump(self) {
        loop {
            let next = {
                let mut state = self.lock();
                let now = Instant::now();
                loop {
                    match state.flying.peek().copied() {
                        Some(Reverse((due, nth, to))) if due <= now => {
                            state.flying.pop();
                            let packet = state.cargo.remove(&nth);
                            if let (Some(packet), Some(to)) = (packet, state.towards.get_mut(&to)) {
                                to.deliver(packet);
                            }
                        }
                        Some(Reverse((due, _, _))) => break Some(due),
                        None => break None,
                    }
                }
            };
            match next {
                Some(due) => {
                    tokio::select! {
                        () = tokio::time::sleep_until(due) => {}
                        () = self.wake.notified() => {}
                    }
                }
                None => self.wake.notified().await,
            }
        }
    }

    /// One packet from `from` towards `to`, through the profile.
    pub fn route(&self, from: EndpointId, to: EndpointId, datagram: &[u8]) -> io::Result<()> {
        let mut state = self.lock();
        let state = &mut *state;
        let now = Instant::now();
        let profile = state.profile.clone();
        let outage = state
            .outage
            .is_some_and(|(until, towards)| now < until && towards.is_none_or(|id| id == to));
        let nth = state.sent;
        state.sent += 1;
        let Some(towards) = state.towards.get_mut(&to) else {
            return Err(io::Error::other("no such endpoint on the fault link"));
        };
        towards.counts.sent += 1;
        // (Every draw is made for every packet: a packet's fate does not depend on which of
        // the faults before it in this list fell on it.)
        let rng = &mut towards.rng;
        let lost = rng.chance(profile.loss);
        let twice = rng.chance(profile.dup);
        let held_back = rng.chance(profile.reorder);
        let jitter = [(); 2].map(|()| (rng.chance(0.5), profile.jitter.mul_f64(rng.unit())));
        if outage {
            towards.counts.black_holed += 1;
            return Ok(());
        }
        if lost {
            towards.counts.lost += 1;
            return Ok(());
        }
        // A limited link: the packet goes once the link is free and takes its size's time to
        // send; with the buffer full it is dropped, as a bottleneck's queue drops its tail.
        let mut waits = Duration::ZERO;
        if let Some(rate) = profile.rate.filter(|rate| *rate > 0) {
            let free = towards.busy_until.max(now);
            if free.duration_since(now) > profile.queue {
                towards.counts.overflowed += 1;
                return Ok(());
            }
            towards.counts.waited += u64::from(free > now);
            let bits = datagram.len() as u64 * 8;
            let done = free + Duration::from_nanos(bits * 1_000_000_000 / rate);
            towards.busy_until = done;
            waits = done.duration_since(now);
        }
        let packet = || Packet {
            from: custom_addr(from),
            data: datagram.into(),
        };
        let copies = if twice { 2 } else { 1 };
        towards.counts.duplicated += copies - 1;
        let mut arrive = Vec::new();
        for (earlier, by) in jitter.into_iter().take(copies as usize) {
            let delay = match earlier {
                true => profile.delay.saturating_sub(by),
                false => profile.delay + by,
            };
            let mut due = (now + waits + delay).max(towards.in_order);
            if held_back {
                due += (profile.delay + profile.jitter).max(Duration::from_millis(5));
            } else {
                towards.in_order = due;
            }
            arrive.push(due);
        }
        towards.counts.held_back += u64::from(held_back);
        // (At once where nothing holds it: a clean link adds no timer's wait.)
        let mut flies = false;
        for (copy, due) in arrive.into_iter().enumerate() {
            if due <= now {
                towards.deliver(packet());
            } else {
                // (A second copy has a number of its own, after every packet sent so far.)
                let nth = nth * 2 + copy as u64;
                state.cargo.insert(nth, packet());
                state.flying.push(Reverse((due, nth, to)));
                flies = true;
            }
        }
        if flies {
            self.wake.notify_one();
        }
        Ok(())
    }
}

impl Towards {
    fn deliver(&mut self, packet: Packet) {
        let bytes = packet.data.len() as u64;
        match self.inbox.try_send(packet) {
            Ok(()) => {
                self.counts.delivered += 1;
                self.counts.bytes += bytes;
            }
            Err(_) => self.counts.unread += 1,
        }
    }
}

fn custom_addr(id: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(TRANSPORT_ID, id.as_bytes())
}

fn endpoint_id(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != TRANSPORT_ID {
        return Err(io::Error::other("no address of the fault link"));
    }
    let bytes = <&[u8; 32]>::try_from(addr.data()).map_err(io::Error::other)?;
    EndpointId::from_bytes(bytes).map_err(io::Error::other)
}

/// One endpoint's place on the link, until iroh binds it.
struct LinkTransport {
    net: FaultNet,
    id: EndpointId,
    packets: Mutex<Option<mpsc::Receiver<Packet>>>,
}

impl std::fmt::Debug for LinkTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LinkTransport({})", self.id.fmt_short())
    }
}

impl CustomTransport for LinkTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let mut packets = self.packets.lock().unwrap_or_else(PoisonError::into_inner);
        let packets = packets.take();
        let packets = packets.ok_or_else(|| io::Error::other("the fault link is bound once"))?;
        Ok(Box::new(LinkEndpoint {
            net: self.net.clone(),
            id: self.id,
            local: n0_watcher::Watchable::new(vec![custom_addr(self.id)]),
            packets,
        }))
    }
}

struct LinkEndpoint {
    net: FaultNet,
    id: EndpointId,
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
    packets: mpsc::Receiver<Packet>,
}

impl std::fmt::Debug for LinkEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LinkEndpoint({})", self.id.fmt_short())
    }
}

impl CustomEndpoint for LinkEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.local.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(LinkSender {
            net: self.net.clone(),
            id: self.id,
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let mut filled = 0;
        for ((buf, meta), info) in bufs.iter_mut().zip(metas.iter_mut()).zip(recv_infos) {
            let packet = match self.packets.poll_recv(cx) {
                Poll::Ready(Some(packet)) => packet,
                Poll::Ready(None) if filled == 0 => {
                    return Poll::Ready(Err(io::Error::other("the fault link is gone")));
                }
                Poll::Ready(None) | Poll::Pending => break,
            };
            // (One larger than the buffer is dropped, as a network would drop it.)
            let Some(into) = buf.get_mut(..packet.data.len()) else {
                continue;
            };
            into.copy_from_slice(&packet.data);
            meta.len = packet.data.len();
            meta.stride = packet.data.len();
            *info = RecvInfo::new(packet.from, Some(custom_addr(self.id)));
            filled += 1;
        }
        match filled {
            0 => Poll::Pending,
            filled => Poll::Ready(Ok(filled)),
        }
    }
}

struct LinkSender {
    net: FaultNet,
    id: EndpointId,
}

impl std::fmt::Debug for LinkSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LinkSender({})", self.id.fmt_short())
    }
}

impl CustomSender for LinkSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == TRANSPORT_ID
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let sent = endpoint_id(dst).and_then(|to| {
            let segment = transmit.segment_size.unwrap_or(transmit.contents.len());
            let mut datagrams = transmit.contents.chunks(segment.max(1));
            datagrams.try_for_each(|datagram| self.net.route(self.id, to, datagram))
        });
        Poll::Ready(sent)
    }
}
