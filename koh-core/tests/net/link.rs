//! A fault-injecting network for iroh endpoints, below QUIC.
//!
//! Endpoints bound with [`FaultNet::endpoint`] have no IP or relay transport: their only path is
//! this in-process link, so every packet between them passes through it and nothing can route
//! around it. The link drops, delays, jitters, duplicates and reorders packets from a seeded RNG,
//! can black-hole everything for an interval, and counts what it delivers to each endpoint.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use iroh::endpoint::presets;
use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use iroh_base::CustomAddr;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::sync::mpsc;
use tokio::time::Instant;

/// This transport's id in iroh's custom-address space ("koh").
const TRANSPORT_ID: u64 = 0x006b_6f68;

/// How the link treats each packet. Every endpoint's outgoing packets get the same treatment.
#[derive(Clone, Debug, Default)]
pub struct Profile {
    /// Probability that a packet is dropped.
    pub loss: f64,
    /// One-way delay before jitter.
    pub delay: Duration,
    /// The delay varies uniformly by up to this much either way (never below zero).
    pub jitter: Duration,
    /// Probability that a packet is delivered twice.
    pub dup: f64,
    /// Probability that a packet is held back by an extra `delay + jitter`, so later packets
    /// overtake it.
    pub reorder: f64,
}

/// Packets and bytes, counted per destination endpoint.
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

struct Packet {
    from: CustomAddr,
    data: Bytes,
}

struct State {
    profile: Profile,
    rng: StdRng,
    /// Everything sent before this instant is dropped.
    outage_until: Option<Instant>,
    inboxes: HashMap<EndpointId, mpsc::UnboundedSender<Packet>>,
    /// Everything sent towards each endpoint, before faults.
    sent: HashMap<EndpointId, Count>,
    /// Everything the link let through to each endpoint (duplicates counted twice).
    delivered: HashMap<EndpointId, Count>,
}

/// The shared network. Clone it to hand it to several endpoints.
#[derive(Clone)]
pub struct FaultNet {
    state: Arc<Mutex<State>>,
}

impl FaultNet {
    pub fn new(profile: Profile, seed: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                profile,
                rng: StdRng::seed_from_u64(seed),
                outage_until: None,
                inboxes: HashMap::new(),
                sent: HashMap::new(),
                delivered: HashMap::new(),
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A panicking test thread must not hide the link from the rest of the test.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drop every packet sent during the next `duration`.
    pub fn black_hole(&self, duration: Duration) {
        self.lock().outage_until = Instant::now().checked_add(duration);
    }

    /// What has been sent towards `id` so far, before faults.
    pub fn sent(&self, id: EndpointId) -> Count {
        self.lock().sent.get(&id).copied().unwrap_or_default()
    }

    /// What the link has let through to `id` so far.
    pub fn delivered(&self, id: EndpointId) -> Count {
        self.lock().delivered.get(&id).copied().unwrap_or_default()
    }

    /// The address that reaches `id` over this link, and nothing else.
    pub fn addr(id: EndpointId) -> EndpointAddr {
        EndpointAddr::from_parts(id, [TransportAddr::Custom(custom_addr(id))])
    }

    /// Bind an endpoint whose only transport is this link, configured the way koh configures
    /// every endpoint (identity, transport config, and the ALPN when it `accept`s).
    pub async fn endpoint(&self, secret: SecretKey, accept: bool) -> anyhow::Result<Endpoint> {
        let id = secret.public();
        let (tx, rx) = mpsc::unbounded_channel();
        self.lock().inboxes.insert(id, tx);
        let transport = Arc::new(LinkTransport {
            net: self.clone(),
            id,
            inbox: Mutex::new(Some(rx)),
        });
        Ok(
            koh_core::transport_iroh::configure(
                Endpoint::builder(presets::Minimal),
                secret,
                accept,
            )
            .clear_ip_transports()
            .add_custom_transport(transport)
            .bind()
            .await?,
        )
    }

    /// Route one packet from `from` to `to` through the profile.
    fn route(&self, from: EndpointId, to: EndpointId, datagram: &[u8]) -> io::Result<()> {
        let data = Bytes::copy_from_slice(datagram);
        let mut state = self.lock();
        let inbox = state
            .inboxes
            .get(&to)
            .cloned()
            .ok_or_else(|| io::Error::other("no such endpoint on the fault link"))?;
        state.sent.entry(to).or_default().add(data.len());
        let now = Instant::now();
        if state.outage_until.is_some_and(|until| now < until) {
            return Ok(());
        }
        let profile = state.profile.clone();
        if state.rng.gen_bool(profile.loss) {
            return Ok(());
        }
        let copies = if state.rng.gen_bool(profile.dup) {
            2
        } else {
            1
        };
        let mut delays = Vec::with_capacity(copies);
        for _ in 0..copies {
            let offset = profile.jitter.mul_f64(state.rng.gen_range(0.0..=1.0));
            let mut delay = if state.rng.gen_bool(0.5) {
                profile.delay.saturating_sub(offset)
            } else {
                profile.delay.saturating_add(offset)
            };
            if state.rng.gen_bool(profile.reorder) {
                delay = delay
                    .saturating_add(profile.delay)
                    .saturating_add(profile.jitter);
            }
            delays.push(delay);
        }
        let counter = state.delivered.entry(to).or_default();
        for _ in &delays {
            counter.add(data.len());
        }
        drop(state);
        let from = custom_addr(from);
        for delay in delays {
            let packet = Packet {
                from: from.clone(),
                data: data.clone(),
            };
            if delay.is_zero() {
                let _ = inbox.send(packet);
            } else {
                let inbox = inbox.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = inbox.send(packet);
                });
            }
        }
        Ok(())
    }
}

fn custom_addr(id: EndpointId) -> CustomAddr {
    CustomAddr::from_parts(TRANSPORT_ID, id.as_bytes())
}

fn endpoint_id(addr: &CustomAddr) -> io::Result<EndpointId> {
    if addr.id() != TRANSPORT_ID {
        return Err(io::Error::other("not a fault-link address"));
    }
    let bytes = <&[u8; 32]>::try_from(addr.data()).map_err(io::Error::other)?;
    EndpointId::from_bytes(bytes).map_err(io::Error::other)
}

/// One endpoint's attachment to the link.
struct LinkTransport {
    net: FaultNet,
    id: EndpointId,
    inbox: Mutex<Option<mpsc::UnboundedReceiver<Packet>>>,
}

impl std::fmt::Debug for LinkTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkTransport")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl CustomTransport for LinkTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let inbox = self
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| io::Error::other("fault-link transport bound twice"))?;
        Ok(Box::new(LinkEndpoint {
            net: self.net.clone(),
            id: self.id,
            local: n0_watcher::Watchable::new(vec![custom_addr(self.id)]),
            inbox,
        }))
    }
}

struct LinkEndpoint {
    net: FaultNet,
    id: EndpointId,
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
    inbox: mpsc::UnboundedReceiver<Packet>,
}

impl std::fmt::Debug for LinkEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkEndpoint")
            .field("id", &self.id)
            .finish_non_exhaustive()
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
        let mut filled: usize = 0;
        for ((buf, meta), info) in bufs.iter_mut().zip(metas.iter_mut()).zip(recv_infos) {
            let packet = match self.inbox.poll_recv(cx) {
                Poll::Ready(Some(packet)) => packet,
                Poll::Ready(None) if filled == 0 => {
                    return Poll::Ready(Err(io::Error::other("fault link closed")));
                }
                Poll::Ready(None) | Poll::Pending => break,
            };
            let Some(dst) = buf.get_mut(..packet.data.len()) else {
                // Larger than the receive buffer: a real network would drop it too.
                continue;
            };
            dst.copy_from_slice(&packet.data);
            meta.len = packet.data.len();
            meta.stride = packet.data.len();
            *info = RecvInfo::new(packet.from, Some(custom_addr(self.id)));
            filled = filled.saturating_add(1);
        }
        if filled == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(filled))
        }
    }
}

#[derive(Debug)]
struct LinkSender {
    net: FaultNet,
    id: EndpointId,
}

impl std::fmt::Debug for FaultNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultNet").finish_non_exhaustive()
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
        let to = match endpoint_id(dst) {
            Ok(to) => to,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for datagram in transmit.contents.chunks(segment) {
            if let Err(e) = self.net.route(self.id, to, datagram) {
                return Poll::Ready(Err(e));
            }
        }
        Poll::Ready(Ok(()))
    }
}
