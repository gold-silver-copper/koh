//! A fault-injecting network for iroh endpoints, below QUIC.
//!
//! An endpoint bound with [`FaultNet::endpoint`] has no IP and no relay transport: its only path
//! is this link in the test's own process, so every packet between two of them passes through
//! it and nothing can route around it. The link drops everything for an interval, and counts
//! what it carried and dropped towards each endpoint.

use std::collections::HashMap;
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
use tokio::sync::mpsc;
use tokio::time::Instant;

/// This transport's number among iroh's custom addresses ("koh").
const TRANSPORT_ID: u64 = 0x006b_6f68;

/// The packets that wait for an endpoint to read them. A full inbox drops the next packet.
const INBOX: usize = 8192;

/// What became of the packets sent towards one endpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Dropped while the link was black-holed.
    pub black_holed: u64,
    /// The bytes handed to the endpoint.
    pub bytes: u64,
}

#[derive(Debug)]
struct Packet {
    from: CustomAddr,
    data: Arc<[u8]>,
}

/// One endpoint's side of the link: what is on its way to it.
struct Towards {
    inbox: mpsc::Sender<Packet>,
    counts: Counts,
}

struct State {
    /// Everything sent before this is dropped.
    outage: Option<Instant>,
    towards: HashMap<EndpointId, Towards>,
}

/// The network. Clone it to hand it to several endpoints.
#[derive(Clone)]
pub struct FaultNet {
    state: Arc<Mutex<State>>,
}

impl std::fmt::Debug for FaultNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FaultNet")
    }
}

impl FaultNet {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                outage: None,
                towards: HashMap::new(),
            })),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        // A test thread that panicked must not hide the link from the rest of the test.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drops every packet sent during the next `duration`.
    pub fn black_hole(&self, duration: Duration) {
        self.lock().outage = Some(Instant::now() + duration);
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
        let (inbox, packets) = mpsc::channel(INBOX);
        let counts = Counts::default();
        self.lock().towards.insert(id, Towards { inbox, counts });
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

    /// One packet from `from` towards `to`: dropped during an outage, else handed on at once.
    fn route(&self, from: EndpointId, to: EndpointId, datagram: &[u8]) -> io::Result<()> {
        let mut state = self.lock();
        let outage = state.outage.is_some_and(|until| Instant::now() < until);
        let Some(towards) = state.towards.get_mut(&to) else {
            return Err(io::Error::other("no such endpoint on the fault link"));
        };
        if outage {
            towards.counts.black_holed += 1;
            return Ok(());
        }
        let packet = Packet {
            from: custom_addr(from),
            data: datagram.into(),
        };
        if towards.inbox.try_send(packet).is_ok() {
            towards.counts.bytes += datagram.len() as u64;
        }
        Ok(())
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
#[derive(Debug)]
struct LinkTransport {
    net: FaultNet,
    id: EndpointId,
    packets: Mutex<Option<mpsc::Receiver<Packet>>>,
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

#[derive(Debug)]
struct LinkEndpoint {
    net: FaultNet,
    id: EndpointId,
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
    packets: mpsc::Receiver<Packet>,
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

#[derive(Debug)]
struct LinkSender {
    net: FaultNet,
    id: EndpointId,
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
