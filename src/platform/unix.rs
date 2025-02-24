use crate::platform::{PingerConfig, PingerError};
use pnet_packet::{
    icmp::{IcmpCode, IcmpTypes},
    icmpv6::{Icmpv6Code, Icmpv6Types},
    util, Packet,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, select, time};

pub struct Pinger<'a> {
    socket: Arc<UdpSocket>,
    target: SocketAddr,
    identifier: u16,
    sequence: AtomicU16,
    payload: &'a [u8],
    timeout: Duration,
}

impl<'a> Pinger<'a> {
    pub async fn new(
        config: PingerConfig,
        target: IpAddr,
        payload: &'a [u8],
    ) -> Result<Self, PingerError> {
        let target = SocketAddr::new(target, 0);
        let ttl = config.ttl.unwrap_or(128) as u32;
        let identifier = config.identifier.unwrap_or(rand::random());
        let sequence = AtomicU16::new(config.sequence.unwrap_or(1));
        let timeout = config.timeout.unwrap_or(Duration::from_secs(1));

        let socket = match target.ip() {
            IpAddr::V4(_) => Socket::new_raw(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?,
            IpAddr::V6(_) => Socket::new_raw(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?,
        };

        socket.set_nonblocking(true)?;

        match config.source.unwrap_or(match target.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }) {
            IpAddr::V4(ip) => {
                socket.bind(&SocketAddrV4::new(ip, identifier).into())?;
                socket.set_ttl(ttl)?;
            }
            IpAddr::V6(ip) => {
                socket.bind(&SocketAddrV6::new(ip, identifier, 0, 0).into())?;
                socket.set_unicast_hops_v6(ttl)?;
            }
        }

        let socket = UdpSocket::from_std(socket.into())?;
        socket.connect(target).await?;

        Ok(Pinger {
            socket: Arc::new(socket),
            target,
            identifier,
            sequence,
            payload,
            timeout,
        })
    }

    pub async fn ping(&self) -> Result<Duration, PingerError> {
        let mut buffer = vec![0; 8 + self.payload.len()];

        match self.target.ip() {
            IpAddr::V4(_) => {
                use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;

                let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
                packet.set_icmp_type(IcmpTypes::EchoRequest);
                packet.set_icmp_code(IcmpCode::new(0));
                packet.set_identifier(self.identifier);
                packet.set_sequence_number(self.sequence.load(Ordering::Acquire));
                packet.set_payload(self.payload);
                packet.set_checksum(util::checksum(packet.packet(), 1));

                let packet_len = packet.packet().len();
                debug_assert_eq!(buffer.len(), packet_len);
            }
            IpAddr::V6(_) => {
                use pnet_packet::icmpv6::echo_request::MutableEchoRequestPacket;

                let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
                packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                packet.set_icmpv6_code(Icmpv6Code::new(0));
                packet.set_identifier(self.identifier);
                packet.set_sequence_number(self.sequence.load(Ordering::Acquire));
                packet.set_payload(self.payload);
                packet.set_checksum(util::checksum(packet.packet(), 1));

                let packet_len = packet.packet().len();
                debug_assert_eq!(buffer.len(), packet_len);
            }
        }

        let mut timeout = time::interval(self.timeout);
        timeout.tick().await;

        let now = Instant::now();
        self.socket.send(&buffer).await?;

        loop {
            select! {
                _ = timeout.tick() => {
                    return Err(PingerError::Timeout(self.timeout));
                },
                v = recv_loop(self.socket.clone(), self.identifier) => {
                    if v.is_ok() {
                        break;
                    }
                }
            }
        }
        let usage = now.elapsed();

        self.sequence.fetch_add(1, Ordering::Release);
        Ok(usage)
    }
}

async fn recv_loop(socket: Arc<UdpSocket>, identifier: u16) -> io::Result<()> {
    let mut buffer = vec![0u8; 1500];

    loop {
        let (u, source) = socket.recv_from(&mut buffer).await?;

        match source {
            SocketAddr::V4(_) => {
                use pnet_packet::icmp::echo_reply::EchoReplyPacket;

                if let Some(packet) = EchoReplyPacket::new(&buffer) {
                    if packet.get_identifier() == identifier {
                        return Ok(());
                    }
                }
            }
            SocketAddr::V6(_) => {
                use pnet_packet::icmpv6::echo_reply::EchoReplyPacket;

                if let Some(packet) = EchoReplyPacket::new(&buffer) {
                    if packet.get_identifier() == identifier {
                        return Ok(());
                    }
                }
            }
        }

        if u > 0 {
            buffer.clear();
        }
    }
}
