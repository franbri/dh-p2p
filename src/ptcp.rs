use std::{
    cmp,
    collections::VecDeque,
    time::{Duration, Instant},
};

use crate::util::{hex, Result};

/// Largest TCP chunk carried in one PTCP packet. Keeps datagrams below the
/// common path MTU, fragmented UDP is often dropped by NATs and firewalls.
pub const MAX_PAYLOAD: usize = 1200;

/// Initial retransmission timeout, doubled on every retry
const RTO: Duration = Duration::from_millis(800);
const MAX_RETRIES: u32 = 6;
const MAX_UNACKED: usize = 2048;

/// Out-of-order packets kept while waiting for a missing one
const MAX_REORDER: usize = 512;
/// Give up waiting for a missing packet after this long
const GAP_TIMEOUT: Duration = Duration::from_secs(3);
/// Consecutive in-order packets needed before trusting the peer's counters
const VERIFY_STREAK: u32 = 3;
/// Disable reordering if the peer's counters keep disagreeing with ours
const MAX_RESYNCS: u32 = 5;

pub struct PTCPPayload {
    pub realm: u32,
    pub data: Vec<u8>,
}

pub enum PTCPBody {
    Sync,
    Command(Vec<u8>),
    Payload(PTCPPayload),
    Bind(u32, u32),
    Status(u32, String),
    Heartbeat,
    Empty,
}

pub struct PTCPPacket {
    pub sent: u32,
    pub recv: u32,
    pid: u32,
    lmid: u32,
    rmid: u32,
    pub body: PTCPBody,
}

fn be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

impl PTCPPayload {
    fn parse(data: &[u8]) -> Result<PTCPPayload> {
        if data.len() < 12 {
            bail!("Invalid payload: too short");
        }

        // first 4 bytes it header
        let header = be_u32(data, 0);
        let length = header & 0xFFFF;
        let realm = be_u32(data, 4);
        let padding = be_u32(data, 8);
        let data = data[12..].to_vec();

        if padding != 0 {
            bail!("Invalid payload: padding");
        }
        if length != data.len() as u32 {
            bail!("Invalid payload: length {} != {}", length, data.len());
        }

        Ok(PTCPPayload { realm, data })
    }

    fn serialize(&self) -> Vec<u8> {
        let length = self.data.len() as u32;
        let header = 0x10000000 | length;

        [
            header.to_be_bytes().as_slice(),
            &self.realm.to_be_bytes(),
            &0u32.to_be_bytes(),
            &self.data,
        ]
        .concat()
    }
}

impl std::fmt::Debug for PTCPPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "length: {}, realm: 0x{:08x}, data: [{}{}]",
            self.data.len(),
            self.realm,
            hex(&self.data[0..cmp::min(self.data.len(), 16)]),
            if self.data.len() > 16 { " ..." } else { "" },
        )
    }
}

impl std::fmt::Debug for PTCPBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PTCPBody::Sync => write!(f, "Sync"),
            PTCPBody::Command(data) => write!(f, "Command([{}])", hex(data)),
            PTCPBody::Payload(payload) => write!(f, "{:?}", payload),
            PTCPBody::Bind(realm, port) => {
                write!(f, "Bind {{ realm: 0x{:08x}, port: {} }}", realm, port)
            }
            PTCPBody::Status(realm, status) => {
                write!(f, "Status {{ realm: 0x{:08x}, status: {} }}", realm, status)
            }
            PTCPBody::Heartbeat => write!(f, "Heartbeat"),
            PTCPBody::Empty => write!(f, "Empty"),
        }
    }
}

impl std::fmt::Debug for PTCPPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PTCPPacket {{ sent: {}, recv: {}, pid: 0x{:08x}, lmid: 0x{:08x}, rmid: 0x{:08x}, body: {:?} }}",
            self.sent, self.recv, self.pid, self.lmid, self.rmid, self.body
        )
    }
}

impl PTCPBody {
    fn parse(data: &[u8]) -> Result<PTCPBody> {
        if data.is_empty() {
            return Ok(PTCPBody::Empty);
        }

        if data.len() < 4 {
            bail!("Invalid body: too short");
        }

        Ok(match data[0] {
            0x00 => PTCPBody::Sync,
            0x10 => PTCPBody::Payload(PTCPPayload::parse(data)?),
            0x11 if data.len() >= 16 => PTCPBody::Bind(be_u32(data, 4), be_u32(data, 12)),
            0x12 if data.len() >= 12 => {
                let realm = be_u32(data, 4);
                let status = String::from_utf8_lossy(&data[12..]).to_string();
                PTCPBody::Status(realm, status)
            }
            0x13 => PTCPBody::Heartbeat,
            _ => PTCPBody::Command(data.to_vec()),
        })
    }

    fn serialize(&self) -> Vec<u8> {
        match self {
            PTCPBody::Sync => b"\x00\x03\x01\x00".to_vec(),
            PTCPBody::Command(data) => data.to_vec(),
            PTCPBody::Payload(payload) => payload.serialize(),
            PTCPBody::Bind(realm, port) => [
                b"\x11\x00\x00\x00".as_slice(),
                &realm.to_be_bytes(),
                b"\x00\x00\x00\x00",
                &port.to_be_bytes(),
                b"\x7f\x00\x00\x01",
            ]
            .concat(),
            PTCPBody::Status(realm, status) => [
                b"\x12\x00\x00\x00".as_slice(),
                &realm.to_be_bytes(),
                b"\x00\x00\x00\x00",
                status.as_bytes(),
            ]
            .concat(),
            PTCPBody::Heartbeat => b"\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
            PTCPBody::Empty => Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            PTCPBody::Sync => 4,
            PTCPBody::Command(data) => data.len(),
            PTCPBody::Payload(payload) => payload.data.len() + 12,
            PTCPBody::Bind(_, _) => 20,
            PTCPBody::Status(_, status) => status.len() + 12,
            PTCPBody::Heartbeat => 12,
            PTCPBody::Empty => 0,
        }
    }
}

impl PTCPPacket {
    pub fn parse(data: &[u8]) -> Result<PTCPPacket> {
        if data.len() < 24 {
            bail!("Invalid packet: too short");
        }

        if &data[0..4] != b"PTCP" {
            bail!("Invalid packet: bad magic");
        }

        Ok(PTCPPacket {
            sent: be_u32(data, 4),
            recv: be_u32(data, 8),
            pid: be_u32(data, 12),
            lmid: be_u32(data, 16),
            rmid: be_u32(data, 20),
            body: PTCPBody::parse(&data[24..])?,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        [
            b"PTCP".as_slice(),
            &self.sent.to_be_bytes(),
            &self.recv.to_be_bytes(),
            &self.pid.to_be_bytes(),
            &self.lmid.to_be_bytes(),
            &self.rmid.to_be_bytes(),
            &self.body.serialize(),
        ]
        .concat()
    }

    pub fn log(&self, direction: &str) {
        if !crate::util::verbose() {
            return;
        }

        debug!("{} {:?}", direction, self);

        if let PTCPBody::Payload(p) = &self.body {
            if p.data.len() > 4 && p.data.iter().all(|b| *b < 0x80) {
                debug!("{}", String::from_utf8_lossy(&p.data));
            }
        }
    }
}

/// `a` is at or after `b` in the wrapping u32 sequence space
fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

struct Unacked {
    end: u32,
    data: Vec<u8>,
    sent_at: Instant,
    retries: u32,
}

/**
 * PTCP session state.
 *
 * Besides the counters required by the protocol, the session adds the
 * reliability UDP lacks: duplicate suppression, reordering and
 * retransmission. Both are only enabled once the peer's counters have been
 * observed to behave as expected, so a device that counts differently falls
 * back to the original best-effort behavior instead of stalling.
 */
pub struct PTCPSession {
    sent: u32,
    recv: u32,
    count: u32,
    id: u32,
    rmid: u32,

    unacked: VecDeque<Unacked>,
    acks_verified: bool,

    ordering_verified: bool,
    in_order_streak: u32,
    resyncs: u32,
    reorder: Vec<PTCPPacket>,
    gap_since: Option<Instant>,

    last_rx: Instant,
    pub retransmitted: u64,
    pub duplicates: u64,
}

impl PTCPSession {
    pub fn new() -> PTCPSession {
        PTCPSession {
            sent: 0,
            recv: 0,
            count: 0,
            id: 0,
            rmid: 0,
            unacked: VecDeque::new(),
            acks_verified: false,
            ordering_verified: false,
            in_order_streak: 0,
            resyncs: 0,
            reorder: Vec::new(),
            gap_since: None,
            last_rx: Instant::now(),
            retransmitted: 0,
            duplicates: 0,
        }
    }

    pub fn send(&mut self, body: PTCPBody) -> PTCPPacket {
        let sent = self.sent;
        let recv = self.recv;
        let pid = match body {
            PTCPBody::Sync => 0x0002FFFF,
            _ => 0x0000FFFF - self.count,
        };
        let lmid = self.id;
        let rmid = self.rmid;
        let len = body.len() as u32;

        /*
         * Update counters
         */
        self.sent = self.sent.wrapping_add(len);

        self.id = self.id.wrapping_add(1);
        self.count = self.count.wrapping_add(match body {
            PTCPBody::Sync => 0,
            PTCPBody::Empty => 0,
            _ => 1,
        });

        let packet = PTCPPacket {
            sent,
            recv,
            pid,
            lmid,
            rmid,
            body,
        };

        if len > 0 {
            if self.unacked.len() >= MAX_UNACKED {
                self.unacked.pop_front();
            }
            self.unacked.push_back(Unacked {
                end: self.sent,
                data: packet.serialize(),
                sent_at: Instant::now(),
                retries: 0,
            });
        }

        packet
    }

    /**
     * Process a received packet and return the packets that are now
     * deliverable, in order. Empty (ack only) packets are always returned.
     */
    pub fn recv(&mut self, packet: PTCPPacket) -> Vec<PTCPPacket> {
        self.last_rx = Instant::now();
        self.rmid = packet.lmid;
        self.on_ack(packet.recv);

        let len = packet.body.len() as u32;

        if len == 0 {
            return vec![packet];
        }

        if !self.ordering_verified {
            if packet.sent == self.recv {
                self.in_order_streak += 1;
                if self.in_order_streak >= VERIFY_STREAK && self.resyncs < MAX_RESYNCS {
                    debug!("PTCP: peer counters verified, enabling reordering");
                    self.ordering_verified = true;
                }
            } else {
                self.in_order_streak = 0;
            }

            // best effort: accept everything
            self.recv = packet.sent.wrapping_add(len);
            return vec![packet];
        }

        if !seq_ge(packet.sent, self.recv) {
            // already received, the peer missed our ack
            self.duplicates += 1;
            return Vec::new();
        }

        if packet.sent != self.recv {
            if !self.reorder.iter().any(|p| p.sent == packet.sent) {
                self.reorder.push(packet);
            }
            self.gap_since.get_or_insert_with(Instant::now);

            if self.reorder.len() > MAX_REORDER {
                return self.skip_gap();
            }

            return Vec::new();
        }

        self.recv = self.recv.wrapping_add(len);
        let mut out = vec![packet];
        self.drain_reorder(&mut out);
        out
    }

    fn drain_reorder(&mut self, out: &mut Vec<PTCPPacket>) {
        loop {
            let recv = self.recv;
            self.reorder.retain(|p| seq_ge(p.sent, recv));

            match self.reorder.iter().position(|p| p.sent == recv) {
                Some(i) => {
                    let p = self.reorder.swap_remove(i);
                    self.recv = self.recv.wrapping_add(p.body.len() as u32);
                    out.push(p);
                }
                None => break,
            }
        }

        if self.reorder.is_empty() {
            self.gap_since = None;
        }
    }

    /**
     * The missing packet is not coming: jump to the next buffered one.
     */
    fn skip_gap(&mut self) -> Vec<PTCPPacket> {
        let recv = self.recv;
        let next = self
            .reorder
            .iter()
            .map(|p| p.sent)
            .min_by_key(|s| s.wrapping_sub(recv));

        let mut out = Vec::new();

        if let Some(next) = next {
            warn!(
                "PTCP: lost {} bytes from device, stream may glitch",
                next.wrapping_sub(recv)
            );
            self.recv = next;
            self.gap_since = None;
            self.drain_reorder(&mut out);
        }

        self.resyncs += 1;
        if self.resyncs >= MAX_RESYNCS {
            warn!("PTCP: device counters unreliable, disabling reordering");
            self.ordering_verified = false;
            let recv = self.recv;
            self.reorder.sort_by_key(|p| p.sent.wrapping_sub(recv));
            out.append(&mut self.reorder);
            self.gap_since = None;
        }

        out
    }

    fn on_ack(&mut self, peer_recv: u32) {
        while let Some(front) = self.unacked.front() {
            if !seq_ge(peer_recv, front.end) {
                break;
            }

            if !self.acks_verified && front.end == peer_recv {
                debug!("PTCP: peer acks verified, enabling retransmission");
                self.acks_verified = true;
            }

            self.unacked.pop_front();
        }
    }

    /**
     * Forget everything sent so far, used once a handshake has completed
     */
    pub fn clear_unacked(&mut self) {
        self.unacked.clear();
    }

    /**
     * Periodic housekeeping. Returns the datagrams to retransmit and the
     * packets released from the reorder buffer.
     */
    pub fn poll(&mut self) -> (Vec<Vec<u8>>, Vec<PTCPPacket>) {
        let now = Instant::now();

        let released = match self.gap_since {
            Some(t) if now.duration_since(t) >= GAP_TIMEOUT => self.skip_gap(),
            _ => Vec::new(),
        };

        let mut resend = Vec::new();

        if self.acks_verified {
            for u in self.unacked.iter_mut() {
                if u.retries >= MAX_RETRIES {
                    continue;
                }
                if now.duration_since(u.sent_at) >= RTO * (1 << u.retries) {
                    u.retries += 1;
                    u.sent_at = now;
                    resend.push(u.data.clone());
                }
            }
        }

        self.retransmitted += resend.len() as u64;

        (resend, released)
    }

    /// Time since the last packet from the peer
    pub fn idle(&self) -> Duration {
        self.last_rx.elapsed()
    }

    /// Whether the peer acknowledged everything sent so far
    pub fn all_acked(&self) -> bool {
        self.unacked.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_packet(sent: u32, recv: u32, data: &[u8]) -> PTCPPacket {
        PTCPPacket {
            sent,
            recv,
            pid: 0,
            lmid: 0,
            rmid: 0,
            body: PTCPBody::Payload(PTCPPayload {
                realm: 1,
                data: data.to_vec(),
            }),
        }
    }

    fn payloads(packets: Vec<PTCPPacket>) -> Vec<u8> {
        packets
            .into_iter()
            .flat_map(|p| match p.body {
                PTCPBody::Payload(p) => p.data,
                _ => Vec::new(),
            })
            .collect()
    }

    fn verified_session() -> (PTCPSession, u32) {
        let mut s = PTCPSession::new();
        let mut off = 0;
        for _ in 0..VERIFY_STREAK {
            assert_eq!(s.recv(data_packet(off, 0, b"x")).len(), 1);
            off += 13;
        }
        assert!(s.ordering_verified);
        (s, off)
    }

    #[test]
    fn roundtrip() {
        let mut s = PTCPSession::new();
        let bodies = vec![
            PTCPBody::Sync,
            PTCPBody::Heartbeat,
            PTCPBody::Bind(0x12345678, 554),
            PTCPBody::Status(0xdeadbeef, "CONN".to_string()),
            PTCPBody::Payload(PTCPPayload {
                realm: 7,
                data: b"hello".to_vec(),
            }),
            PTCPBody::Empty,
        ];

        for body in bodies {
            let len = body.len();
            let bytes = s.send(body).serialize();
            assert_eq!(bytes.len(), 24 + len);
            let parsed = PTCPPacket::parse(&bytes).unwrap();
            assert_eq!(parsed.serialize(), bytes);
        }
    }

    #[test]
    fn malformed_packets_are_errors() {
        assert!(PTCPPacket::parse(b"PTCP").is_err());
        assert!(PTCPPacket::parse(&[0u8; 24]).is_err());
        let mut p = data_packet(0, 0, b"abc").serialize();
        p.truncate(p.len() - 1);
        assert!(PTCPPacket::parse(&p).is_err());
        // truncated Bind is treated as an opaque command, not a panic
        let mut p = data_packet(0, 0, b"").serialize();
        p.truncate(24);
        p.extend_from_slice(b"\x11\x00\x00\x00\x00");
        assert!(PTCPPacket::parse(&p).is_ok());
    }

    #[test]
    fn duplicates_are_dropped() {
        let (mut s, off) = verified_session();
        assert_eq!(s.recv(data_packet(off, 0, b"a")).len(), 1);
        assert_eq!(s.recv(data_packet(off, 0, b"a")).len(), 0);
        assert_eq!(s.duplicates, 1);
    }

    #[test]
    fn reordered_packets_are_delivered_in_order() {
        let (mut s, off) = verified_session();
        assert!(s.recv(data_packet(off + 13, 0, b"b")).is_empty());
        assert!(s.recv(data_packet(off + 26, 0, b"c")).is_empty());
        let out = s.recv(data_packet(off, 0, b"a"));
        assert_eq!(payloads(out), b"abc");
        assert!(s.gap_since.is_none());
    }

    #[test]
    fn unverified_session_accepts_everything() {
        let mut s = PTCPSession::new();
        assert_eq!(s.recv(data_packet(100, 0, b"a")).len(), 1);
        assert_eq!(s.recv(data_packet(100, 0, b"a")).len(), 1);
        assert!(!s.ordering_verified);
    }

    #[test]
    fn retransmission_requires_verified_acks() {
        let mut s = PTCPSession::new();
        s.send(PTCPBody::Heartbeat);
        for u in s.unacked.iter_mut() {
            u.sent_at -= RTO * 2;
        }
        assert!(s.poll().0.is_empty());

        // ack the heartbeat exactly, then lose the next packet
        let mut ack = data_packet(0, 12, b"");
        ack.body = PTCPBody::Empty;
        s.recv(ack);
        assert!(s.acks_verified);
        assert!(s.all_acked());

        s.send(PTCPBody::Heartbeat);
        for u in s.unacked.iter_mut() {
            u.sent_at -= RTO * 2;
        }
        assert_eq!(s.poll().0.len(), 1);
    }
}
