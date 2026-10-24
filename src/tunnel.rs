use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream, UdpSocket,
    },
    sync::mpsc,
    task::JoinHandle,
    time::{interval, MissedTickBehavior},
};

use crate::{
    dh::Tunnel,
    ptcp::{PTCPBody, PTCPPacket, PTCPPayload, PTCPSession, MAX_PAYLOAD},
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(100);
/// Declare the device gone after this long without any packet
const DEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// Wait for the device to accept a new connection
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Chunks buffered towards a client before it is considered stuck
const CLIENT_QUEUE: usize = 8192;

enum ClientEvent {
    Data(u32, Vec<u8>),
    Closed(u32),
}

struct Client {
    addr: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    reader: JoinHandle<()>,
}

struct Pending {
    addr: SocketAddr,
    stream: TcpStream,
    since: Instant,
}

struct State<'a> {
    socket: &'a UdpSocket,
    session: PTCPSession,
    remote_port: u16,
    events: mpsc::Sender<ClientEvent>,
    clients: HashMap<u32, Client>,
    pending: HashMap<u32, Pending>,
}

/**
 * Forward TCP connections accepted on `listener` to `remote_port` on the
 * device until the tunnel dies. Returns the reason.
 *
 * Everything touching the PTCP session runs in this single task, client
 * sockets are served by small reader / writer tasks connected via channels.
 */
pub async fn run(tunnel: Tunnel, listener: &TcpListener, remote_port: u16) -> String {
    let socket = &tunnel.socket;
    let (events, mut events_rx) = mpsc::channel::<ClientEvent>(256);

    let mut state = State {
        socket,
        session: tunnel.session,
        remote_port,
        events,
        clients: HashMap::new(),
        pending: HashMap::new(),
    };

    let mut heartbeat = interval(HEARTBEAT_INTERVAL);
    let mut poll = interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Skip);

    let mut buf = vec![0u8; 65536];

    let reason = loop {
        tokio::select! {
            res = listener.accept() => match res {
                Ok((stream, addr)) => state.on_accept(stream, addr).await,
                Err(e) => warn!("Accept failed: {}", e),
            },

            res = socket.recv(&mut buf) => match res {
                Ok(n) => match PTCPPacket::parse(&buf[0..n]) {
                    Ok(packet) => state.on_packet(packet).await,
                    Err(e) => debug!("Ignoring datagram: {}", e),
                },
                // transient, e.g. ICMP unreachable; liveness check decides
                Err(e) => debug!("Receive failed: {}", e),
            },

            Some(ev) = events_rx.recv() => match ev {
                ClientEvent::Data(realm, data) => state.on_client_data(realm, data).await,
                ClientEvent::Closed(realm) => state.on_client_closed(realm).await,
            },

            _ = heartbeat.tick() => state.send(PTCPBody::Heartbeat).await,

            _ = poll.tick() => {
                if let Some(reason) = state.on_poll().await {
                    break reason;
                }
            },
        }
    };

    debug!(
        "Session stats: {} retransmitted, {} duplicates",
        state.session.retransmitted, state.session.duplicates
    );

    for (_, client) in state.clients.drain() {
        client.reader.abort();
        info!("Closing connection from {}", client.addr);
    }

    reason
}

impl State<'_> {
    async fn send(&mut self, body: PTCPBody) {
        let packet = self.session.send(body);
        packet.log(">>>");

        if let Err(e) = self.socket.send(&packet.serialize()).await {
            debug!("Send failed: {}", e);
        }
    }

    async fn on_accept(&mut self, stream: TcpStream, addr: SocketAddr) {
        let _ = stream.set_nodelay(true);

        let mut realm = rand::random::<u32>();
        while realm == 0 || self.clients.contains_key(&realm) || self.pending.contains_key(&realm) {
            realm = rand::random();
        }

        info!("Accepted connection from {} (realm {:08x})", addr, realm);

        self.pending.insert(
            realm,
            Pending {
                addr,
                stream,
                since: Instant::now(),
            },
        );
        self.send(PTCPBody::Bind(realm, self.remote_port.into()))
            .await;
    }

    async fn on_packet(&mut self, packet: PTCPPacket) {
        packet.log("<<<");

        let needs_ack = packet.body.len() > 0;

        for p in self.session.recv(packet) {
            self.dispatch(p).await;
        }

        // ack duplicates too, the device resends until it sees one
        if needs_ack {
            self.send(PTCPBody::Empty).await;
        }
    }

    async fn dispatch(&mut self, packet: PTCPPacket) {
        match packet.body {
            PTCPBody::Status(realm, status) => self.on_status(realm, &status).await,
            PTCPBody::Payload(p) => self.on_payload(p).await,
            _ => {}
        }
    }

    async fn on_status(&mut self, realm: u32, status: &str) {
        if status == "CONN" {
            match self.pending.remove(&realm) {
                Some(pending) => self.start_client(realm, pending),
                None => debug!("CONN for unknown realm {:08x}", realm),
            }
            return;
        }

        if let Some(pending) = self.pending.remove(&realm) {
            warn!(
                "Device refused connection from {} to port {}: {}",
                pending.addr, self.remote_port, status
            );
        } else if let Some(client) = self.clients.remove(&realm) {
            info!("Device closed connection from {}", client.addr);
            client.reader.abort();
            // acknowledge the disconnection
            self.send(PTCPBody::Status(realm, "DISC".to_string())).await;
        }
    }

    async fn on_payload(&mut self, payload: PTCPPayload) {
        let Some(client) = self.clients.get(&payload.realm) else {
            debug!("Data for unknown realm {:08x}", payload.realm);
            return;
        };

        match client.tx.try_send(payload.data) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("Client {} is not reading, dropping it", client.addr);
                self.close_client(payload.realm).await;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.close_client(payload.realm).await;
            }
        }
    }

    fn start_client(&mut self, realm: u32, pending: Pending) {
        info!(
            "Connection from {} established ({}ms)",
            pending.addr,
            pending.since.elapsed().as_millis()
        );

        let (reader, writer) = pending.stream.into_split();
        let (tx, rx) = mpsc::channel(CLIENT_QUEUE);

        let reader = tokio::spawn(client_reader(reader, realm, self.events.clone()));
        tokio::spawn(client_writer(writer, rx));

        self.clients.insert(
            realm,
            Client {
                addr: pending.addr,
                tx,
                reader,
            },
        );
    }

    async fn close_client(&mut self, realm: u32) {
        if let Some(client) = self.clients.remove(&realm) {
            info!("Connection from {} closed", client.addr);
            client.reader.abort();
            self.send(PTCPBody::Status(realm, "DISC".to_string())).await;
        }
    }

    async fn on_client_data(&mut self, realm: u32, data: Vec<u8>) {
        if !self.clients.contains_key(&realm) {
            return;
        }

        for chunk in data.chunks(MAX_PAYLOAD) {
            self.send(PTCPBody::Payload(PTCPPayload {
                realm,
                data: chunk.to_vec(),
            }))
            .await;
        }
    }

    async fn on_client_closed(&mut self, realm: u32) {
        self.close_client(realm).await;
    }

    async fn on_poll(&mut self) -> Option<String> {
        let (resend, released) = self.session.poll();

        for data in resend {
            if let Err(e) = self.socket.send(&data).await {
                debug!("Resend failed: {}", e);
            }
        }

        for p in released {
            self.dispatch(p).await;
        }

        let expired: Vec<u32> = self
            .pending
            .iter()
            .filter(|(_, p)| p.since.elapsed() >= CONNECT_TIMEOUT)
            .map(|(realm, _)| *realm)
            .collect();

        for realm in expired {
            if let Some(p) = self.pending.remove(&realm) {
                warn!("Device did not accept connection from {} in time", p.addr);
                self.send(PTCPBody::Status(realm, "DISC".to_string())).await;
            }
        }

        let idle = self.session.idle();
        if idle >= DEAD_TIMEOUT {
            return Some(format!("no response from device for {}s", idle.as_secs()));
        }

        None
    }
}

/**
 * Read data from the client and send it to the session
 */
async fn client_reader(mut reader: OwnedReadHalf, realm: u32, events: mpsc::Sender<ClientEvent>) {
    let mut buf = vec![0u8; 16384];

    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                debug!("Realm {:08x}: closed by client", realm);
                break;
            }
            Ok(n) => {
                if events
                    .send(ClientEvent::Data(realm, buf[0..n].to_vec()))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            Err(e) => {
                debug!("Realm {:08x}: {}", realm, e);
                break;
            }
        }
    }

    let _ = events.send(ClientEvent::Closed(realm)).await;
}

/**
 * Write data from the session back to the client
 */
async fn client_writer(mut writer: OwnedWriteHalf, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        if writer.write_all(&data).await.is_err() {
            return;
        }
    }

    let _ = writer.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dh::Tunnel;

    /**
     * Minimal device: accepts binds, echoes payloads in upper case and drops
     * every `loss`-th datagram it sends.
     */
    async fn fake_device(socket: UdpSocket, loss: usize) {
        let mut session = PTCPSession::new();
        let mut buf = vec![0u8; 65536];
        let mut count = 0;
        let mut poll = interval(Duration::from_millis(50));

        loop {
            let mut out = Vec::new();

            tokio::select! {
                n = socket.recv(&mut buf) => {
                    let packet = PTCPPacket::parse(&buf[0..n.unwrap()]).unwrap();
                    let needs_ack = packet.body.len() > 0;

                    for p in session.recv(packet) {
                        match p.body {
                            PTCPBody::Bind(realm, 554) => {
                                out.push(session.send(PTCPBody::Status(realm, "CONN".into())).serialize())
                            }
                            PTCPBody::Payload(p) => out.push(
                                session
                                    .send(PTCPBody::Payload(PTCPPayload {
                                        realm: p.realm,
                                        data: p.data.to_ascii_uppercase(),
                                    }))
                                    .serialize(),
                            ),
                            _ => {}
                        }
                    }

                    if needs_ack {
                        out.push(session.send(PTCPBody::Empty).serialize());
                    }
                }
                _ = poll.tick() => out.extend(session.poll().0),
            }

            for data in out {
                count += 1;
                if loss > 0 && count % loss == 0 {
                    continue;
                }
                socket.send(&data).await.unwrap();
            }
        }
    }

    async fn setup(loss: usize) -> SocketAddr {
        let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        device.connect(socket.local_addr().unwrap()).await.unwrap();
        socket.connect(device.local_addr().unwrap()).await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(fake_device(device, loss));
        tokio::spawn(async move {
            let tunnel = Tunnel {
                peer: socket.peer_addr().unwrap(),
                socket,
                session: PTCPSession::new(),
                relay: false,
            };
            run(tunnel, &listener, 554).await
        });

        addr
    }

    async fn echo(addr: SocketAddr, messages: usize) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut expected = Vec::new();

        for i in 0..messages {
            let msg = format!("message {} {}\n", i, "x".repeat(i * 37 % 3000));
            stream.write_all(msg.as_bytes()).await.unwrap();
            expected.extend_from_slice(msg.to_ascii_uppercase().as_bytes());
        }

        let mut got = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut got))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn tunnels_tcp() {
        let addr = setup(0).await;
        echo(addr, 50).await;
        // a second, concurrent pair of connections
        tokio::join!(echo(addr, 20), echo(addr, 20));
    }

    #[tokio::test]
    async fn survives_packet_loss() {
        let addr = setup(7).await;
        echo(addr, 100).await;
    }
}
