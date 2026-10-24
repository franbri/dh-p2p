use base64::Engine;
use sha1::Digest;
use std::{
    collections::HashMap,
    fmt,
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::{self, Instant},
};
use xml::reader::{EventReader, XmlEvent};

use crate::{
    auth::{DeviceAuth, DEFAULT_RANDSALT},
    ptcp::{PTCPBody, PTCPPacket, PTCPSession},
    util::{bind_udp, hex, local_ip_for, resolve, Result},
};

static MAIN_SERVER: &str = "www.easy4ipcloud.com:8800";

static USERNAME: &str = "cba1b29e32cb17aa46b8ff9e73c7f40b";
static USERKEY: &str = "996103384cdf19179e19243e959bbf8b";

/// Per-attempt wait for a signaling response, grows with each attempt
const REQUEST_TIMEOUT: Duration = Duration::from_millis(1500);
const REQUEST_ATTEMPTS: u32 = 4;
/// Wait for the device to answer through the cloud
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);
const CHANNEL_ATTEMPTS: u32 = 2;
/// PTCP handshake request/response
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(8);
const EXCHANGE_RESEND: Duration = Duration::from_secs(1);
/// Hole punching probes
const PUNCH_INTERVAL: Duration = Duration::from_millis(250);
const DRAIN_TIMEOUT: Duration = Duration::from_millis(1500);

pub struct Options {
    pub serial: String,
    pub credentials: Option<(String, String)>,
    pub punch_timeout: Duration,
}

pub struct Tunnel {
    pub socket: UdpSocket,
    pub session: PTCPSession,
    pub peer: SocketAddr,
    pub relay: bool,
}

/// Signaling worked but the direct link to the device did not, relay may help
#[derive(Debug)]
pub struct DirectFailed(pub String);

impl fmt::Display for DirectFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DirectFailed {}

fn direct_failed(e: crate::util::Error) -> crate::util::Error {
    Box::new(DirectFailed(e.to_string()))
}

/// Error that retrying will not fix
#[derive(Debug)]
pub struct Fatal(pub String);

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Fatal {}

/**
 * Inverted STUN address attribute: port + IPv4, all bits flipped
 */
fn ip_to_bytes(addr: SocketAddr) -> Vec<u8> {
    let ip = match addr {
        SocketAddr::V4(a) => a.ip().octets(),
        SocketAddr::V6(_) => [0; 4],
    };

    [addr.port().to_be_bytes().as_slice(), &ip]
        .concat()
        .iter()
        .map(|b| !b)
        .collect()
}

fn is_binding_request(data: &[u8]) -> bool {
    data.len() >= 20 && data[0] == 0xFF && data[1] == 0xFE
}

fn binding_response(
    cookie: &[u8],
    trans_id: &[u8],
    cid: &[u8],
    length: &[u8; 2],
    addr: SocketAddr,
) -> Vec<u8> {
    [
        b"\xfe\xfe".as_slice(),
        length,
        cookie,
        trans_id,
        b"\x7f\xd6\xff\xf7",
        cid,
        b"\xff\xfb\xff\xf7\xff\xfe",
        &ip_to_bytes(addr),
    ]
    .concat()
}

/**
 * Connect to the device, either directly using UDP hole punching or through
 * the cloud relay.
 */
pub async fn connect(opts: &Options, relay_mode: bool) -> Result<Tunnel> {
    let serial = &opts.serial;
    let mut sig = Signaling::new();

    let main = resolve(MAIN_SERVER).await?;
    debug!("Main server: {}", main);

    // `socket` talks to the device: the p2p-channel request and the device
    // connection must share the same local port
    let socket = bind_udp()?;
    let socket2 = bind_udp()?;

    sig.call(&socket, main, "/probe/p2psrv", None).await?;

    let res = sig
        .call(&socket, main, &format!("/online/p2psrv/{}", serial), None)
        .await
        .map_err(|e| format!("device {} is offline or unknown ({})", serial, e))?;
    let p2psrv = resolve(res.field("body/US")?).await?;

    let res = sig.call(&socket, main, "/online/relay", None).await?;
    let relay = resolve(res.field("body/Address")?).await?;

    sig.call(&socket2, p2psrv, &format!("/probe/device/{}", serial), None)
        .await?;

    let auth = match &opts.credentials {
        Some((username, password)) => {
            let info = sig
                .call(&socket2, p2psrv, &format!("/info/device/{}", serial), None)
                .await;
            let randsalt = match &info {
                Ok(res) => res.find("RandSalt"),
                Err(e) => {
                    debug!("Device info unavailable: {}", e);
                    None
                }
            }
            .unwrap_or(DEFAULT_RANDSALT);
            debug!("RandSalt: {}", randsalt);

            Some(DeviceAuth::new(username, password, randsalt))
        }
        None => None,
    };

    let cid: [u8; 8] = rand::random();
    let identify = cid
        .iter()
        .map(|b| format!("{:x}", b))
        .collect::<Vec<_>>()
        .join(" ");

    // advertise the real LAN address so a device on the same network can
    // reach us without hairpin NAT
    let local_ip = local_ip_for(main).await.unwrap_or(Ipv4Addr::LOCALHOST);
    let laddr = format!("{}:{}", local_ip, socket.local_addr()?.port());

    let channel_body = match &auth {
        None => format!(
            "<body><Identify>{}</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>{}</LocalAddr><version>5.0.0</version></body>",
            identify, laddr,
        ),
        Some(auth) => {
            let nonce = DeviceAuth::nonce();
            let laddr = auth.encrypt(&nonce, &laddr);
            format!(
                "<body>{}<Identify>{}</Identify><IpEncrptV2>true</IpEncrptV2><LocalAddr>{}</LocalAddr><version>5.0.0</version></body>",
                auth.xml(&nonce, &laddr), identify, laddr,
            )
        }
    };
    let channel_path = format!("/device/{}/p2p-channel", serial);
    let channel_cseq = sig.next_cseq();
    sig.send(
        &socket,
        main,
        &channel_path,
        Some(&channel_body),
        channel_cseq,
    )
    .await?;

    let res = sig.call(&socket2, relay, "/relay/agent", None).await?;
    let token = res.field("body/Token")?.to_string();
    let agent_str = res.field("body/Agent")?.to_string();
    let agent = resolve(&agent_str).await?;

    sig.call(
        &socket2,
        agent,
        &format!("/relay/start/{}", token),
        Some("<body><Client>:0</Client></body>"),
    )
    .await?;

    let mut res = None;
    for attempt in 0..CHANNEL_ATTEMPTS {
        if attempt > 0 {
            debug!("No answer from device, resending p2p-channel request");
            sig.send(
                &socket,
                main,
                &channel_path,
                Some(&channel_body),
                channel_cseq,
            )
            .await?;
        }

        res = sig
            .wait_final(&socket, main, Some(channel_cseq), CHANNEL_TIMEOUT)
            .await?;
        if res.is_some() {
            break;
        }
    }
    let res = res.ok_or("device did not answer the p2p-channel request")?;

    if res.code == 403 {
        return Err(Box::new(Fatal(match auth {
            None => "device requires authentication when creating P2P channel, \
                     try again with --username and --password"
                .to_string(),
            Some(_) => "device rejected the username or password (403)".to_string(),
        })));
    }
    if res.code >= 300 {
        return Err(format!("p2p-channel failed: {} {}", res.code, res.status).into());
    }

    let mut device_laddr = res.field("body/LocalAddr")?.to_string();
    let device_pub: SocketAddr = res
        .field("body/PubAddr")?
        .parse()
        .map_err(|e| format!("invalid device address: {}", e))?;

    let device_nonce = match &auth {
        Some(auth) => {
            let nonce = res.field("body/Nonce")?.to_string();
            device_laddr = auth.decrypt(&nonce, &device_laddr)?;
            Some(nonce)
        }
        None => None,
    };
    let device_laddr: Option<SocketAddr> = device_laddr.parse().ok();
    debug!("Device: public {}, local {:?}", device_pub, device_laddr);

    let relay_auth = match (&auth, &device_nonce) {
        (Some(auth), Some(nonce)) => auth.xml(nonce, ""),
        _ => String::new(),
    };
    let relay_path = format!("/device/{}/relay-channel", serial);
    let relay_body = format!(
        "<body>{}<agentAddr>{}</agentAddr></body>",
        relay_auth, agent_str
    );
    let relay_cseq = sig.next_cseq();

    // the device answers through the agent
    let mut ready = false;
    for _ in 0..CHANNEL_ATTEMPTS {
        sig.send(&socket2, main, &relay_path, Some(&relay_body), relay_cseq)
            .await?;

        if let Some(res) = sig
            .wait_final(&socket2, agent, None, CHANNEL_TIMEOUT)
            .await?
        {
            if res.code >= 300 {
                return Err(format!("relay-channel failed: {} {}", res.code, res.status).into());
            }
            ready = true;
            break;
        }
    }
    if !ready {
        bail!("device did not answer the relay-channel request");
    }

    socket2.connect(agent).await?;
    let mut session = PTCPSession::new();

    exchange(&socket2, &mut session, PTCPBody::Sync, "relay sync", |b| {
        !matches!(b, PTCPBody::Empty)
    })
    .await?;

    if relay_mode {
        session.clear_unacked();
        return Ok(Tunnel {
            socket: socket2,
            session,
            peer: agent,
            relay: true,
        });
    }

    let res = exchange(
        &socket2,
        &mut session,
        PTCPBody::Command(b"\x17\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()),
        "relay sign",
        |b| matches!(b, PTCPBody::Command(c) if c.len() > 12),
    )
    .await
    .map_err(direct_failed)?;

    let sign = match res.body {
        PTCPBody::Command(c) => c[12..].to_vec(),
        _ => unreachable!(),
    };
    debug!("Sign: {}", hex(&sign));

    let peer = punch(
        &socket,
        &mut sig,
        &cid,
        device_pub,
        device_laddr,
        auth.is_some(),
        opts.punch_timeout,
    )
    .await?;

    socket.connect(peer).await?;
    let mut session = PTCPSession::new();

    exchange(&socket, &mut session, PTCPBody::Sync, "device sync", |b| {
        matches!(b, PTCPBody::Sync)
    })
    .await
    .map_err(direct_failed)?;

    exchange(
        &socket,
        &mut session,
        PTCPBody::Command(
            [
                b"\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".as_slice(),
                &sign,
            ]
            .concat(),
        ),
        "device authentication",
        |b| matches!(b, PTCPBody::Command(c) if c[0] == 0x1A),
    )
    .await
    .map_err(direct_failed)?;

    if let Err(e) = exchange(
        &socket,
        &mut session,
        PTCPBody::Command(b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec()),
        "device authentication ack",
        |b| matches!(b, PTCPBody::Empty),
    )
    .await
    {
        warn!("{}, continuing anyway", e);
    }

    session.clear_unacked();

    Ok(Tunnel {
        socket,
        session,
        peer,
        relay: false,
    })
}

/**
 * UDP hole punching with the inverted STUN exchange.
 *
 * Probes are repeated until the device answers since the first ones are
 * usually dropped by our NAT before the device has punched its side. Both the
 * public and the LAN address of the device are tried, and the device's real
 * source address is learned from its answer, which differs from the
 * advertised one behind port-rewriting NATs.
 */
async fn punch(
    socket: &UdpSocket,
    sig: &mut Signaling,
    cid: &[u8; 8],
    device_pub: SocketAddr,
    device_laddr: Option<SocketAddr>,
    authenticated: bool,
    timeout: Duration,
) -> Result<SocketAddr> {
    let cookie: [u8; 4] = rand::random();
    let trans_id: [u8; 12] = rand::random();
    let cid: Vec<u8> = cid.iter().map(|b| !b).collect();

    let mut targets = vec![device_pub];
    if let Some(laddr) = device_laddr {
        if laddr != device_pub && !laddr.ip().is_unspecified() && !laddr.ip().is_loopback() {
            targets.push(laddr);
        }
    }
    let is_device = |src: &SocketAddr| targets.iter().any(|t| t.ip() == src.ip());

    let request = [
        b"\xff\xfe\xff\xe7".as_slice(),
        &cookie,
        &trans_id,
        b"\x7f\xd5\xff\xf7",
        &cid,
        b"\xff\xfb\xff\xf7\xff\xfe",
        &ip_to_bytes(device_pub),
    ]
    .concat();

    info!("Punching hole to {:?}", targets);

    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 65536];

    let (data, peer) = 'found: loop {
        if let Some(i) = sig
            .stash
            .iter()
            .position(|(d, src)| is_device(src) && d.len() >= 20)
        {
            let (d, src) = sig.stash.remove(i);
            break 'found (d, src);
        }

        for target in &targets {
            debug!(">>> {} Raw [{}]", target, hex(&request));
            if let Err(e) = socket.send_to(&request, target).await {
                debug!("Send to {} failed: {}", target, e);
            }
        }

        let next = cmp_min(Instant::now() + PUNCH_INTERVAL, deadline);
        loop {
            match time::timeout_at(next, socket.recv_from(&mut buf)).await {
                Err(_) => break,
                Ok(Err(e)) => debug!("Receive failed: {}", e),
                Ok(Ok((n, src))) => {
                    debug!("<<< {} Raw [{}]", src, hex(&buf[0..n]));
                    if is_device(&src) && n >= 20 {
                        break 'found (buf[0..n].to_vec(), src);
                    }
                }
            }
        }

        if Instant::now() >= deadline {
            return Err(Box::new(DirectFailed(
                "hole punching timed out, the device is not reachable directly (strict NAT or firewall)"
                    .to_string(),
            )));
        }
    };

    info!("Device answered from {}", peer);

    let laddr = device_laddr.unwrap_or(device_pub);
    let rtrans_id = data[8..20].to_vec();
    let response = binding_response(&cookie, &rtrans_id, &cid, b"\xff\xe7", laddr);
    debug!(">>> {} Raw [{}]", peer, hex(&response));
    socket.send_to(&response, peer).await?;

    if authenticated {
        // mirrors main.py, the purpose of this exchange is not fully known
        recv_from_peer(socket, peer, &mut buf).await;

        let confirm = binding_response(&cookie, &rtrans_id, &cid, b"\xff\xf3", laddr);
        for _ in 0..5 {
            debug!(">>> {} Raw [{}]", peer, hex(&confirm));
            socket.send_to(&confirm, peer).await?;
        }
    }

    // let the device finish its side, answering its binding requests
    for _ in 0..5 {
        let Some(data) = recv_from_peer(socket, peer, &mut buf).await else {
            break;
        };

        if is_binding_request(&data) {
            let response = binding_response(&cookie, &data[8..20], &cid, b"\xff\xe7", laddr);
            socket.send_to(&response, peer).await?;
        }
    }

    Ok(peer)
}

/**
 * Next datagram from the device, None once it goes quiet
 */
async fn recv_from_peer(socket: &UdpSocket, peer: SocketAddr, buf: &mut [u8]) -> Option<Vec<u8>> {
    loop {
        match time::timeout(DRAIN_TIMEOUT, socket.recv_from(buf)).await {
            Err(_) => return None,
            Ok(Ok((n, src))) if src.ip() == peer.ip() => {
                debug!("<<< {} Raw [{}]", src, hex(&buf[0..n]));
                return Some(buf[0..n].to_vec());
            }
            _ => continue,
        }
    }
}

fn cmp_min(a: Instant, b: Instant) -> Instant {
    if a < b {
        a
    } else {
        b
    }
}

/**
 * Send a PTCP packet and wait for the matching answer, resending it while the
 * peer has not acknowledged it.
 */
async fn exchange(
    socket: &UdpSocket,
    session: &mut PTCPSession,
    body: PTCPBody,
    what: &str,
    accept: impl Fn(&PTCPBody) -> bool,
) -> Result<PTCPPacket> {
    let packet = session.send(body);
    packet.log(">>>");
    let bytes = packet.serialize();

    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let mut buf = vec![0u8; 65536];
    let mut first = true;

    loop {
        if first || !session.all_acked() {
            socket.send(&bytes).await?;
            first = false;
        }

        let next = cmp_min(Instant::now() + EXCHANGE_RESEND, deadline);

        loop {
            match time::timeout_at(next, socket.recv(&mut buf)).await {
                Err(_) => break,
                Ok(Err(e)) => debug!("Receive failed: {}", e),
                Ok(Ok(n)) => match PTCPPacket::parse(&buf[0..n]) {
                    Ok(p) => {
                        p.log("<<<");
                        for p in session.recv(p) {
                            if accept(&p.body) {
                                return Ok(p);
                            }
                        }
                    }
                    Err(e) => debug!("Ignoring datagram: {}", e),
                },
            }
        }

        if Instant::now() >= deadline {
            bail!("timeout waiting for {}", what);
        }
    }
}

struct Signaling {
    cseq: u32,
    /// Datagrams from unexpected sources, kept for the hole punching
    stash: Vec<(Vec<u8>, SocketAddr)>,
}

impl Signaling {
    fn new() -> Signaling {
        Signaling {
            cseq: 0,
            stash: Vec::new(),
        }
    }

    fn next_cseq(&mut self) -> u32 {
        self.cseq += 1;
        self.cseq
    }

    async fn send(
        &self,
        socket: &UdpSocket,
        to: SocketAddr,
        path: &str,
        body: Option<&str>,
        cseq: u32,
    ) -> Result<()> {
        let req = build_request(path, body, cseq);

        debug!(">>> {}\n{}\n---", to, req);

        socket.send_to(req.as_bytes(), to).await?;
        Ok(())
    }

    /**
     * Wait for a response from `from`. Returns None on timeout.
     */
    async fn recv(
        &mut self,
        socket: &UdpSocket,
        from: SocketAddr,
        cseq: Option<u32>,
        timeout: Duration,
    ) -> Result<Option<DHResponse>> {
        let deadline = Instant::now() + timeout;
        let mut buf = vec![0u8; 65536];

        loop {
            let (n, src) = match time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
                Err(_) => return Ok(None),
                Ok(Err(e)) => {
                    // e.g. ICMP port unreachable, wait for the retry
                    debug!("Receive failed: {}", e);
                    continue;
                }
                Ok(Ok(r)) => r,
            };

            if src != from {
                debug!("<<< {} (unexpected) Raw [{}]", src, hex(&buf[0..n.min(32)]));
                if self.stash.len() < 32 {
                    self.stash.push((buf[0..n].to_vec(), src));
                }
                continue;
            }

            let text = String::from_utf8_lossy(&buf[0..n]);
            debug!("<<< {}\n{}\n---", src, text);

            let res = match DHResponse::parse(&text) {
                Ok(res) => res,
                Err(e) => {
                    debug!("Ignoring invalid response: {}", e);
                    continue;
                }
            };

            if let (Some(expected), Some(got)) = (cseq, res.cseq()) {
                if expected != got {
                    debug!("Ignoring stale response (CSeq {} != {})", got, expected);
                    continue;
                }
            }

            return Ok(Some(res));
        }
    }

    /**
     * Wait for a final (non 1xx) response
     */
    async fn wait_final(
        &mut self,
        socket: &UdpSocket,
        from: SocketAddr,
        cseq: Option<u32>,
        timeout: Duration,
    ) -> Result<Option<DHResponse>> {
        let deadline = Instant::now() + timeout;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.recv(socket, from, cseq, remaining).await? {
                Some(res) if res.code < 200 => continue,
                res => return Ok(res),
            }
        }
    }

    /**
     * Request/response with retransmission, UDP datagrams do get lost
     */
    async fn call(
        &mut self,
        socket: &UdpSocket,
        to: SocketAddr,
        path: &str,
        body: Option<&str>,
    ) -> Result<DHResponse> {
        let cseq = self.next_cseq();

        for attempt in 1..=REQUEST_ATTEMPTS {
            self.send(socket, to, path, body, cseq).await?;

            if let Some(res) = self
                .wait_final(socket, to, Some(cseq), REQUEST_TIMEOUT * attempt)
                .await?
            {
                if res.code >= 300 {
                    bail!("{} failed: {} {}", path, res.code, res.status);
                }
                return Ok(res);
            }

            debug!("No response to {} from {}, retrying", path, to);
        }

        bail!("no response from {} to {}", to, path)
    }
}

fn build_request(path: &str, body: Option<&str>, cseq: u32) -> String {
    let method = match body {
        Some(_) => "DHPOST",
        None => "DHGET",
    };
    let body = body.unwrap_or("");

    // random a 32-bit number
    let nonce = rand::random::<u32>();
    // iso8601 time string
    let currdate = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let pwd = format!("{}{}DHP2P:{}:{}", nonce, currdate, USERNAME, USERKEY);

    // sha1 then base64
    let mut hasher = sha1::Sha1::new();
    hasher.update(pwd);
    let digest = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());

    format!(
        "\
        {} {} HTTP/1.1\r\n\
        CSeq: {}\r\n\
        Authorization: WSSE profile=\"UsernameToken\"\r\n\
        X-WSSE: UsernameToken Username=\"{}\", PasswordDigest=\"{}\", Nonce=\"{}\", Created=\"{}\"\r\n\r\n{}",
        method, path, cseq, USERNAME, digest, nonce, currdate, body,
    )
}

#[derive(Debug)]
#[allow(dead_code)]
struct DHResponse {
    version: String,
    code: u16,
    status: String,
    headers: HashMap<String, String>,
    body: HashMap<String, String>,
}

impl DHResponse {
    fn parse_body(body: &str) -> Result<HashMap<String, String>> {
        let mut parser = EventReader::from_str(body);
        let mut stack = Vec::new();
        let mut tree = HashMap::new();

        loop {
            match parser.next()? {
                XmlEvent::StartElement { name, .. } => {
                    stack.push(name.local_name);
                }
                XmlEvent::EndElement { .. } => {
                    stack.pop();
                }
                XmlEvent::Characters(s) => {
                    tree.insert(stack.join("/"), s);
                }
                XmlEvent::EndDocument => break,
                _ => {}
            }
        }

        Ok(tree)
    }

    fn parse(res: &str) -> Result<DHResponse> {
        let (head, body) = res.split_once("\r\n\r\n").unwrap_or((res, ""));

        let mut lines = head.split("\r\n");
        let mut status_line = lines.next().unwrap_or("").splitn(3, ' ');

        let version = status_line.next().unwrap_or("").to_string();
        if !version.starts_with("HTTP/") {
            bail!("not a response");
        }
        let code = status_line
            .next()
            .ok_or("missing status code")?
            .parse::<u16>()?;
        let status = status_line.next().unwrap_or("").to_string();

        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
            .collect();

        let body = match body.trim() {
            "" => HashMap::new(),
            body => DHResponse::parse_body(body)?,
        };

        Ok(DHResponse {
            version,
            code,
            status,
            headers,
            body,
        })
    }

    fn cseq(&self) -> Option<u32> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("CSeq"))
            .and_then(|(_, v)| v.parse().ok())
    }

    fn field(&self, key: &str) -> Result<&str> {
        self.body
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("missing {} in response", key).into())
    }

    /// Find an element by name anywhere in the body
    fn find(&self, name: &str) -> Option<&str> {
        self.body
            .iter()
            .find(|(k, _)| {
                k.rsplit('/')
                    .next()
                    .is_some_and(|n| n.eq_ignore_ascii_case(name))
            })
            .map(|(_, v)| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_response() {
        let res = DHResponse::parse(
            "HTTP/1.1 200 OK\r\nCSeq: 3\r\nContent-Length: 10\r\n\r\n<body><US>1.2.3.4:8800</US></body>",
        )
        .unwrap();
        assert_eq!(res.code, 200);
        assert_eq!(res.status, "OK");
        assert_eq!(res.cseq(), Some(3));
        assert_eq!(res.field("body/US").unwrap(), "1.2.3.4:8800");
        assert_eq!(res.find("us"), Some("1.2.3.4:8800"));
    }

    #[test]
    fn parse_response_without_body() {
        let res = DHResponse::parse("HTTP/1.1 100 Trying\r\nCSeq: 1\r\n\r\n").unwrap();
        assert_eq!(res.code, 100);
        assert!(res.body.is_empty());
    }

    #[test]
    fn parse_garbage() {
        assert!(DHResponse::parse("PTCP\x00\x00").is_err());
        assert!(DHResponse::parse("HTTP/1.1 abc").is_err());
        assert!(DHResponse::parse("HTTP/1.1 200 OK\r\n\r\n<body><a>").is_err());
    }

    #[test]
    fn address_attribute() {
        let addr: SocketAddr = "192.168.1.200:22508".parse().unwrap();
        assert_eq!(ip_to_bytes(addr), b"\xa8\x13\x3f\x57\xfe\x37");
    }
}
