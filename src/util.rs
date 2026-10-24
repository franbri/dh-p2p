use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
};

use tokio::net::{lookup_host, UdpSocket};

pub type Error = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, Error>;

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(verbose: bool) {
    VERBOSE.store(verbose, Ordering::Relaxed);
}

pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

pub fn timestamp() -> String {
    chrono::Local::now().format("%H:%M:%S%.3f").to_string()
}

macro_rules! info {
    ($($arg:tt)*) => {
        println!("[{}] {}", $crate::util::timestamp(), format_args!($($arg)*))
    };
}

macro_rules! warn {
    ($($arg:tt)*) => {
        eprintln!("[{}] WARN {}", $crate::util::timestamp(), format_args!($($arg)*))
    };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::util::verbose() {
            println!("[{}] {}", $crate::util::timestamp(), format_args!($($arg)*))
        }
    };
}

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*).into())
    };
}

pub fn hex(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

/**
 * Resolve `host:port`, preferring IPv4 since all sockets are IPv4
 */
pub async fn resolve(addr: &str) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = lookup_host(addr)
        .await
        .map_err(|e| format!("Failed to resolve {}: {}", addr, e))?
        .collect();

    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .copied()
        .ok_or_else(|| format!("No IPv4 address found for {}", addr).into())
}

/**
 * Bind a UDP socket on an ephemeral port with enlarged kernel buffers.
 *
 * Video streams arrive in bursts; with the default receive buffer the kernel
 * silently drops datagrams, which shows up as corrupted or frozen video.
 */
pub fn bind_udp() -> Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    for size in [8 << 20, 4 << 20, 1 << 20] {
        if socket.set_recv_buffer_size(size).is_ok() {
            break;
        }
    }
    let _ = socket.set_send_buffer_size(1 << 20);

    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)).into())?;

    Ok(UdpSocket::from_std(socket.into())?)
}

/**
 * Find the LAN address the OS would use to reach `remote`.
 * No packet is sent, connecting a UDP socket only selects a route.
 */
pub async fn local_ip_for(remote: SocketAddr) -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(remote).await.ok()?;

    match socket.local_addr().ok()? {
        SocketAddr::V4(addr) if !addr.ip().is_unspecified() => Some(*addr.ip()),
        _ => None,
    }
}
