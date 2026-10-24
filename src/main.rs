use clap::Parser;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

use crate::{
    dh::{DirectFailed, Fatal, Options, Tunnel},
    util::{set_verbose, Result},
};

#[macro_use]
mod util;
mod auth;
mod dh;
mod ptcp;
mod tunnel;

const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A session that lived this long resets the reconnection backoff
const STABLE_SESSION: Duration = Duration::from_secs(60);

#[derive(Parser)]
#[command(about = "A PoC implementation of TCP tunneling over Dahua P2P protocol.", long_about = None)]
struct Cli {
    /// Bind address, port and remote port
    #[arg(
        short,
        long,
        value_name = "[bind_address:]port:remote_port",
        default_value = "127.0.0.1:1554:554"
    )]
    port: String,
    /// Always use relay mode (slower, but works behind any NAT)
    #[arg(short, long)]
    relay: bool,
    /// Never fall back to relay mode when the direct connection fails
    #[arg(long, conflicts_with = "relay")]
    no_relay: bool,
    /// Device username, for devices requiring authentication
    #[arg(short, long, env = "DH_USERNAME", requires = "password")]
    username: Option<String>,
    /// Device password, for devices requiring authentication
    #[arg(
        long,
        env = "DH_PASSWORD",
        hide_env_values = true,
        requires = "username"
    )]
    password: Option<String>,
    /// Seconds to wait for the device during hole punching
    #[arg(long, value_name = "SECONDS", default_value_t = 8)]
    punch_timeout: u64,
    /// Exit when the connection is lost instead of reconnecting
    #[arg(long)]
    no_reconnect: bool,
    /// Print every packet
    #[arg(short, long)]
    verbose: bool,
    /// Serial number of the camera
    serial: String,
}

fn parse_port(spec: &str) -> Option<(String, u16, u16)> {
    let parts: Vec<&str> = spec.rsplitn(3, ':').collect();

    match parts.as_slice() {
        [remote, port] => Some((
            "127.0.0.1".to_string(),
            port.parse().ok()?,
            remote.parse().ok()?,
        )),
        [remote, port, addr] => Some((
            addr.trim_matches(|c| c == '[' || c == ']').to_string(),
            port.parse().ok()?,
            remote.parse().ok()?,
        )),
        _ => None,
    }
}

async fn establish(opts: &Options, relay: bool, no_relay: bool) -> Result<Tunnel> {
    if relay {
        return dh::connect(opts, true).await;
    }

    match dh::connect(opts, false).await {
        Ok(tunnel) => Ok(tunnel),
        Err(e) if !no_relay && e.is::<DirectFailed>() => {
            warn!("Direct connection failed: {}", e);
            info!("Falling back to relay mode");
            dh::connect(opts, true).await
        }
        Err(e) => Err(e),
    }
}

#[tokio::main]
async fn main() {
    let args = Cli::parse();
    set_verbose(args.verbose);

    let Some((bind_address, bind_port, remote_port)) = parse_port(&args.port) else {
        eprintln!("Invalid port specification: {}", args.port);
        std::process::exit(2);
    };

    // Bind the listener first so a busy port is reported immediately
    let listener = match TcpListener::bind((bind_address.as_str(), bind_port)).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to listen on {}:{}: {}", bind_address, bind_port, e);
            std::process::exit(1);
        }
    };

    let opts = Options {
        serial: args.serial,
        credentials: args.username.zip(args.password),
        punch_timeout: Duration::from_secs(args.punch_timeout),
    };

    let mut backoff = Duration::from_secs(1);
    let mut announced = false;

    let run = async {
        loop {
            info!("Connecting to device {}", opts.serial);

            match establish(&opts, args.relay, args.no_relay).await {
                Ok(tunnel) => {
                    let started = Instant::now();

                    info!(
                        "PTCP session established via {} ({})",
                        if tunnel.relay { "relay" } else { "direct P2P" },
                        tunnel.peer
                    );

                    if !announced {
                        announced = true;
                        println!("Ready to connect!");
                        if remote_port == 554 {
                            println!(
                                "RTSP URL: rtsp://{}{}/cam/realmonitor?channel=1&subtype=0",
                                bind_address,
                                if bind_port != 554 {
                                    format!(":{}", bind_port)
                                } else {
                                    String::new()
                                }
                            );
                        }
                    }

                    let reason = tunnel::run(tunnel, &listener, remote_port).await;
                    warn!("Connection to device lost: {}", reason);

                    if started.elapsed() >= STABLE_SESSION {
                        backoff = Duration::from_secs(1);
                    }
                }
                Err(e) if e.is::<Fatal>() => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
                Err(e) => warn!("Connection failed: {}", e),
            }

            if args.no_reconnect {
                std::process::exit(1);
            }

            info!("Reconnecting in {}s", backoff.as_secs());
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    };

    tokio::select! {
        _ = run => {}
        _ = tokio::signal::ctrl_c() => info!("Interrupted, exiting"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_spec() {
        assert_eq!(
            parse_port("1554:554"),
            Some(("127.0.0.1".into(), 1554, 554))
        );
        assert_eq!(
            parse_port("0.0.0.0:554:554"),
            Some(("0.0.0.0".into(), 554, 554))
        );
        assert_eq!(parse_port("[::1]:80:8080"), Some(("::1".into(), 80, 8080)));
        assert_eq!(parse_port("554"), None);
        assert_eq!(parse_port("a:b"), None);
    }
}
