# RTSP Streaming with Dahua P2P Protocol Implementation

This is a proof of concept implementation of RTSP over Dahua P2P protocol. It works with Dahua and derived cameras / NVRs.

## Motivation

The Dahua P2P protocol is utilized for remote access to Dahua devices. It is commonly used by Dahua apps such as [gDMSS Lite](https://play.google.com/store/apps/details?id=com.mm.android.direct.gdmssphoneLite) on Android or [SmartPSS](https://dahuawiki.com/SmartPSS), [KBiVMS](https://kbvisiongroup.com/support/download-center.html) on Windows.

In my specific scenario, I have a KBVision CCTV system. Although I can access the cameras using the KBiVMS client, I primarily use non-Windows platforms. Therefore, I wanted to explore alternative options for streaming the video using an RTSP client, which is more widely supported. As a result, I decided to experiment with reimplementing the Dahua P2P protocol.

## Files

- Rust implementation:
  - `src/main.rs` - Command line and reconnection loop
  - `src/dh.rs` - Signaling, hole punching and handshake
  - `src/ptcp.rs` - PTCP protocol and session reliability
  - `src/tunnel.rs` - TCP to PTCP forwarding
  - `src/auth.rs` - Device authentication
  - `Cargo.toml` - Rust dependencies
- Python implementation:
  - `main.py` - Main script
  - `helpers.py` - Helper functions
  - `requirements.txt` - Python dependencies
- Others:
  - `dh-p2p.lua` - Wireshark dissector for Dahua P2P protocol
  - `contrib/` - systemd service and install script

## Rust implementation

Rust implementation utilizing async programming and message passing pattern, making it more efficient and flexible.

### Rust usage

```text
A PoC implementation of TCP tunneling over Dahua P2P protocol.

Usage: dh-p2p [OPTIONS] <SERIAL>

Arguments:
  <SERIAL>  Serial number of the camera

Options:
  -p, --port <[bind_address:]port:remote_port>
          Bind address, port and remote port [default: 127.0.0.1:1554:554]
  -r, --relay
          Always use relay mode (slower, but works behind any NAT)
      --no-relay
          Never fall back to relay mode when the direct connection fails
  -u, --username <USERNAME>
          Device username, for devices requiring authentication [env: DH_USERNAME=]
      --password <PASSWORD>
          Device password, for devices requiring authentication [env: DH_PASSWORD]
      --punch-timeout <SECONDS>
          Seconds to wait for the device during hole punching [default: 8]
      --no-reconnect
          Exit when the connection is lost instead of reconnecting
  -v, --verbose
          Print every packet
  -h, --help
          Print help
```

Example:

```bash
cargo run --release -- -p 0.0.0.0:1554:554 <SERIAL>
ffplay -rtsp_transport tcp -i "rtsp://<username>:<password>@127.0.0.1:1554/cam/realmonitor?channel=1&subtype=0"
```

For devices that answer `403` when the P2P channel is created, pass the device credentials (prefer the environment variables so the password does not show up in the process list):

```bash
DH_USERNAME=admin DH_PASSWORD=secret cargo run --release -- <SERIAL>
```

### Connectivity

The Rust implementation tries hard to keep the tunnel up on unreliable networks:

- **Signaling retries**: requests to the Easy4IPCloud servers are retransmitted with a growing timeout, so a single lost UDP datagram no longer hangs the handshake.
- **Hole punching**: probes are repeated for `--punch-timeout` seconds, to both the public and the LAN address of the device, and the device's real source address is learned from its answer (port-rewriting NATs). The client advertises its real LAN address instead of `127.0.0.1`, so a device on the same network can be reached without hairpin NAT.
- **Automatic relay fallback**: if the direct connection cannot be established, the tunnel falls back to relay mode (disable with `--no-relay`).
- **Reliable PTCP**: lost packets are retransmitted, duplicates are dropped and reordered packets are delivered in order. This is only enabled once the device's counters have been observed to match ours, otherwise the original best-effort behavior is kept.
- **Liveness and reconnection**: heartbeats are sent every 5 seconds, a device silent for 30 seconds is considered gone and the tunnel reconnects with exponential backoff. The local port stays open across reconnections.
- **Smaller datagrams and larger buffers**: client data is split into chunks that fit common path MTUs (fragmented UDP is often dropped), and the UDP receive buffer is enlarged to absorb video bursts.
- **No crashes on bad input**: malformed packets, unknown connections and refused connections are logged and ignored instead of panicking.

### Running as a system service

`contrib/` holds a systemd unit for a machine dedicated to running tunnels. Each camera / NVR gets its own instance and config file in `/etc/dh-p2p/`:

```bash
./contrib/install.sh                       # build, install binary, unit and sysctl
sudoedit /etc/dh-p2p/camera.env            # set SERIAL, PORT, credentials
sudo systemctl enable --now dh-p2p@camera
journalctl -u dh-p2p@camera -f
```

For another device, copy `contrib/example.env` to `/etc/dh-p2p/<name>.env` (mode `600`) with a different local port and enable `dh-p2p@<name>`. The service runs as an unprivileged dynamic user that may only bind ports below 1024. Re-run `install.sh` after `git pull` to update; running tunnels are restarted.

## Python implementation

The Python implementation of DH-P2P is a simple and straightforward approach. It is used for drafting and testing purposes due to its quick and easy-to-write nature. Additionally, the implementation is more linear and follows a top-down execution flow, making it easier to understand. Python, being a popular programming language, further contributes to its accessibility and familiarity among developers.

### Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run
python main.py [CAMERA_SERIAL]

# Stream (e.g. with ffplay) rtsp://[username]:[password]@127.0.0.1/cam/realmonitor?channel=1&subtype=0
ffplay -rtsp_transport tcp -i "rtsp://[username]:[password]@127.0.0.1/cam/realmonitor?channel=1&subtype=0"
```

### Python usage

To use the script with a device that requires authentication when creating a channel, use the `-t 1` option.

When running in `--debug` mode or when the `--type` > 0, the `USERNAME` and `PASSWORD` arguments are mandatory. Additionally, make sure that `ffplay` is in the system path when debug mode is enabled.

```text
usage: main.py [-h] [-u USERNAME] [-p PASSWORD] [-d] serial

positional arguments:
  serial                Serial number of the camera

options:
  -h, --help            show this help message and exit
  -d, --debug           Enable debug mode
  -t TYPE, --type TYPE  Type of the camera
  -u USERNAME, --username USERNAME
                        Username of the camera
  -p PASSWORD, --password PASSWORD
                        Password of the camer
```

### Limitations

- Single threaded, so only one client can connect at a time
- Polling based, so it's inefficient and inflexible
- Not fully implemented (e.g. only simplex keep-alive, no mulpile connections, etc.)
- Work better with `ffplay` and `-rtsp_transport tcp` option
- Still unstable, can crash at any time

## Protocol description

For reverse engineering the protocol, I used [Wireshark](https://www.wireshark.org/) and [KBiVMS V2.02.0](https://kbvisiongroup.com/support/download-center.html) as a client on Windows. Using `dh-p2p.lua` dissector, you can see the protocol in Wireshark easier.

For RTSP client, either [VLC](https://www.videolan.org/vlc/) or [ffplay](https://ffmpeg.org/ffplay.html) can be used for easier control of the signals.

### Overview

```mermaid
graph LR
  App[[This script]]
  Service[Easy4IPCloud]
  Device[Camera/NVR]
  App -- 1 --> Service
  Service -- 2 --> Device
  App <-. 3 .-> Device
```

The Dahua P2P protocol initiates with a P2P handshake. This process involves locating the device using its Serial Number (SN) via a third-party service, Easy4IPCloud:

1. The script queries the service to retrieve the device's status and IP address.
2. The service then communicates with the device to prepare it for connection.
3. Finally, the script establishes a connection with the device.

```mermaid
graph LR
  Device[Camera/NVR]
  App[[This script]]
  Client1[RTSP Client 1]
  Client2[RTSP Client 2]
  Clientn[RTSP Client n]
  Client1 -- TCP --> App
  Client2 -- TCP --> App
  Clientn -- TCP --> App
  App <-. UDP\nPTCP protocol .-> Device
```

Following the P2P handshake, the script begins to listen for RTSP connections on port 554. Upon a client's connection, the script initiates a new realm within the PTCP protocol. Essentially, this script serves as a tunnel between the client and the device, facilitating communication through PTCP encapsulation.

### P2P handshake

```mermaid
sequenceDiagram
  participant A as This script
  participant B as Easy4IPCloud
  participant C1 as P2P Server
  participant C2 as Relay Server
  participant C3 as Agent Server
  participant D as Camera/NVR

  A->>B: /probe/p2psrv
  B-->>A: ;
  A->>B: /online/p2psrv/{SN}
  B-->>A: p2psrv info

  A->>C1: /probe/device/{SN}
  C1-->>A: ;

  A->>C1: /info/device/{SN}
  C1-->>A: [randsalt]

  A->>B: /online/relay
  B-->>A: relay info

  A->>B: /device/{SN}/p2p-channel (*)

  par
    A->>C2: /relay/agent
    C2-->>A: agent info + token
    A->>C3: /relay/start/{token}
    C3-->>A: ;
  end

  B-->>A: device info

  A->>B: /device/{SN}/relay-channel + agent info

  C3-->>A: Server Nat Info!
  A->>C3: PTCP SYN
  A->>C3: PTCP request sign
  C3-->>A: PTCP sign

  A->>D: PTCP handshake (*)
```

_Note_: Both connections marked with `(*)` and all subsequent connections to the device must use the same UDP local port.

### PTCP protocol

PTCP (PhonyTCP) is a proprietary protocol developed by Dahua. It serves the purpose of encapsulating TCP packets within UDP packets, enabling the creation of a tunnel between a client and a device behind a NAT.

Please note that official documentation for PTCP is not available. The information provided here is based on reverse engineering.

### PTCP packet header

The PTCP packet header is a fixed 24-byte structure, as outlined below:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             magic                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             sent                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             recv                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             pid                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             lmid                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             rmid                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `magic`: A constant value, `PTCP`.
- `sent` and `recv`: Track the number of bytes sent and received, respectively.
- `pid`: The Packet ID.
- `lmid`: The Local ID.
- `rmid`: The Local ID of previously received packet.

### PTCP packet body

The packet body varies in size (0, 4, 12 bytes or more) based on the packet type. Its structure is as follows:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      type       |                     len                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             realm                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             padding                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `type`: Specifies the packet type.
- `len`: The length of the `data` field.
- `realm`: The Realm ID of the connection.
- `padding`: Padding bytes, always set to 0.
- `data`: The packet data.

Packet types:

- Special:
  - Empty body
  - `0x00`: SYN, the body is always 4 bytes `0x00030100`.
- Realm:
  - `0x10`: TCP data, where `len` is the length of the TCP data.
  - `0x11`: Binding port request.
  - `0x12`: Connection status, where the data is either `CONN` or `DISC`.
- Common (with `realm` set to 0):
  - `0x13`: Heartbeat, where `len` is always 0.
  - `0x17`
  - `0x18`
  - `0x19`: Authentication.
  - `0x1a`: Server response after `0x19`.
  - `0x1b`: Client response after `0x1a`.

## Acknowledgments

This project has been inspired and influenced by the following projects and people:

- [mcw0/PoC](https://github.com/mcw0/PoC): The foundational structure for the handshake and the PTCP protocol.
- [@p2p-sys](https://github.com/p2p-sys): The idea of inverting the STUN protocol.
