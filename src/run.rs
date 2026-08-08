//! Proxy / transform runtime: userspace forwarder, kernel-mode dispatch,
//! key derivation, and the packet obfuscation primitives.

use std::{
    collections::HashMap,
    io::ErrorKind,
    net::{SocketAddr, SocketAddrV4},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

// `Ipv4Addr` is only referenced by the kernel-mode client fallback listen
// address, so gate it behind the feature to keep default builds warning-free.
#[cfg(feature = "kernel")]
use std::net::Ipv4Addr;

use anyhow::{Result, bail};
use log::{debug, error, info};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    spawn,
    sync::{mpsc, RwLock},
};

use crate::ForwarderArgs;

// `kernel` is declared as a crate-root module in main.rs (src/kernel.rs).
#[cfg(feature = "kernel")]
use crate::kernel;

const MAX_UDP_SIZE: usize = u16::MAX as usize;
// Largest possible UDP payload: 65535 bytes - 20 (IP header) - 8 (UDP header).
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize - 28;
// Per-worker cap on concurrent sessions. Each session holds a socket and a
// task until the inactivity timeout, so unbounded sessions would let
// spoofed sources exhaust file descriptors.
const MAX_SESSIONS_PER_WORKER: usize = 256;
pub const DERIVED_KEY_NUM: usize = 64;
const DERIVED_KEY_LEN: usize = 8;
// The standard WireGuard listen port; assumed on the kernel-mode server when
// `--forward` is omitted (matches `wg-quick`'s default). Used only by the
// `kernel` feature's `run_kernel`.
#[cfg(feature = "kernel")]
const DEFAULT_WG_PORT: u16 = 51820;

#[inline]
fn xor_transform(data: &mut [u8], key: &[u8; 8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

/// Maximum padding appended to a 32-byte keepalive data packet (0..=64
/// random bytes, so a padded keepalive lands in [32, 96] on the wire).
const KEEPALIVE_PAD_MAX: usize = 64;
/// Bit 7 of packet[2] (the key-byte index) marks data padding presence:
/// 0 = padded keepalive, 1 = plain data packet. The pad length is inferred
/// from the wire length (pad = len - 32), so this single flag is all the
/// decoder needs. Using only the top bit keeps the rest of packet[2]
/// random, so the byte's distribution stays wide (128 values per class).
const KEEPALIVE_PAD_BIT: u8 = 0x80;

fn obfuscate(packet: &mut [u8], len: usize, key: &Key, is_encode: bool) -> Result<usize> {
    // NOTE: `packet` is the full scratch buffer (MAX_UDP_SIZE bytes) and
    // `len` is the actual datagram length, so all bounds checks below must
    // use `len`. Bytes past `len` hold stale data from previous datagrams
    // and must never be read, transformed, or forwarded.
    if len < 4 {
        bail!("packet too short: {len} bytes");
    }

    // Padding appended by the encode path to data keepalive packets
    // (exactly 32 bytes): 0..=64 random bytes. Bit 7 of the key-byte
    // index (packet[2]) is cleared to mark the padded keepalive, and the
    // pad length is inferred from the wire length. The low 3 bits still
    // select the derived-key byte for the type mask (`Key::get_key_byte`
    // uses `index % 8`). Non-keepalive data packets set bit 7 so the
    // decoder can never confuse them with a padded keepalive. Handshakes
    // are unchanged (their padding is implied by the fixed canonical
    // sizes, and packet[2] stays fully random).
    let (message_type, used_key, data_pad, is_keepalive_pad) = if is_encode {
        let message_type = packet[0];
        packet[0..4].copy_from_slice(&getrandom::u32()?.to_le_bytes());
        let used_key = key.get(&packet[..2])?;
        let mut kbidx = packet[2];
        let data_pad = if message_type == 4 && len == 32 {
            // Cap so `len + pad` never exceeds the UDP payload limit.
            let pad = ((getrandom::u32()? as u8 % (KEEPALIVE_PAD_MAX as u8 + 1)) as usize)
                .min(MAX_UDP_PAYLOAD.saturating_sub(len));
            // Padded keepalive: bit 7 = 0.
            kbidx &= !KEEPALIVE_PAD_BIT;
            packet[2] = kbidx;
            pad
        } else {
            // Non-keepalive data: bit 7 = 1 marks "no padding".
            if message_type == 4 {
                kbidx |= KEEPALIVE_PAD_BIT;
                packet[2] = kbidx;
            }
            0
        };
        packet[3] = message_type ^ Key::get_key_byte(used_key, kbidx);
        (message_type, used_key, data_pad, false)
    } else {
        let used_key = key.get(&packet[..2])?;
        let message_type = packet[3] ^ Key::get_key_byte(used_key, packet[2]);
        // Capture the keepalive flag before the header is cleared.
        let is_keepalive_pad = message_type == 4 && (packet[2] & KEEPALIVE_PAD_BIT) == 0;

        packet[0] = message_type;
        packet[1..4].fill(0);
        (message_type, used_key, 0, is_keepalive_pad)
    };

    Ok(match message_type {
        // data
        4 => {
            if is_encode {
                if len < 16 {
                    bail!("truncated data packet: {len} bytes");
                }
                xor_transform(&mut packet[4..16], used_key);
                // Only keepalives (exactly 32 bytes) are padded.
                let padding_len = if len == 32 { len + data_pad } else { len };
                getrandom::fill(&mut packet[len..padding_len])?;
                padding_len
            } else if is_keepalive_pad {
                // Padded keepalive: the pad length is inferred from the
                // wire length (the flag in packet[2] is the marker).
                if (32..=32 + KEEPALIVE_PAD_MAX).contains(&len) {
                    xor_transform(&mut packet[4..16], used_key);
                    32
                } else {
                    // Flagged as keepalive but outside the valid length
                    // range: not a padded keepalive from a current peer
                    // (e.g. a plain data packet from an older peer whose
                    // packet[2] bit 7 is random). Pass it through
                    // untouched instead of dropping it.
                    if len < 16 {
                        bail!("truncated data packet: {len} bytes");
                    }
                    xor_transform(&mut packet[4..16], used_key);
                    len
                }
            } else {
                if len < 16 {
                    bail!("truncated data packet: {len} bytes");
                }
                xor_transform(&mut packet[4..16], used_key);
                len
            }
        }
        // handshake and cookie
        1..=3 => {
            if is_encode {
                let padding_size = (getrandom::u32()? as u8 % 64) as usize;
                // Cap at the real UDP payload limit (65507 bytes); anything
                // larger would fail in send_to with EMSGSIZE.
                let padding_len = (len + padding_size).min(MAX_UDP_PAYLOAD);
                // XOR only the bytes that will actually be sent (the real
                // packet plus the padding region); the rest of the scratch
                // buffer holds stale data and must not be touched.
                xor_transform(&mut packet[4..padding_len], used_key);
                getrandom::fill(&mut packet[len..padding_len])?;
                padding_len
            } else {
                let size = match message_type {
                    1 => 148,
                    2 => 92,
                    3 => 64,
                    _ => unreachable!(),
                };
                if len < size {
                    bail!("truncated handshake packet: {len} < {size} bytes");
                }
                xor_transform(&mut packet[4..size], used_key);
                size
            }
        }
        x => bail!("invalid message type: {x}"),
    })
}

fn new_reuseport_udp_socket(addr: SocketAddrV4) -> Result<UdpSocket> {
    let udp_sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    #[cfg(not(windows))]
    {
        // SO_REUSEADDR + SO_REUSEPORT together: REUSEPORT allows several
        // workers (and a restarted process) to share the port, and REUSEADDR
        // lets a restart rebind while a previous instance's sockets are
        // still lingering (on macOS/BSD the two interact, and REUSEPORT
        // alone is not always enough to avoid EADDRINUSE).
        udp_sock.set_reuse_address(true)?;
        udp_sock.set_reuse_port(true)?;
        udp_sock.set_cloexec(true)?;
    }

    udp_sock.set_nonblocking(true)?;
    udp_sock.bind(&socket2::SockAddr::from(addr))?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    Ok(udp_sock.try_into()?)
}

async fn handle_forward_socket(
    is_client: bool,
    listen_socket: Arc<UdpSocket>,
    proxy_socket: Arc<UdpSocket>,
    original_src: SocketAddr,
    key: &Key,
    sessions: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    timeout_duration: Duration,
) {
    let mut buf = [0u8; MAX_UDP_SIZE];
    loop {
        match tokio::time::timeout(timeout_duration, proxy_socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from_addr))) => {
                debug!("Reverse: Received {len} bytes from {from_addr}");

                let trim_len = match obfuscate(&mut buf[..], len, key, !is_client) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("[Session {original_src}] Failed to transform packet: {e}");
                        continue;
                    }
                };

                if let Err(e) = listen_socket.send_to(&buf[..trim_len], original_src).await {
                    error!(
                        "[Session {original_src}] Failed to send packet back to original source: {e}",
                    );
                    break;
                }
            }
            // An error occurred while receiving on the proxy socket
            Ok(Err(e)) => {
                error!("[Session {original_src}] Error receiving from proxy socket: {e}");
                break;
            }
            // A timeout occurred
            Err(_) => {
                info!("[Session {original_src}] Timed out due to inactivity.");
                break;
            }
        }
    }

    info!("[Session {original_src}] Closing and cleaning up.");
    sessions.write().await.remove(&original_src);
}

// TCP transport mode ------------------------------------------------------
//
// `--tcp` replaces the plain-UDP network between the two manglers with TCP
// connections. The client binds a local UDP port (where the WireGuard peer
// points), the server listens on a TCP port, and each WireGuard datagram
// crosses the tunnel as one TCP frame:
//
//   [ 2-byte length ^ used_key ][ obfuscate-encoded datagram ]
//
// The payload is exactly what UDP mode puts on the wire: the output of
// `obfuscate` (encode) -- `[ 2-byte random key index ][ key-byte index ]
// [ type ^ key byte ][ XORed body (+ random handshake padding) ]`. Its
// first 2 bytes are the key index, so the derived key used for the length
// field is selected exactly as `obfuscate` selects it: `Key::get` on those
// 2 bytes. The two length bytes are XORed with two bytes of that derived
// key -- the first with `Key::get_key_byte(used_key, 3)`, the second with
// index 6 -- which both hides the length and lets a byte stream carry
// datagrams. Because the payload itself is already obfuscated, no raw
// WireGuard bytes ever appear on the TCP stream.

const TCP_FRAME_HEADER_LEN: usize = 2;
// Frames carry UDP datagrams, so the payload is bounded by the largest
// possible UDP payload.
const MAX_TCP_PAYLOAD: usize = MAX_UDP_PAYLOAD;
// Every `obfuscate` output is at least 4 bytes (the transformed header);
// anything shorter on the wire means a wrong key or a corrupt frame.
const MIN_TCP_PAYLOAD: usize = 4;

/// Per-session frame queue handle on the TCP client: `src_addr` -> sender.
/// Wrapped in `Arc` so a session can verify (by pointer identity) that the
/// map entry it cleans up is still its own.
type TcpSessionSender = Arc<mpsc::UnboundedSender<Vec<u8>>>;
type TcpSessions = Arc<RwLock<HashMap<SocketAddr, TcpSessionSender>>>;

/// Build the 2-byte TCP frame length field for a payload of `payload_len`
/// bytes: `(payload_len as LE u16) XORed with derived key bytes 3 and 6`.
/// The `used_key` is the 8-byte derived key selected by the payload's own
/// first 2 bytes (the key index), exactly as `obfuscate` selects it.
fn encode_tcp_frame_header(
    payload_len: usize,
    used_key: &[u8; DERIVED_KEY_LEN],
) -> [u8; TCP_FRAME_HEADER_LEN] {
    assert!(payload_len <= MAX_TCP_PAYLOAD);
    let len_le = (payload_len as u16).to_le_bytes();
    [
        len_le[0] ^ Key::get_key_byte(used_key, 3),
        len_le[1] ^ Key::get_key_byte(used_key, 6),
    ]
}

/// Decode the payload length out of a 2-byte TCP frame length field
/// (undoes the derived-key XOR on both bytes). Rejects lengths larger than
/// any UDP datagram could be.
fn decode_tcp_frame_header(
    len_field: &[u8; TCP_FRAME_HEADER_LEN],
    used_key: &[u8; DERIVED_KEY_LEN],
) -> Result<usize> {
    let len_le = [
        len_field[0] ^ Key::get_key_byte(used_key, 3),
        len_field[1] ^ Key::get_key_byte(used_key, 6),
    ];
    let payload_len = u16::from_le_bytes(len_le) as usize;
    if payload_len > MAX_TCP_PAYLOAD {
        bail!("oversized TCP frame: {payload_len} bytes");
    }
    Ok(payload_len)
}

/// Encode a raw WireGuard datagram into a complete TCP frame in-place in
/// `frame`: the datagram (first `len` bytes of `frame[TCP_FRAME_HEADER_LEN..]`)
/// is obfuscated exactly as UDP mode encodes it, and the 2-byte length
/// field is written in front. Returns the total frame length.
fn encode_tcp_frame(frame: &mut [u8], len: usize, key: &Key) -> Result<usize> {
    let mangled_len = obfuscate(&mut frame[TCP_FRAME_HEADER_LEN..], len, key, true)?;
    let used_key = key.get(&frame[TCP_FRAME_HEADER_LEN..TCP_FRAME_HEADER_LEN + 2])?;
    let header = encode_tcp_frame_header(mangled_len, used_key);
    frame[..TCP_FRAME_HEADER_LEN].copy_from_slice(&header);
    Ok(mangled_len + TCP_FRAME_HEADER_LEN)
}

/// Read and decode the next TCP frame from `reader` into `payload[..len]`.
/// The payload read back is the obfuscate-encoded datagram (its first 2
/// bytes are the key index the length field was keyed on); the caller
/// passes it to `obfuscate(.., false)` to recover the WireGuard datagram.
/// Returns `Ok(None)` when the connection ends cleanly at a frame boundary
/// (peer closed), `Ok(Some(len))` for a complete frame, or an error for a
/// truncated/oversized frame or a transport failure.
async fn read_tcp_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    payload: &mut [u8],
    key: &Key,
) -> Result<Option<usize>> {
    let mut len_field = [0u8; TCP_FRAME_HEADER_LEN];
    match reader.read_exact(&mut len_field).await {
        Ok(_) => {}
        // EOF before a frame's first byte: clean close by the peer
        // (a mid-header EOF is not byte-perfect, but the session is over
        // either way).
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    // The length field is keyed by the payload's own key index, so read
    // the payload's first 2 bytes before we can decode the length.
    match reader.read_exact(&mut payload[..TCP_FRAME_HEADER_LEN]).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let used_key = key.get(&payload[..TCP_FRAME_HEADER_LEN])?;
    let payload_len = decode_tcp_frame_header(&len_field, used_key)?;
    if !(MIN_TCP_PAYLOAD..=MAX_TCP_PAYLOAD).contains(&payload_len) {
        bail!("invalid TCP frame length: {payload_len}");
    }
    if payload_len > payload.len() {
        bail!("TCP frame does not fit the receive buffer: {payload_len}");
    }
    reader
        .read_exact(&mut payload[TCP_FRAME_HEADER_LEN..payload_len])
        .await
        .map_err(anyhow::Error::from)?;
    Ok(Some(payload_len))
}

fn new_reuseport_tcp_listener(addr: SocketAddrV4) -> Result<TcpListener> {
    let tcp_sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)?;
    #[cfg(not(windows))]
    {
        // SO_REUSEADDR lets a restarted server rebind while previous
        // connections are still draining in TIME_WAIT (TCP-only: every
        // session is its own connection, and the server closes it, so the
        // port is routinely full of TIME_WAIT entries for 2*MSL). Without
        // it, `bind` fails with EADDRINUSE right after a restart even
        // though no listener is active. SO_REUSEPORT alone does not bypass
        // TIME_WAIT -- it only allows sharing the port between sockets.
        tcp_sock.set_reuse_address(true)?;
        tcp_sock.set_reuse_port(true)?;
        tcp_sock.set_cloexec(true)?;
    }
    tcp_sock.set_nonblocking(true)?;
    tcp_sock.bind(&socket2::SockAddr::from(addr))?;
    tcp_sock.listen(1024)?;
    let tcp_sock: std::net::TcpListener = tcp_sock.into();
    Ok(tcp_sock.try_into()?)
}

/// One TCP tunnel session on the client: `src_addr` is the local WireGuard
/// process's UDP address it relays for. Frames queued by the listener loop
/// are written into the TCP stream by a dedicated writer task, and frames
/// received from the server are sent back to `src_addr` over the shared
/// listen socket.
#[allow(clippy::too_many_arguments)]
async fn client_tcp_session(
    src_addr: SocketAddr,
    forward: SocketAddrV4,
    listen_socket: Arc<UdpSocket>,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    session_tx: TcpSessionSender,
    sessions: TcpSessions,
    timeout_duration: Duration,
    key: Key,
) {
    let stream = match TcpStream::connect(forward).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("[Session {src_addr}] Failed to connect to server at {forward}: {e}");
            sessions.write().await.remove(&src_addr);
            return;
        }
    };
    // Frames are already packaged datagrams; Nagle would serialize them
    // against the ACK clock (one frame per RTT on a real WAN). Send every
    // frame as soon as it is written.
    if let Err(e) = stream.set_nodelay(true) {
        error!("[Session {src_addr}] set_nodelay failed: {e}");
    }
    info!("[Session {src_addr}] TCP connection to {forward} established.");

    let (mut reader, mut writer) = stream.into_split();

    // Outbound path (frames queued by the listener loop -> TCP), as its
    // own task so a busy stream of outbound frames can never starve the
    // inbound path below (a single select loop would always prefer
    // whichever direction has data queued).
    let writer_task = spawn(async move {
        while let Some(frame) = rx.recv().await {
            if let Err(e) = writer.write_all(&frame).await {
                error!("[Session {src_addr}] Failed to write to TCP stream: {e}");
                break;
            }
        }
    });

    // Inbound path (TCP frames -> UDP back to the WireGuard source).
    let mut payload = vec![0u8; MAX_TCP_PAYLOAD];
    loop {
        match tokio::time::timeout(
            timeout_duration,
            read_tcp_frame(&mut reader, &mut payload, &key),
        )
        .await
        {
            Ok(Ok(Some(len))) => {
                // The frame payload is an obfuscate-encoded datagram;
                // restore the raw WireGuard packet before forwarding.
                let wg_len = match obfuscate(&mut payload[..], len, &key, false) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("[Session {src_addr}] Failed to deobfuscate packet: {e}");
                        continue;
                    }
                };
                if let Err(e) = listen_socket.send_to(&payload[..wg_len], src_addr).await {
                    error!("[Session {src_addr}] Failed to send packet back to source: {e}");
                    break;
                }
            }
            Ok(Ok(None)) => {
                info!("[Session {src_addr}] TCP connection closed by the server.");
                break;
            }
            Ok(Err(e)) => {
                error!("[Session {src_addr}] Failed to read TCP frame: {e}");
                break;
            }
            Err(_) => {
                info!("[Session {src_addr}] Timed out due to inactivity.");
                break;
            }
        }
    }

    info!("[Session {src_addr}] Closing and cleaning up.");
    // Stop the writer task; dropping the halves and the receiver closes
    // the stream and the channel.
    writer_task.abort();
    // Only remove the entry this session still owns (a fresh session may
    // already have been inserted for the same source).
    let mut guard = sessions.write().await;
    if guard
        .get(&src_addr)
        .is_some_and(|tx| Arc::ptr_eq(tx, &session_tx))
    {
        guard.remove(&src_addr);
    }
}

/// TCP client: binds a local UDP port (where the WireGuard peer points)
/// and opens one TCP connection per WireGuard source socket to the server.
/// TCP client: binds a local UDP port (where the WireGuard peer points)
/// and opens one TCP connection per WireGuard source socket to the server.
async fn run_tcp_client(
    listen: SocketAddrV4,
    forward: SocketAddrV4,
    timeout_duration: Duration,
    key: Key,
) -> Result<()> {
    info!("Listening on UDP: {listen}");

    // Same per-worker structure as the UDP proxy: each worker binds its own
    // reuseport socket and keeps its own sessions map.
    for _ in 0..get_cpus_num() {
        let key = key.clone();
        tokio::spawn(async move {
            let listen_socket = match new_reuseport_udp_socket(listen) {
                Ok(v) => Arc::new(v),
                Err(e) => {
                    // With SO_REUSEADDR set, an EADDRINUSE here means the
                    // local UDP port is really in use (e.g. a previous
                    // client still running on the same --listen port).
                    error!(
                        "can not create the listen_socket on {listen}: {e} \
                         (another wg-mangler still running on this port?)"
                    );
                    return;
                }
            };
            let sessions: TcpSessions = Arc::new(RwLock::new(HashMap::new()));

            // + TCP_FRAME_HEADER_LEN bytes of headroom for the length field
            // (obfuscate may also add up to 63 bytes of handshake padding,
            // but the receive buffer is sized for the full UDP payload).
            let mut buf = [0u8; MAX_TCP_PAYLOAD + TCP_FRAME_HEADER_LEN];
            loop {
                let (len, src_addr) =
                    match listen_socket.recv_from(&mut buf[TCP_FRAME_HEADER_LEN..]).await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("listen_socket recv_from error: {e}");
                            continue;
                        }
                    };
                debug!("listen socket: received {len} bytes from {src_addr}");

                // Encode the raw WireGuard datagram into a full TCP frame
                // in place: obfuscate it exactly as UDP mode does, then
                // write the [ length ^ used_key ] field in front.
                let frame_len = match encode_tcp_frame(&mut buf, len, &key) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("[Session {src_addr}] Failed to obfuscate packet: {e}");
                        continue;
                    }
                };
                let frame = buf[..frame_len].to_vec();

                // Reuse this source's session, or open a TCP tunnel (and a
                // reader task) for a new source. Clone out of the read
                // guard first so the match arms never touch the lock while
                // the read guard is still alive (the write lock below must
                // not wait on it -- same pattern as the UDP proxy).
                let existing = sessions.read().await.get(&src_addr).cloned();
                let tx = match existing {
                    Some(tx) => tx,
                    None => {
                        let (tx, rx) = mpsc::unbounded_channel();
                        let tx = Arc::new(tx);
                        let mut guard = sessions.write().await;
                        if let Some(tx) = guard.get(&src_addr) {
                            tx.clone()
                        } else {
                            if guard.len() >= MAX_SESSIONS_PER_WORKER {
                                error!(
                                    "[Session {src_addr}] Session limit ({MAX_SESSIONS_PER_WORKER}) reached; dropping packet"
                                );
                                continue;
                            }
                            info!("[Session {src_addr}] New connection established.");
                            guard.insert(src_addr, tx.clone());
                            {
                                let listen_socket = listen_socket.clone();
                                let sessions = sessions.clone();
                                let key = key.clone();
                                let session_tx = tx.clone();
                                spawn(async move {
                                    client_tcp_session(
                                        src_addr,
                                        forward,
                                        listen_socket,
                                        rx,
                                        session_tx,
                                        sessions,
                                        timeout_duration,
                                        key,
                                    )
                                    .await;
                                });
                            }
                            tx
                        }
                    }
                };

                if let Err(e) = tx.send(frame) {
                    // The session's TCP connection is gone; drop the entry
                    // so the next packet from this source opens a fresh one.
                    error!("[Session {src_addr}] Failed to queue frame for TCP stream: {e}");
                    sessions.write().await.remove(&src_addr);
                }
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

/// One accepted TCP connection on the server: frames arriving on the stream
/// are sent as datagrams to `forward` (the local WireGuard daemon), and the
/// daemon's replies are framed and streamed back to the client. The session
/// ends when the connection closes, or when no datagram arrives for
/// `timeout_duration`.
async fn server_tcp_session(
    stream: TcpStream,
    peer: SocketAddr,
    forward: SocketAddrV4,
    timeout_duration: Duration,
    key: Key,
) {
    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(v) => Arc::new(v),
        Err(e) => {
            error!("[Session {peer}] can not create the forwarder socket: {e}");
            return;
        }
    };
    // See client_tcp_session: frames are already packaged datagrams and
    // must not wait on the Nagle/ACK clock (one frame per RTT on a WAN).
    if let Err(e) = stream.set_nodelay(true) {
        error!("[Session {peer}] set_nodelay failed: {e}");
    }
    let (mut reader, mut writer) = stream.into_split();

    // Inbound path: TCP frames from the client -> UDP to the WG daemon.
    // `closed_tx` drops (and so wakes the outbound select below) whenever
    // this task exits for any reason.
    let (_closed_tx, mut closed_rx) = tokio::sync::watch::channel(false);
    let udp_in = udp.clone();
    let key_in = key.clone();
    let reader_task = spawn(async move {
        let mut payload = vec![0u8; MAX_TCP_PAYLOAD];
        loop {
            let len = match read_tcp_frame(&mut reader, &mut payload, &key_in).await {
                Ok(Some(len)) => len,
                Ok(None) => {
                    info!("[Session {peer}] Connection closed by the client.");
                    break;
                }
                Err(e) => {
                    error!("[Session {peer}] Failed to read TCP frame: {e}");
                    break;
                }
            };
            // The frame payload is an obfuscate-encoded datagram; restore
            // the raw WireGuard packet before forwarding to the daemon.
            let wg_len = match obfuscate(&mut payload[..], len, &key_in, false) {
                Ok(v) => v,
                Err(e) => {
                    error!("[Session {peer}] Failed to deobfuscate packet: {e}");
                    break;
                }
            };
            if let Err(e) = udp_in.send_to(&payload[..wg_len], forward).await {
                error!("[Session {peer}] Failed to send packet to {forward}: {e}");
                break;
            }
        }
    });

    // Outbound path: WG daemon replies -> TCP frames back to the client.
    let mut buf = [0u8; MAX_TCP_PAYLOAD + TCP_FRAME_HEADER_LEN];
    loop {
        tokio::select! {
            // The inbound task ended (EOF, error): break immediately
            // instead of waiting out the inactivity timeout.
            _ = closed_rx.changed() => break,
            recv = tokio::time::timeout(
                timeout_duration,
                udp.recv_from(&mut buf[TCP_FRAME_HEADER_LEN..]),
            ) => {
                let len = match recv {
                    Ok(Ok((len, _from_addr))) => len,
                    Ok(Err(e)) => {
                        error!("[Session {peer}] Error receiving from forwarder socket: {e}");
                        break;
                    }
                    Err(_) => {
                        info!("[Session {peer}] Timed out due to inactivity.");
                        break;
                    }
                };
                // Encode the WG daemon's raw datagram into a full TCP
                // frame in place, like the client's send path.
                let frame_len = match encode_tcp_frame(&mut buf, len, &key) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("[Session {peer}] Failed to obfuscate packet: {e}");
                        break;
                    }
                };
                if let Err(e) = writer.write_all(&buf[..frame_len]).await {
                    error!("[Session {peer}] Failed to write to TCP stream: {e}");
                    break;
                }
            }
        }
    }

    // Stop the inbound task (it may be blocked on a TCP read). Dropping
    // both halves of the stream and the last socket ref closes the session.
    reader_task.abort();
}

/// TCP server: listens on the public TCP port and accepts one tunnel
/// connection per WireGuard source.
async fn run_tcp_server(
    listen: SocketAddrV4,
    forward: SocketAddrV4,
    timeout_duration: Duration,
    key: Key,
) -> Result<()> {
    info!("Listening on TCP: {listen}");

    for _ in 0..get_cpus_num() {
        let key = key.clone();
        tokio::spawn(async move {
            let listener = match new_reuseport_tcp_listener(listen) {
                Ok(v) => v,
                Err(e) => {
                    // With SO_REUSEADDR set, an EADDRINUSE here means a real
                    // listener is still bound to the port (a stale process
                    // from a previous run), not just TIME_WAIT entries.
                    error!(
                        "can not create the listener on {listen}: {e} \
                         (another wg-mangler still running on this port?)"
                    );
                    return;
                }
            };
            // Bound connections so floods cannot exhaust sockets and tasks.
            let session_count = Arc::new(AtomicUsize::new(0));
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("listener accept error: {e}");
                        continue;
                    }
                };
                if session_count.load(Ordering::Relaxed) >= MAX_SESSIONS_PER_WORKER {
                    error!(
                        "[Session {peer}] Session limit ({MAX_SESSIONS_PER_WORKER}) reached; dropping connection"
                    );
                    drop(stream);
                    continue;
                }
                session_count.fetch_add(1, Ordering::Relaxed);
                let session_count = session_count.clone();
                let key = key.clone();
                spawn(async move {
                    server_tcp_session(stream, peer, forward, timeout_duration, key).await;
                    session_count.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn run_tcp_forwarder(args: ForwarderArgs, is_client: bool) -> Result<()> {
    let listen = args.listen.expect("listen checked by run_dispatch");
    let forward = args.forward.expect("forward checked by run_dispatch");
    let timeout_duration = Duration::from_secs(args.timeout);
    let key = Key::new(args.key);

    if is_client {
        run_tcp_client(listen, forward, timeout_duration, key).await
    } else {
        run_tcp_server(listen, forward, timeout_duration, key).await
    }
}

pub fn generate_key() -> Result<()> {
    let mut arr = [0u8; 32];
    getrandom::fill(&mut arr[..])?;

    println!("{}", bs58::encode(arr).into_string());
    Ok(())
}

#[derive(Clone)]
pub struct Key(pub [[u8; DERIVED_KEY_LEN]; DERIVED_KEY_NUM]);

impl Key {
    pub fn new(seed: [u8; 32]) -> Key {
        let mut derived = [[0u8; DERIVED_KEY_LEN]; DERIVED_KEY_NUM];
        for (i, v) in derived.iter_mut().enumerate() {
            // SHA-256 is a stable, platform-independent KDF: both ends must
            // derive identical keys regardless of Rust version or arch.
            // (std DefaultHasher is explicitly NOT stable across releases.)
            let mut hasher = Sha256::new();
            hasher.update(seed);
            hasher.update((i as u32).to_le_bytes());
            v.copy_from_slice(&hasher.finalize()[..DERIVED_KEY_LEN]);
        }

        Key(derived)
    }

    fn get(&self, index: &[u8]) -> Result<&[u8; DERIVED_KEY_LEN]> {
        let index: [u8; 2] = index.try_into()?;
        let index = u16::from_le_bytes(index);
        Ok(&self.0[index as usize % DERIVED_KEY_NUM])
    }

    fn get_key_byte(key: &[u8; DERIVED_KEY_LEN], index: u8) -> u8 {
        key[index as usize % DERIVED_KEY_LEN]
    }
}

#[inline]
#[cfg(windows)]
fn get_cpus_num() -> usize {
    // Windows has no SO_REUSEPORT, so only a single listener can bind the
    // port; one worker is the only correct setup there.
    1
}

#[inline]
#[cfg(not(windows))]
fn get_cpus_num() -> usize {
    num_cpus::get()
}

/// Dispatch to kernel, TCP, or userspace mode based on the CLI flags.
pub async fn run_dispatch(args: ForwarderArgs, is_client: bool) -> Result<()> {
    if args.tcp {
        // TCP mode never involves the kernel and does not use the key.
        if args.kernel {
            bail!("--tcp and --kernel are mutually exclusive");
        }
        if args.listen.is_none() {
            bail!(
                "tcp mode requires --listen (the local UDP port on the \
                 client, the public TCP port on the server)"
            );
        }
        if args.forward.is_none() {
            bail!(
                "tcp mode requires --forward (the server's TCP endpoint \
                 on the client, the local WireGuard daemon on the server)"
            );
        }
        run_tcp_forwarder(args, is_client).await
    } else if args.kernel {
        // Kernel mode: the client binds nothing locally -- `--listen` is not
        // needed (the interface is picked from the route to the peer, and
        // the peer's ports/IP come from `--forward`). The server still needs
        // the mangler port (`--listen`); `--forward` is optional there.
        if !is_client && args.listen.is_none() {
            bail!("server mode requires --listen (the public mangler port)");
        }
        run_kernel(args, is_client).await
    } else {
        if args.listen.is_none() {
            bail!(
                "userspace mode requires --listen (the local port WireGuard \
                 points at); omit it only with --kernel"
            );
        }
        if args.forward.is_none() {
            bail!(
                "userspace mode requires --forward (the address to forward \
                 decoded packets to)"
            );
        }
        run_forwarder(args, is_client).await
    }
}

/// Kernel eBPF mode: load XDP/TC programs and let the kernel do the transform.
#[cfg(feature = "kernel")]
async fn run_kernel(args: ForwarderArgs, is_client: bool) -> Result<()> {
    let forward_v4 = match args.forward {
        // Explicit `--forward` (both roles): clap already parsed and
        // resolved it (`IP:port` or `domain:port`, always IPv4).
        Some(addr) => addr,
        // Kernel server without `--forward`: the WireGuard daemon runs on
        // this host, so only its listen port is used (the XDP decode rewrites
        // the dst port of matching packets onto it; the remote IP is not used
        // server-side because decoded packets are delivered locally, never
        // re-forwarded). Assume the standard wg port.
        None if !is_client => {
            info!(
                "kernel server: --forward omitted, assuming the local WireGuard \
                 daemon listens on the standard port {DEFAULT_WG_PORT}"
            );
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_WG_PORT)
        }
        // Kernel client: the peer's endpoint is required (ports + remote IP
        // are injected into the eBPF CONFIG map).
        None => bail!(
            "kernel client mode requires --forward (the peer's mangler endpoint: \
             IP:MG_PORT)"
        ),
    };

    let listen = args.listen.unwrap_or_else(|| {
        // Client in kernel mode: unused (no local bind, interface is picked
        // from the route to the peer). Provide a placeholder.
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)
    });
    kernel::run_kernel_ebpf(
        listen,
        forward_v4,
        &args.key,
        is_client,
        args.iface.as_deref(),
    )
    .await?;

    Ok(())
}

/// Kernel eBPF mode stub (non-Linux / feature disabled).
#[cfg(not(feature = "kernel"))]
async fn run_kernel(args: ForwarderArgs, _is_client: bool) -> Result<()> {
    let _ = args; // suppress unused warning
    bail!(
        "kernel eBPF mode requires the `kernel` feature and Linux.\n\
         Rebuild with: cargo build --features kernel --release\n\
         Or omit --kernel to use the standard userspace proxy."
    );
}

async fn run_forwarder(args: ForwarderArgs, is_client: bool) -> Result<()> {
    let listen = args.listen.expect("listen checked by run_dispatch");
    info!("Listening on: {listen}");

    let key = Key::new(args.key);
    let timeout_duration = Duration::from_secs(args.timeout);
    let forward_addr = args.forward.expect("forward checked by run_dispatch");

    // NOTE: each worker binds its own SO_REUSEPORT listener and keeps its
    // own session table. This relies on the kernel steering all packets of
    // a given client 4-tuple to the same socket (Linux reuseport hashing
    // stays consistent while the socket set is unchanged), so a client's
    // sessions are never split across workers.
    for _ in 0..get_cpus_num() {
        let key = key.clone();
        tokio::spawn(async move {
            let listen_socket = match new_reuseport_udp_socket(listen) {
                Ok(v) => v,
                Err(e) => {
                    error!("can not create the listen_socket: {e}");
                    return;
                }
            };
            let listen_socket = Arc::new(listen_socket);
            let sessions: Arc<RwLock<HashMap<_, Arc<UdpSocket>>>> =
                Arc::new(RwLock::new(HashMap::new()));

            let mut buf = [0u8; MAX_UDP_SIZE];

            loop {
                let (len, src_addr) = match listen_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("listen_socket recv_from error: {e}");
                        continue;
                    }
                };
                debug!("listen socket: received {len} bytes from {src_addr}");

                // Validate and mangle the packet BEFORE creating a session:
                // an invalid packet from an unknown source must not be able
                // to allocate a session (socket + task) that lingers until
                // it times out, or spoofed sources could exhaust resources.
                let padding_len = match obfuscate(&mut buf[..], len, &key, is_client) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("[Session {src_addr}] Failed to obfuscate packet: {e}");
                        continue;
                    }
                };

                // Fast path: reuse an existing session for this source.
                let existing = sessions.read().await.get(&src_addr).cloned();
                let proxy_socket = if let Some(socket) = existing {
                    socket
                } else {
                    // New session: bind the proxy socket outside the lock so
                    // we never await while holding the sessions lock (the
                    // reverse-path cleanup task needs it to remove expired
                    // sessions).
                    let socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(v) => Arc::new(v),
                        Err(e) => {
                            error!("[Session {src_addr}] can not create the forwarder_socket: {e}");
                            // Keep serving the other clients on this worker.
                            continue;
                        }
                    };

                    let mut guard = sessions.write().await;
                    // NOTE: the forward loop is the only task that inserts
                    // sessions (reverse-path tasks only remove), so a plain
                    // get-then-insert is race-free here. Use the entry API if
                    // a concurrent inserter is ever introduced.
                    if let Some(socket) = guard.get(&src_addr) {
                        socket.clone()
                    } else {
                        // Bound sessions so spoofed sources cannot exhaust
                        // sockets and tasks: each session occupies a socket
                        // and a task until the inactivity timeout.
                        if guard.len() >= MAX_SESSIONS_PER_WORKER {
                            error!(
                                "[Session {src_addr}] Session limit ({MAX_SESSIONS_PER_WORKER}) reached; dropping packet"
                            );
                            continue;
                        }

                        info!("[Session {src_addr}] New connection established.");
                        guard.insert(src_addr, socket.clone());

                        {
                            let listen_socket = listen_socket.clone();
                            let key = key.clone();
                            let sessions = sessions.clone();
                            let forwarder_socket = socket.clone();
                            spawn(async move {
                                handle_forward_socket(
                                    is_client,
                                    listen_socket,
                                    forwarder_socket,
                                    src_addr,
                                    &key,
                                    sessions,
                                    timeout_duration,
                                )
                                .await;
                            });
                        }

                        socket
                    }
                };

                if let Err(e) = proxy_socket
                    .send_to(&buf[..padding_len], forward_addr)
                    .await
                {
                    error!("[Session {src_addr}] Failed to send_to packet: {e}");
                    // The proxy socket is likely broken. Remove the session
                    // so the next packet from this source binds a fresh
                    // socket; the old reverse-path task keeps draining the
                    // old socket until it times out, so upstream replies
                    // already in flight are still forwarded in the meantime.
                    sessions.write().await.remove(&src_addr);
                }
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [7u8; 32];

    fn test_packet(msg_type: u8, size: usize) -> ([u8; MAX_UDP_SIZE], [u8; MAX_UDP_SIZE]) {
        let mut buf = [0u8; MAX_UDP_SIZE];
        let mut original = [0u8; MAX_UDP_SIZE];
        for (i, byte) in original.iter_mut().enumerate().take(size) {
            *byte = (i as u8).wrapping_mul(31).wrapping_add(msg_type);
        }
        // WireGuard header: byte 0 is the type, bytes 1..4 are reserved (zero).
        original[0] = msg_type;
        original[1..4].fill(0);
        buf[..size].copy_from_slice(&original[..size]);
        (buf, original)
    }

    #[test]
    fn round_trip_all_message_types() {
        let key = Key::new(TEST_KEY);

        // handshake initiation / response / cookie: decode trims to the fixed size
        for (msg_type, size) in [(1u8, 148usize), (2, 92), (3, 64)] {
            let (mut buf, original) = test_packet(msg_type, size);
            let encoded = obfuscate(&mut buf[..], size, &key, true).unwrap();
            assert!(
                (size..=size + 63).contains(&encoded),
                "unexpected encoded length {encoded}"
            );
            let decoded = obfuscate(&mut buf[..], encoded, &key, false).unwrap();
            assert_eq!(decoded, size);
            assert_eq!(buf[..size], original[..size]);
        }

        // data keepalive: 0..=64 random padding is appended (the fixed
        // 32-byte keepalive length is hidden); decode strips it back.
        let (mut buf, original) = test_packet(4, 32);
        let encoded = obfuscate(&mut buf[..], 32, &key, true).unwrap();
        assert!(
            (32..=32 + KEEPALIVE_PAD_MAX).contains(&encoded),
            "unexpected data encoded length {encoded}"
        );
        let decoded = obfuscate(&mut buf[..], encoded, &key, false).unwrap();
        assert_eq!(decoded, 32);
        assert_eq!(buf[..32], original[..32]);
    }

    #[test]
    fn handshake_decode_restores_exact_wireguard_header() {
        let key = Key::new(TEST_KEY);
        let (mut buf, original) = test_packet(1, 148);
        obfuscate(&mut buf[..], 148, &key, true).unwrap();
        // Decoded bytes 0..4 must be exactly (type, 0, 0, 0).
        let _ = obfuscate(&mut buf[..], 148, &key, false).unwrap();
        assert_eq!(&buf[..4], &[1, 0, 0, 0]);
        assert_eq!(buf[..148], original[..148]);
    }

    #[test]
    fn rejects_short_packets_without_panicking() {
        let key = Key::new(TEST_KEY);
        let mut buf = [0u8; MAX_UDP_SIZE];

        // 0..3 bytes: too short for the 4-byte header (both directions)
        for len in 0..4 {
            assert!(obfuscate(&mut buf[..], len, &key, true).is_err());
            assert!(obfuscate(&mut buf[..], len, &key, false).is_err());
        }

        // truncated data packet
        buf[0] = 4;
        for len in 4..16 {
            assert!(obfuscate(&mut buf[..], len, &key, false).is_err());
        }

        // truncated handshake / cookie packets
        buf[0] = 1;
        for len in 4..148 {
            assert!(obfuscate(&mut buf[..], len, &key, false).is_err());
        }
        buf[0] = 2;
        for len in 4..92 {
            assert!(obfuscate(&mut buf[..], len, &key, false).is_err());
        }
        buf[0] = 3;
        for len in 4..64 {
            assert!(obfuscate(&mut buf[..], len, &key, false).is_err());
        }
    }

    #[test]
    fn padding_never_exceeds_buffer() {
        let key = Key::new(TEST_KEY);
        let mut buf = [0u8; MAX_UDP_SIZE];

        // Largest possible UDP payload (65507) with type 1 → padding is applied
        let len = u16::MAX as usize - 28;
        buf[0] = 1;
        let encoded = obfuscate(&mut buf[..], len, &key, true).unwrap();
        assert!(encoded <= MAX_UDP_SIZE);
        assert!(encoded >= len);
    }

    #[test]
    fn rejects_invalid_message_type() {
        let key = Key::new(TEST_KEY);
        let mut buf = [0u8; MAX_UDP_SIZE];

        // encode: byte 0 is not a valid WireGuard message type
        buf[0] = 5;
        assert!(obfuscate(&mut buf[..], 32, &key, true).is_err());

        // decode: craft a mangled header whose decoded type is invalid
        buf[0..2].copy_from_slice(&[1, 0]); // key index (1 % 64)
        buf[2] = 0; // key byte index
        let used_key = key.get(&buf[..2]).unwrap();
        buf[3] = 5 ^ Key::get_key_byte(used_key, 0);
        assert!(obfuscate(&mut buf[..], 32, &key, false).is_err());
    }

    #[test]
    fn key_derivation_is_deterministic() {
        assert_eq!(Key::new(TEST_KEY).0, Key::new(TEST_KEY).0);
    }

    #[test]
    fn decode_drops_padding() {
        let key = Key::new(TEST_KEY);

        // Padding size is random (0..=63), so encode until we actually get
        // a padded handshake packet.
        let (mut buf, original, encoded) = loop {
            let (mut buf, original) = test_packet(1, 148);
            let encoded = obfuscate(&mut buf[..], 148, &key, true).unwrap();
            if encoded > 148 {
                break (buf, original, encoded);
            }
        };

        // Corrupt the padding region: decode must ignore it completely and
        // return exactly the fixed handshake size.
        buf[148..encoded].fill(0xA5);
        let decoded = obfuscate(&mut buf[..], encoded, &key, false).unwrap();
        assert_eq!(decoded, 148);
        assert_eq!(buf[..148], original[..148]);
    }

    #[test]
    fn data_decode_drops_padding() {
        let key = Key::new(TEST_KEY);

        // Data padding is random (0..=31); encode until we get a padded
        // keepalive (the length is no longer a fixed 32 bytes).
        let (mut buf, original, encoded) = loop {
            let (mut buf, original) = test_packet(4, 32);
            let encoded = obfuscate(&mut buf[..], 32, &key, true).unwrap();
            if encoded > 32 {
                break (buf, original, encoded);
            }
        };

        // Corrupt the padding region: decode must strip it using the
        // padding length encoded in the key-byte index (byte 2), restoring
        // the exact original packet.
        buf[32..encoded].fill(0xA5);
        let decoded = obfuscate(&mut buf[..], encoded, &key, false).unwrap();
        assert_eq!(decoded, 32);
        assert_eq!(buf[..32], original[..32]);
    }

    #[test]
    fn data_non_keepalive_has_no_padding() {
        let key = Key::new(TEST_KEY);
        // A real data packet (64 bytes = the smallest possible inner IP
        // datagram, 16-aligned + AEAD tag) must not be padded and must
        // decode back to its exact length. The encode path keeps the
        // keepalive flag out of packet[2] for these, so the decoder never
        // mistakes them for a padded keepalive.
        for size in [64usize, 65, 100, 1500] {
            let (mut buf, original) = test_packet(4, size);
            let encoded = obfuscate(&mut buf[..], size, &key, true).unwrap();
            assert_eq!(encoded, size);
            let decoded = obfuscate(&mut buf[..], encoded, &key, false).unwrap();
            assert_eq!(decoded, size);
            assert_eq!(buf[..size], original[..size]);
        }
    }

    #[test]
    fn keepalive_flag_out_of_range_passes_through() {
        let key = Key::new(TEST_KEY);
        // A 112-byte data packet whose packet[2] bit 7 happens to be 0
        // (e.g. from an older peer that does not set the flag). It must be
        // passed through untouched, not treated as a padded keepalive
        // (which can only be 32..=96 bytes) and not dropped.
        let (mut buf, original) = test_packet(4, 112);
        let encoded = obfuscate(&mut buf[..], 112, &key, true).unwrap();
        assert_eq!(encoded, 112);
        buf[2] &= 0x7f; // clear bit 7, as an older peer's packet would
        let decoded = obfuscate(&mut buf[..], 112, &key, false).unwrap();
        assert_eq!(decoded, 112);
        assert_eq!(buf[..112], original[..112]);
    }

    // Verifying the kernel checksum math─────────────────
    // RFC/BE word space: the kernel sums network-order 16-bit words
    // (verified against real captures; the earlier LE-halfword model was off
    // by a byte swap and every packet was dropped by the receiving kernel).
    // The trimmed path recomputes from scratch and never trusts the on-wire
    // checksum field -- the key to working over CHECKSUM_PARTIAL offload
    // paths (veth: the field only holds the pseudo-header sum).

    fn be_sum(bytes: &[u8]) -> u32 {
        let mut s = 0u32;
        let mut i = 0;
        while i + 1 < bytes.len() {
            s += ((bytes[i] as u32) << 8) | bytes[i + 1] as u32;
            i += 2;
        }
        if i < bytes.len() {
            s += (bytes[i] as u32) << 8;
        }
        s
    }

    fn fold16(s: u32) -> u32 {
        let s = (s & 0xffff) + (s >> 16);
        (s & 0xffff) + (s >> 16)
    }

    fn udp_checksum(pseudo: &[u8], udp: &[u8], payload: &[u8]) -> u16 {
        let mut d = Vec::with_capacity(pseudo.len() + udp.len() + payload.len());
        d.extend_from_slice(pseudo);
        d.extend_from_slice(udp);
        d.extend_from_slice(payload);
        let sum = fold16(be_sum(&d));
        (0xffff - sum) as u16
    }

    /// The field value of the kernel's CHECKSUM_PARTIAL state:
    /// fold(Σ_pseudo), uncomplemented (verified against real captures:
    /// field == fold16 of the pseudo-header BE word sum).
    /// The pseudo-header only holds src/dst/proto/ulen; port rewrites do
    /// not affect it.
    fn partial_pseudo(src: [u8; 4], dst: [u8; 4], ulen: u16) -> u16 {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&ulen.to_be_bytes());
        fold16(be_sum(&pseudo)) as u16
    }

    fn csum_add(field: u16, delta: u32) -> u16 {
        let c = ((!field as u32) & 0xffff) + (delta & 0xffff) + ((delta >> 16) & 0xffff);
        let c = (c & 0xffff) + (c >> 16);
        // second fold: absorbs the carry-out of the first (kernel csum_fold
        // does the same); without it a folded sum >= 0x10000 is truncated
        // instead of wrapped and the field is off by one
        let c = (c & 0xffff) + (c >> 16);
        !c as u16
    }

    #[test]
    fn csum_add_fuzz_matches_reference_fold() {
        // Independent reference: fold the full sum down mod 65535 (twice,
        // exactly like the kernel's csum_fold) and complement. The production
        // fold must agree even at the exact carry-out boundary (s == 0x1FFFF
        // and friends), which the existing interop tests cannot hit reliably
        // (they would need a 1-in-65536 luck per randomized packet).
        fn ref_csum_add(field: u16, delta: u32) -> u16 {
            let s = ((!field as u32) & 0xffff) + (delta & 0xffff) + ((delta >> 16) & 0xffff);
            let s = (s & 0xffff) + (s >> 16);
            let s = (s & 0xffff) + (s >> 16);
            !s as u16
        }
        // boundary deltas across the whole field space
        let deltas: [u32; 8] = [
            0,
            1,
            0xffff,
            0x10000,
            0x1ffff,
            0x2ffff,
            u32::MAX,
            0xdeadbeef,
        ];
        for field in 0..=u16::MAX {
            for &delta in &deltas {
                assert_eq!(
                    csum_add(field, delta),
                    ref_csum_add(field, delta),
                    "field={field:#06x} delta={delta:#x}"
                );
            }
        }
        // exhaustive delta sweep around the carry boundaries
        for delta in 0u32..=0x3ffff {
            assert_eq!(
                csum_add(0xffff, delta),
                ref_csum_add(0xffff, delta),
                "delta={delta:#x}"
            );
        }
        // exhaustive field sweep with a heavy delta
        let delta = 0x2ffffu32;
        for field in 0..=u16::MAX {
            assert_eq!(
                csum_add(field, delta),
                ref_csum_add(field, delta),
                "field={field:#06x}"
            );
        }
    }

    #[test]
    fn decode_trim_recomputes_checksum_fresh() {
        // The trimmed path never reads the on-wire checksum field: it
        // recomputes over the final bytes. So whether the field holds a full
        // checksum, the CHECKSUM_PARTIAL pseudo-header sum, or even garbage,
        // the result must be identical and equal to a fresh computation over
        // the trimmed packet.
        let key = Key::new([0x42u8; 32]);
        let src = [203, 0, 113, 9];
        let dst = [10, 0, 0, 1];
        let mangler_port = 10950u16;
        let wg_port = 54560u16;
        let mut seed = 0x9e3779b9u32;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            seed
        };
        for _ in 0..3000 {
            let msg_type = 1 + (rnd() % 3) as u8;
            let size = match msg_type {
                1 => 148usize,
                2 => 92,
                _ => 64,
            };
            // Real encode (random pad 0..=63); if there is no pad, append
            // one byte manually (decode only keeps [..size]; pad bytes are
            // irrelevant).
            let (mut buf, _original) = test_packet(msg_type, size);
            let mut encoded = obfuscate(&mut buf[..], size, &key, true).unwrap();
            if encoded == size {
                buf[size] = 0x5a;
                encoded += 1;
            }
            let sport = 51820u16;
            let ulen = (8 + encoded) as u16;
            let full_check = wire_checksum(src, dst, sport, mangler_port, ulen, &buf[..encoded]);
            let partial_check = partial_pseudo(src, dst, ulen);
            let garbage = 1 + (rnd() % 0xfffe) as u16;
            for check in [full_check, partial_check, garbage] {
                let (out, new_check, new_dport) = ebpf_decode_mirror(
                    &buf[..encoded],
                    &key,
                    true,
                    mangler_port,
                    wg_port,
                    src,
                    dst,
                    sport,
                    mangler_port,
                    ulen,
                    check,
                );
                assert_eq!(out.len(), size, "pad={} check={check:04x}", encoded - size);
                assert_eq!(new_dport, wg_port);
                let expect =
                    wire_checksum(src, dst, sport, wg_port, (size + 8) as u16, &out[..size]);
                assert_eq!(
                    new_check,
                    expect,
                    "pad={} check={check:04x}",
                    encoded - size
                );
            }
        }
    }

    #[test]
    fn decode_incremental_matches_fresh() {
        // Untrimmed path (only type 4 and the pad>64 anomaly): the
        // incremental update (csum_diff + port delta) must equal a fresh
        // computation over the final bytes -- requires the on-wire field to
        // be a full checksum (real-NIC scenario).
        let key = Key::new([0x42u8; 32]);
        let src = [203, 0, 113, 9];
        let dst = [10, 0, 0, 1];
        let mangler_port = 10950u16;
        let wg_port = 54560u16;
        let mut seed = 0xdeadbeefu32;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            seed
        };
        for _ in 0..3000 {
            let is_server = rnd() & 1 == 0;
            // A plausible real data packet: inner IP >= 20B, 16-aligned +
            // AEAD tag, so always >= 64 bytes. The [32, 63] keepalive range
            // is the keepalive-trim path and never contains a real packet.
            let size = 64 + (rnd() % 60) as usize;
            let (mut buf, _original) = test_packet(4, size);
            let wire_len = obfuscate(&mut buf[..], size, &key, true).unwrap();
            let sport = 51820u16;
            let ulen = (8 + wire_len) as u16;
            let check = wire_checksum(src, dst, sport, mangler_port, ulen, &buf[..wire_len]);
            if check == 0 {
                continue; // 0 = no checksum; the mirror keeps 0 (same as eBPF)
            }
            let (out, new_check, _) = ebpf_decode_mirror(
                &buf[..wire_len],
                &key,
                is_server,
                mangler_port,
                wg_port,
                src,
                dst,
                sport,
                mangler_port,
                ulen,
                check,
            );
            assert_eq!(out.len(), wire_len);
            let nd = if is_server { wg_port } else { mangler_port };
            let expect = wire_checksum(src, dst, sport, nd, ulen, &out);
            assert_eq!(new_check, expect, "wire={wire_len} is_server={is_server}");
        }
    }

    #[test]
    fn encode_partial_keeps_pseudo_field_complete_updates_delta() {
        // Encode: under CHECKSUM_PARTIAL the field is fold(Σ_pseudo) and
        // unaffected by the transform (the pseudo-header only holds
        // src/dst/proto/ulen); with a full checksum the incremental update
        // must equal a fresh computation. Also check that a PARTIAL input
        // keeps the field at fold(Σ_pseudo).
        let key = Key::new([0x42u8; 32]);
        let src = [203, 0, 113, 9];
        let dst = [10, 0, 0, 1];
        let mangler_port = 10950u16;
        let wg_port = 54560u16;
        let mut seed = 0x12345a11u32;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            seed
        };
        for _ in 0..3000 {
            let msg_type = 1 + (rnd() % 4) as u8;
            let size = match msg_type {
                1 => 148usize,
                2 => 92,
                3 => 64,
                _ => 40,
            };
            let (buf, _original) = test_packet(msg_type, size);
            let sport = wg_port;
            let dport = 51820u16;
            let ulen = (8 + size) as u16;
            let is_server = rnd() & 1 == 0;

            let full_check = wire_checksum(src, dst, sport, dport, ulen, &buf[..size]);
            let partial_check = partial_pseudo(src, dst, ulen);

            // COMPLETE input: the incremental update must equal a fresh computation
            let (mangled, enc_check, new_sport) = ebpf_encode_mirror(
                &buf[..size],
                &key,
                is_server,
                mangler_port,
                wg_port,
                src,
                dst,
                sport,
                dport,
                ulen,
                full_check,
                &mut rnd,
            );
            let ns = if is_server { mangler_port } else { sport };
            assert_eq!(new_sport, ns);
            let expect = wire_checksum(src, dst, ns, dport, ulen, &mangled);
            assert_eq!(enc_check, expect, "type={msg_type} is_server={is_server}");

            // PARTIAL input: the field stays at fold(Σ_pseudo) -- the
            // device completes the payload part over the final bytes, and
            // the result matches a fresh computation (completion invariant).
            let (_mangled2, p_check, new_sport2) = ebpf_encode_mirror(
                &buf[..size],
                &key,
                is_server,
                mangler_port,
                wg_port,
                src,
                dst,
                sport,
                dport,
                ulen,
                partial_check,
                &mut rnd,
            );
            assert_eq!(p_check, partial_pseudo(src, dst, ulen), "type={msg_type}");
            // The PARTIAL branch leaves the field exactly as the kernel's
            // own send path would write it for this packet (pseudo-header
            // unchanged), so the device completes the mangled packet exactly
            // like a normal one -- correctness by construction, no need to
            // model the device formula.
            let ns2 = if is_server { mangler_port } else { sport };
            assert_eq!(new_sport2, ns2);
        }
    }

    // kernel/userspace interop: on-wire bytes + checksums
    //
    // The two mirrors below strictly replicate the eBPF try_decode /
    // try_encode transform logic (header restore/randomize + body XOR
    // key[(i-4)%8] + port rewrite + trim + fresh recompute/incremental/
    // CHECKSUM_PARTIAL keep). Together with the userspace obfuscate they
    // must restore the original messages in both directions, and the
    // checksums must equal a fresh computation over the final bytes (the
    // trimmed path recomputes, never trusting the on-wire field) -- that is
    // exactly what on-wire interop requires.

    /// Delta for a 2-byte BE field: plain (new - old) mod 65535 in the
    /// RFC/BE sum space (no byte swap).
    fn word_delta_test(old: u16, new: u16) -> u32 {
        let d = (new as i32) - (old as i32);
        if d < 0 { (d + 65535) as u32 } else { d as u32 }
    }

    /// Semantics of bpf_csum_diff(from=pre, to=post): Σpost - Σpre
    /// (mod 65535, BE space -- the kernel's csum_partial and the field
    /// share the same space).
    fn csum_delta_test(pre: &[u8], post: &[u8]) -> u32 {
        let fs = fold16(be_sum(pre));
        let ts = fold16(be_sum(post));
        (ts + 0xffff - fs) % 65535
    }

    /// Same as the eBPF try_decode: returns (restored bytes, new checksum,
    /// new dport). The input payload is the on-wire (mangled) bytes;
    /// `sport/dport/ulen/check` are the on-wire UDP header values;
    /// `is_server` controls the port rewrite 10950->54560.
    /// Trimmed path: fresh recompute (on-wire field ignored); untrimmed/data:
    /// incremental update.
    #[allow(clippy::too_many_arguments)]
    fn ebpf_decode_mirror(
        payload: &[u8],
        key: &Key,
        is_server: bool,
        mangler_port: u16,
        wg_port: u16,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        ulen: u16,
        check: u16,
    ) -> (Vec<u8>, u16, u16) {
        let kbidx = payload[2];
        let used_key = key.get(&payload[..2]).unwrap();
        let msg_type = payload[3] ^ Key::get_key_byte(used_key, kbidx);
        let (size, chg_end) = match msg_type {
            4 => (0, 16),
            1 => (148, 148),
            2 => (92, 92),
            3 => (64, 64),
            _ => return (payload.to_vec(), check, dport),
        };
        // Data keepalives: the snapshot covers the full 32-byte message
        // (restored header + untouched ciphertext) for the from-scratch
        // checksum; handshakes keep snap_end == chg_end == size.
        let snap_end = if msg_type == 4 { 32 } else { chg_end };
        let sn = snap_end;
        let mut pre = vec![0u8; sn];
        pre.copy_from_slice(&payload[..sn]);
        let mut post = pre.clone();
        post[0] = msg_type;
        post[1..4].fill(0);
        // XOR only the changed header region (data: 4..16; handshake: body).
        for i in 4..chg_end {
            post[i] ^= used_key[(i - 4) % 8];
        }
        let wire_len = payload.len();
        let mut trimmed = wire_len;
        let mut new_ulen = ulen;
        if msg_type != 4 && wire_len != size {
            let pad = wire_len - size;
            if pad <= 64 {
                new_ulen = (size + 8) as u16;
                trimmed = size;
            }
        } else if msg_type == 4
            && (kbidx & KEEPALIVE_PAD_BIT) == 0
            && wire_len >= 32
            && wire_len <= 32 + KEEPALIVE_PAD_MAX
        {
            // Userspace keepalive padding: bit 7 of packet[2] is 0 and the
            // pad length is inferred from the wire length.
            new_ulen = (32 + 8) as u16;
            trimmed = 32;
        }
        let new_dport = if is_server { wg_port } else { dport };
        let new_check = if check != 0 {
            if trimmed != wire_len {
                // fresh: pseudo-header + UDP header (new ulen/dport) + restored body
                let mut pseudo = Vec::new();
                pseudo.extend_from_slice(&src);
                pseudo.extend_from_slice(&dst);
                pseudo.push(0);
                pseudo.push(17);
                pseudo.extend_from_slice(&new_ulen.to_be_bytes());
                let mut udp = Vec::new();
                udp.extend_from_slice(&sport.to_be_bytes());
                udp.extend_from_slice(&new_dport.to_be_bytes());
                udp.extend_from_slice(&new_ulen.to_be_bytes());
                udp.extend_from_slice(&[0, 0]);
                udp_checksum(&pseudo, &udp, &post)
            } else {
                let mut delta = csum_delta_test(&pre, &post);
                if is_server {
                    delta += word_delta_test(mangler_port, wg_port);
                }
                csum_add(check, delta)
            }
        } else {
            0
        };
        let mut out = payload.to_vec();
        out[..sn].copy_from_slice(&post);
        out.truncate(trimmed); // eBPF: bpf_xdp_adjust_tail trims the padding
        (out, new_check, new_dport)
    }

    /// Same as the eBPF try_encode: returns (mangled bytes, new checksum,
    /// new sport). When `is_server`, the source port is rewritten
    /// wg_port -> mangler_port. Under CHECKSUM_PARTIAL (field ==
    /// fold(Σ_pseudo)) the field is left unchanged -- the device completes
    /// the payload over the final bytes; with a full checksum, incremental.
    #[allow(clippy::too_many_arguments)]
    fn ebpf_encode_mirror(
        payload: &[u8],
        key: &Key,
        is_server: bool,
        mangler_port: u16,
        wg_port: u16,
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        _dport: u16,
        ulen: u16,
        check: u16,
        mut rnd: impl FnMut() -> u32,
    ) -> (Vec<u8>, u16, u16) {
        let msg_type = payload[0];
        let sn: usize = match msg_type {
            4 => 16,
            1 => 148,
            2 => 92,
            3 => 64,
            _ => panic!("bad type"),
        };
        let mut pre = vec![0u8; sn];
        pre.copy_from_slice(&payload[..sn]);
        let mut post = pre.clone();
        let r = rnd();
        let kidx = (r & 0xffff) as u16;
        let mut kbidx = (r >> 16) as u8;
        // Data packets set bit 7 to mark "no padding" (matches the eBPF
        // try_encode), so the peer's decoder never mistakes them for a
        // padded keepalive.
        if msg_type == 4 {
            kbidx |= KEEPALIVE_PAD_BIT;
        }
        let used_key = key.get(&kidx.to_le_bytes()).unwrap();
        post[0] = (kidx & 0xff) as u8;
        post[1] = (kidx >> 8) as u8;
        post[2] = kbidx;
        post[3] = msg_type ^ Key::get_key_byte(used_key, kbidx);
        for i in 4..sn {
            post[i] ^= used_key[(i - 4) % 8];
        }
        let new_sport = if is_server { mangler_port } else { sport };
        let new_check = if check != 0 {
            if check == partial_pseudo(src, dst, ulen) {
                // CHECKSUM_PARTIAL: pseudo-header untouched, field kept
                check
            } else {
                let mut delta = csum_delta_test(&pre, &post);
                if is_server {
                    delta += word_delta_test(wg_port, mangler_port);
                }
                csum_add(check, delta)
            }
        } else {
            0
        };
        let mut out = payload.to_vec();
        out[..sn].copy_from_slice(&post);
        (out, new_check, new_sport)
    }

    /// Assemble the IP/UDP header (pseudo-header + UDP header + payload)
    /// and return the full checksum
    fn wire_checksum(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        ulen: u16,
        payload: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src);
        pseudo.extend_from_slice(&dst);
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&ulen.to_be_bytes());
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&ulen.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp_checksum(&pseudo, &udp, payload)
    }

    #[test]
    fn kernel_userspace_interop_round_trip() {
        let key = Key::new([0x42u8; 32]);
        let src = [203, 0, 113, 9]; // peer public IP
        let dst = [10, 0, 0, 1]; // local IP
        let mangler_port = 10950u16;
        let wg_port = 54560u16;
        let mut seed = 0x1234abcdu32;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            seed
        };

        // Data keepalives (32 bytes) are included: userspace pads them with
        // 0..=31 random bytes (length encoded in the key-byte index high
        // bits) and the kernel decode path trims them back to 32, so
        // userspace<->kernel keepalive interoperability holds. The 32-byte
        // keepalive is used rather than a larger data packet because
        // userspace only pads keepalives and the [32, 63] keepalive range
        // never applies to real data packets.
        for (msg_type, size) in [(1u8, 148usize), (2, 92), (3, 64), (4, 32)] {
            let (mut buf, original) = test_packet(msg_type, size);

            // Direction 1: userspace encode -> kernel decode (server)
            let encoded = obfuscate(&mut buf[..], size, &key, true).unwrap();
            let wire_ulen = (8 + encoded) as u16;
            let wire_check =
                wire_checksum(src, dst, 51820, mangler_port, wire_ulen, &buf[..encoded]);
            let (decoded, new_check, new_dport) = ebpf_decode_mirror(
                &buf[..encoded],
                &key,
                true,
                mangler_port,
                wg_port,
                src,
                dst,
                51820,
                mangler_port,
                wire_ulen,
                wire_check,
            );
            assert_eq!(decoded.len(), size, "type {msg_type}");
            assert_eq!(&decoded[..size], &original[..size], "type {msg_type} bytes");
            let expect_check = wire_checksum(
                src,
                dst,
                51820,
                wg_port,
                (size + 8) as u16,
                &decoded[..size],
            );
            assert_eq!(new_check, expect_check, "type {msg_type} checksum");
            assert_eq!(new_dport, wg_port);

            // Direction 2: kernel encode (server) -> userspace decode
            // the WG daemon's original message from wg_port -> TC encode + sport rewrite
            let (mangled, enc_check, new_sport) = ebpf_encode_mirror(
                &original[..size],
                &key,
                true,
                mangler_port,
                wg_port,
                src,
                dst,
                wg_port,
                51820,
                (size + 8) as u16,
                wire_checksum(
                    src,
                    dst,
                    wg_port,
                    51820,
                    (size + 8) as u16,
                    &original[..size],
                ),
                &mut rnd,
            );
            assert_eq!(new_sport, mangler_port);
            // the checksum delta must be correct (fresh over on-wire bytes)
            let expect_enc =
                wire_checksum(src, dst, mangler_port, 51820, (size + 8) as u16, &mangled);
            assert_eq!(enc_check, expect_enc, "type {msg_type} enc checksum");
            // userspace decode must restore (note: kernel never pads; len unchanged)
            let mut dec_buf = [0u8; MAX_UDP_SIZE];
            dec_buf[..mangled.len()].copy_from_slice(&mangled);
            let decoded = obfuscate(&mut dec_buf[..], mangled.len(), &key, false).unwrap();
            assert_eq!(decoded, size, "type {msg_type} userspace decoded len");
            assert_eq!(
                &dec_buf[..size],
                &original[..size],
                "type {msg_type} userspace decoded bytes"
            );

            // Direction 3: kernel encode -> kernel decode (dual-kernel deployment)
            let (mangled2, enc2, _) = ebpf_encode_mirror(
                &original[..size],
                &key,
                true,
                mangler_port,
                wg_port,
                src,
                dst,
                wg_port,
                51820,
                (size + 8) as u16,
                wire_checksum(
                    src,
                    dst,
                    wg_port,
                    51820,
                    (size + 8) as u16,
                    &original[..size],
                ),
                &mut rnd,
            );
            let ulen2 = (8 + mangled2.len()) as u16;
            let check2 = wire_checksum(src, dst, mangler_port, 51820, ulen2, &mangled2);
            let (decoded2, ncheck2, dport2) = ebpf_decode_mirror(
                &mangled2,
                &key,
                false,
                mangler_port,
                wg_port,
                src,
                dst,
                mangler_port,
                51820,
                ulen2,
                check2,
            );
            assert_eq!(decoded2.len(), size, "type {msg_type} kk len");
            assert_eq!(
                &decoded2[..size],
                &original[..size],
                "type {msg_type} kk bytes"
            );
            let expect_kk = wire_checksum(
                src,
                dst,
                mangler_port,
                51820,
                (size + 8) as u16,
                &decoded2[..size],
            );
            assert_eq!(ncheck2, expect_kk, "type {msg_type} kk checksum");
            assert_eq!(dport2, 51820);
            assert_eq!(enc2, check2); // encoded on-wire checksum matches a fresh computation
        }
    }

    #[test]
    fn wrong_key_is_rejected() {
        let key_a = Key::new([7u8; 32]);
        let key_b = Key::new([8u8; 32]);

        // Pick a key index whose derived byte differs between the two keys
        // (per-index collision chance is 2^-8, so this exits quickly).
        let mut index = 0usize;
        while key_a.0[index][0] == key_b.0[index][0] {
            index += 1;
        }

        // Hand-craft a mangled data packet: key index `index`, key byte
        // index 0, header XORed with key A's byte. `obfuscate` is
        // in-place/destructive, so a fresh packet is needed for each decode
        // attempt.
        let craft = || -> ([u8; MAX_UDP_SIZE], [u8; MAX_UDP_SIZE]) {
            let (mut buf, original) = test_packet(4, 32);
            buf[0..2].copy_from_slice(&(index as u16).to_le_bytes());
            buf[2] = 0;
            buf[3] = 4 ^ Key::get_key_byte(&key_a.0[index], 0);
            xor_transform(&mut buf[4..16], &key_a.0[index]);
            (buf, original)
        };

        // Decoding with the wrong key must fail: the derived message type is
        // neither a valid type nor a valid length for one.
        let (mut buf, _) = craft();
        assert!(obfuscate(&mut buf[..], 32, &key_b, false).is_err());

        // Sanity check: the correct key decodes a fresh packet back to the
        // original.
        let (mut buf, original) = craft();
        let decoded = obfuscate(&mut buf[..], 32, &key_a, false).unwrap();
        assert_eq!(decoded, 32);
        assert_eq!(buf[..32], original[..32]);
    }

    // TCP transport framing ------------------------------------------------

    /// A minimal valid WireGuard data packet (a 32-byte keepalive).
    fn wg_keepalive() -> Vec<u8> {
        let mut pkt = vec![0u8; 32];
        pkt[0] = 4; // data message type
        pkt
    }

    /// A minimal valid WireGuard handshake initiation (148 bytes).
    fn wg_handshake() -> Vec<u8> {
        let mut pkt = vec![0u8; 148];
        pkt[0] = 1; // handshake initiation type
        pkt
    }

    /// Encode `wg` into a complete TCP frame and write it to `tx`.
    /// Returns the frame bytes (as `encode_tcp_frame` laid them out).
    async fn push_frame(
        tx: &mut tokio::io::DuplexStream,
        wg: &[u8],
        key: &Key,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; MAX_TCP_PAYLOAD + TCP_FRAME_HEADER_LEN];
        frame[TCP_FRAME_HEADER_LEN..TCP_FRAME_HEADER_LEN + wg.len()].copy_from_slice(wg);
        let frame_len = encode_tcp_frame(&mut frame, wg.len(), key).unwrap();
        tx.write_all(&frame[..frame_len]).await.unwrap();
        frame[..frame_len].to_vec()
    }

    #[test]
    fn tcp_frame_header_round_trip() {
        let key = Key::new(TEST_KEY);
        for payload_len in [0usize, 1, 16, 148, 1500, MAX_TCP_PAYLOAD] {
            for key_index in [[0xA5u8, 0x3Cu8], [0x00u8, 0x00u8], [0xFFu8, 0xFFu8]] {
                let used_key = key.get(&key_index).unwrap();
                let header = encode_tcp_frame_header(payload_len, used_key);
                let decoded = decode_tcp_frame_header(&header, used_key).unwrap();
                assert_eq!(decoded, payload_len);
            }
        }
    }

    #[test]
    fn tcp_frame_header_rejects_oversized_length() {
        let key = Key::new(TEST_KEY);
        // 65508 = 0xFFE4 LE exceeds MAX_TCP_PAYLOAD (65507). Build the
        // length field by hand with the derived-length XOR the encode uses.
        let len_le = 65508u16.to_le_bytes();
        let used_key = key.get(&[0x00, 0x00]).unwrap();
        let len_field = [
            len_le[0] ^ Key::get_key_byte(used_key, 3),
            len_le[1] ^ Key::get_key_byte(used_key, 6),
        ];
        assert!(decode_tcp_frame_header(&len_field, used_key).is_err());
    }

    #[test]
    fn tcp_frame_length_xor_uses_derived_key_bytes() {
        let key = Key::new(TEST_KEY);
        // Same payload length under different key indices: the length bytes
        // must differ on the wire, and decoding must recover the length
        // for either index.
        let ka = key.get(&[0x12, 0x34]).unwrap();
        let kb = key.get(&[0xAB, 0xCD]).unwrap();
        let a = encode_tcp_frame_header(148, ka);
        let b = encode_tcp_frame_header(148, kb);
        assert_ne!(a, b);
        assert_eq!(decode_tcp_frame_header(&a, ka).unwrap(), 148);
        assert_eq!(decode_tcp_frame_header(&b, kb).unwrap(), 148);

        // And the XOR uses exactly the derived bytes 3 and 6.
        let len_le = 148u16.to_le_bytes();
        assert_eq!(a[0], len_le[0] ^ Key::get_key_byte(ka, 3));
        assert_eq!(a[1], len_le[1] ^ Key::get_key_byte(ka, 6));
    }

    #[test]
    fn tcp_frame_wrong_key_does_not_decode() {
        let key_a = Key::new([7u8; 32]);
        let key_b = Key::new([8u8; 32]);

        // Pick a key index whose derived bytes at positions 3 and 6 differ
        // between the two keys (per-byte collision chance 2^-8 each).
        let mut index = 0usize;
        while key_a.0[index][3] == key_b.0[index][3]
            || key_a.0[index][6] == key_b.0[index][6]
        {
            index += 1;
        }
        let index_bytes = (index as u16).to_le_bytes();

        let header = encode_tcp_frame_header(100, key_a.get(&index_bytes).unwrap());
        // Decoding with the wrong key must not recover the original length:
        // either the garbage length is rejected as oversized, or it is
        // wrong (both derived bytes differ, so the low byte cannot match).
        if let Ok(len) = decode_tcp_frame_header(&header, key_b.get(&index_bytes).unwrap()) {
            assert_ne!(len, 100);
        }
        // Sanity: the right key decodes it exactly.
        assert_eq!(
            decode_tcp_frame_header(&header, key_a.get(&index_bytes).unwrap()).unwrap(),
            100
        );
    }

    #[tokio::test]
    async fn tcp_frame_stream_round_trip() {
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        let key = Key::new(TEST_KEY);

        // A 32-byte keepalive data packet: the frame payload carries
        // 0..=31 bytes of random padding, which decode strips back to 32.
        let wg = wg_keepalive();
        let _ = push_frame(&mut tx, &wg, &key).await;
        let mut buf = vec![0u8; MAX_TCP_PAYLOAD];
        let len = read_tcp_frame(&mut rx, &mut buf, &key).await.unwrap().unwrap();
        assert!(len >= wg.len() && len <= wg.len() + KEEPALIVE_PAD_MAX);
        // The frame payload is the obfuscate-encoded datagram; decoding it
        // must recover the original WireGuard packet.
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(wg_len, wg.len());
        assert_eq!(&buf[..wg_len], &wg[..]);

        // A handshake initiation: the frame payload carries 0..=63 bytes of
        // random padding, which decode strips back to 148.
        let wg2 = wg_handshake();
        let _ = push_frame(&mut tx, &wg2, &key).await;
        let len = read_tcp_frame(&mut rx, &mut buf, &key).await.unwrap().unwrap();
        assert!(len >= wg2.len() && len <= wg2.len() + 63);
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(wg_len, wg2.len());
        assert_eq!(&buf[..wg_len], &wg2[..]);

        // A clean EOF at a frame boundary reads as None, not an error.
        drop(tx);
        assert!(read_tcp_frame(&mut rx, &mut buf, &key).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn tcp_frame_stream_partial_frames() {
        let (mut tx, mut rx) = tokio::io::duplex(4096);
        let key = Key::new(TEST_KEY);

        // Two frames written byte-by-byte (any TCP fragmentation): the
        // stream reader must reassemble both exactly.
        for wg in [wg_keepalive(), wg_keepalive()] {
            let mut frame = vec![0u8; MAX_TCP_PAYLOAD + TCP_FRAME_HEADER_LEN];
            frame[TCP_FRAME_HEADER_LEN..TCP_FRAME_HEADER_LEN + wg.len()].copy_from_slice(&wg);
            let frame_len = encode_tcp_frame(&mut frame, wg.len(), &key).unwrap();
            for byte in &frame[..frame_len] {
                tx.write_all(&[*byte]).await.unwrap();
            }
        }
        let mut buf = vec![0u8; MAX_TCP_PAYLOAD];
        let len = read_tcp_frame(&mut rx, &mut buf, &key).await.unwrap().unwrap();
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(&buf[..wg_len], &wg_keepalive()[..]);
        let len = read_tcp_frame(&mut rx, &mut buf, &key).await.unwrap().unwrap();
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(&buf[..wg_len], &wg_keepalive()[..]);

        // EOF in the middle of a header counts as a clean close.
        tx.write_all(&[0x00]).await.unwrap();
        drop(tx);
        assert!(read_tcp_frame(&mut rx, &mut buf, &key).await.unwrap().is_none());
    }
}
