//! Proxy / transform runtime: userspace forwarder, kernel-mode dispatch,
//! key derivation, and the packet obfuscation primitives.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    io::ErrorKind,
    net::SocketAddr,
    rc::Rc,
    sync::Arc,
    time::Duration,
};

#[cfg(feature = "kernel")]
use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Result, bail};
#[cfg(target_os = "linux")]
use compio::buf::{IoBufMut, SetLen};
use compio::{
    BufResult,
    buf::{IntoInner, IoBuf, Slice},
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    runtime::spawn,
    signal, time,
};
#[cfg(target_os = "linux")]
use futures_util::StreamExt;
use futures_util::{future::Either, future::select, pin_mut};
use log::{debug, error, info};
use sha2::{Digest, Sha256};

use crate::ForwarderArgs;

#[cfg(feature = "kernel")]
use crate::kernel;

// Largest possible UDP payload: 65535 bytes - 20 (IP header) - 8 (UDP header).
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize - 28;
const RECV_BUF_SIZE: usize = 2048;
const MAX_SESSIONS_PER_WORKER: usize = 256;
pub const DERIVED_KEY_NUM: usize = 64;
const DERIVED_KEY_LEN: usize = 8;
#[cfg(feature = "kernel")]
const DEFAULT_WG_PORT: u16 = 51820;
/// Bit 7 of packet[2] (the key-byte index) marks data padding presence:
/// 0 = padded keepalive, 1 = plain data packet. The pad length is inferred
/// from the wire length (pad = len - 32), so this single flag is all the
/// decoder needs. Using only the top bit keeps the rest of packet[2]
/// random, so the byte's distribution stays wide (128 values per class).
const KEEPALIVE_PAD_BIT: u8 = 0x80;

// io_uring tuning (compio `ProactorBuilder`).
//
// The defaults are conservative (SQ/CQ depth 256, buffer pool 8 x 8 KiB).
// A worker may host up to `MAX_SESSIONS_PER_WORKER` sessions, each with
// send/recv ops in flight, so the ring is enlarged to avoid submit stalls
// under bursts. The provided-buffer pool is used by the multishot UDP
// receive; more buffers let the kernel queue more datagrams before the
// worker drains them. These values are no-ops (or ignored) on the polling
// and IOCP backends.
/// io_uring submission queue depth per worker (~24 B per entry).
const IO_URING_CAPACITY: u32 = 1024;
/// Completion queue depth (io_uring only; defaults to the SQ depth).
const IO_URING_CQ_SIZE: u32 = 1024;
/// Number of buffers in the per-runtime provided-buffer pool.
const IO_URING_BUFFER_POOL_SIZE: u16 = 64;
/// Per-buffer size: the multishot `recvmsg` writes a 16 B `io_uring_recvmsg_out`
/// header plus a 128 B source address before the payload, so 8 KiB leaves
/// ample headroom for WireGuard-sized packets.
const IO_URING_BUFFER_LEN: usize = 8192;

/// Build the `ProactorBuilder` used by every worker runtime, with the
/// io_uring tuning above. Kernel-gated features (`single_issuer`, 6.0+;
/// `defer_taskrun`, 6.1+) are enabled only when the running kernel supports
/// them -- setting them on an older kernel would make `io_uring_setup`
/// fail and the whole runtime fall back to polling.
fn configured_proactor() -> compio::driver::ProactorBuilder {
    let mut builder = compio::driver::Proactor::builder();
    builder
        .capacity(IO_URING_CAPACITY)
        .cqsize(IO_URING_CQ_SIZE)
        .buffer_pool_size(std::num::NonZeroU16::new(IO_URING_BUFFER_POOL_SIZE).expect("nonzero"))
        .buffer_pool_buffer_len(IO_URING_BUFFER_LEN);
    #[cfg(target_os = "linux")]
    {
        let (major, minor) = linux_kernel_version();
        if (major, minor) >= (6, 1) {
            // `defer_taskrun` (6.1+) requires `single_issuer` (6.0+); both
            // are valid here because each worker runtime is driven by a
            // single thread.
            builder.single_issuer(true).defer_taskrun(true);
        } else if (major, minor) >= (6, 0) {
            builder.single_issuer(true);
        }
    }
    builder
}

/// The running Linux kernel version `(major, minor)`, parsed from
/// `/proc/sys/kernel/osrelease` (e.g. "6.12.76-linuxkit"). Unknown/other
/// values degrade to `(0, 0)`, which enables none of the gated features.
#[cfg(target_os = "linux")]
fn linux_kernel_version() -> (u32, u32) {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut parts = release.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}

/// Run the future produced by `make_body` on a dedicated thread with its
/// own compio runtime (thread-per-core: one driver per worker). The future
/// is created *inside* the thread because compio sockets are `!Send` -- a
/// worker body that holds one across an await is not `Send`, so it must
/// never cross a thread boundary. A runtime failure is logged; the thread
/// then exits silently.
fn spawn_worker_thread<F, Fut>(make_body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .name("wg-mangler-worker".to_string())
        .spawn(move || {
            let body = make_body();
            match compio::runtime::Runtime::builder()
                .with_proactor(configured_proactor())
                .build()
            {
                Ok(rt) => rt.block_on(body),
                Err(e) => error!("can not create worker runtime: {e}"),
            }
        })
        .expect("failed to spawn worker thread");
}

/// Non-blocking "is a datagram queued?" probe (FIONREAD). compio exposes no
/// `try_recv`, so the drain loops gate a regular `recv` on this instead of
/// submitting-and-cancelling an operation (which would drop the buffer).
fn has_queued_datagram(sock: &UdpSocket) -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let mut n: libc::c_int = 0;
        // SAFETY: `sock` is a live, valid socket fd; FIONREAD stores the
        // size of the next queued datagram in `n`.
        unsafe { libc::ioctl(sock.as_raw_fd(), libc::FIONREAD, &mut n) == 0 && n > 0 }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{FIONREAD, ioctlsocket};
        let mut n: u32 = 0;
        // SAFETY: `sock` is a live, valid socket; FIONREAD stores the size
        // of the next queued datagram in `n`.
        unsafe { ioctlsocket(sock.as_raw_socket(), FIONREAD, &mut n) == 0 && n > 0 }
    }
}

#[inline]
fn xor_transform(data: &mut [u8], key: &[u8; 8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn obfuscate(packet: &mut [u8], len: usize, key: &Key, is_encode: bool) -> Result<usize> {
    // NOTE: `packet` is the full scratch buffer (its capacity is the caller's
    // receive buffer) and `len` is the actual datagram length, so all bounds
    // checks below must use `len`, and every write past `len` (padding) is
    // capped at `packet.len()`. Bytes past `len` hold stale data from previous
    // datagrams and must never be read, transformed, or forwarded.
    if len < 4 {
        bail!("packet too short: {len} bytes");
    }

    let (message_type, used_key, is_keepalive_pad) = if is_encode {
        let message_type = packet[0];
        getrandom::fill(&mut packet[0..4])?;
        let used_key = key.get(&packet[..2])?;
        let is_keepalive_pad = if message_type == 4 && len == 32 {
            packet[2] &= !KEEPALIVE_PAD_BIT;
            true
        } else {
            packet[2] |= KEEPALIVE_PAD_BIT;
            false
        };
        packet[3] = message_type ^ Key::get_key_byte(used_key, packet[2]);
        (message_type, used_key, is_keepalive_pad)
    } else {
        let used_key = key.get(&packet[..2])?;
        let message_type = packet[3] ^ Key::get_key_byte(used_key, packet[2]);
        packet[0] = message_type;
        let is_keepalive_pad = message_type == 4 && (packet[2] & KEEPALIVE_PAD_BIT) == 0;
        packet[1..4].fill(0);
        (message_type, used_key, is_keepalive_pad)
    };

    Ok(match message_type {
        // data
        4 => {
            // Every path below operates on the same 12-byte window and
            // rejects truncated packets the same way; only the return
            // length differs.
            if len < 16 {
                bail!("truncated data packet: {len} bytes");
            }

            xor_transform(&mut packet[4..16], used_key);
            if is_keepalive_pad {
                if is_encode {
                    let padding_len = (len + getrandom::u32()? as u8 as usize).min(packet.len());
                    getrandom::fill(&mut packet[len..padding_len])?;
                    padding_len
                } else if len >= 32 && len <= 32 + u8::MAX as usize {
                    32
                } else {
                    len
                }
            } else {
                len
            }
        }
        // handshake and cookie
        1..=3 => {
            if is_encode {
                let mut rnd = [0u8; 64];
                getrandom::fill(&mut rnd)?;
                let padding_size = (rnd[0] % 64) as usize;
                let padding_len = (len + padding_size).min(packet.len());
                // XOR only the real packet bytes (the padding region is
                // overwritten with random data immediately after, so XORing
                // it would be wasted work); the rest of the scratch buffer
                // holds stale data and must not be touched.
                xor_transform(&mut packet[4..len], used_key);
                let pad = padding_len - len;
                packet[len..padding_len].copy_from_slice(&rnd[1..1 + pad]);
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

fn new_reuseport_udp_socket(addr: SocketAddr) -> Result<UdpSocket> {
    let udp_sock = socket2::Socket::new(
        match addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        },
        socket2::Type::DGRAM,
        None,
    )?;
    if let SocketAddr::V6(_) = addr {
        // Bind `[::]:port` as IPv6-only so it can neither silently receive
        // v4-mapped datagrams nor collide with a v4 listener on the same
        // port under SO_REUSEPORT.
        udp_sock.set_only_v6(true)?;
    }
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
    // A larger receive queue absorbs WireGuard's short bursts without
    // drops on the local relay socket (Linux doubles the requested value).
    let _ = udp_sock.set_recv_buffer_size(UDP_RCVBUF);
    udp_sock.bind(&socket2::SockAddr::from(addr))?;
    let udp_sock: std::net::UdpSocket = udp_sock.into();
    Ok(UdpSocket::from_std(udp_sock)?)
}

/// Bind an ephemeral UDP socket, connect it to the peer, and enlarge its
/// receive queue. Connecting means `send`/`recv` skip the per-datagram
/// destination lookup and the kernel filters replies to the peer's exact
/// 4-tuple -- safe because every proxy socket talks to exactly one peer
/// (`forward_addr`), which always replies from that address (the remote
/// mangler's SO_REUSEPORT workers all share `forward_addr`, and the local
/// WireGuard daemon replies from its own bound address).
async fn new_proxy_socket(forward_addr: SocketAddr) -> Result<Arc<UdpSocket>> {
    // Bind an ephemeral socket of the peer's address family, so a v4 peer
    // gets a v4 proxy socket and a v6 peer a v6 one.
    let bind_addr = match forward_addr {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0; 16], 0)),
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(forward_addr).await?;
    if let Err(e) = socket2::SockRef::from(&socket).set_recv_buffer_size(UDP_RCVBUF) {
        debug!("set_recv_buffer_size failed: {e}");
    }
    Ok(Arc::new(socket))
}

/// Find (or create, on first contact) the forward proxy session for
/// `src_addr` and return its connected proxy socket. Spawns the reverse-path
/// task when a new session is created. Returns `None` when the packet must
/// be dropped (socket creation failure or the per-worker session limit).
/// Shared by the array- and `BufferRef`-based relay paths.
#[allow(clippy::too_many_arguments)]
async fn get_proxy_socket(
    is_client: bool,
    listen_socket: &Arc<UdpSocket>,
    forward_addr: SocketAddr,
    src_addr: SocketAddr,
    key: &Key,
    sessions: &Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    timeout_duration: Duration,
) -> Option<Arc<UdpSocket>> {
    // Fast path: reuse an existing session for this source.
    let existing = sessions.borrow().get(&src_addr).cloned();
    if let Some(socket) = existing {
        return Some(socket);
    }

    // New session: bind + connect the proxy socket outside the borrow so
    // we never await while holding the sessions borrow (the reverse-path
    // cleanup task needs it to remove expired sessions).
    let socket = match new_proxy_socket(forward_addr).await {
        Ok(v) => v,
        Err(e) => {
            error!("[Session {src_addr}] can not create the forwarder_socket: {e}");
            // Keep serving the other clients on this worker.
            return None;
        }
    };

    // NOTE: the forward loop is the only task that inserts sessions
    // (reverse-path tasks only remove), so a plain get-then-insert is
    // race-free here. Use the entry API if a concurrent inserter is
    // ever introduced. The borrow is scoped so it never crosses an
    // await (the spawn below runs after it ends).
    let existing = {
        let mut sessions = sessions.borrow_mut();
        if let Some(socket) = sessions.get(&src_addr) {
            Some(socket.clone())
        } else {
            // Bound sessions so spoofed sources cannot exhaust sockets and
            // tasks: each session occupies a socket and a task until the
            // inactivity timeout.
            if sessions.len() >= MAX_SESSIONS_PER_WORKER {
                error!(
                    "[Session {src_addr}] Session limit ({MAX_SESSIONS_PER_WORKER}) reached; dropping packet"
                );
                return None;
            }
            info!("[Session {src_addr}] New connection established.");
            sessions.insert(src_addr, socket.clone());
            None
        }
    };
    Some(match existing {
        Some(socket) => socket,
        None => {
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
            })
            .detach();
            socket
        }
    })
}

/// Relay one received WireGuard datagram on the userspace UDP forwarder:
/// validate + obfuscate it, route it to the source's session (creating the
/// session on first contact), and send it to the peer through the proxy
/// socket. Shared by the listen loop's first recv and its non-blocking
/// drain. Takes the receive buffer by value (compio's IO owns buffers) and
/// returns it for the next recv.
#[allow(clippy::too_many_arguments)]
async fn relay_udp_datagram(
    is_client: bool,
    listen_socket: &Arc<UdpSocket>,
    forward_addr: SocketAddr,
    src_addr: SocketAddr,
    mut buf: [u8; RECV_BUF_SIZE],
    len: usize,
    key: &Key,
    sessions: &Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    timeout_duration: Duration,
) -> [u8; RECV_BUF_SIZE] {
    // Validate and mangle the packet BEFORE creating a session: an invalid
    // packet from an unknown source must not be able to allocate a session
    // (socket + task) that lingers until it times out, or spoofed sources
    // could exhaust resources.
    let padding_len = match obfuscate(&mut buf[..], len, key, is_client) {
        Ok(v) => v,
        Err(e) => {
            error!("[Session {src_addr}] Failed to obfuscate packet: {e}");
            return buf;
        }
    };

    let Some(proxy_socket) = get_proxy_socket(
        is_client,
        listen_socket,
        forward_addr,
        src_addr,
        key,
        sessions,
        timeout_duration,
    )
    .await
    else {
        return buf;
    };

    // compio's send owns the buffer, so pass a `Slice` view over the exact
    // bytes and recover the buffer from the returned view.
    let BufResult(res, view) = proxy_socket.send(buf.slice(..padding_len)).await;
    buf = view.into_inner();
    if let Err(e) = res {
        error!("[Session {src_addr}] Failed to send packet: {e}");
        // The proxy socket is likely broken. Remove the session so the next
        // packet from this source binds a fresh socket; the old reverse-path
        // task keeps draining the old socket until it times out, so upstream
        // replies already in flight are still forwarded in the meantime.
        sessions.borrow_mut().remove(&src_addr);
    }
    buf
}

/// Zero-copy relay for the io_uring multishot path: the datagram arrives in
/// a runtime-pooled `BufferRef`, is obfuscated in place, and is sent
/// straight out of the pool buffer (no scratch copy). The `BufferRef` is
/// returned to the pool when it drops. Linux-only (`recv_from_multi`).
///
/// `offset` is where the datagram starts inside the pool buffer: the
/// multishot `recvmsg` writes an `io_uring_recvmsg_out` header plus the
/// source address before the payload, so the payload is not at offset 0.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn relay_udp_datagram_ref(
    is_client: bool,
    listen_socket: &Arc<UdpSocket>,
    forward_addr: SocketAddr,
    src_addr: SocketAddr,
    mut bref: compio::driver::BufferRef,
    offset: usize,
    key: &Key,
    sessions: &Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    timeout_duration: Duration,
) {
    let len = bref.len() - offset;
    // Widen the view to the whole pooled buffer so `obfuscate` has room to
    // append random padding: `set_capacity` clamps to the pool buffer's real
    // size. The bytes past the payload are stale pool memory that
    // `obfuscate` only overwrites (with padding) before it is ever read.
    bref.set_capacity(usize::MAX);
    let uninit = bref.as_uninit();
    let cap = uninit.len();
    // SAFETY: `[offset..offset + len]` holds the received datagram
    // (initialized), and the region beyond it is writable pool memory that
    // `obfuscate` fills before reading it.
    let full = unsafe { std::slice::from_raw_parts_mut(uninit.as_mut_ptr().cast::<u8>(), cap) };
    let payload = &mut full[offset..];
    let padding_len = match obfuscate(payload, len, key, is_client) {
        Ok(v) => v,
        Err(e) => {
            error!("[Session {src_addr}] Failed to obfuscate packet: {e}");
            return;
        }
    };
    // Mark the padded datagram as the buffer's length so the send below
    // transmits exactly the payload bytes.
    // SAFETY: `obfuscate` just wrote `padding_len - len` bytes into the
    // payload region, which is within the buffer and now initialized.
    unsafe { bref.set_len(offset + padding_len) };

    let Some(proxy_socket) = get_proxy_socket(
        is_client,
        listen_socket,
        forward_addr,
        src_addr,
        key,
        sessions,
        timeout_duration,
    )
    .await
    else {
        return;
    };

    let BufResult(res, _view) = proxy_socket
        .send(bref.slice(offset..offset + padding_len))
        .await;
    if let Err(e) = res {
        error!("[Session {src_addr}] Failed to send packet: {e}");
        // The proxy socket is likely broken. Remove the session so the next
        // packet from this source binds a fresh socket; the old reverse-path
        // task keeps draining the old socket until it times out, so upstream
        // replies already in flight are still forwarded in the meantime.
        sessions.borrow_mut().remove(&src_addr);
    }
    // `_view` (the `Slice<BufferRef>`) drops here, returning the buffer to
    // the pool.
}

async fn handle_forward_socket(
    is_client: bool,
    listen_socket: Arc<UdpSocket>,
    proxy_socket: Arc<UdpSocket>,
    original_src: SocketAddr,
    key: &Key,
    sessions: Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    timeout_duration: Duration,
) {
    let buf = [0u8; RECV_BUF_SIZE];
    'session: loop {
        match time::timeout(timeout_duration, proxy_socket.recv(buf)).await {
            Ok(BufResult(Ok(len), mut buf)) => {
                debug!("Reverse: Received {len} bytes");

                let trim_len = match obfuscate(&mut buf[..], len, key, !is_client) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("[Session {original_src}] Failed to transform packet: {e}");
                        continue;
                    }
                };

                let BufResult(res, view) = listen_socket
                    .send_to(buf.slice(..trim_len), original_src)
                    .await;
                buf = view.into_inner();
                if let Err(e) = res {
                    error!(
                        "[Session {original_src}] Failed to send packet back to original source: {e}",
                    );
                    break 'session;
                }

                // Non-blocking drain: upstream replies arrive in bursts (one
                // per forwarded datagram); forward whatever is already queued
                // in this wakeup instead of one blocking recv per packet.
                for _ in 0..UDP_DRAIN_CAP {
                    if !has_queued_datagram(&proxy_socket) {
                        break;
                    }
                    let BufResult(res, mut received) = proxy_socket.recv(buf).await;
                    match res {
                        Ok(0) => break,
                        Ok(len) => {
                            let trim_len = match obfuscate(&mut received[..], len, key, !is_client)
                            {
                                Ok(v) => v,
                                Err(e) => {
                                    error!(
                                        "[Session {original_src}] Failed to transform packet: {e}"
                                    );
                                    continue;
                                }
                            };
                            let BufResult(res, view) = listen_socket
                                .send_to(received.slice(..trim_len), original_src)
                                .await;
                            buf = view.into_inner();
                            if let Err(e) = res {
                                error!(
                                    "[Session {original_src}] Failed to send packet back to original source: {e}",
                                );
                                // Same as above: a send failure tears the
                                // session down.
                                break 'session;
                            }
                        }
                        Err(e) => {
                            if e.kind() != ErrorKind::WouldBlock {
                                error!("[Session {original_src}] proxy_socket recv error: {e}");
                            }
                            break;
                        }
                    }
                }
            }
            // An error occurred while receiving on the proxy socket
            Ok(BufResult(Err(e), _)) => {
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
    sessions.borrow_mut().remove(&original_src);
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

/// Capacity of every pooled frame: a full UDP datagram plus headroom for
/// the 2-byte TCP length field written in front.
const FRAME_CAP: usize = MAX_TCP_PAYLOAD + TCP_FRAME_HEADER_LEN;

/// A reusable encoded TCP frame. `buf` is always `FRAME_CAP` bytes so the
/// producer can `recv` straight into it; `buf[..len]` is the frame to
/// transmit (2-byte length field + obfuscate-encoded datagram).
struct Frame {
    buf: Box<[u8]>,
    len: usize,
}

/// Recycler for `Frame` buffers, shared between the UDP receive loop
/// (producer) and the TCP writer task (consumer). The client hot path used
/// to copy every encoded frame into a fresh `Vec` (`buf[..len].to_vec()`);
/// with a pool, the receive happens directly into a pooled buffer, the
/// frame moves to the writer by ownership, and the writer returns it after
/// the write -- no per-packet allocation or copy. compio's thread-per-core
/// model keeps every pool user on one thread, so a plain `RefCell` is all
/// the synchronization it needs.
#[derive(Clone)]
struct FramePool {
    free: Rc<RefCell<Vec<Frame>>>,
}

impl FramePool {
    fn new() -> Self {
        FramePool {
            free: Rc::new(RefCell::new(Vec::new())),
        }
    }

    /// Take a frame buffer from the pool, or allocate a fresh one when the
    /// pool is empty.
    fn acquire(&self) -> Frame {
        let buf = self
            .free
            .borrow_mut()
            .pop()
            .map(|f| f.buf)
            .unwrap_or_else(|| vec![0u8; FRAME_CAP].into_boxed_slice());
        Frame { buf, len: 0 }
    }

    /// Return a frame buffer to the pool for reuse.
    fn release(&self, frame: Frame) {
        self.free.borrow_mut().push(frame);
    }
}

/// Maximum bytes coalesced into a single `writev` before the TCP writer
/// flushes. Frames are pre-packaged datagrams; batching is what turns a
/// burst of frames into one syscall instead of one per frame.
const TCP_WRITE_BATCH_BYTES: usize = 64 * 1024;
/// Maximum frames coalesced into a single `writev`.
const TCP_WRITE_BATCH_FRAMES: usize = 32;
/// Cap on datagrams drained non-blocking after one blocking recv, so a
/// sustained burst cannot monopolize a worker.
const UDP_DRAIN_CAP: usize = 64;
/// UDP receive buffer size for the mangler's listen / relay sockets.
/// WireGuard peers emit short bursts; a larger kernel queue absorbs them
/// without drops. Linux doubles the requested value, so 512 KiB requests
/// ~1 MiB of kernel buffer.
const UDP_RCVBUF: usize = 512 * 1024;
/// TCP send/receive buffer size for the tunnel streams. Mostly a no-op on
/// modern kernels (which autotune), kept for low-end boxes whose sysctls
/// cap autotuning low.
const TCP_BUFSIZE: usize = 512 * 1024;

/// Per-session frame queue handle on the TCP client: `src_addr` -> sender.
/// Wrapped in `Arc` so a session can verify (by pointer identity) that the
/// map entry it cleans up is still its own.
type TcpSessionSender = Arc<flume::Sender<Frame>>;
type TcpSessions = Rc<RefCell<HashMap<SocketAddr, TcpSessionSender>>>;

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

/// Bytes read per `read` syscall on the TCP stream. Frames are parsed out
/// of this buffer, so a burst of back-to-back frames costs one syscall per
/// chunk instead of three `read_exact` calls per frame.
const TCP_READ_CHUNK: usize = 16 * 1024;

/// A buffered reader that parses wg-mangler TCP frames out of a byte
/// stream (each frame is `[2-byte length ^ key][2-byte key index][payload]`).
/// It tops the buffer up with one `read` at a time and serves frames from
/// it, so a burst of frames costs ~1 syscall per chunk instead of the 3
/// `read_exact` calls the old `read_tcp_frame` made per frame (length
/// field, key index, body). Frames larger than the chunk are streamed
/// directly out of the socket.
struct TcpFrameReader<R: AsyncRead + Unpin> {
    reader: R,
    buf: Vec<u8>,
    len: usize,
    pos: usize,
    eof: bool,
}

impl<R: AsyncRead + Unpin> TcpFrameReader<R> {
    fn new(reader: R) -> Self {
        TcpFrameReader {
            reader,
            buf: vec![0u8; TCP_READ_CHUNK],
            len: 0,
            pos: 0,
            eof: false,
        }
    }

    /// Move unread bytes to the front and top the buffer up with one read.
    /// Returns `Ok(false)` on clean EOF (no new bytes were available).
    async fn refill(&mut self) -> std::io::Result<bool> {
        self.buf.copy_within(self.pos..self.len, 0);
        self.len -= self.pos;
        self.pos = 0;
        // compio's io API owns the buffer across the call, so take the
        // `Vec` out, `append` (reads into the spare capacity after the
        // still-valid bytes) and put it back.
        let mut buf = std::mem::take(&mut self.buf);
        buf.truncate(self.len);
        let BufResult(res, buf) = self.reader.append(buf).await;
        self.buf = buf;
        let n = res?;
        if n == 0 {
            self.eof = true;
            return Ok(false);
        }
        self.len += n;
        Ok(true)
    }

    /// Ensure at least `need` bytes are buffered; `Ok(false)` on clean EOF
    /// before that many bytes are available.
    async fn ensure(&mut self, need: usize) -> std::io::Result<bool> {
        while self.len - self.pos < need {
            if self.eof {
                return Ok(false);
            }
            if !self.refill().await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Read the next frame's obfuscate-encoded payload into `payload`
    /// (`payload[..len]`; its first 2 bytes are the key index the length
    /// field was keyed on). The caller passes it to `obfuscate(.., false)`
    /// to recover the WireGuard datagram. Returns `Ok(None)` when the
    /// connection ends cleanly at a frame boundary (peer closed), or an
    /// error for a truncated/oversized frame or a transport failure.
    async fn next_frame(&mut self, payload: &mut [u8], key: &Key) -> Result<Option<usize>> {
        // Header: 2-byte length field + 2-byte key index.
        if !self.ensure(TCP_FRAME_HEADER_LEN * 2).await? {
            // EOF before a frame's first byte: clean close by the peer
            // (a mid-header EOF is not byte-perfect, but the session is
            // over either way).
            return Ok(None);
        }
        let len_field = [self.buf[self.pos], self.buf[self.pos + 1]];
        let key_index = [self.buf[self.pos + 2], self.buf[self.pos + 3]];
        let used_key = key.get(&key_index)?;
        let payload_len = decode_tcp_frame_header(&len_field, used_key)?;
        if !(MIN_TCP_PAYLOAD..=MAX_TCP_PAYLOAD).contains(&payload_len) {
            bail!("invalid TCP frame length: {payload_len}");
        }
        if payload_len > payload.len() {
            bail!("TCP frame does not fit the receive buffer: {payload_len}");
        }
        payload[..TCP_FRAME_HEADER_LEN].copy_from_slice(&key_index);
        self.pos += TCP_FRAME_HEADER_LEN * 2;

        // Body: the rest of the obfuscate-encoded datagram.
        let body_len = payload_len - TCP_FRAME_HEADER_LEN;
        let buffered = self.len - self.pos;
        if buffered >= body_len {
            payload[TCP_FRAME_HEADER_LEN..payload_len]
                .copy_from_slice(&self.buf[self.pos..self.pos + body_len]);
            self.pos += body_len;
        } else {
            // The frame is larger than what is buffered: consume the
            // buffer, then stream the remainder through the reader's own
            // buffer (compio cannot read directly into a borrowed slice,
            // so this copies chunk at a time instead of straight into
            // `payload`). Large frames are rare, so the extra copy is
            // acceptable.
            payload[TCP_FRAME_HEADER_LEN..TCP_FRAME_HEADER_LEN + buffered]
                .copy_from_slice(&self.buf[self.pos..self.len]);
            self.pos = self.len;
            let mut done = buffered;
            while done < body_len {
                if self.eof {
                    bail!("truncated TCP frame body");
                }
                if self.pos == self.len && !self.refill().await? {
                    bail!("truncated TCP frame body");
                }
                let take = (self.len - self.pos).min(body_len - done);
                payload[TCP_FRAME_HEADER_LEN + done..TCP_FRAME_HEADER_LEN + done + take]
                    .copy_from_slice(&self.buf[self.pos..self.pos + take]);
                self.pos += take;
                done += take;
            }
        }
        Ok(Some(payload_len))
    }
}

/// Write a batch of encoded frames to `writer` in a single `writev` syscall
/// and return every frame to the pool afterwards (whether the write
/// succeeded or not). An empty batch is a no-op.
async fn write_frame_batch<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frames: &mut Vec<Frame>,
    pool: &FramePool,
) -> std::io::Result<()> {
    if frames.is_empty() {
        return Ok(());
    }
    // `write_vectored_all` loops internally until every byte is out (or an
    // error occurs), so a burst of frames is usually one syscall for the
    // whole batch. compio's `IoBuf` requires owned `'static` buffers, so
    // each frame's box is taken out (leaving an empty placeholder), sliced
    // to the frame's length, and put back after the write.
    let mut views: Vec<Slice<Box<[u8]>>> = Vec::with_capacity(frames.len());
    for f in frames.iter_mut() {
        let buf = std::mem::replace(&mut f.buf, vec![].into_boxed_slice());
        views.push(buf.slice(..f.len));
    }
    let BufResult(res, views) = writer.write_vectored_all(views).await;
    for (f, view) in frames.iter_mut().zip(views) {
        f.buf = view.into_inner();
    }
    // The batch buffers are no longer used: recycle every frame regardless
    // of outcome.
    for f in frames.drain(..) {
        pool.release(f);
    }
    res
}

/// Non-blocking drain of a connected relay socket: encode up to `cap`
/// already-queued datagrams into pooled frames. Returns an empty vector
/// when nothing is queued. `peer` is only used for error logging.
async fn drain_udp_batch(
    udp: &UdpSocket,
    pool: &FramePool,
    key: &Key,
    peer: SocketAddr,
    cap: usize,
) -> Vec<Frame> {
    let mut batch = Vec::with_capacity(cap);
    for _ in 0..cap {
        if !has_queued_datagram(udp) {
            break;
        }
        let mut buf = pool.acquire().buf;
        // Receive directly into the buffer past the 2-byte length header
        // (via a `Slice` view) so the datagram already sits where the
        // encode step needs it -- no shift copy.
        let BufResult(res, view) = udp.recv(buf.slice(TCP_FRAME_HEADER_LEN..)).await;
        buf = view.into_inner();
        match res {
            Ok(0) => {
                pool.release(Frame { buf, len: 0 });
                break;
            }
            Ok(len) => match encode_tcp_frame(&mut buf, len, key) {
                Ok(frame_len) => batch.push(Frame {
                    buf,
                    len: frame_len,
                }),
                Err(e) => {
                    error!("[Session {peer}] Failed to obfuscate packet: {e}");
                    pool.release(Frame { buf, len: 0 });
                    break;
                }
            },
            Err(e) => {
                pool.release(Frame { buf, len: 0 });
                if e.kind() != ErrorKind::WouldBlock {
                    error!("[Session {peer}] Error draining forwarder socket: {e}");
                }
                break;
            }
        }
    }
    batch
}

/// Enqueue one encoded frame for `src_addr` on the TCP client, opening a
/// new TCP tunnel (and reader task) on first contact from that source.
/// The frame buffer is handed to the session's writer by ownership and
/// recycled when the write completes; on the rare failure paths it is
/// returned to the pool here.
#[allow(clippy::too_many_arguments)]
async fn route_tcp_frame(
    src_addr: SocketAddr,
    frame: Frame,
    forward: SocketAddr,
    listen_socket: &Arc<UdpSocket>,
    sessions: &TcpSessions,
    timeout_duration: Duration,
    key: &Key,
    pool: &FramePool,
) {
    // Reuse this source's session, or open a TCP tunnel (and a reader task)
    // for a new source. Clone out of the read guard first so the match arms
    // never touch the borrow while the read borrow is still alive (the write
    // borrow below must not wait on it -- same pattern as the UDP proxy).
    let existing = sessions.borrow().get(&src_addr).cloned();
    let tx = match existing {
        Some(tx) => tx,
        None => {
            let (tx, rx) = flume::unbounded();
            let tx = Arc::new(tx);
            let existing = {
                let mut sessions = sessions.borrow_mut();
                if let Some(tx) = sessions.get(&src_addr) {
                    Some(tx.clone())
                } else {
                    if sessions.len() >= MAX_SESSIONS_PER_WORKER {
                        error!(
                            "[Session {src_addr}] Session limit ({MAX_SESSIONS_PER_WORKER}) reached; dropping packet"
                        );
                        pool.release(frame);
                        return;
                    }
                    info!("[Session {src_addr}] New connection established.");
                    sessions.insert(src_addr, tx.clone());
                    None
                }
            };
            match existing {
                Some(tx) => tx,
                None => {
                    {
                        let listen_socket = listen_socket.clone();
                        let sessions = sessions.clone();
                        let key = key.clone();
                        let session_tx = tx.clone();
                        let pool = pool.clone();
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
                                pool,
                            )
                            .await;
                        })
                        .detach();
                    }
                    tx
                }
            }
        }
    };

    if let Err(send_err) = tx.send(frame) {
        // The session's TCP connection is gone; drop the entry so the next
        // packet from this source opens a fresh one, and recycle the frame.
        error!("[Session {src_addr}] Failed to queue frame for TCP stream");
        sessions.borrow_mut().remove(&src_addr);
        pool.release(send_err.0);
    }
}

fn new_reuseport_tcp_listener(addr: SocketAddr) -> Result<TcpListener> {
    let tcp_sock = socket2::Socket::new(
        match addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        },
        socket2::Type::STREAM,
        None,
    )?;
    if let SocketAddr::V6(_) = addr {
        // Same reasoning as the UDP listener: keep the IPv6 listener from
        // silently accepting v4-mapped connections.
        tcp_sock.set_only_v6(true)?;
    }
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
    Ok(TcpListener::from_std(tcp_sock)?)
}

/// One TCP tunnel session on the client: `src_addr` is the local WireGuard
/// process's UDP address it relays for. Frames queued by the listener loop
/// are written into the TCP stream by a dedicated writer task, and frames
/// received from the server are sent back to `src_addr` over the shared
/// listen socket.
#[allow(clippy::too_many_arguments)]
async fn client_tcp_session(
    src_addr: SocketAddr,
    forward: SocketAddr,
    listen_socket: Arc<UdpSocket>,
    rx: flume::Receiver<Frame>,
    session_tx: TcpSessionSender,
    sessions: TcpSessions,
    timeout_duration: Duration,
    key: Key,
    pool: FramePool,
) {
    let stream = match TcpStream::connect(forward).await {
        Ok(stream) => stream,
        Err(e) => {
            error!("[Session {src_addr}] Failed to connect to server at {forward}: {e}");
            sessions.borrow_mut().remove(&src_addr);
            return;
        }
    };
    // Frames are already packaged datagrams; Nagle would serialize them
    // against the ACK clock (one frame per RTT on a real WAN). Send every
    // frame as soon as it is written.
    if let Err(e) = stream.set_nodelay(true) {
        error!("[Session {src_addr}] set_nodelay failed: {e}");
    }
    // compio's TcpStream exposes no buffer-size setters; go through socket2
    // (compio sockets implement `AsFd`, so `SockRef` works directly).
    if let Err(e) = socket2::SockRef::from(&stream).set_send_buffer_size(TCP_BUFSIZE) {
        debug!("[Session {src_addr}] set_send_buffer_size failed: {e}");
    }
    info!("[Session {src_addr}] TCP connection to {forward} established.");

    let (reader, mut writer) = stream.into_split();

    // Outbound path (frames queued by the listener loop -> TCP), as its
    // own task so a busy stream of outbound frames can never starve the
    // inbound path below (a single select loop would always prefer
    // whichever direction has data queued). Frames already queued behind
    // the first one are coalesced into a single `writev`.
    let writer_task = spawn(async move {
        let mut batch: Vec<Frame> = Vec::with_capacity(TCP_WRITE_BATCH_FRAMES);
        while let Ok(frame) = rx.recv_async().await {
            let mut batch_bytes = frame.len;
            batch.push(frame);
            while batch.len() < TCP_WRITE_BATCH_FRAMES && batch_bytes < TCP_WRITE_BATCH_BYTES {
                match rx.try_recv() {
                    Ok(f) => {
                        batch_bytes += f.len;
                        batch.push(f);
                    }
                    Err(_) => break,
                }
            }
            if let Err(e) = write_frame_batch(&mut writer, &mut batch, &pool).await {
                error!("[Session {src_addr}] Failed to write to TCP stream: {e}");
                break;
            }
        }
    });

    // Inbound path (TCP frames -> UDP back to the WireGuard source). The
    // buffered frame reader coalesces back-to-back frames into one `read`.
    let mut frame_reader = TcpFrameReader::new(reader);
    let mut payload = vec![0u8; MAX_TCP_PAYLOAD];
    loop {
        match time::timeout(
            timeout_duration,
            frame_reader.next_frame(&mut payload, &key),
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
                let BufResult(res, view) = listen_socket
                    .send_to(payload.slice(..wg_len), src_addr)
                    .await;
                payload = view.into_inner();
                if let Err(e) = res {
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
    drop(writer_task);
    // Only remove the entry this session still owns (a fresh session may
    // already have been inserted for the same source).
    let mut sessions = sessions.borrow_mut();
    if sessions
        .get(&src_addr)
        .is_some_and(|tx| Arc::ptr_eq(tx, &session_tx))
    {
        sessions.remove(&src_addr);
    }
}

/// TCP client: binds a local UDP port (where the WireGuard peer points)
/// and opens one TCP connection per WireGuard source socket to the server.
/// TCP client: binds a local UDP port (where the WireGuard peer points)
/// and opens one TCP connection per WireGuard source socket to the server.
async fn run_tcp_client(
    listen: SocketAddr,
    forward: SocketAddr,
    timeout_duration: Duration,
    key: Key,
) -> Result<()> {
    info!("Listening on UDP: {listen}");

    // Same per-worker structure as the UDP proxy: each worker binds its own
    // reuseport socket and keeps its own sessions map. Every worker runs on
    // its own thread with its own compio runtime (thread-per-core).
    for _ in 0..get_cpus_num() {
        let key = key.clone();
        spawn_worker_thread(move || async move {
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
            let sessions: TcpSessions = Rc::new(RefCell::new(HashMap::new()));
            // Frames travel through a per-worker pool: receive directly into
            // a pooled buffer, hand it to the session writer by ownership,
            // and recycle it once the write completes. This keeps the hot
            // path allocation- and copy-free.
            let pool = FramePool::new();

            loop {
                let mut buf = pool.acquire().buf;
                // Receive directly into the buffer past the 2-byte length
                // field (via a `Slice` view) so the datagram already sits
                // where `encode_tcp_frame` needs it -- no shift copy.
                let BufResult(res, view) = listen_socket
                    .recv_from(buf.slice(TCP_FRAME_HEADER_LEN..))
                    .await;
                buf = view.into_inner();
                let (len, src_addr) = match res {
                    Ok(v) => v,
                    Err(e) => {
                        error!("listen_socket recv_from error: {e}");
                        pool.release(Frame { buf, len: 0 });
                        continue;
                    }
                };
                debug!("listen socket: received {len} bytes from {src_addr}");
                // Encode the raw WireGuard datagram into a full TCP frame in
                // place: obfuscate it exactly as UDP mode does, then write
                // the [ length ^ used_key ] field in front.
                let frame = match encode_tcp_frame(&mut buf, len, &key) {
                    Ok(frame_len) => Frame {
                        buf,
                        len: frame_len,
                    },
                    Err(e) => {
                        error!("[Session {src_addr}] Failed to obfuscate packet: {e}");
                        pool.release(Frame { buf, len: 0 });
                        continue;
                    }
                };
                route_tcp_frame(
                    src_addr,
                    frame,
                    forward,
                    &listen_socket,
                    &sessions,
                    timeout_duration,
                    &key,
                    &pool,
                )
                .await;

                // Non-blocking drain: datagrams already queued behind the
                // one above go through the same encode+route path in this
                // iteration, so a burst costs one blocking recv plus a poll
                // per packet instead of one blocking recv per packet.
                for _ in 0..UDP_DRAIN_CAP {
                    if !has_queued_datagram(&listen_socket) {
                        break;
                    }
                    let mut buf = pool.acquire().buf;
                    let BufResult(res, view) = listen_socket
                        .recv_from(buf.slice(TCP_FRAME_HEADER_LEN..))
                        .await;
                    buf = view.into_inner();
                    let (len, src_addr) = match res {
                        Ok(v) => v,
                        Err(e) => {
                            error!("listen_socket recv_from error: {e}");
                            pool.release(Frame { buf, len: 0 });
                            break;
                        }
                    };
                    debug!("listen socket: drained {len} bytes from {src_addr}");
                    let frame = match encode_tcp_frame(&mut buf, len, &key) {
                        Ok(frame_len) => Frame {
                            buf,
                            len: frame_len,
                        },
                        Err(e) => {
                            error!("[Session {src_addr}] Failed to obfuscate packet: {e}");
                            pool.release(Frame { buf, len: 0 });
                            continue;
                        }
                    };
                    route_tcp_frame(
                        src_addr,
                        frame,
                        forward,
                        &listen_socket,
                        &sessions,
                        timeout_duration,
                        &key,
                        &pool,
                    )
                    .await;
                }
            }
        });
    }

    signal::ctrl_c().await?;
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
    forward: SocketAddr,
    timeout_duration: Duration,
    key: Key,
    pool: FramePool,
) {
    // Bind an ephemeral relay socket of the WG daemon's address family.
    let udp = match UdpSocket::bind(match forward {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0; 16], 0)),
    })
    .await
    {
        Ok(v) => Arc::new(v),
        Err(e) => {
            error!("[Session {peer}] can not create the forwarder socket: {e}");
            return;
        }
    };
    // Connect the relay socket to the WG daemon up front: `send` then skips
    // the per-datagram destination lookup and `recv` has the kernel filter
    // by the connected 4-tuple. This relies on the daemon always replying
    // from `forward`, which holds for a single local WireGuard instance.
    if let Err(e) = udp.connect(forward).await {
        error!("[Session {peer}] can not connect the forwarder socket to {forward}: {e}");
        return;
    }
    if let Err(e) = socket2::SockRef::from(&*udp).set_recv_buffer_size(UDP_RCVBUF) {
        debug!("[Session {peer}] set_recv_buffer_size failed: {e}");
    }
    // See client_tcp_session: frames are already packaged datagrams and
    // must not wait on the Nagle/ACK clock (one frame per RTT on a WAN).
    if let Err(e) = stream.set_nodelay(true) {
        error!("[Session {peer}] set_nodelay failed: {e}");
    }
    if let Err(e) = socket2::SockRef::from(&stream).set_recv_buffer_size(TCP_BUFSIZE) {
        debug!("[Session {peer}] set_recv_buffer_size failed: {e}");
    }
    let (reader, mut writer) = stream.into_split();

    // Inbound path: TCP frames from the client -> UDP to the WG daemon.
    // `closed_tx` drops (and so wakes the outbound select below) whenever
    // this task exits for any reason.
    let (closed_tx, closed_rx) = flume::unbounded::<()>();
    let udp_in = udp.clone();
    let key_in = key.clone();
    let reader_task = spawn(async move {
        let _closed_tx = closed_tx;
        // The buffered frame reader coalesces back-to-back frames into one
        // `read` syscall per chunk.
        let mut frame_reader = TcpFrameReader::new(reader);
        let mut payload = vec![0u8; MAX_TCP_PAYLOAD];
        loop {
            let len = match frame_reader.next_frame(&mut payload, &key_in).await {
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
            let BufResult(res, view) = udp_in.send(payload.slice(..wg_len)).await;
            payload = view.into_inner();
            if let Err(e) = res {
                error!("[Session {peer}] Failed to send packet to {forward}: {e}");
                break;
            }
        }
    });

    // Outbound path: WG daemon replies -> TCP frames back to the client.
    // Replies arrive in bursts (one per inbound frame), so after the first
    // blocking recv we drain whatever is already queued non-blocking and
    // send the whole batch with a single writev, then recycle the buffers.
    loop {
        // Wait for either the inbound task to finish (closed) or a WG
        // daemon reply, whichever comes first.
        let recv_fut = async {
            let buf = pool.acquire().buf;
            match time::timeout(
                timeout_duration,
                udp.recv(buf.slice(TCP_FRAME_HEADER_LEN..)),
            )
            .await
            {
                Ok(BufResult(Ok(len), view)) => OutboundRecv::Datagram(len, view.into_inner()),
                Ok(BufResult(Err(e), _)) => OutboundRecv::IoError(e),
                Err(_) => OutboundRecv::Timeout,
            }
        };
        pin_mut!(recv_fut);
        let closed_fut = closed_rx.recv_async();
        pin_mut!(closed_fut);
        match select(recv_fut, closed_fut).await {
            // The inbound task ended (EOF, error): break immediately
            // instead of waiting out the inactivity timeout.
            Either::Right((_, _)) => break,
            Either::Left((outcome, _)) => match outcome {
                OutboundRecv::Timeout => {
                    info!("[Session {peer}] Timed out due to inactivity.");
                    break;
                }
                OutboundRecv::IoError(e) => {
                    error!("[Session {peer}] Error receiving from forwarder socket: {e}");
                    break;
                }
                OutboundRecv::Datagram(len, mut buf) => {
                    // Encode the WG daemon's raw datagram into a full TCP
                    // frame in place, like the client's send path.
                    let first = match encode_tcp_frame(&mut buf, len, &key) {
                        Ok(frame_len) => Frame {
                            buf,
                            len: frame_len,
                        },
                        Err(e) => {
                            error!("[Session {peer}] Failed to obfuscate packet: {e}");
                            break;
                        }
                    };
                    let mut batch: Vec<Frame> = Vec::with_capacity(TCP_WRITE_BATCH_FRAMES);
                    batch.push(first);
                    // Replies arrive in bursts (one per inbound frame); drain
                    // whatever is already queued and send it all in one writev.
                    batch.extend(
                        drain_udp_batch(
                            &udp,
                            &pool,
                            &key,
                            peer,
                            TCP_WRITE_BATCH_FRAMES - batch.len(),
                        )
                        .await,
                    );
                    if let Err(e) = write_frame_batch(&mut writer, &mut batch, &pool).await {
                        error!("[Session {peer}] Failed to write to TCP stream: {e}");
                        break;
                    }
                }
            },
        }
    }

    // Stop the inbound task (it may be blocked on a TCP read). Dropping
    // both halves of the stream and the last socket ref closes the session.
    drop(reader_task);
}

/// Outcome of the server session's timed wait for a WG daemon reply.
/// The pooled buffer is only recovered on the success path; on error or
/// timeout the session ends anyway, so it is dropped rather than returned.
enum OutboundRecv {
    Datagram(usize, Box<[u8]>),
    IoError(std::io::Error),
    Timeout,
}

/// TCP server: listens on the public TCP port and accepts one tunnel
/// connection per WireGuard source.
async fn run_tcp_server(
    listen: SocketAddr,
    forward: SocketAddr,
    timeout_duration: Duration,
    key: Key,
) -> Result<()> {
    info!("Listening on TCP: {listen}");

    for _ in 0..get_cpus_num() {
        let key = key.clone();
        spawn_worker_thread(move || async move {
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
            let session_count = Rc::new(Cell::new(0usize));
            // One frame pool per worker, shared by all sessions it accepts.
            let pool = FramePool::new();
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("listener accept error: {e}");
                        continue;
                    }
                };
                if session_count.get() >= MAX_SESSIONS_PER_WORKER {
                    error!(
                        "[Session {peer}] Session limit ({MAX_SESSIONS_PER_WORKER}) reached; dropping connection"
                    );
                    drop(stream);
                    continue;
                }
                session_count.set(session_count.get() + 1);
                let session_count = session_count.clone();
                let key = key.clone();
                let pool = pool.clone();
                spawn(async move {
                    server_tcp_session(stream, peer, forward, timeout_duration, key, pool).await;
                    session_count.set(session_count.get() - 1);
                })
                .detach();
            }
        });
    }

    signal::ctrl_c().await?;
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
    // Report the actual async backend in use (io_uring on Linux, IOCP on
    // Windows, epoll/kqueue polling elsewhere). Useful to confirm the
    // io_uring path is active on deployment machines.
    let backend = match compio::runtime::Runtime::with_current(|rt| rt.driver_type()) {
        compio::driver::DriverType::IoUring => "io_uring (Linux)",
        compio::driver::DriverType::IOCP => "iocp (Windows)",
        compio::driver::DriverType::Poll => "polling (epoll/kqueue)",
    };
    info!("async backend: {backend}");

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
        // resolved it (`IP:port` or `domain:port`). The eBPF programs
        // match IPv4 addresses only, so IPv6 endpoints are rejected.
        Some(SocketAddr::V4(v4)) => v4,
        Some(SocketAddr::V6(_)) => bail!(
            "kernel eBPF mode requires an IPv4 --forward (the eBPF programs \
             match IPv4 addresses only)"
        ),
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

    let listen = match args.listen {
        Some(SocketAddr::V4(v4)) => v4,
        Some(SocketAddr::V6(_)) => bail!(
            "kernel eBPF mode requires an IPv4 --listen (the eBPF programs \
             match IPv4 addresses only)"
        ),
        // Client in kernel mode: unused (no local bind, interface is picked
        // from the route to the peer). Provide a placeholder.
        None => SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    };
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

/// UDP relay worker loop for backends without multishot receive
/// (epoll/kqueue/IOCP, or io_uring when it is unavailable): one blocking
/// `recv_from` followed by a FIONREAD-gated non-blocking drain, so a burst
/// costs one blocking recv plus a poll per packet.
async fn udp_relay_worker_drain(
    is_client: bool,
    listen_socket: &Arc<UdpSocket>,
    forward_addr: SocketAddr,
    key: &Key,
    sessions: &Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    timeout_duration: Duration,
) {
    let mut buf = [0u8; RECV_BUF_SIZE];
    loop {
        let BufResult(res, b) = listen_socket.recv_from(buf).await;
        buf = b;
        let (len, src_addr) = match res {
            Ok(v) => v,
            Err(e) => {
                error!("listen_socket recv_from error: {e}");
                continue;
            }
        };
        debug!("listen socket: received {len} bytes from {src_addr}");
        buf = relay_udp_datagram(
            is_client,
            listen_socket,
            forward_addr,
            src_addr,
            buf,
            len,
            key,
            sessions,
            timeout_duration,
        )
        .await;

        // Non-blocking drain: datagrams already queued behind the one above
        // go through the same relay path in this iteration.
        for _ in 0..UDP_DRAIN_CAP {
            if !has_queued_datagram(listen_socket) {
                break;
            }
            let BufResult(res, b) = listen_socket.recv_from(buf).await;
            buf = b;
            let (len, src_addr) = match res {
                Ok(v) => v,
                Err(e) => {
                    if e.kind() != ErrorKind::WouldBlock {
                        error!("listen_socket recv_from error: {e}");
                    }
                    break;
                }
            };
            debug!("listen socket: drained {len} bytes from {src_addr}");
            buf = relay_udp_datagram(
                is_client,
                listen_socket,
                forward_addr,
                src_addr,
                buf,
                len,
                key,
                sessions,
                timeout_duration,
            )
            .await;
        }
    }
}

/// UDP relay worker loop on Linux: drives the listen socket with an
/// io_uring multishot receive (`IORING_OP_RECV_MULTISHOT`, kernel >= 5.19).
/// The kernel writes datagrams straight into its provided-buffer pool and
/// the runtime hands each one to us as a `BufferRef`; each datagram is
/// obfuscated in place and sent straight out of the pool buffer (zero
/// copy). The win over the drain loop is the amortized syscall cost (one
/// multishot submission serves many datagrams) plus no per-packet buffer
/// handoff.
#[cfg(target_os = "linux")]
async fn udp_relay_worker_uring(
    is_client: bool,
    listen_socket: &Arc<UdpSocket>,
    forward_addr: SocketAddr,
    key: &Key,
    sessions: &Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>>,
    timeout_duration: Duration,
) {
    // `recv_from_multi` lazily initializes the runtime's buffer pool (tuned
    // to 64 x 8 KiB in `configured_proactor`), which fits WireGuard-sized
    // packets and absorbs bursts. A transient error (e.g. the kernel briefly
    // running out of provided buffers under a huge burst) terminates the
    // stream; restart it instead of dropping the worker, but give up after a
    // run of consecutive errors so an unsupported kernel does not spin.
    let mut consecutive_errors = 0u32;
    loop {
        let mut stream = Box::pin(listen_socket.recv_from_multi());
        while let Some(item) = stream.next().await {
            let item = match item {
                Ok(v) => v,
                Err(e) => {
                    consecutive_errors += 1;
                    error!("listen_socket recv_from_multi error: {e}");
                    if consecutive_errors >= 5 {
                        error!("too many consecutive multishot errors; giving up on this worker");
                        return;
                    }
                    break;
                }
            };
            consecutive_errors = 0;
            let src_addr = match item.addr().and_then(|a| a.as_socket()) {
                Some(addr) => addr,
                None => continue,
            };
            // The multishot `recvmsg` writes a header + source address before
            // the payload; derive the payload's offset so the zero-copy relay
            // can obfuscate and send exactly the datagram.
            let data_len = item.data().len();
            let bref = item.into_inner();
            let offset = bref.len() - data_len;
            debug!("listen socket: received {data_len} bytes from {src_addr}");
            relay_udp_datagram_ref(
                is_client,
                listen_socket,
                forward_addr,
                src_addr,
                bref,
                offset,
                key,
                sessions,
                timeout_duration,
            )
            .await;
        }
        // The stream ended (cleanly or after an error): recreate it after a
        // short pause so a broken multishot does not busy-spin.
        time::sleep(Duration::from_millis(1)).await;
    }
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
        spawn_worker_thread(move || async move {
            let listen_socket = match new_reuseport_udp_socket(listen) {
                Ok(v) => v,
                Err(e) => {
                    error!("can not create the listen_socket: {e}");
                    return;
                }
            };
            let listen_socket = Arc::new(listen_socket);
            let sessions: Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>> =
                Rc::new(RefCell::new(HashMap::new()));

            #[cfg(target_os = "linux")]
            {
                // Prefer the io_uring multishot loop; fall back to the drain
                // loop when the runtime fell back to polling (io_uring
                // unavailable in this environment).
                let is_uring =
                    compio::runtime::Runtime::with_current(|rt| rt.driver_type().is_iouring());
                if is_uring {
                    udp_relay_worker_uring(
                        is_client,
                        &listen_socket,
                        forward_addr,
                        &key,
                        &sessions,
                        timeout_duration,
                    )
                    .await;
                } else {
                    udp_relay_worker_drain(
                        is_client,
                        &listen_socket,
                        forward_addr,
                        &key,
                        &sessions,
                        timeout_duration,
                    )
                    .await;
                }
            }
            #[cfg(not(target_os = "linux"))]
            udp_relay_worker_drain(
                is_client,
                &listen_socket,
                forward_addr,
                &key,
                &sessions,
                timeout_duration,
            )
            .await;
        });
    }

    signal::ctrl_c().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::buf::{IoBuf, IoBufMut};
    use std::{
        collections::VecDeque,
        future::poll_fn,
        task::{Poll, Waker},
    };

    const MAX_UDP_SIZE: usize = u16::MAX as usize;
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
            (32..=32 + u8::MAX as usize).contains(&encoded),
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

        // Data padding is random (0..=255); encode until we get a padded
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
        // A 300-byte data packet whose packet[2] bit 7 happens to be 0
        // (e.g. from an older peer that does not set the flag). It must be
        // passed through untouched, not treated as a padded keepalive
        // (which can only be 32..=287 bytes) and not dropped.
        let (mut buf, original) = test_packet(4, 300);
        let encoded = obfuscate(&mut buf[..], 300, &key, true).unwrap();
        assert_eq!(encoded, 300);
        buf[2] &= 0x7f; // clear bit 7, as an older peer's packet would
        let decoded = obfuscate(&mut buf[..], 300, &key, false).unwrap();
        assert_eq!(decoded, 300);
        assert_eq!(buf[..300], original[..300]);
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
                // A zero UDP checksum field means "no checksum" (RFC 768);
                // the decode path deliberately leaves it untouched, so a
                // fresh recompute cannot be expected. This is reachable for
                // certain `ulen` (random padding), making the test flaky.
                if check == 0 {
                    continue;
                }
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
            && wire_len <= 32 + u8::MAX as usize
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

    /// In-memory duplex stream replacing `tokio::io::duplex` for the frame
    /// reader/writer tests: both ends share a single byte queue, writes
    /// append to it and wake the reader, reads drain it. Dropping an end
    /// marks its side closed, so the peer sees a clean EOF once the queue
    /// is empty (writes never block: the queue is unbounded).
    #[derive(Clone)]
    struct MockDuplex {
        inner: Rc<RefCell<MockDuplexInner>>,
        id: u8,
    }

    struct MockDuplexInner {
        buf: VecDeque<u8>,
        read_waker: Option<Waker>,
        closed: [bool; 2],
    }

    impl MockDuplex {
        fn pair() -> (MockDuplex, MockDuplex) {
            let inner = Rc::new(RefCell::new(MockDuplexInner {
                buf: VecDeque::new(),
                read_waker: None,
                closed: [false, false],
            }));
            (
                MockDuplex {
                    inner: inner.clone(),
                    id: 0,
                },
                MockDuplex { inner, id: 1 },
            )
        }
    }

    impl Drop for MockDuplex {
        fn drop(&mut self) {
            let mut inner = self.inner.borrow_mut();
            inner.closed[self.id as usize] = true;
            if let Some(w) = inner.read_waker.take() {
                w.wake();
            }
        }
    }

    impl AsyncRead for MockDuplex {
        async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
            // `poll_fn`'s closure is `FnMut`, so the buffer is held in an
            // `Option` and moved out only when the read completes.
            let mut buf = Some(buf);
            poll_fn(|cx| {
                let mut inner = self.inner.borrow_mut();
                if !inner.buf.is_empty() {
                    let b = buf.as_mut().unwrap();
                    let n = inner.buf.len().min(b.buf_capacity());
                    {
                        let dst = b.as_uninit();
                        for (i, byte) in inner.buf.drain(..n).enumerate() {
                            dst[i].write(byte);
                        }
                    }
                    // SAFETY: the first `n` bytes were just written above.
                    unsafe { b.set_len(n) };
                    if let Some(w) = inner.read_waker.take() {
                        w.wake();
                    }
                    Poll::Ready(BufResult(Ok(n), buf.take().unwrap()))
                } else if inner.closed[(self.id ^ 1) as usize] {
                    // SAFETY: an empty buffer has no bytes to mark initialized.
                    unsafe { buf.as_mut().unwrap().set_len(0) };
                    Poll::Ready(BufResult(Ok(0), buf.take().unwrap()))
                } else {
                    inner.read_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
            .await
        }
    }

    impl AsyncWrite for MockDuplex {
        async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
            let n = buf.buf_len();
            {
                let mut inner = self.inner.borrow_mut();
                inner.buf.extend(buf.as_init().iter().copied());
                if let Some(w) = inner.read_waker.take() {
                    w.wake();
                }
            }
            BufResult(Ok(n), buf)
        }

        async fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        async fn shutdown(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

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
    async fn push_frame(tx: &mut MockDuplex, wg: &[u8], key: &Key) -> Vec<u8> {
        let mut frame = vec![0u8; MAX_TCP_PAYLOAD + TCP_FRAME_HEADER_LEN];
        frame[TCP_FRAME_HEADER_LEN..TCP_FRAME_HEADER_LEN + wg.len()].copy_from_slice(wg);
        let frame_len = encode_tcp_frame(&mut frame, wg.len(), key).unwrap();
        let BufResult(res, view) = tx.write_all(frame.slice(..frame_len)).await;
        res.unwrap();
        let frame = view.into_inner();
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
        while key_a.0[index][3] == key_b.0[index][3] || key_a.0[index][6] == key_b.0[index][6] {
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

    #[compio::test]
    async fn tcp_frame_stream_round_trip() {
        let (mut tx, rx) = MockDuplex::pair();
        let key = Key::new(TEST_KEY);
        let mut fr = TcpFrameReader::new(rx);

        // A 32-byte keepalive data packet: the frame payload carries
        // 0..=31 bytes of random padding, which decode strips back to 32.
        let wg = wg_keepalive();
        let _ = push_frame(&mut tx, &wg, &key).await;
        let mut buf = vec![0u8; MAX_TCP_PAYLOAD];
        let len = fr.next_frame(&mut buf, &key).await.unwrap().unwrap();
        assert!(len >= wg.len() && len <= wg.len() + u8::MAX as usize);
        // The frame payload is the obfuscate-encoded datagram; decoding it
        // must recover the original WireGuard packet.
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(wg_len, wg.len());
        assert_eq!(&buf[..wg_len], &wg[..]);

        // A handshake initiation: the frame payload carries 0..=63 bytes of
        // random padding, which decode strips back to 148.
        let wg2 = wg_handshake();
        let _ = push_frame(&mut tx, &wg2, &key).await;
        let len = fr.next_frame(&mut buf, &key).await.unwrap().unwrap();
        assert!(len >= wg2.len() && len <= wg2.len() + 63);
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(wg_len, wg2.len());
        assert_eq!(&buf[..wg_len], &wg2[..]);

        // A clean EOF at a frame boundary reads as None, not an error.
        drop(tx);
        assert!(fr.next_frame(&mut buf, &key).await.unwrap().is_none());
    }

    #[compio::test]
    async fn tcp_frame_stream_partial_frames() {
        let (mut tx, rx) = MockDuplex::pair();
        let key = Key::new(TEST_KEY);
        let mut fr = TcpFrameReader::new(rx);

        // Two frames written byte-by-byte (any TCP fragmentation): the
        // stream reader must reassemble both exactly.
        for wg in [wg_keepalive(), wg_keepalive()] {
            let mut frame = vec![0u8; MAX_TCP_PAYLOAD + TCP_FRAME_HEADER_LEN];
            frame[TCP_FRAME_HEADER_LEN..TCP_FRAME_HEADER_LEN + wg.len()].copy_from_slice(&wg);
            let frame_len = encode_tcp_frame(&mut frame, wg.len(), &key).unwrap();
            for byte in &frame[..frame_len] {
                let BufResult(res, _) = tx.write_all([*byte]).await;
                res.unwrap();
            }
        }
        let mut buf = vec![0u8; MAX_TCP_PAYLOAD];
        let len = fr.next_frame(&mut buf, &key).await.unwrap().unwrap();
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(&buf[..wg_len], &wg_keepalive()[..]);
        let len = fr.next_frame(&mut buf, &key).await.unwrap().unwrap();
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(&buf[..wg_len], &wg_keepalive()[..]);

        // EOF in the middle of a header counts as a clean close.
        let BufResult(res, _) = tx.write_all([0x00]).await;
        res.unwrap();
        drop(tx);
        assert!(fr.next_frame(&mut buf, &key).await.unwrap().is_none());
    }

    #[compio::test]
    async fn tcp_frame_reader_large_frame() {
        let (mut tx, rx) = MockDuplex::pair();
        let key = Key::new(TEST_KEY);
        let mut fr = TcpFrameReader::new(rx);

        // A data packet larger than TCP_READ_CHUNK exercises the direct-read
        // path where the frame body overflows the reader buffer.
        let mut wg = vec![0u8; TCP_READ_CHUNK + 4096];
        wg[0] = 4; // data message type
        let _ = push_frame(&mut tx, &wg, &key).await;

        let mut buf = vec![0u8; MAX_TCP_PAYLOAD];
        let len = fr.next_frame(&mut buf, &key).await.unwrap().unwrap();
        let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
        assert_eq!(wg_len, wg.len());
        assert_eq!(&buf[..wg_len], &wg[..]);
    }

    #[test]
    fn frame_pool_recycles_buffers() {
        let pool = FramePool::new();
        let a = pool.acquire();
        assert_eq!(a.buf.len(), FRAME_CAP);
        assert_eq!(a.len, 0);
        let ptr = a.buf.as_ptr();
        pool.release(a);
        // The next acquire returns the same allocation, len reset.
        let b = pool.acquire();
        assert_eq!(b.buf.as_ptr(), ptr);
        assert_eq!(b.buf.len(), FRAME_CAP);
        assert_eq!(b.len, 0);
    }

    #[compio::test]
    async fn tcp_write_batch_delivers_all_frames() {
        let pool = FramePool::new();
        let key = Key::new(TEST_KEY);
        let (mut writer, reader) = MockDuplex::pair();
        let mut fr = TcpFrameReader::new(reader);

        // Encode a few datagrams into pooled frames.
        let dgs = [wg_keepalive(), wg_handshake(), wg_keepalive()];
        let mut frames: Vec<Frame> = Vec::new();
        for wg in &dgs {
            let mut f = pool.acquire();
            f.buf[TCP_FRAME_HEADER_LEN..TCP_FRAME_HEADER_LEN + wg.len()].copy_from_slice(wg);
            f.len = encode_tcp_frame(&mut f.buf, wg.len(), &key).unwrap();
            frames.push(f);
        }

        // One writev must deliver every frame intact over the stream.
        write_frame_batch(&mut writer, &mut frames, &pool)
            .await
            .unwrap();
        assert!(frames.is_empty(), "batch consumed");

        let mut buf = vec![0u8; MAX_TCP_PAYLOAD];
        for wg in &dgs {
            let len = fr.next_frame(&mut buf, &key).await.unwrap().unwrap();
            let wg_len = obfuscate(&mut buf[..], len, &key, false).unwrap();
            assert_eq!(&buf[..wg_len], &wg[..]);
        }

        // Every batch buffer is back in the pool for reuse.
        assert_eq!(pool.free.borrow().len(), dgs.len());
    }

    #[compio::test]
    async fn tcp_server_udp_drain_batches_queued_datagrams() {
        let pool = FramePool::new();
        let key = Key::new(TEST_KEY);

        // A real loopback UDP pair: `udp` is the connected relay socket the
        // server drains, `peer` plays the WireGuard daemon.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(peer.local_addr().unwrap()).await.unwrap();

        let dgs = [wg_keepalive(), wg_handshake(), wg_keepalive()];
        for wg in &dgs {
            let BufResult(res, _) = peer.send_to(wg.clone(), udp.local_addr().unwrap()).await;
            res.unwrap();
        }

        // Consume the first datagram with a blocking recv, then drain the
        // rest -- exactly how the server's outbound loop works.
        let first = vec![0u8; MAX_UDP_SIZE];
        let BufResult(res, first) = udp.recv(first).await;
        let n = res.unwrap();
        assert_eq!(&first[..n], &dgs[0][..]);

        // The drain must pick up every remaining datagram, in order,
        // encoded. On a loaded loopback the later datagrams may not have
        // reached `udp`'s receive queue yet, so retry until they arrive
        // (recycling partial batches back into the pool).
        let expected = dgs.len() - 1;
        let mut batch = Vec::new();
        for _ in 0..200 {
            batch = drain_udp_batch(&udp, &pool, &key, udp.local_addr().unwrap(), 4).await;
            if batch.len() == expected {
                break;
            }
            for f in batch.drain(..) {
                pool.release(f);
            }
            time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(batch.len(), expected, "remaining queued datagrams drained");

        let mut payload = vec![0u8; MAX_TCP_PAYLOAD];
        for (f, wg) in batch.iter().zip(&dgs[1..]) {
            let payload_len = f.len - TCP_FRAME_HEADER_LEN;
            payload[..payload_len].copy_from_slice(&f.buf[TCP_FRAME_HEADER_LEN..f.len]);
            let wg_len = obfuscate(&mut payload[..], payload_len, &key, false).unwrap();
            assert_eq!(&payload[..wg_len], &wg[..]);
        }

        // Nothing left queued after the drain.
        assert!(
            drain_udp_batch(&udp, &pool, &key, udp.local_addr().unwrap(), 4)
                .await
                .is_empty()
        );
    }

    #[compio::test]
    async fn udp_forwarder_relays_datagram() {
        let key = Key::new(TEST_KEY);
        let listen_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forward = peer.local_addr().unwrap();
        let sessions: Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>> =
            Rc::new(RefCell::new(HashMap::new()));

        // A keepalive datagram relayed through a fresh (connected) proxy
        // socket must arrive at the peer obfuscated and decode back to the
        // original WireGuard packet.
        let wg = wg_keepalive();
        let mut buf = [0u8; RECV_BUF_SIZE];
        buf[..wg.len()].copy_from_slice(&wg);
        let _buf = relay_udp_datagram(
            true,
            &listen_socket,
            forward,
            "127.0.0.1:1".parse().unwrap(),
            buf,
            wg.len(),
            &key,
            &sessions,
            Duration::from_secs(1),
        )
        .await;

        // Use a heap buffer: a 64 KiB stack array would be embedded in the
        // recv future and blow the test thread's stack.
        let rbuf = vec![0u8; MAX_UDP_SIZE];
        let BufResult(res, mut rbuf) = peer.recv_from(rbuf).await;
        let (n, _from) = res.unwrap();
        let wg_len = obfuscate(&mut rbuf[..], n, &key, false).unwrap();
        assert_eq!(&rbuf[..wg_len], &wg[..]);
    }

    /// Build a worker-style compio runtime (with the tuned io_uring proactor)
    /// and return it only when the io_uring driver is actually active, so the
    /// multishot tests skip under emulation/polling fallback.
    #[cfg(target_os = "linux")]
    fn io_uring_runtime() -> Option<compio::runtime::Runtime> {
        let rt = compio::runtime::Runtime::builder()
            .with_proactor(configured_proactor())
            .build()
            .expect("runtime");
        rt.driver_type().is_iouring().then_some(rt)
    }

    /// Exercise the io_uring multishot receive path (`recv_from_multi`) on
    /// Linux: a burst of datagrams must be delivered in order, each with the
    /// right source address. Runs only on Linux (multishot is io-uring-only).
    #[cfg(target_os = "linux")]
    #[test]
    fn udp_multishot_recv_delivers_datagrams_in_order() {
        let Some(rt) = io_uring_runtime() else {
            eprintln!("skipping: io_uring driver not active");
            return;
        };
        rt.block_on(async {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let dst = udp.local_addr().unwrap();
            // A burst larger than compio's default 8-buffer pool, so the
            // enlarged provided-buffer pool is exercised.
            for i in 0..32u8 {
                let BufResult(res, _) = peer.send_to(vec![i; 32], dst).await;
                res.unwrap();
            }

            let mut stream = Box::pin(udp.recv_from_multi());
            for i in 0..32u8 {
                let item = stream.next().await.expect("multishot item").expect("ok");
                assert_eq!(item.data(), &[i; 32][..]);
                assert_eq!(
                    item.addr().and_then(|a| a.as_socket()),
                    Some(peer.local_addr().unwrap())
                );
            }
        });
    }

    /// End-to-end check of the zero-copy multishot relay on Linux: a
    /// datagram received into the runtime's pool (`BufferRef`) is obfuscated
    /// in place and forwarded straight out of the pool buffer, and the peer
    /// decodes it back to the original WireGuard packet.
    #[cfg(target_os = "linux")]
    #[test]
    fn udp_multishot_relay_zero_copy_forwards_datagram() {
        let Some(rt) = io_uring_runtime() else {
            eprintln!("skipping: io_uring driver not active");
            return;
        };
        rt.block_on(async {
            let key = Key::new(TEST_KEY);
            let listen_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let forward = peer.local_addr().unwrap();
            let sessions: Rc<RefCell<HashMap<SocketAddr, Arc<UdpSocket>>>> =
                Rc::new(RefCell::new(HashMap::new()));

            // A client datagram into the listen socket.
            let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let wg = wg_keepalive();
            let BufResult(res, _) = client
                .send_to(wg.clone(), listen_socket.local_addr().unwrap())
                .await;
            res.unwrap();

            // Multishot recv -> zero-copy relay to the peer.
            let mut stream = Box::pin(listen_socket.recv_from_multi());
            let item = stream.next().await.expect("multishot item").expect("ok");
            let src_addr = item.addr().and_then(|a| a.as_socket()).expect("src addr");
            let data_len = item.data().len();
            let bref = item.into_inner();
            let offset = bref.len() - data_len;
            relay_udp_datagram_ref(
                true,
                &listen_socket,
                forward,
                src_addr,
                bref,
                offset,
                &key,
                &sessions,
                Duration::from_secs(1),
            )
            .await;

            // The peer receives the obfuscated datagram; decode it back.
            let rbuf = vec![0u8; MAX_UDP_SIZE];
            let r = compio::time::timeout(Duration::from_secs(5), peer.recv_from(rbuf)).await;
            let BufResult(res, mut rbuf) = r.expect("peer recv timeout");
            let (n, _from) = res.unwrap();
            let wg_len = obfuscate(&mut rbuf[..], n, &key, false).unwrap();
            assert_eq!(&rbuf[..wg_len], &wg[..]);
        });
    }
}
