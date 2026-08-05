use std::{
    collections::HashMap,
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use sha2::{Digest, Sha256};

use anyhow::{Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use log::{debug, error, info};
use tokio::{net::UdpSocket, spawn, sync::RwLock};

const MAX_UDP_SIZE: usize = u16::MAX as usize;
// Largest possible UDP payload: 65535 bytes - 20 (IP header) - 8 (UDP header).
const MAX_UDP_PAYLOAD: usize = u16::MAX as usize - 28;
// Per-worker cap on concurrent sessions. Each session holds a socket and a
// task until the inactivity timeout, so unbounded sessions would let
// spoofed sources exhaust file descriptors.
const MAX_SESSIONS_PER_WORKER: usize = 256;
const DERIVED_KEY_NUM: usize = 64;
const DERIVED_KEY_LEN: usize = 8;

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenerateKey,
    Server(ForwarderArgs),
    Client(ForwarderArgs),
}

#[derive(Args)]
struct ForwarderArgs {
    #[arg(long, short)]
    listen: SocketAddrV4,

    #[arg(long, short)]
    forward: String,

    #[arg(long, short)]
    key: String,

    #[arg(long, default_value_t = 180)]
    timeout: u64,
}

#[inline]
fn xor_transform(data: &mut [u8], key: &[u8; 8]) {
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn obfuscate(packet: &mut [u8], len: usize, key: &Key, is_encode: bool) -> Result<usize> {
    // NOTE: `packet` is the full scratch buffer (MAX_UDP_SIZE bytes) and
    // `len` is the actual datagram length, so all bounds checks below must
    // use `len`. Bytes past `len` hold stale data from previous datagrams
    // and must never be read, transformed, or forwarded.
    if len < 4 {
        bail!("packet too short: {len} bytes");
    }

    let (message_type, used_key) = if is_encode {
        let message_type = packet[0];
        packet[0..4].copy_from_slice(&getrandom::u32()?.to_le_bytes());
        let used_key = key.get(&packet[..2])?;
        packet[3] = message_type ^ Key::get_key_byte(used_key, packet[2]);
        (message_type, used_key)
    } else {
        let used_key = key.get(&packet[..2])?;
        let message_type = packet[3] ^ Key::get_key_byte(used_key, packet[2]);

        packet[0] = message_type;
        packet[1..4].fill(0);
        (message_type, used_key)
    };

    Ok(match message_type {
        // data
        4 => {
            if len < 16 {
                bail!("truncated data packet: {len} bytes");
            }
            xor_transform(&mut packet[4..16], used_key);
            len
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

fn generate_key() -> Result<()> {
    let mut arr = [0u8; 32];
    getrandom::fill(&mut arr[..])?;

    println!("{}", bs58::encode(arr).into_string());
    Ok(())
}

#[derive(Clone)]
struct Key([[u8; DERIVED_KEY_LEN]; DERIVED_KEY_NUM]);

impl Key {
    fn new(seed: [u8; 32]) -> Key {
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

async fn run_forwarder(args: ForwarderArgs, is_client: bool) -> Result<()> {
    info!("Listening on: {}", args.listen);

    let key = Key::new(
        bs58::decode(args.key.as_bytes())
            .into_array_const::<32>()
            .map_err(|e| {
                anyhow!("invalid key: {e} (expected a base58-encoded 32-byte secret from `generate-key`)")
            })?,
    );
    let timeout_duration = Duration::from_secs(args.timeout);
    let forward_addr = tokio::net::lookup_host(&args.forward)
        .await?
        .next()
        .ok_or_else(|| anyhow!("invalid forward address"))?;

    // NOTE: each worker binds its own SO_REUSEPORT listener and keeps its
    // own session table. This relies on the kernel steering all packets of
    // a given client 4-tuple to the same socket (Linux reuseport hashing
    // stays consistent while the socket set is unchanged), so a client's
    // sessions are never split across workers.
    for _ in 0..get_cpus_num() {
        let key = key.clone();
        tokio::spawn(async move {
            let listen_socket = match new_reuseport_udp_socket(args.listen) {
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
                            error!(
                                "[Session {src_addr}] can not create the forwarder_socket: {e}"
                            );
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

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey => generate_key(),
        Commands::Server(args) => run_forwarder(args, false).await,
        Commands::Client(args) => run_forwarder(args, true).await,
    }
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

        // data packet: length is preserved, no padding
        let (mut buf, original) = test_packet(4, 32);
        let encoded = obfuscate(&mut buf[..], 32, &key, true).unwrap();
        assert_eq!(encoded, 32);
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
}
