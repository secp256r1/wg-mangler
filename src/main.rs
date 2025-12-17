use std::{
    collections::{HashMap, hash_map::Entry},
    hash::{DefaultHasher, Hasher},
    net::{SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use log::{debug, error, info};
use tokio::{net::UdpSocket, sync::RwLock};

const MAX_UDP_SIZE: usize = u16::MAX as usize;
const DERIVED_KEY_NUM: usize = 64;

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
    if packet.len() < 16 {
        bail!("invalid message length");
    }

    let (message_type, used_key) = if is_encode {
        let message_type = packet[0];
        packet[0..4].copy_from_slice(getrandom::u32()?.to_le_bytes().as_slice());
        let used_key = key.get(packet[2]);
        packet[3] = message_type ^ used_key[0];
        (message_type, used_key)
    } else {
        let used_key = key.get(packet[2]);
        let message_type = packet[3] ^ used_key[0];

        packet[0] = message_type;
        packet[1..4].copy_from_slice([0u8; 3].as_slice());
        (message_type, used_key)
    };

    Ok(match message_type {
        // data
        4 => {
            xor_transform(&mut packet[4..16], used_key);
            len
        }
        // handshake and cookie
        1..=3 => {
            if is_encode {
                xor_transform(&mut packet[4..], used_key);
                let padding_size = (getrandom::u32()? as u8) as usize;
                let padding_len = len + padding_size;
                getrandom::fill(&mut packet[len..padding_len])?;
                padding_len
            } else {
                let size = match message_type {
                    1 => 148,
                    2 => 92,
                    3 => 64,
                    _ => unreachable!(),
                };
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

async fn handle_reverse_traffic(
    is_client: bool,
    main_socket: Arc<UdpSocket>,
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
                        error!("[Session {original_src}] Failed to obfuscate original source: {e}");
                        continue;
                    }
                };

                if let Err(e) = main_socket.send_to(&buf[..trim_len], original_src).await {
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
struct Key([[u8; 8]; DERIVED_KEY_NUM]);

impl Key {
    fn new(seed: [u8; 32]) -> Key {
        let mut derived = [[0u8; 8]; DERIVED_KEY_NUM];
        for (i, v) in derived.iter_mut().enumerate() {
            let mut hasher = DefaultHasher::new();
            hasher.write(&seed);
            hasher.write_usize(i);
            *v = hasher.finish().to_le_bytes();
        }

        Key(derived)
    }

    fn get(&self, index: u8) -> &[u8; 8] {
        &self.0[index as usize % DERIVED_KEY_NUM]
    }
}

#[inline]
#[cfg(windows)]
fn get_cpus_num() -> usize {
    1
}

#[inline]
#[cfg(not(windows))]
fn get_cpus_num() -> usize {
    num_cpus::get()
}

async fn run_forwarder(args: ForwarderArgs, is_client: bool) -> Result<()> {
    info!("Listening on: {}", args.listen);

    let key = Key::new(bs58::decode(args.key.as_bytes()).into_array_const::<32>()?);
    let timeout_duration = Duration::from_secs(args.timeout);
    let forward_addr = tokio::net::lookup_host(&args.forward)
        .await?
        .next()
        .ok_or_else(|| anyhow!("invalid forward address"))?;

    for _ in 0..get_cpus_num() {
        let key = key.clone();
        tokio::spawn(async move {
            let main_socket = match new_reuseport_udp_socket(args.listen) {
                Ok(v) => v,
                Err(e) => {
                    error!("can not create the main_socket: {e}");
                    return;
                }
            };
            let main_socket = Arc::new(main_socket);
            let sessions: Arc<RwLock<HashMap<SocketAddr, Arc<UdpSocket>>>> =
                Arc::new(RwLock::new(HashMap::new()));

            let mut buf = [0u8; MAX_UDP_SIZE];

            loop {
                let (len, src_addr) = match main_socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        error!("main_socket recv_from error: {e}");
                        continue;
                    }
                };
                debug!("listen socket: received {len} bytes from {src_addr}");

                let proxy_socket = match sessions.write().await.entry(src_addr) {
                    Entry::Occupied(entry) => entry.get().clone(),
                    Entry::Vacant(entry) => {
                        info!("[Session {src_addr}] New connection established.");
                        let forwarder_socket = match UdpSocket::bind("0.0.0.0:0").await {
                            Ok(v) => v,
                            Err(e) => {
                                error!(
                                    "[Session {src_addr}] can not create the forwarder_socket: {e}"
                                );
                                break;
                            }
                        };
                        let forwarder_socket = Arc::new(forwarder_socket);
                        entry.insert(forwarder_socket.clone());

                        let task_main_socket = main_socket.clone();
                        let task_key = key.clone();
                        let task_sessions = sessions.clone();
                        let task_forwarder_socket = forwarder_socket.clone();
                        tokio::spawn(async move {
                            handle_reverse_traffic(
                                is_client,
                                task_main_socket,
                                task_forwarder_socket,
                                src_addr,
                                &task_key,
                                task_sessions,
                                timeout_duration,
                            )
                            .await;
                        });

                        forwarder_socket
                    }
                };

                let padding_len = match obfuscate(&mut buf[..], len, &key, is_client) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("[Session {src_addr}] Failed to obfuscate packet: {e}");
                        continue;
                    }
                };

                if let Err(e) = proxy_socket
                    .send_to(&buf[..padding_len], forward_addr)
                    .await
                {
                    error!("[Session {src_addr}] Failed to send_to packet: {e}");
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
