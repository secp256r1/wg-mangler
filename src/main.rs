use std::{
    net::{SocketAddr, SocketAddrV4, ToSocketAddrs},
    str::FromStr,
};

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};

mod run;

#[cfg(feature = "kernel")]
mod kernel;

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

/// Parse a base58-encoded 32-byte shared secret (as printed by
/// `generate-key`) into its raw bytes. Used by clap via `value_parser`,
/// so `--key` is validated and decoded before any subcommand runs.
fn parse_key(s: &str) -> Result<[u8; 32]> {
    bs58::decode(s.as_bytes())
        .into_array_const::<32>()
        .map_err(|e| {
            anyhow!(
                "invalid key: {e} (expected a base58-encoded 32-byte secret from `generate-key`)"
            )
        })
}

/// Parse a forward address: `IP:port` literals are validated exactly as
/// before, and `domain:port` values are resolved to the first IPv4 address
/// the hostname resolves to. Resolution runs once at parse time (before any
/// subcommand runs), the same way clap's `value_parser` treats `--key`.
fn parse_forward(s: &str) -> Result<SocketAddrV4> {
    // Fast path: plain IPv4 literal, identical to clap's built-in
    // `SocketAddrV4` parser that the field used before.
    if let Ok(addr) = SocketAddrV4::from_str(s) {
        return Ok(addr);
    }

    // Otherwise treat it as `host:port` and resolve the hostname to IPv4.
    let (host, port) = s.rsplit_once(':').ok_or_else(|| {
        anyhow!("invalid forward address `{s}`: expected `IP:port` or `domain:port`")
    })?;
    let port: u16 = port
        .parse()
        .map_err(|e| anyhow!("invalid port in `{s}`: {e}"))?;
    let addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| anyhow!("failed to resolve `{host}`: {e}"))?;

    addrs
        .into_iter()
        .find_map(|addr| match addr {
            SocketAddr::V4(v4) => Some(v4),
            SocketAddr::V6(_) => None, // IPv6-only resolution is not usable here
        })
        .ok_or_else(|| anyhow!("`{host}` resolved to no IPv4 address"))
}

#[derive(Args)]
pub struct ForwarderArgs {
    /// Local listen address.
    /// Required for the server, and for the client when running the userspace
    /// proxy (the WireGuard endpoint points here). Unused in kernel mode
    /// (client with `--kernel`), where the transform runs on the wire.
    #[arg(long, short)]
    pub listen: Option<SocketAddrV4>,

    /// Forward address (`IP:port` or `domain:port`; hostnames are resolved
    /// to their first IPv4 address at parse time, before any subcommand
    /// runs).
    /// Required in userspace mode (the proxy's remote endpoint, and for the
    /// server the local WireGuard daemon) and for the kernel client (the
    /// peer's mangler endpoint, which supplies the ports/IP matched on the
    /// wire). Optional in kernel server mode: only the local WG daemon's
    /// listen port is used, defaulting to the standard WG port (51820)
    /// when omitted.
    #[arg(long, short, value_parser = parse_forward)]
    pub forward: Option<SocketAddrV4>,

    #[arg(long, short, value_parser = parse_key)]
    pub key: [u8; 32],

    #[arg(long, default_value_t = 180)]
    pub timeout: u64,

    /// Use kernel eBPF mode instead of the userspace proxy.
    /// Requires Linux and the `kernel` feature.
    #[arg(long, default_value_t = false)]
    pub kernel: bool,

    /// Use the TCP transport mode instead of the plain UDP proxy.
    /// The network between the two manglers runs over TCP connections
    /// (useful where UDP is throttled or filtered): the client connects to
    /// the server, the server accepts connections, and every WireGuard
    /// datagram crosses the tunnel as a TCP frame of the form
    /// `[length ^ used_key 2B][obfuscate-encoded datagram]`.
    /// The payload is the exact wire format of UDP mode (`obfuscate`
    /// output: random 4-byte header + XORed body, handshakes optionally
    /// padded), so no raw WireGuard bytes appear on the stream. Its first
    /// 2 bytes select the derived key from the shared `--key` table
    /// (exactly like the UDP obfuscate header), and the two length bytes
    /// are XORed with derived key bytes 3 and 6.
    /// In this mode `--listen` is a UDP port on the client (where your
    /// WireGuard peer points) and the public TCP port on the server, and
    /// `--forward` is the server's TCP endpoint on the client and your
    /// local WireGuard daemon address on the server. `--key` must be
    /// shared between both ends, as in the UDP mode.
    #[arg(long, default_value_t = false)]
    pub tcp: bool,

    /// Network interface to attach eBPF programs to.
    /// Only used in kernel mode; auto-detected if omitted.
    #[arg(long)]
    pub iface: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKey => run::generate_key(),
        Commands::Server(args) => run::run_dispatch(args, false).await,
        Commands::Client(args) => run::run_dispatch(args, true).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_forward_accepts_ipv4_literal() {
        let addr = parse_forward("1.2.3.4:51820").unwrap();
        assert_eq!(addr, "1.2.3.4:51820".parse::<SocketAddrV4>().unwrap());
    }

    #[test]
    fn parse_forward_resolves_hostname_to_ipv4() {
        // `localhost` resolves via the hosts file on every platform, no
        // network required.
        let addr = parse_forward("localhost:8080").unwrap();
        assert_eq!(addr, SocketAddrV4::new("127.0.0.1".parse().unwrap(), 8080));
    }

    #[test]
    fn parse_forward_rejects_invalid_values() {
        // missing port
        assert!(parse_forward("example.com").is_err());
        assert!(parse_forward("1.2.3.4").is_err());
        // non-numeric port
        assert!(parse_forward("example.com:notaport").is_err());
        // IPv6-only resolution must not silently fall into a v4 frame
        assert!(parse_forward("::1:80").is_err());
        // empty string
        assert!(parse_forward("").is_err());
    }
}