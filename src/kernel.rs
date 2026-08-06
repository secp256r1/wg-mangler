//! eBPF kernel-mode loader for wg-mangler.
//!
//! When `--kernel` is passed, instead of running the userspace proxy,
//! we load the eBPF XDP/TC programs into the kernel, inject the derived
//! keys and configuration, and let the kernel handle the XOR transform
//! in-place on each packet.
//!
//! # Topology (no-proxy topology)
//!
//! ```text
//! client:  WG Endpoint = VPS_IP:MG_PORT
//! server:  WG ListenPort = WG_PORT
//! client TC egress:   dport == MG_PORT (peer)            -> encode
//! client XDP ingress: src == VPS && sport == MG_PORT     -> decode
//!                      (peer-side, already rewritten by the server)
//! server XDP ingress: dport == MG_PORT -> decode + port->WG_PORT
//! server TC egress:   sport == WG_PORT -> encode + sport->MG_PORT
//! ```
//!
//! The server TC hook rewrites the source port WG_PORT -> MG_PORT, making the
//! on-wire 4-tuple identical to the userspace proxy (which sends from its
//! listen port). The client therefore uses the same matching rules no matter
//! which implementation the peer runs, and the WG endpoint stays stable at
//! VPS_IP:MG_PORT without flipping.

use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::{Context, Result};
use aya::{
    Ebpf, include_bytes_aligned,
    maps::Array,
    programs::{SchedClassifier, TcAttachType, Xdp, XdpMode, tc},
};
use log::{info, warn};
use tokio::signal;

use crate::DERIVED_KEY_NUM;

/// Run the eBPF kernel-mode transform.
///
/// * server: `listen` = `0.0.0.0:MG_PORT` (public mangler port),
///   `forward` = `WG_DAEMON_IP:WG_PORT` (the local WireGuard daemon)
/// * client: `listen` = the local port (ignored in kernel mode),
///   `forward` = `VPS_IP:MG_PORT` (the peer's mangler endpoint — the
///   client matches the peer's mangler port on both hooks, because the
///   server rewrites its source port to MG_PORT, exactly like the userspace
///   proxy does)
/// `key`         → raw 32-byte shared secret (base58 decoding happens in the
///                 CLI parser, so the secret is validated before startup)
/// `is_client`   → true for client mode, false for server
/// `iface_name`  → optional network interface name; auto-detected if `None`
pub async fn run_kernel_ebpf(
    listen: SocketAddrV4,
    forward: SocketAddrV4,
    key: &[u8; 32],
    is_client: bool,
    iface_name: Option<&str>,
) -> Result<()> {
    // server: cfg[0]=MG_PORT (listen), cfg[1]=WG_PORT (forward).
    // client: binds nothing locally, matches the peer's traffic -- cfg[0] and
    // cfg[1] both use the peer's mangler port (forward.port()), which is the
    // source/destination port after the server-side rewrite.
    let (cfg_mangler, cfg_wg) = if is_client {
        (forward.port(), forward.port())
    } else {
        (listen.port(), forward.port())
    };
    let remote_ip = forward.ip();

    info!(
        "Kernel eBPF mode ({}): mangler_port={}, wg_port={}, remote_ip={}",
        if is_client { "client" } else { "server" },
        cfg_mangler,
        cfg_wg,
        remote_ip
    );

    // Load the eBPF object
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/wg_mangler_ebpf"
    )))
    .context("failed to load eBPF object")?;

    let derived = crate::Key::new(*key).0;

    let mut keys_map: Array<_, [u8; 8]> =
        Array::try_from(bpf.map_mut("WGKEYS").context("map WGKEYS not found")?)
            .context("failed to get WGKEYS map")?;
    for (i, k) in derived.iter().enumerate() {
        keys_map.set(i as u32, *k, 0)?;
    }
    info!("Injected {} derived keys into BPF map", DERIVED_KEY_NUM);

    // Inject the config
    let mut cfg_map: Array<_, u32> =
        Array::try_from(bpf.map_mut("CONFIG").context("map CONFIG not found")?)
            .context("failed to get CONFIG map")?;
    cfg_map.set(0, cfg_mangler as u32, 0)?; // [0] = mangler port
    cfg_map.set(1, cfg_wg as u32, 0)?; // [1] = wg port
    // [2] = remote_ip in network byte order, matching the eBPF side's
    // `u32::from_be_bytes(src_addr)` comparison.
    cfg_map.set(2, u32::from_be_bytes(remote_ip.octets()), 0)?;

    info!(
        "Config: mangler_port={}, wg_port={}, remote_ip={}",
        cfg_mangler, cfg_wg, remote_ip
    );

    // Determine the interface name.
    // In kernel mode the client binds nothing locally, so resolving the
    // interface from the listen IP would wrongly pick `lo` (common with
    // `--listen 127.0.0.1`) and never see any traffic. Instead, select the
    // interface by the route to the peer. The server's 0.0.0.0/loopback
    // listen addresses fall back to the default route as well.
    let iface_name = match iface_name {
        Some(name) => name.to_string(),
        None => {
            let detect = if is_client {
                *forward.ip()
            } else if listen.ip().is_unspecified() || listen.ip().is_loopback() {
                Ipv4Addr::UNSPECIFIED
            } else {
                *listen.ip()
            };
            find_interface_for_ip(&detect)?
        }
    };
    let program: &mut Xdp = bpf
        .program_mut("wg_decode")
        .context("program wg_decode not found")?
        .try_into()?;
    program.load()?;
    // Prefer native XDP (driver mode); fall back to generic XDP (skb) so
    // veth pairs and virtual NICs without driver XDP support still work.
    let attach = program.attach(&iface_name, XdpMode::Driver);
    match attach {
        Ok(link) => {
            info!("XDP program attached to {} (ingress, native)", iface_name);
            link
        }
        Err(e) => {
            warn!("native XDP attach failed: {e}; falling back to generic XDP (skb)");
            program
                .attach(&iface_name, XdpMode::Skb)
                .context("failed to attach XDP program (native and generic)")?
        }
    };
    info!("Done.");

    // Attach the TC encode hook
    if let Err(e) = tc::qdisc_add_clsact(&iface_name) {
        warn!("qdisc_add_clsact: {e} (ignored; clsact may already exist)");
    }
    let program: &mut SchedClassifier = bpf
        .program_mut("wg_encode")
        .context("program wg_encode not found")?
        .try_into()?;
    program.load()?;
    program
        .attach(&iface_name, TcAttachType::Egress)
        .context("failed to attach TC program")?;
    info!("TC program attached to {} (egress)", iface_name);

    // Wait for shutdown
    info!("Kernel eBPF mode running. Press Ctrl-C to exit.");
    signal::ctrl_c().await?;
    info!("Exiting kernel eBPF mode.");

    Ok(())
}

/// Find the interface that carries traffic to `ip` (auto-detection).
/// 1) the `dev <iface>` of `ip route get <ip>` -- works for local addresses
///    (e.g. the VPS public IP) and remote addresses (the client's route to
///    the peer); uses the real forwarding interface;
/// 2) falls back to the `dev` of `ip route show default`.
fn find_interface_for_ip(ip: &Ipv4Addr) -> Result<String> {
    if !ip.is_unspecified() {
        let output = std::process::Command::new("ip")
            .args(["route", "get", &ip.to_string()])
            .output()
            .context("failed to run `ip route get`")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(dev) = route_dev(&stdout) {
            return Ok(dev);
        }
    }

    let output = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("failed to run `ip route show default`")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(dev) = route_dev(&stdout) {
        return Ok(dev);
    }

    Err(anyhow::anyhow!(
        "cannot determine the egress interface for {ip}; pass --iface explicitly"
    ))
}

/// Extract the interface name following `dev <iface>` from `ip` output.
fn route_dev(stdout: &str) -> Option<String> {
    stdout.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "dev" {
                return it.next().map(str::to_string);
            }
        }
        None
    })
}
