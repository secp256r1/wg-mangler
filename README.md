# wg-mangler

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Usage](#usage)
  - [1. Generate Key](#1-generate-key)
  - [2. Run the Server](#2-run-the-server)
  - [3. Run the Client](#3-run-the-client)
  - [4. Kernel eBPF Mode (Linux)](#4-kernel-ebpf-mode-linux)
- [Why Kernel Mode?](#why-kernel-mode)
- [Acknowledgements](#acknowledgements)
- [Similar Tools](#similar-tools)

## Overview

`wg-mangler` is a lightweight and efficient tool designed to obfuscate WireGuard VPN traffic. It acts as a simple proxy that mangles the headers of WireGuard messages, helping to disguise the traffic from deep packet inspection (DPI).

Its simplicity is a key feature: it requires no `tun` devices and no `nftables` or `iptables` rules. It's built to be resource-friendly, making it ideal for low-power devices, including routers running OpenWrt. Because it only performs a minor XOR transformation on the message headers, the computational overhead is minimal.

## Features

- **Lightweight Obfuscation:** Hides WireGuard traffic with minimal performance impact.
- **Minimal Overhead:** Data packets pass through without any added size; handshake/cookie packets get 0–64 bytes of random padding to hinder length-based fingerprinting.
- **Simple to Use:** No complex setup, `tun` devices, or firewall rules needed.
- **Low Resource Usage:** Small memory and CPU footprint.
- **OpenWrt Support:** Works great on embedded Linux devices.
- **Minimal Latency:** Fast header-only transformation adds negligible delay.

## How It Works

`wg-mangler` runs as a client on your local machine and a server on your VPS, wrapping your existing WireGuard connection.

```text
+-------------------+      +--------------------+      +--------------------+      +-----------------+
| Local WireGuard   | <--> | wg-mangler client  | <--> | wg-mangler server  | <--> |  VPS WireGuard  |
| (e.g. 127.0.0.1)  |      | (e.g. 127.0.0.1)   |      | (Your VPS public IP) |      | (e.g. 127.0.0.1)|
+-------------------+      +--------------------+      +--------------------+      +-----------------+
```

## Usage

The setup involves three steps: generating a shared secret key, running the server on your remote machine (VPS), and running the client on your local machine.

### 1. Generate Key

First, generate a secret key that will be shared between the client and server. Run the following command and save the output to a file.

```sh
wg-mangler generate-key
```

### 2. Run the Server

On your VPS, run `wg-mangler` in **server** mode. It will listen for incoming traffic from your client and forward the decoded packets to your WireGuard server instance.

- `--listen` (`-l`): The public-facing IP and port to listen for client connections (e.g., `0.0.0.0:12345`).
- `--forward` (`-f`): The address and port where your WireGuard server is running (e.g., `127.0.0.1:51820`).
- `--key` (`-k`): The secret key.

```sh
# On your VPS
wg-mangler server --listen 0.0.0.0:12345 --forward 127.0.0.1:51820 --key key
```

### 3. Run the Client

On your local machine, run `wg-mangler` in **client** mode. This will create a local listener for your WireGuard client to connect to. It will encode packets and send them to your `wg-mangler` server.

- `--listen` (`-l`): The local IP and port for your WireGuard client to connect to (e.g., `127.0.0.1:15820`).
- `--forward` (`-f`): The public IP and port of your `wg-mangler` server (e.g., `YOUR_VPS_IP:12345`).
- `--key` (`-k`): The secret key.

```sh
# On your local machine
wg-mangler client --listen 127.0.0.1:15820 --forward YOUR_VPS_IP:12345 --key key
```

Finally, update your local WireGuard client configuration to use the `wg-mangler` client address as its endpoint:

**Original WireGuard Config:**
```
[Peer]
Endpoint = YOUR_VPS_IP:51820
...
```

**New WireGuard Config:**
```
[Peer]
Endpoint = 127.0.0.1:15820
...
```

Now your WireGuard traffic will be seamlessly obfuscated through `wg-mangler`.

### 4. Kernel eBPF Mode (Linux)

The userspace proxy costs one syscall pair + buffer copy + context switch per
packet. On Linux you can instead run the transform inside the kernel with XDP
(ingress) and TC (egress) eBPF programs, so packets are mangled in place with
no userspace involvement — the per-packet overhead drops to a handful of BPF
instructions.

Build with the `kernel` feature (requires a nightly toolchain with the
`rust-src` component and `bpf-linker`):

```sh
rustup toolchain install nightly --profile minimal --component rust-src
cargo install bpf-linker --locked
cargo build --release --features kernel
```

(There is no `rustup target add bpfel-unknown-none` step: the eBPF target's
standard library is built from source with `-Z build-std=core`, which only
needs the `rust-src` component. On macOS, `rustup target add bpfel-unknown-none`
would fail with "no prebuilt artifacts" — ignore it.)

**Cross-compiling with `cross` (e.g. building Linux binaries on macOS):**
`cross` containers have no nightly/bpf-linker, so build the eBPF program on
the host first; `build.rs` then reuses that artifact inside the container
(BPF bytecode is architecture independent, so one build serves all targets):

```sh
RUSTFLAGS='--cfg=bpf_target_arch="x86_64" -Cdebuginfo=2 -Clink-arg=--btf' \
  cargo +nightly build -p wg-mangler-ebpf --bins --release \
  --target bpfel-unknown-none -Z build-std=core
cross build --release --target x86_64-unknown-linux-musl --features kernel
```

If the eBPF sources are newer than the prebuilt artifact, `build.rs` falls
back to `aya-build` and fails inside the container — just rebuild the eBPF
program again. The release workflow (`.github/workflows/release.yaml`)
follows this exact pattern automatically.

Then run the same commands as above with `--kernel`:

```sh
# On your VPS (server side)
wg-mangler server --listen 0.0.0.0:12345 --forward 127.0.0.1:51820 --key key --kernel

# On your local machine (client side)
# `--listen` is optional in kernel mode (the client binds nothing locally);
# the interface is auto-detected from the route to YOUR_VPS_IP.
wg-mangler client --forward YOUR_VPS_IP:12345 --key key --kernel
```

Kernel mode needs root and an interface with XDP support. The interface is
auto-detected (override with `--iface`): the server uses the interface that
owns its listen address (or the default route for `0.0.0.0`), and the client
uses the route to the remote endpoint (`--forward` IP) — never its own
`--listen` address, which is ignored in kernel mode and would otherwise
resolve to `lo`.

**How the programs fit the no-proxy topology** (WireGuard talks directly to
`Endpoint = YOUR_VPS_IP:12345`):

> **Switching the client from userspace to kernel mode changes the WG
> endpoint**: userspace mode proxies on `127.0.0.1` (`Endpoint =
> 127.0.0.1:<listen port>`), kernel mode requires the *remote* endpoint
> (`Endpoint = YOUR_VPS_IP:12345`) — kernel mode binds nothing locally
> (`--listen` is not needed) and only transforms packets on the attached
> interface. Also make sure the client's WireGuard traffic actually
> traverses the attached interface (`tc qdisc`/XDP hooks are
> per-interface); the interface is auto-detected from the route to the
> peer, or pin it with `--iface`.

```text
client:  TC egress:  dport == 12345                  → encode
         XDP ingress: src == VPS && sport == 12345   → decode
server:  XDP ingress: dport == 12345  → decode + port rewrite → 51820
         TC egress:  sport == 51820                  → encode (sport → 12345)
```

Both programs are passive: they only transform matching packets and pass
everything else through (`XDP_PASS` / `TC_ACT_PIPE`). The checksum fixup is
fully incremental (computed directly over big-endian halfwords in the same
RFC/BE space as the checksum field — `bpf_csum_diff` is deliberately avoided
because its result lives in the kernel's rotated wsum space and is off by a
fold rotation when added to a BE-space field; this was the root cause of the
reply-path loss), so even padded handshake packets are trimmed back to their
fixed size on the wire.
The on-wire format is byte-identical to the userspace mode, so a kernel-mode
peer and a userspace peer interoperate freely.

802.1Q / 802.1ad VLAN frames are supported on both hooks (up to two tags,
i.e. single-level QinQ), so tagging the interface — common on OpenWrt WAN
setups — does not silently break the transform.

> Note: the eBPF path applies the XOR transform only. WG peer management,
> sessions and endpoint logic stay in the kernel's WireGuard implementation
> (and `wg` userspace tooling), exactly as in an unmangled setup.

### Why Kernel Mode?

The XOR itself is nearly free — the CPU cost of the userspace proxy is the
per-packet kernel↔userspace crossing: `recvfrom`/`sendto` syscalls, a copy of
`MAX_UDP_SIZE` bytes per datagram, and two context switches plus task
scheduling per packet. Kernel mode removes all of that.

## Acknowledgements

- **LLM:** For assisting with a significant portion of the coding work.
- **[phantun](https://github.com/dndx/phantun)**: A long-term tool used before `wg-mangler`.
- **[udp2raw](https://github.com/wangyu-/udp2raw)**: Another long-term tool used before `wg-mangler`.

## Similar Tools

- **[wg-obfuscator](https://github.com/ClusterM/wg-obfuscator)**
