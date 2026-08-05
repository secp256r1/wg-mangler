## 0.2.1 - 2026-08-05

- **fix(kernel mode): checksum space corrected -- the LE-halfword incremental
  model is abandoned in favor of the RFC/BE word space**. Packet captures on a
  real kernel showed the kernel sums network-order (BE) 16-bit words; the whole
  incremental pipeline was off by a byte swap, so every mutated packet was
  dropped by the receiving kernel (at the IP layer and by the UDP checksum) --
  which is exactly why `--kernel` broke WireGuard connectivity in real use
  (alongside the previously fixed key-index offset, key modulo and port-rewrite
  asymmetries).
  - `wg_decode` trimmed path (handshake packets): **the on-wire checksum field
    is never trusted** -- the UDP checksum is recomputed from scratch over the
    final bytes (pseudo-header + UDP header + snapshot-restored body), and the
    IP header checksum is recomputed from header locals. Correct for both the
    CHECKSUM_PARTIAL offload path (veth: the field only holds the pseudo-header
    sum) and full checksums.
  - `wg_encode`: detects CHECKSUM_PARTIAL (field == the uncomplemented
    fold(Σ_pseudo)) and leaves the field exactly as the kernel's own send path
    would write it (the pseudo-header only holds src/dst/proto/ulen and is
    unaffected by the transform; the device completes the payload over the
    final bytes); with a full checksum it updates precisely via
    `bpf_csum_diff` + a plain `(new-old) mod 65535` port delta.
  - untrimmed/data (type 4) decode stays incremental and equals a fresh
    recomputation under full-checksum input (verified by 3000 randomized unit
    tests).
  - removed `pad_region_delta` / `word_delta(swap16)` / the LE-space derivation;
    module docs rewritten.
- **cli(client)**: `--listen` is now optional and only required by the server
  and by the userspace proxy; in kernel mode the client no longer needs it
  (nothing is bound locally -- ports and interface come from `--forward` and
  the route to the peer).
  - hardening: IPv4 non-first fragments (frag_off offset != 0) carry no UDP
    header; XDP/TC skip them so the payload is never misread as a UDP header
    and corrupted.
- fix(kernel mode): **interface auto-detection no longer uses the listen IP** --
  `--listen` is meaningless in kernel mode; the old logic resolved the client's
  interface from it and wrongly picked `lo` (common with
  `--listen 127.0.0.1`), attaching the programs where no traffic ever flows.
  The client now selects the interface via `ip route get <forward IP>` (the
  real egress to the peer); the server falls back to the default route for
  `0.0.0.0`/loopback listen addresses.
- verified (real kernel 6.12, veth + generic XDP, two containers, **real
  WireGuard tunnel**):
  - phase 1: userspace encode -> kernel decode+trim+port rewrite -> echo ->
    kernel encode -> userspace decode, byte-identical restore ✓
  - phase 2: dual kernel (client TC encode -> server XDP decode -> server TC
    encode -> client XDP decode) plaintext round trip ✓; type-4 data messages
    round trip ✓
  - real WireGuard end-to-end (wg0 in both containers, client endpoint ->
    server mangler port): server kernel + client kernel -> handshake completed,
    ping 4/4 without loss, bidirectional traffic (604/660 B) ✓; server kernel +
    client userspace -> equally working ✓; the tunnel recovers automatically
    after the server's wg0 is restarted ✓; captures confirm the handshake
    response is exactly 92 B and the transform/source-port rewrite take effect
    end to end

## 0.2.0 - 2026-08-05

- **kernel eBPF mode**: add `--kernel` flag to `server` and `client` subcommands.
  When enabled, loads XDP/TC eBPF programs that perform the XOR transform entirely
  in-kernel, bypassing the userspace proxy for near-zero per-packet overhead.
  Requires Linux and `cargo build --features kernel`.
  - `xdp/wg_decode` - ingress: unmangle + restore WireGuard header + XOR body +
    server-side port rewrite (MG_PORT→WG_PORT) + optional padding trim + checksum
    fixup (trim path recomputes fresh in RFC/BE space; untrimmed/data use
    `bpf_csum_diff` deltas — see 0.2.1 notes)
  - `tc/wg_encode` - egress: random header + XOR body + CHECKSUM_PARTIAL-aware
    checksum handling
  - key derivation identical to userspace mode (SHA-256, 64×8-byte keys, same
    header layout and key indexing) → mixed kernel/userspace deployments
    interoperate
  - both paths fail open: any bounds/parse/helper error passes the packet
    through untouched (userspace proxy still does the transform for
    non-matching traffic)
  - maps: `WGKEYS` (array 64×8) and `CONFIG` ([0]=mangler port, [1]=wg port,
    [2]=remote peer IP network-byte-order); remote-IP/port filtering means
    kernel mode is purely passive — it never terminates or proxies flows
  - new files: `wg-mangler-ebpf/` (eBPF crate, aya-ebpf 0.2.1 + network-types),
    `src/kernel.rs` (loader: map injection, XDP attach, TC attach + clsact),
    `build.rs` (aya-build 0.2 invokes nightly bpfel build only when
    `--features kernel` is set on Linux)
- workspace: `Cargo.toml` converted to workspace root; eBPF crate gets a
  dedicated per-package release profile (no strip/lto, `opt-level = "s"`) so the
  kernel loader sees the `.license`/`.maps` sections intact
- `--iface` option to pin the interface for eBPF attachment (auto-detected via
  `ip addr show`/default route otherwise)
- **release/build toolchain**: Linux release binaries are built with
  `--features kernel`. `build.rs` gained a prebuilt-artifact fast path
  (`target/bpfel-unknown-none/release/wg_mangler_ebpf`, used when newer than
  the eBPF sources) so `cross`/CI containers — which have no
  nightly/bpf-linker — can link the kernel feature without provisioning a BPF
  toolchain inside the container; `aya-build` remains the fallback for native
  Linux builds. `.github/workflows/release.yaml` builds the eBPF program once
  on the runner (nightly + rust-src + bpf-linker, `-Z build-std=core`) and
  then cross-compiles all Linux targets with the artifact; macOS/Windows
  builds are unchanged (default features only)
- kernel-mode verifier hardening (both programs pass the Linux 6.12 verifier;
  previously `BPF_PROG_LOAD` returned EPERM):
  - bounds checks are pointer comparisons vs `data_end` (scalar `wire_len`
    compares don't establish verifier ranges); snapshot/copy region bounded by
    one `payload + chg_end <= data_end` check
  - pad-region checksum contribution *derived* from the UDP checksum identity
    (`Σ_pad = field - Σ_pseudo - Σ_udp_hdr - Σ_body mod 65535`) instead of
    reading the variable-offset tail bytes directly (verifier gives variable
    packet offsets `range = 0`); verified by 3000 random direct-vs-derived
    cases + 3000 end-to-end trimmed-checksum cases
  - key-byte selection via scalar u64 shifts instead of array indexing
    (`key[i & 7]` compiles to `ptr |= reg`, rejected as bitwise-op-on-pointer);
    `pad_region_delta` uses u64 wrapping arithmetic because the BPF backend
    has no signed division
  - TC snapshot loads call `bpf_skb_load_bytes` directly with constant
    per-message-type lengths (aya's `load_bytes` clamps to
    `min(skb_remaining, dst.len())` producing a length the verifier can't
    prove non-zero); too-short packets fall through to TC_ACT_PIPE
  - XDP attach tries native (Driver) first and falls back to generic (Skb)
    with a warning on devices without native XDP (e.g. veth)

## 0.1.2 - 2026-08-05

- add datagram length validation to `obfuscate` (short packets are dropped instead of forwarding stale buffer data)
- cap handshake padding so a max-size datagram cannot overflow the scratch buffer (panic)
- hard-cap padded datagrams at the real UDP payload limit (65507 bytes) instead of the buffer size
- only XOR the bytes that will actually be sent when padding handshake packets
- validate incoming packets before allocating a session, preventing resource exhaustion via spoofed sources
- cap sessions per worker (256) so spoofed sources cannot exhaust sockets and tasks
- bind session proxy sockets without holding the sessions lock; keep the worker alive if a bind fails
- clean up sessions when `send_to` fails instead of waiting for the inactivity timeout
- replace `std::hash::DefaultHasher` key derivation with SHA-256 (stable across Rust versions/platforms)
- add unit tests for encode/decode round trips, padded packet handling, wrong-key rejection, and malformed packet rejection

## 0.1.1 - 2025-12-16

- fix compile issue on Windows

## 0.1.0 - 2025-12-16

- first release