## 0.2.4 - 2026-08-08

- **feat(cli): TCP transport mode (`--tcp`)** -- run the network between the
  two manglers over TCP instead of UDP (useful where UDP is throttled or
  filtered). The client binds a local UDP port (same as before) and opens a
  TCP connection per WireGuard source to the server; the server accepts TCP
  connections and relays the frames to/from the local WireGuard daemon over
  UDP, each connection acting as one session with its own forwarder socket.
  - on-wire frame format: `[random 2-byte key index][payload length
    XORed with derived key bytes][payload]` -- the first two random bytes
    are an index into the shared derived-key table, exactly like the first
    two bytes of the UDP `obfuscate` header: the receiver looks up
    `used_key = key.get(index)` and the two length bytes are XORed with
    `get_key_byte(used_key, 3)` and `get_key_byte(used_key, 6)` (LE
    length, bytewise XOR, so decode is symmetric). Payloads are capped at
    the UDP payload limit (65507) and oversized length fields are rejected
    without allocating.
  - `--listen`/`--forward` semantics per role: client -- UDP listen port
    (the WireGuard `Endpoint`) + the server's TCP endpoint; server -- the
    public TCP port + the local WireGuard daemon address. `--key` is
    shared as usual (it derives the per-frame key bytes; a wrong key
    cannot recover the frame length); `--tcp` is rejected together with
    `--kernel`.
  - sessions, limits and timeouts mirror the UDP proxy: 256 sessions per
    worker, `--timeout` inactivity teardown (server closes the connection,
    client follows on EOF), self-healing reconnect on the next packet, and
    EOF/error paths wake the opposite direction via a `watch` channel.
  - **`TCP_NODELAY` on both the client and the server sockets**: every WG
    datagram is written as its own small frame; without it Nagle would
    hold each frame until the previous one is ACKed, pacing one frame per
    RTT on a real WAN (page loads crawl). The client session also runs the
    outbound and inbound paths as two separate tasks so heavy outbound
    traffic can never starve the inbound path (the original single select
    loop biased toward whichever direction had queued data). Session map
    entries now hold `Arc<UnboundedSender>` so cleanup removes an entry by
    pointer identity -- no removal can ever take out a newly re-created
    session.
  - hardened the session lookup in the tcp client loop: the sessions read
    guard is cloned before taking the write lock (the match-scrutinee
    pattern deadlocked the worker loop).
  - unit tests for the frame format (header round trip, per-frame key XOR,
    oversized-length rejection, stream reassembly via `tokio::io::duplex`,
    clean-EOF handling); verified end-to-end with a local TCP client +
    server + UDP echo proxy.

## 0.2.3 - 2026-08-06

- fix(ebpf): **incremental delta no longer uses `bpf_csum_diff`** -- the
  helper returns a value in the kernel's *rotated* wsum space (`csum_partial`
  accumulates native LE dwords; `csum_from32to16` folds without the byte
  swap `csum_fold` applies), so combining it with `csum_add` (BE-space
  field math) was wrong by exactly that fold rotation. Real captures
  (client eth0 ingress, XDP post-decode): decoded payloads showed
  checksum `0x74c0`/`0xa4b4` where fresh recomputation gives
  `0xdd57`/`0x94c4` -- every decode-then-deliver packet was dropped by the
  kernel, killing the reply path. Delta is now computed inline over
  big-endian halfwords (`ΣBE(to) − ΣBE(from)` mod 65535), the same space
  the field lives in; verified offline against the captured packets and by
  3000 randomized unit tests (decode-incremental == fresh recompute).

## 0.2.2 - 2026-08-06

- fix(ebpf): **incremental checksum now folds twice** (`csum_add` in
  `wg_decode`/`wg_encode` and in the matching userspace mirror). The single
  fold truncated a folded sum >= 0x10000 instead of wrapping the carry, so
  the checksum field was off by one for about 1 in 65535 packets on the hot
  incremental path (every full-checksum data packet on encode, untrimmed
  decode) — now identical to the kernel's `csum_fold`. A new
  `csum_add_fuzz_matches_reference_fold` test forces the exact carry
  boundary, which random tests can never hit reliably.
- feat(ebpf): **802.1Q / 802.1ad (and single-level QinQ) support on both
  hooks** — up to two VLAN tags are skipped via the EtherType chain, so
  VLAN-tagged WireGuard traffic (common on OpenWrt WAN interfaces) is
  transformed like plain frames instead of silently passing through.
- fix(ebpf): **`bpf_xdp_adjust_tail` return value is now checked and the
  trim runs before any mutation** — if the kernel refuses to shrink the
  packet (e.g. generic XDP on a non-linear skb) the transform bails out
  untouched instead of leaving a half-mangled packet in the receive path.

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
    final bytes); with a full checksum it updates precisely via a hand-rolled
    big-endian halfword delta + a plain `(new-old) mod 65535` port delta.
    (Root-caused fix: `bpf_csum_diff` returns a value in the kernel's rotated
    wsum space — `csum_partial` accumulates native LE dwords and
    `csum_from32to16` folds without the byte swap `csum_fold` applies — so
    adding it to a BE-space field was wrong by the fold rotation. Real
    captures: helper path wrote 0x74c0 where the true value is 0xdd57; the
    direct BE-halfword computation reproduces the true value exactly.)
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
    fixup (trim path recomputes fresh in RFC/BE space; untrimmed/data use an
    inline big-endian halfword delta — see 0.2.1 notes)
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