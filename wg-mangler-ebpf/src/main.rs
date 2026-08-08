//! wg-mangler kernel-mode transform (eBPF).
//!
//! * `wg_decode` (XDP ingress) — undo the mangling applied by a wg-mangler
//!   peer: restore the 4-byte header (`type,0,0,0`), XOR the message body
//!   with the derived key, rewrite the UDP dst port (server side,
//!   MG_PORT → WG_PORT) and trim random handshake padding to the fixed size.
//! * `wg_encode` (TC egress) — mangle locally-generated WireGuard traffic:
//!   randomize the 4-byte header (LE key index, key-byte index, XORed type),
//!   XOR the message body, rewrite the UDP src port (server side,
//!   WG_PORT → MG_PORT, so the on-wire 4-tuple matches the userspace proxy)
//!   and fix the UDP checksum.
//!
//! Both hooks understand 802.1Q / 802.1ad (and single-level QinQ): up to two
//! VLAN tags are skipped, so VLAN-tagged WG traffic (common on OpenWrt WAN
//! interfaces) is transformed just like plain frames.
//!
//! The wire format is byte-identical to the userspace proxy (see the README),
//! so mixed kernel/userspace deployments interoperate: decode accepts and
//! trims the optional random padding that userspace peers add. The body-XOR
//! convention matches userspace exactly: body byte `i` (>= 4) uses
//! `key[(i-4) % 8]` while header byte 3 uses `key[kbidx % 8]` with
//! `kbidx = packet[2]`.
//!
//! # Checksum notes (verified against a real kernel and real captures)
//!
//! All sums are the kernel's one's-complement sums over *big-endian* 16-bit
//! words (RFC space). An earlier LE-halfword model was wrong by a byte swap
//! and every mutated packet was dropped by the receiving kernel.
//!
//! * Decode, trimmed handshake: the checksum is recomputed from scratch
//!   over the final bytes (pseudo-header + UDP header + restored body from
//!   the stack snapshot). The received checksum field is *never* trusted —
//!   this is what makes checksum-offload paths (veth: the field only holds
//!   the pseudo-header sum) work.
//! * Decode, untrimmed handshake / data messages: only the first
//!   16..=148 bytes change, so the checksum is updated incrementally with
//!   a hand-rolled big-endian halfword delta (the RFC/BE sum space the
//!   field lives in) plus a plain word delta for the port rewrite. Exact
//!   when the received field is a full checksum (real NICs); on offload
//!   paths the field is only the pseudo-sum and these two rare paths stay
//!   untouched (they are not produced by our own
//!   encode, which never pads and trims what it can).
//!   `bpf_csum_diff` is *not* used: its result lives in the kernel's
//!   rotated wsum space (`csum_partial` accumulates native dwords,
//!   `csum_from32to16` folds without `csum_fold`'s byte swap), so adding it
//!   to a BE-space field is off by the fold rotation — verified against
//!   real captures where the helper wrote 0x74c0 but the true value is
//!   0xdd57.
//! * Encode: the egress skb is `CHECKSUM_PARTIAL` when TX offload is on —
//!   the kernel writes the *uncomplemented* pseudo-header sum into the
//!   field and the device completes the payload part. We detect that state
//!   by recomputing the pseudo-header sum; since the pseudo-header (src,
//!   dst, proto, ulen) is never changed by the transform, the field is left
//!   exactly as the kernel's own send path would write it and the device
//!   completes it correctly. When the field is a full checksum (offload
//!   off), an incremental update is applied — folded twice like the
//!   kernel's own `csum_fold`, so a carry-out of the first fold is wrapped
//!   back instead of truncated.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, xdp_action},
    helpers::generated::{
        bpf_get_prandom_u32, bpf_skb_load_bytes, bpf_xdp_adjust_tail,
    },
    macros::{classifier, map, xdp},
    maps::Array,
    programs::{TcContext, XdpContext},
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
    vlan::VlanHdr,
};

/// Maximum number of 802.1Q/802.1ad tags to skip (single tag, or two in
/// QinQ deployments). Deeper nesting is passed through untransformed.
const MAX_VLAN_TAGS: usize = 2;

/// Snapshot size: >= the largest changed region (148-byte handshake init).
const SNAP: usize = 160;
/// Upstream (userspace) peers pad handshakes by at most 63 bytes.
const MAX_PAD: u32 = 64;
/// Data keepalives (32 bytes) get 0..=64 random padding from userspace;
/// bit 7 of the key-byte index (packet[2]) marks padding presence:
/// 0 = padded keepalive, 1 = plain data packet. The pad length is inferred
/// from the wire length (pad = len - 32).
const KEEPALIVE_PAD_MAX: u32 = 64;
const KEEPALIVE_PAD_BIT: u8 = 0x80;

/// 64 derived 8-byte keys (index = LE bytes 0-1 of the header).
#[map]
static WGKEYS: Array<[u8; 8]> = Array::with_max_entries(64, 0);

/// [0] = mangler port (low 16 bits)
/// [1] = wg port (low 16 bits)
/// [2] = remote peer IP (network-byte-order u32)
#[map]
static CONFIG: Array<u32> = Array::with_max_entries(3, 0);

#[inline(always)]
fn cfg(idx: u32) -> u32 {
    CONFIG.get(idx).copied().unwrap_or(0)
}

#[inline(always)]
fn key_at(idx: u16) -> [u8; 8] {
    // userspace `Key::get` masks with `index % 64`; must match here. `idx`
    // is a 16-bit random value; without the mask an out-of-range lookup of
    // the 64-entry array returns NULL (all-zero key).
    WGKEYS.get((idx % 64) as u32).copied().unwrap_or([0u8; 8])
}

// RFC/BE-space checksum helpers──────────────────────────────────

/// Fold a u32 sum into the 16-bit one's-complement sum space (mod 65535).
#[inline(always)]
fn fold16(s: u32) -> u16 {
    let s = (s & 0xffff) + (s >> 16);
    let s = (s & 0xffff) + (s >> 16);
    s as u16
}

/// Sum of `post[..SNAP]` as big-endian halfwords (bytes past the message
/// body are zero and contribute nothing). Stack-only reads: verifier-safe.
#[inline(always)]
fn body_sum(post: &[u8; SNAP]) -> u16 {
    let mut s: u32 = 0;
    let mut i = 0usize;
    while i + 1 < SNAP {
        s += ((post[i] as u32) << 8) | post[i + 1] as u32;
        i += 2;
    }
    fold16(s)
}

/// Full UDP checksum over (pseudo-header + UDP header + payload) in the
/// RFC/BE word space. The UDP checksum slot counts as zero.
#[inline(always)]
fn udp_checksum(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    ulen: u16,
    body: u16,
) -> u16 {
    let mut s: u32 = 0;
    s += ((src[0] as u32) << 8) | src[1] as u32;
    s += ((src[2] as u32) << 8) | src[3] as u32;
    s += ((dst[0] as u32) << 8) | dst[1] as u32;
    s += ((dst[2] as u32) << 8) | dst[3] as u32;
    s += IpProto::Udp as u32; // pseudo-header 0x00,0x11 word
    s += ulen as u32;
    s += sport as u32;
    s += dport as u32;
    s += ulen as u32;
    // UDP checksum slot = 0
    s += body as u32;
    (!fold16(s)) as u16
}

/// The value the kernel's send path writes for a `CHECKSUM_PARTIAL` skb:
/// the *uncomplemented* folded sum of the pseudo-header (verified against
/// a real capture). The pseudo-header contains only src/dst/proto/ulen, so
/// body XOR and port rewrites never change it.
#[inline(always)]
fn partial_pseudo(src: [u8; 4], dst: [u8; 4], ulen: u16) -> u16 {
    let mut s: u32 = 0;
    s += ((src[0] as u32) << 8) | src[1] as u32;
    s += ((src[2] as u32) << 8) | src[3] as u32;
    s += ((dst[0] as u32) << 8) | dst[1] as u32;
    s += ((dst[2] as u32) << 8) | dst[3] as u32;
    s += IpProto::Udp as u32;
    s += ulen as u32;
    fold16(s)
}

/// IPv4 header checksum over the final header (RFC/BE word space).
#[inline(always)]
fn ip_checksum(
    vihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frags: u16,
    ttl: u8,
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
) -> u16 {
    let mut s: u32 = 0;
    s += ((vihl as u32) << 8) | tos as u32;
    s += tot_len as u32;
    s += id as u32;
    s += frags as u32;
    s += ((ttl as u32) << 8) | proto as u32;
    // checksum slot = 0
    s += ((src[0] as u32) << 8) | src[1] as u32;
    s += ((src[2] as u32) << 8) | src[3] as u32;
    s += ((dst[0] as u32) << 8) | dst[1] as u32;
    s += ((dst[2] as u32) << 8) | dst[3] as u32;
    (!fold16(s)) as u16
}

/// Incremental one's-complement checksum update:
/// `field' = ~((~field) + delta)` with mod-65535 folding (delta is the
/// kernel sum-space delta, may exceed 16 bits). The fold runs twice, like
/// the kernel's `csum_fold`: the first pass folds the 32-bit sum down to
/// ~16 bits, the second absorbs the carry-out of the first. Without it a
/// sum landing on exactly 0x1FFFF (or any folded value >= 0x10000) is
/// truncated instead of wrapped and the resulting field is off by one.
#[inline(always)]
fn csum_add(field: u16, delta: u32) -> u16 {
    let c = ((!field as u32) & 0xffff) + (delta & 0xffff) + ((delta >> 16) & 0xffff);
    let c = (c & 0xffff) + (c >> 16);
    let c = (c & 0xffff) + (c >> 16);
    !c as u16
}

/// Sum-space delta between two regions: `fold16(Σ BE16(to)) − fold16(Σ BE16(from))`
/// computed directly over big-endian halfwords (RFC space, same as the UDP
/// checksum field).
///
/// `bpf_csum_diff` is deliberately NOT used: its return value lives in the
/// kernel's rotated csum space (`csum_partial` accumulates native LE dwords
/// and `csum_from32to16` folds without the byte swap that `csum_fold`
/// applies), so adding it to a BE-space field via `csum_add` is off by the
/// fold rotation. Verified on real packets: the helper path wrote 0x74c0
/// where the true value is 0xdd57; the manual BE model reproduces the
/// true value exactly.
#[inline(always)]
fn csum_delta(from: *const u8, from_len: u32, to: *const u8, to_len: u32) -> Result<u32, ()> {
    // Both regions are the same length in every call site; guard anyway.
    let n = (from_len.min(to_len) as usize).min(SNAP) & !1;
    let mut sf: u32 = 0;
    let mut st: u32 = 0;
    let mut i: usize = 0;
    // Fixed upper bound so the verifier can prove the packet/stack reads
    // are in bounds; `i < n` only decides whether to accumulate.
    while i < SNAP {
        let f0 = unsafe { *from.add(i) } as u32;
        let f1 = unsafe { *from.add(i + 1) } as u32;
        let t0 = unsafe { *to.add(i) } as u32;
        let t1 = unsafe { *to.add(i + 1) } as u32;
        if i + 1 < n {
            sf += (f0 << 8) | f1;
            st += (t0 << 8) | t1;
        } else if i < n {
            // Odd tail byte counts as a single BE halfword.
            sf += f0 << 8;
            st += t0 << 8;
        }
        i += 2;
    }
    // Fold 32-bit sums to 16 bits; max 74 words * 0xffff < 2^31, so one
    // conditional wrap after the first fold suffices.
    let fs = (sf & 0xffff) + (sf >> 16);
    let fs = if fs >= 65535 { fs - 65535 } else { fs };
    let ft = (st & 0xffff) + (st >> 16);
    let ft = if ft >= 65535 { ft - 65535 } else { ft };
    // delta = fold(to) - fold(from) mod 65535
    let mut d = ft + 65535 - fs;
    if d >= 65535 {
        d -= 65535;
    }
    Ok(d)
}

/// Delta for replacing a 2-byte big-endian field value (port), plain
/// `(new - old) mod 65535` in the RFC/BE sum space (no byte swap).
#[inline(always)]
fn word_delta(old: u16, new: u16) -> u32 {
    let d = (new as i32) - (old as i32);
    if d < 0 {
        (d + 65535) as u32
    } else {
        d as u32
    }
}

// XDP ingress: decode────────────────────────────────────────────

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

/// Returns `(ip, udp, l3_off)`: the IPv4 and UDP headers plus the offset of
/// the IPv4 header inside the frame. 802.1Q/802.1ad (and QinQ) tags are
/// skipped via the EtherType chain, so VLAN-tagged WireGuard traffic is
/// transformed like any other frame.
#[inline(always)]
unsafe fn parse_udp(ctx: &XdpContext) -> Result<(*const Ipv4Hdr, *const UdpHdr, usize), ()> {
    let eth = ptr_at::<EthHdr>(ctx, 0)?;
    let mut etype = (*eth).ether_type;
    let mut l3_off = EthHdr::LEN;
    for _ in 0..MAX_VLAN_TAGS {
        let is_vlan = etype == EtherType::Ieee8021q as u16
            || etype == EtherType::Ieee8021ad as u16
            || etype == EtherType::Ieee8021QinQ1 as u16
            || etype == EtherType::Ieee8021QinQ2 as u16;
        if !is_vlan {
            break;
        }
        let vlan = ptr_at::<VlanHdr>(ctx, l3_off)?;
        etype = (*vlan).ether_type;
        l3_off += VlanHdr::LEN;
    }
    if etype != EtherType::Ipv4 as u16 {
        return Err(());
    }
    let ip = ptr_at::<Ipv4Hdr>(ctx, l3_off)?;
    if (*ip).proto != IpProto::Udp as u8 {
        return Err(());
    }
    // Non-first fragments carry no UDP header (the payload starts at the
    // IP payload offset): skip them, otherwise the payload would be misread
    // as a UDP header and could be corrupted.
    if u16::from_be_bytes((*ip).frags) & 0x1fff != 0 {
        return Err(());
    }
    let udp = ptr_at::<UdpHdr>(ctx, l3_off + Ipv4Hdr::LEN)?;
    Ok((ip, udp, l3_off))
}

#[xdp]
pub fn wg_decode(ctx: XdpContext) -> u32 {
    match unsafe { try_decode(&ctx) } {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

unsafe fn try_decode(ctx: &XdpContext) -> Result<u32, ()> {
    let (ip, udp, l3_off) = parse_udp(ctx)?;

    let mangler_port = (cfg(0) & 0xffff) as u16;
    let wg_port = (cfg(1) & 0xffff) as u16;
    let remote_ip = cfg(2);

    // server: packets addressed to MG_PORT
    let is_server = u16::from_be_bytes((*udp).dst) == mangler_port;
    // client: packets from the peer (the server rewrites its source port to MG_PORT)
    let is_client = !is_server
        && u32::from_be_bytes((*ip).src_addr) == remote_ip
        && u16::from_be_bytes((*udp).src) == mangler_port;

    if !is_server && !is_client {
        return Ok(xdp_action::XDP_PASS);
    }

    let payload = (udp as *const u8).add(UdpHdr::LEN) as *mut u8;

    // Bounds must be established by pointer-vs-data_end comparisons (the
    // verifier only recognizes PTR_TO_PACKET vs PTR_TO_PACKET_END; scalar
    // wire_len comparisons are ineffective).
    if (payload as *const u8).add(4) > ctx.data_end() as *const u8 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Parse (no mutation yet)
    let kidx = u16::from_le_bytes([*payload, *payload.add(1)]);
    let kbidx = *payload.add(2);
    let key = key_at(kidx);
    // Indexing `key[i & 7]` compiles to a bitwise OR on a pointer, which
    // the verifier rejects; pack the key into a u64 scalar instead and
    // extract bytes with shifts.
    let key_bits = u64::from_le_bytes(key);
    let msg_type = *payload.add(3)
        ^ (((key_bits >> (((kbidx as u32) & 7) * 8)) & 0xff) as u8);

    let (size, chg_end): (u32, u32) = match msg_type {
        4 => (0, 16),
        1 => (148, 148),
        2 => (92, 92),
        3 => (64, 64),
        _ => return Ok(xdp_action::XDP_PASS),
    };
    // Data keepalives can be trimmed to 32 bytes (userspace pads them with
    // 0..=31 bytes); the snapshot must cover the full 32-byte message
    // (restored 16-byte header + untouched ciphertext) for the from-scratch
    // checksum. Handshakes keep snap_end == chg_end == size.
    let snap_end = if msg_type == 4 { 32u32 } else { chg_end };
    // Bounds for the whole mutated region (including snapshot reads):
    if (payload as *const u8).add(chg_end as usize) > ctx.data_end() as *const u8 {
        return Ok(xdp_action::XDP_PASS);
    }
    if (payload as *const u8).add(snap_end as usize) > ctx.data_end() as *const u8 {
        return Ok(xdp_action::XDP_PASS);
    }
    let wire_len = (ctx.data_end() - payload as usize) as u32;
    let sn = snap_end.min(SNAP as u32) as usize;

    // Snapshot + restore (before any mutation)
    let mut pre = [0u8; SNAP];
    let mut post = [0u8; SNAP];
    core::ptr::copy_nonoverlapping(payload, pre.as_mut_ptr(), sn);
    post[..sn].copy_from_slice(&pre[..sn]);
    post[0] = msg_type;
    post[1] = 0;
    post[2] = 0;
    post[3] = 0;
    // XOR only the changed header region (data: 4..16; handshake: the whole
    // body up to chg_end == size). Ciphertext beyond that is untouched.
    for i in 4..(chg_end as usize) {
        // userspace convention: packet[4+j] ^= key[j % 8], i.e. key[(i-4) % 8]
        post[i] ^= ((key_bits >> ((((i - 4) as u32) & 7) * 8)) & 0xff) as u8;
    }

    // Header fields -> locals (reads before mutation)
    let sport = u16::from_be_bytes((*udp).src);
    let dport = u16::from_be_bytes((*udp).dst);
    let old_ulen = u16::from_be_bytes((*udp).len);
    let old_check = u16::from_be_bytes((*udp).check);
    let src_addr = (*ip).src_addr;
    let dst_addr = (*ip).dst_addr;

    let mut new_ulen: u16 = old_ulen;
    let mut trim_len: u32 = 0;
    let mut trim_to: u32 = size;
    if msg_type != 4 && wire_len != size {
        let pad = wire_len - size;
        if pad <= MAX_PAD {
            new_ulen = (size + 8) as u16;
            trim_len = pad;
        }
    } else if msg_type == 4
        && (kbidx & KEEPALIVE_PAD_BIT) == 0
        && wire_len >= 32
        && wire_len <= 32 + KEEPALIVE_PAD_MAX
    {
        // Userspace keepalive padding: bit 7 of the key-byte index
        // (packet[2]) is 0 and the pad length is inferred from the wire
        // length.
        trim_to = 32;
        new_ulen = (trim_to + 8) as u16;
        trim_len = wire_len - 32;
    }

    let new_dport = if is_server { wg_port } else { dport };

    // Checksum
    // Trimmed path: recompute from scratch (the on-wire field is never
    // trusted -- under CHECKSUM_PARTIAL it is only the pseudo-header sum,
    // so incremental derivation would be wrong). Untrimmed/data messages:
    // only [0, chg_end) changes, update precisely with csum_diff plus the
    // port delta (requires the on-wire field to be a full checksum).
    let mut new_check: u16 = 0;
    if old_check != 0 {
        if trim_len != 0 {
            let body = body_sum(&post);
            new_check = udp_checksum(src_addr, dst_addr, sport, new_dport, new_ulen, body);
        } else {
            let mut delta = csum_delta(pre.as_ptr(), sn as u32, post.as_ptr(), sn as u32)?;
            if is_server {
                delta += word_delta(mangler_port, wg_port);
            }
            new_check = csum_add(old_check, delta);
        }
    }

    // Trim the padding *before* any mutation: if `bpf_xdp_adjust_tail`
    // fails (e.g. generic XDP on a non-linear/GRO skb) the packet must be
    // left exactly as it arrived, so bail out of the whole transform here.
    if trim_len != 0 {
        let shrink = (trim_to as i64 - wire_len as i64) as i32;
        if unsafe { bpf_xdp_adjust_tail(ctx.ctx, shrink) } != 0 {
            return Ok(xdp_action::XDP_PASS);
        }
    }

    // Re-derive packet pointers *after* adjust_tail: the helper changes
    // data_end, so the old `payload` pointer is stale. It also must not be
    // reused because its `as usize` form (used for `wire_len` above) may be
    // spilled to the same stack slot as the pointer; reloading it after the
    // helper call comes back as an inttoptr'd scalar and the verifier
    // rejects the packet write ("R1 invalid mem access 'scalar'").
    let udp_mut = ptr_at_mut::<UdpHdr>(ctx, l3_off + Ipv4Hdr::LEN)?;
    let payload = (udp_mut as *const u8).add(UdpHdr::LEN) as *mut u8;
    // Re-establish the mutation-region bounds against the (possibly
    // shortened) data_end; `sn` is the snapshot/write length (handshake
    // size, or 32 for data keepalives), which the trimmed packet satisfies
    // exactly.
    if (payload as *const u8).add(sn as usize) > ctx.data_end() as *const u8 {
        return Ok(xdp_action::XDP_PASS);
    }
    core::ptr::copy_nonoverlapping(post.as_ptr(), payload, sn);
    if old_check != 0 {
        (*udp_mut).check = new_check.to_be_bytes();
    }
    if is_server {
        (*udp_mut).dst = wg_port.to_be_bytes();
    }

    // Recompute the IP header checksum for the trimmed packet (the UDP len
    // field and the IP total length shrink by `trim_len`)
    if trim_len != 0 {
        let ip_mut = ptr_at_mut::<Ipv4Hdr>(ctx, l3_off)?;
        let ihl = ((*ip_mut).vihl & 0x0f) as u16;
        let new_tlen = ihl * 4 + 8 + trim_to as u16;
        (*udp_mut).len = new_ulen.to_be_bytes();
        (*ip_mut).tot_len = new_tlen.to_be_bytes();
        (*ip_mut).check = ip_checksum(
            (*ip_mut).vihl,
            (*ip_mut).tos,
            new_tlen,
            u16::from_be_bytes((*ip_mut).id),
            u16::from_be_bytes((*ip_mut).frags),
            (*ip_mut).ttl,
            (*ip_mut).proto,
            (*ip_mut).src_addr,
            (*ip_mut).dst_addr,
        )
        .to_be_bytes();
    }

    Ok(xdp_action::XDP_PASS)
}

// TC egress: encode─────────────────────────────────────────────

#[classifier]
pub fn wg_encode(ctx: TcContext) -> i32 {
    match unsafe { try_encode(&ctx) } {
        Ok(action) => action,
        Err(_) => TC_ACT_PIPE,
    }
}

unsafe fn try_encode(ctx: &TcContext) -> Result<i32, ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    let mut etype = eth.ether_type;
    let mut l3_off = EthHdr::LEN;
    // 802.1Q / 802.1ad (and QinQ) tags: skip up to MAX_VLAN_TAGS levels so
    // VLAN-tagged WireGuard traffic is mangled like untagged frames.
    // NOTE: do not turn this into a rolled loop over the variable `l3_off`
    // -- the BPF backend then emits `ptr <<= 16` on the context pointer
    // ("pointer arithmetic with <<= operator prohibited"). Peel the tag
    // slots at constant offsets instead.
    let v1: VlanHdr = ctx.load(l3_off).map_err(|_| ())?;
    let v1_vlan = etype == EtherType::Ieee8021q as u16
        || etype == EtherType::Ieee8021ad as u16
        || etype == EtherType::Ieee8021QinQ1 as u16
        || etype == EtherType::Ieee8021QinQ2 as u16;
    if v1_vlan {
        etype = v1.ether_type;
        l3_off += VlanHdr::LEN;
        let v2: VlanHdr = ctx.load(l3_off).map_err(|_| ())?;
        let v2_vlan = etype == EtherType::Ieee8021q as u16
            || etype == EtherType::Ieee8021ad as u16
            || etype == EtherType::Ieee8021QinQ1 as u16
            || etype == EtherType::Ieee8021QinQ2 as u16;
        if v2_vlan {
            etype = v2.ether_type;
            l3_off += VlanHdr::LEN;
        }
    }
    if etype != EtherType::Ipv4 as u16 {
        return Ok(TC_ACT_PIPE);
    }
    let ip: Ipv4Hdr = ctx.load(l3_off).map_err(|_| ())?;
    if ip.proto != IpProto::Udp as u8 {
        return Ok(TC_ACT_PIPE);
    }
    // Non-first fragments carry no UDP header; skip (see try_decode).
    if u16::from_be_bytes(ip.frags) & 0x1fff != 0 {
        return Ok(TC_ACT_PIPE);
    }
    let udp: UdpHdr = ctx.load(l3_off + Ipv4Hdr::LEN).map_err(|_| ())?;

    let mangler_port = (cfg(0) & 0xffff) as u16;
    let wg_port = (cfg(1) & 0xffff) as u16;

    // client: packets to the peer's MG_PORT; server: packets from the local WG port
    let is_client = u16::from_be_bytes(udp.dst) == mangler_port;
    let is_server = u16::from_be_bytes(udp.src) == wg_port;
    if !is_client && !is_server {
        return Ok(TC_ACT_PIPE);
    }

    let payload_off = l3_off + Ipv4Hdr::LEN + UdpHdr::LEN;
    let wire_len = (ctx.len() as usize)
        .checked_sub(payload_off)
        .unwrap_or(0) as u32;
    if wire_len < 4 {
        return Ok(TC_ACT_PIPE);
    }

    let hdr: u32 = ctx.load(payload_off).map_err(|_| ())?;
    let msg_type = (hdr & 0xff) as u8;
    if msg_type != 4 && !(1..=3).contains(&msg_type) {
        return Ok(TC_ACT_PIPE);
    }

    // Snapshot
    // NOTE: aya's load_bytes cannot be used (it clamps to
    // min(skb-remaining, buf.len()), producing a variable length the
    // verifier cannot prove non-zero); call the raw helper with a
    // per-branch constant length. Overly short packets return EFAULT -> PIPE.
    let mut pre = [0u8; SNAP];
    let mut post = [0u8; SNAP];
    let sn: usize = if msg_type == 4 {
        if wire_len < 16 {
            return Ok(TC_ACT_PIPE);
        }
        let ret =
            unsafe { bpf_skb_load_bytes(ctx.skb.skb.cast(), payload_off as u32, pre.as_mut_ptr().cast(), 16) };
        if ret != 0 {
            return Err(());
        }
        16
    } else {
        let s: u32 = match msg_type {
            1 => 148,
            2 => 92,
            _ => 64,
        };
        if wire_len < s {
            return Ok(TC_ACT_PIPE);
        }
        let ret = unsafe {
            bpf_skb_load_bytes(ctx.skb.skb.cast(), payload_off as u32, pre.as_mut_ptr().cast(), s)
        };
        if ret != 0 {
            return Err(());
        }
        s as usize
    };
    post[..sn].copy_from_slice(&pre[..sn]);

    // Random header: bytes0-1 = LE key index, byte2 = key-byte index, byte3 = type ^ key
    let rnd = unsafe { bpf_get_prandom_u32() };
    let kidx = (rnd & 0xffff) as u16;
    let mut kbidx = (rnd >> 16) as u8;
    // Data packets set bit 7 of the key-byte index to mark "no padding"
    // (keepalives are not padded by the kernel path), so the peer's
    // decoder can tell a plain data packet from a padded keepalive.
    if msg_type == 4 {
        kbidx |= KEEPALIVE_PAD_BIT;
    }
    let key = key_at(kidx);
    let key_bits = u64::from_le_bytes(key);
    post[0] = (kidx & 0xff) as u8;
    post[1] = (kidx >> 8) as u8;
    post[2] = kbidx;
    post[3] = msg_type ^ (((key_bits >> (((kbidx as u32) & 7) * 8)) & 0xff) as u8);
    for i in 4..sn {
        // userspace convention: packet[4+j] ^= key[j % 8], i.e. key[(i-4) % 8]
        post[i] ^= ((key_bits >> ((((i - 4) as u32) & 7) * 8)) & 0xff) as u8;
    }

    // Checksum
    let sport = u16::from_be_bytes(udp.src);
    let _dport = u16::from_be_bytes(udp.dst);
    let ulen = u16::from_be_bytes(udp.len);
    let check = u16::from_be_bytes(udp.check);
    let src_addr = ip.src_addr;
    let dst_addr = ip.dst_addr;
    let new_sport = if is_server { mangler_port } else { sport };
    let mut new_check: u16 = check;
    if check != 0 {
        if check == partial_pseudo(src_addr, dst_addr, ulen) {
            // CHECKSUM_PARTIAL: the field is the uncomplemented fold(Σ_pseudo);
            // the device completes the payload part. The pseudo-header
            // (src/dst/proto/ulen) is untouched by the transform, so the
            // field keeps exactly the value the kernel's own send path would
            // write -- body XOR and the port rewrite are accounted for by the
            // device when it completes the checksum over the final bytes.
            new_check = check;
        } else {
            // COMPLETE/NONE: the field is a full checksum -> incremental update
            let mut delta = csum_delta(pre.as_ptr(), sn as u32, post.as_ptr(), sn as u32)?;
            if is_server {
                delta += word_delta(wg_port, mangler_port);
            }
            new_check = csum_add(check, delta);
        }
    }

    // Write back
    let hdr_new = u32::from_le_bytes([post[0], post[1], post[2], post[3]]);
    ctx.store(payload_off, &hdr_new, 0).map_err(|_| ())?;
    for i in 4..sn {
        ctx.store(payload_off + i, &post[i], 0).map_err(|_| ())?;
    }
    if is_server {
        // The UDP header starts with the source port at payload_off - 8; BE.
        ctx.store(payload_off - UdpHdr::LEN, &new_sport.to_be_bytes(), 0)
            .map_err(|_| ())?;
    }
    if check != 0 {
        ctx.store(payload_off - UdpHdr::LEN + 6, &new_check.to_be_bytes(), 0)
            .map_err(|_| ())?;
    }

    Ok(TC_ACT_PIPE)
}

#[cfg(not(test))]
#[no_mangle]
#[link_section = "license"]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
