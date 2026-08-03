# Red-Team Bypass Audit — v4.3.0-rc.1

Date: 2026-07-21
Owner-authorized: defensive review of the Aegis eBPF firewall by its author.
Branch at time of audit: `codex/v4.3.0-rc.1-release-hardening`
Last commit covered: `6602061` (this audit's P2 doc-comment fixes)

## Scope

Read-only red-team pass for eBPF firewall bypass. Three classic eBPF-firewall
bypass classes were checked against the live datapath:

1. IPv4 ingress parse path (tiny fragments, total_len trust, degenerate packets,
   wildcard blocklist escape, allowlist spoofing).
2. Connection-tracking state machine (state injection, UDP pseudo-flows,
   sequence validation, map exhaustion, XDP/TC asymmetry).
3. IPv6 extension header parsing (fragment header, RH0, AH length, HBH
   ordering, loop bounds, 1500-byte cap semantics).

Three first-party agents ran these checks in parallel; their evidence was
cross-checked by reading the cited lines in the repo. This document is the
merged, de-duplicated plan for the next session.

## Bottom line

The IPv4 ingress path is well-defended. Three concrete bypasses exist, two of
them on the IPv6 path, plus one latent hazard in conntrack. Nothing here is
exploitable through IPv4 today. The IPv6 path and the conntrack
feature-as-advertised need work.

## Confirmed bypasses (P0/P1)

### P0-1 — IPv6 Fragment Header unconditionally bypasses every L4 rule

Evidence:
- `aegis-ebpf/src/main.rs:772-776` — `NEXTHADR_FRAGMENT => return Ok(XDP_PASS)`
- `aegis-tc/src/main.rs:167-171` — `NEXTHADR_FRAGMENT => return Ok(TC_ACT_OK)`

Effect: any attacker who prepends a Fragment Header (frag_off=0, M=0) to an
otherwise-malicious IPv6 TCP/UDP packet bypasses the IPv6 exact blocklist
(`main.rs:845`), wildcard blocklist (`main.rs:871`), TC egress blocklists,
and port-scan detection. This is the **opposite** of the IPv4 path, which is
fail-closed (`aegis-ebpf/src/main.rs:449-452`).

Planned fix (next session):
- Replace unconditional PASS with fail-closed DROP for non-first fragments
  (offset > 0 OR M=1). Use the existing, currently-unused `Ipv6FragHdr`
  struct (`aegis-ebpf/src/headers.rs:88-115`, which already exposes
  `offset()` and `more_fragments()` accessors).
- Decision required for first fragments (offset=0, M=1): drop fail-closed
  (mirrors IPv4) or parse and apply L4 rules. Author to decide policy.
- Apply the same change in `aegis-tc/src/main.rs`.

Verification: build eBPF+TC via `cargo run -p xtask -- build-all`, load on a
test interface, send crafted IPv6 fragment packets (scapy), confirm DROP and
the THREAT_IPV6_* log line.

### P0-2 — RH0 (Routing Header Type 0) not detected

Evidence:
- `aegis-ebpf/src/main.rs:787-796` — Routing handled generically via
  `Ipv6ExtHdr`; `routing_type` is never read.
- `aegis-tc/src/main.rs:181-189` — same generic handling on egress.
- `aegis-ebpf/src/headers.rs:117-126` — `Ipv6RoutingHdr` (with `routing_type`
  and `segments_left`) is defined but unused.

Effect: RFC 5095 (Dec 2007) mandates that compliant nodes MUST silently
discard RH0; Aegis does not. RH0 is a known amplification vector. Packets
with `routing_type == 0` traverse the parser and reach L4 processing.

Planned fix (next session):
- In the `NEXTHDR_ROUTING` arm, after reading `Ipv6ExtHdr`, also read the
  third byte (`routing_type`) via `ptr_at::<Ipv6RoutingHdr>` and DROP if
  `routing_type == 0`.
- Keep RH2 (Mobile IPv6) and SRH paths passing through unchanged.
- Mirror in `aegis-tc/src/main.rs`.

Verification: send `IPv6/Q{RoutingHdr(type=0, segs=...)}/TCP` via scapy,
confirm DROP and a new `THREAT_IPV6_RH0` log line (constant to be added to
`aegis-common/src/lib.rs`).

### P1-1 — Allowlist + static RFC1918 whitelist with no anti-spoofing

Evidence:
- `aegis-ebpf/src/main.rs:364-381` — `ALLOWLIST.get(src_addr)` → XDP_PASS
  before any deny check.
- `aegis-ebpf/src/main.rs:357-361, 384-401` — static RFC1918 / CGNAT (100.64/10)
  / loopback whitelist → XDP_PASS before any deny check.
- No uRPF / reverse-path check anywhere in `aegis-ebpf/src/main.rs` (confirmed
  by full-file read).

Effect: an attacker who can spoof a source IP in an allowlist entry or in
100.64/10 / 10/8 / 172.16/12 / 192.168/16 / 127/8 bypasses every deny rule.
The 100.64/10 inclusion is particularly risky on internet-facing interfaces;
CGNAT space is not "internal" in the trust sense.

Planned fix (next session):
- Either (a) gate the static RFC1918 whitelist behind a per-interface config
  flag defaulting to off on internet-facing NICs, or (b) remove 100.64/10
  and 127/8 from the hard-coded whitelist (loopback never needs to traverse
  XDP; CGNAT is not a trust boundary).
- Document a deployment requirement: strict `rp_filter=1` on protected
  interfaces, enforced by install.sh preflight if possible.
- Author to choose (a) vs (b). This is a policy call, not a code call.

Verification: send a packet with spoofed `100.64.x.x` source from the
internet side, confirm DROP after the fix.

## Latent hazard (P2-ish, but do NOT enable without reading this)

### Conntrack is a telemetry sink, not a security control

Evidence:
- `aegis-ebpf/src/main.rs` declares no CONN_TRACK map; XDP is stateless
  (asserted at `main.rs:506` and `main.rs:896`).
- `aegis-tc/src/main.rs:77,81` declares `CONN_TRACK` / `CONN_TRACK_IPV6` as
  `LruHashMap` with `MAP_CAP_CONNTRACK = 65536`.
- TC insert sites: `aegis-tc/src/main.rs:235, 260, 524, 547, 571`.
- **`CONN_ESTABLISHED` (value 3) is never written by any code path.** The
  handshake state machine in `aegis-common/src/lib.rs:140-145` is aspirational.
- The single read site (`aegis-tc/src/main.rs:541`) does a 5-tuple lookup
  but no decision depends on it.
- `CFG_CONN_TRACK` (`aegis-common/src/lib.rs:265`) is written by userspace
  (`map_manager.rs:466-470`) but never read by either BPF program — the
  conn_track config flag is a no-op.
- `conntrack_hits` counter is always 0 (no BPF program ever increments it);
  it is shown in the TUI and exported as `aegis_conntrack_hits_total`.

Hazard: if a future maintainer reads the (now-corrected) comment near
`main.rs:403` or the aspirational state constants and implements a real
established-flow fast-path, every classic conntrack weakness becomes live:
- single-packet state injection at `CONN_SYN_SENT`
- UDP "pseudo-flows" created with no handshake
- 5-tuple-only key with no seq/ack validation (`ConnTrackState` has no
  seq/window fields — `aegis-common/src/lib.rs:130-137`)
- LRU eviction under map exhaustion (DoS via ~65k unique outbound 5-tuples;
  DNS resolver querying attacker-controlled subdomains is sufficient)

Recommended next-session questions (NOT a fix yet):
- Is conntrack intended to become a security control, or stay telemetry?
  If telemetry: remove the misleading `conntrack_hits` counter and the dead
  `CFG_CONN_TRACK` write, and add a TUI note "conntrack = telemetry only".
  If security control: scope a full design (seq validation, handshake
  tracking, asymmetric-routing story, map-pressure accounting) before any
  datapath change. Do NOT wire up a fast-path incrementally.

## Additional non-bypass findings (for completeness)

- `aegis-tc/src/main.rs:124-128` — TC is fail-open (`Err(_) => TC_ACT_OK`),
  asymmetric with XDP which is fail-closed (`Err(_) => XDP_ABORTED`, treated
  as drop at `main.rs:282`). Worth a deliberate decision: should TC also be
  fail-closed? Egress fail-open is more conventional but should be explicit.
- `aegis-ebpf/src/main.rs:782,792` and TC mirror — the 1500-byte cap on
  `l4_offset` is an absolute offset from the L2 frame, not relative to
  `payload_len`. An attacker can declare a tiny `payload_len` while embedding
  a fake extension chain that pushes `l4_offset` to 1499; the kernel will
  compute a different L4 offset from `payload_len`, creating a semantics gap.
  Medium severity; fix by bounding `l4_offset` against `ip_offset + payload_len`.
- Jumbo frames (up to 9000 bytes) and TSO/GSO egress packets will be
  spuriously dropped by the 1500-byte cap on jumbo-enabled NICs.
- HBH-not-first (RFC 8200 §4.1) is not enforced; HBH appearing later than
  immediately after the fixed header is parsed identically to the canonical
  order, diverging from the kernel's strict parser.

## What was verified as SOLID (no action needed)

These were checked and are correct — listed so the next session does not
re-investigate them:

- IPv4 tiny/overlapping fragments — `0x3FFF` mask at `main.rs:450` catches
  both MF=1 first fragments and all offset>0 fragments. No bypass.
- IPv4 `total_len` trust — `total_len` is informational + a lower-bound drop
  only; L4 parsing always uses `ptr_at` with real packet bounds. No bypass.
- IPv6 AH length — `(ext_len + 2) * 4` matches RFC 4302. Correct.
- IPv6 generic ext-header length — `(ext_len + 1) * 8` matches RFC 8200.
- Wildcard blocklist — `{src_ip, 0, 0}` key is synthesized firewall-side;
  attacker cannot influence the lookup key. No bypass.
- Truncated IPv4 packets — `ptr_at` Err → `XDP_ABORTED` → counted as drop.
- Extension header loop cap of 4 — fail-closed; chains > 4 drop with
  `THREAT_IPV6_EXT_CHAIN`. (Side effect: ESP traffic is dropped because
  NEXTHDR_ESP is not in any match arm — add ESP to the match if IPsec
  matters in deployment.)

## Recommended order for the next session

1. Start here: read this document and the cited file:line evidence.
2. Re-run the evidence checks yourself (don't trust this doc blindly) —
   the cited lines may have shifted if other work landed first.
3. Fix P0-1 (IPv6 Fragment PASS) first. Smallest, clearest win. Build the
   eBPF program in a known-good environment (see "Environment note" below).
4. Fix P0-2 (RH0). Same area of the code.
5. Decide P1-1 policy (allowlist + RFC1918). This is a deployment-policy call.
6. Address the conntrack question deliberately, not as a side task.
7. For each P0/P1 fix: add a regression test alongside (scapy script under
   `test/`, or extend the verification harness). The ABI contract canary at
   `aegis-cli/tests/test_abi_contract.rs` is the model.

## Environment note (important)

The eBPF/TC build (`cargo run -p xtask -- build-all`) currently fails in this
environment with `LLVM issued diagnostic with error severity: stack arguments
are not supported / aggregate returns are not supported`. This failure
reproduces on the clean commit before this audit's edits, so it is a
toolchain/environment issue (likely an LLVM/bpf target mismatch in the
pinned nightly or in the bundled bpf-linker), NOT a code regression from the
audit. The workspace build, clippy, and rustfmt all pass clean.

Before any P0/P1 datapath fix can be validated, the eBPF build environment
must be repaired. Start with: `rustup show`, check `rust-toolchain.toml`
(pinned to `nightly-2026-02-12`), and confirm bpf-linker matches. The host
LLVM may need to be the version expected by the pinned rustc.

## Commits in this audit session

- `5f0fe92` — `test(cli): add eBPF<->userspace ABI contract canary`
- `6ab00c5` — `docs(event-loop): fix stale BLOCKLIST capacity comment`
- `6602061` — `docs(ebpf): correct misleading comments flagged by red-team audit`

None of these change runtime behavior. The ABI canary is the only one that
adds executable code, and it is a pure read-only test.
