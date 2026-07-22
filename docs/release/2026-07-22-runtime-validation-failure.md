# v4.3.0-rc.1 Runtime Validation Failure — July 22, 2026

**Status: NOT READY FOR PRODUCTION.** The hardening source and compilation are
correct, but runtime validation of the IPv6 Fragment drop (P0-1) failed: the
loaded program passes fragment packets instead of dropping them. This document
records what was observed so the next session can root-cause it.

This is an honest record, not a success claim. **Do not ship v4.3.0-rc.1 to
production until this is resolved.**

- Date: `2026-07-22`
- HEAD at time of test: `8b31de7` (the hardening commits are present in source)
- Test host: the production machine itself, live WiFi `wlp0s20f3` + isolated
  veth pair (`aegis-veth0`/`aegis-veth1`).
- Loaded XDP tag observed: `7e824a2ae6f63177`

## What was attempted

1. Built both BPF programs clean (`cargo run -p xtask -- build-all`) — pass.
2. Rebuilt `aegis-cli` so its embedded object matches the fresh build —
   verified the embedded XDP ELF md5 equals the target object md5
   (`fc5e6dcaf650db8183e84fc2ca32d814`, 25448 bytes).
3. Loaded the hardened build on `wlp0s20f3` (production WiFi) and on an
   isolated veth pair. Both attached successfully; network stayed up.
4. Injected 10 IPv6/Fragment-Header/TCP packets (`nh=6, offset=0, m=0`, the
   exact P0-1 bypass shape) from `aegis-veth1` so they hit XDP ingress on
   `aegis-veth0`.
5. Read the per-CPU `STATS` map before/after injection.

## Observed result (the failure)

```
pkts_seen: +10
pkts_pass: +10
pkts_drop:  +0   ← expected +10
```

All 10 fragment packets were **PASSED**, not dropped. The P0-1 fix did not
take effect at runtime.

A plain IPv6/TCP packet (no fragment header) over the same path was also
passed — consistent with the IPv6 default policy being PASS (unlike IPv4,
which defaults to DROP). That part is by design.

## What was verified as correct

| Check | Result |
|---|---|
| Source contains the fragment-drop branch (`THREAT_IPV6_FRAGMENT`) | ✅ |
| Target ELF `.text(xdp)` contains `if r1 == 0x2c goto` (fragment cmp) | ✅ |
| Target ELF contains RH0 detection (`*(r1+2) == 0x0`) | ✅ |
| `embedded_xdp` cfg is set; embedded object md5 == target md5 | ✅ |
| Loaded program contains the `0x2c` fragment comparison | ✅ |
| Loaded program contains a `0x16` (THREAT_IPV6_FRAGMENT=22) immediate load | ❌ **0 occurrences** |
| Runtime: fragment packets are dropped | ❌ **PASS observed** |

The loaded program contains the fragment *comparison* but does **not** contain
the threat-type-22 load that the drop/log path requires. Its observable
behavior matches the **old** code (`return Ok(XDP_PASS)` in the fragment arm).

## Working hypothesis (NOT yet proven)

The source and the compiled target object are correct. The embedded object in
`aegis-cli` matches the target. Yet the loaded program's bytecode does not
match the target's bytecode. The most likely explanations, in order:

1. **Aya loader / BPF object caching.** `aegis-cli` loads via Aya; a stale
   object may be served from an Aya-side cache or a pinned-map/program path
   that survived the detach. The `cleanup-pins --force-orphaned` was run once
   but the symptom persisted across multiple reloads.
2. **Embedding path indirection.** `include_bytes!(env!("AEGIS_XDP_OBJ"))`
   resolves at rustc time; if `build.rs`'s `rerun-if-changed` did not fire on
   the object's *content* (only mtime), an older embedded copy could survive a
   rebuild. The md5 check contradicts this, but the contradiction is itself a
   clue that something is being substituted at load time.
3. **The branch is dead-code-eliminated or reordered by the eBPF linker**
   such that the fragment cmp exists but jumps to the generic PASS tail. The
   disassembly (fragment cmp present, threat-22 load absent) is consistent
   with this, but a full control-flow trace was not completed.

None of these is confirmed.

## Impact on the release

- The **six hardening commits** (`3fecb4e`..`8b31de7`) are correct at the
  source level and were verified by the static gate (build, clippy, fmt,
  tests, ABI canary, ELF section validation). They remain on the branch.
- **They are NOT pushed** and the release is NOT tagged. The prior push
  (`200de44..8b31de7`) is on `origin/codex/v4.3.0-rc.1-release-hardening` —
  see the note below.
- The previous push to GitHub already includes these commits. Operators who
  pull this branch should treat P0-1/P0-2 as **unverified at runtime** until
  this is resolved.

## Production system state (post-test)

- The host's WiFi (`wlp0s20f3`) has Aegis attached (XDP + TC), and the network
  is healthy (0% packet loss). The loaded program's exact provenance could not
  be confirmed, so it should be treated as "unknown hardening state".
- A backup of the pre-hardening objects exists at
  `/usr/local/share/aegis/aegis.o.pre-hardening-20260722-010415` and
  `…/aegis-tc.o.pre-hardening-20260722-010415` if a known-good rollback is
  needed.
- The isolated veth test pair was removed; no lingering test interfaces.

## Next-session entry points

1. Resolve the loaded-vs-target bytecode mismatch. Suggested approach: write a
   minimal Aya-independent loader (libbpf C, or `bpftrace`/`bpftool prog load`
   with the legacy-maps quirk worked around) to load the target object
   directly and re-run the fragment verdict. This isolates whether the fault
   is in Aya's load path or in the object itself.
2. Once loading is isolated, re-run the three scapy regression scripts
  (`test/ipv6_fragment_bypass.py`, `test/ipv6_rh0_bypass.py`,
  `test/ipv4_spoof_cgnat.py`) against the directly-loaded object and confirm
  DROP + the correct `threat_type` in the event stream.
3. Only after runtime DROP is confirmed: re-push, tag the release, and update
   `docs/release/2026-07-21-v4.3.0-rc.1-hardening.md` to replace "Not proven
   in this session" with the actual runtime evidence.

## Note on the earlier push

The branch `codex/v4.3.0-rc.1-release-hardening` was pushed to
`github.com/m4rba4s/Aegis-eBPF` **before** this runtime failure was
discovered. The pushed commits are source-correct but runtime-unverified. Do
not cut a release tag from them until the runtime DROP is confirmed. If a tag
must be issued defensively, document this limitation in the release notes.
