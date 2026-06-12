# Host Freeze Postmortem - June 12, 2026

## Status

- Incident: workstation became effectively unresponsive and required a hard
  reset.
- Verified cause class: severe host memory and swap pressure.
- Aegis causation: not established.
- Release evidence from the interrupted run: invalid.

## Observed Evidence

The affected boot ended abruptly at approximately 07:30 EDT on June 12, 2026.
No kernel panic, kernel OOM kill, eBPF verifier failure, hard lockup, or Aegis
release-gate command was recorded in the host journal immediately before the
reset.

Host monitoring did record:

- at 07:20, memory use was 91.72%,
- `MemAvailable` was approximately 2.55 GiB,
- the 8 GiB zram swap device was effectively full,
- committed memory was 152.28% of RAM plus swap,
- page reclaim and swap activity were active,
- PCP reported severe demand for real memory at 07:27:43,
- KWin reported its main thread hanging at 07:29:59 and 07:30:08,
- libvirt lost the VM keepalive connection at 07:30:25,
- thermal throttling alerts had occurred repeatedly during the preceding hour.

The PCP process archive showed a `qemu-system-x86_64` process reaching
approximately 11.4 GiB RSS. Multiple Firefox processes collectively consumed
several additional GiB, with the largest individual process reaching about
1.48 GiB RSS. The IDE and background package activity added further pressure.

## Conclusion

The strongest supported explanation is host resource overcommit: a large VM,
browser processes, IDE processes, and background activity exhausted available
RAM and zram swap until the desktop and VM stopped responding.

The evidence does not prove that the bounded Aegis packet replay caused the
pressure. The release command may have been running inside the VM and therefore
would not appear as a host process, but the host-side failure mode was memory
exhaustion rather than an observed eBPF or kernel crash.

## Corrective Controls

1. Run privileged and stress gates only in a disposable VM.
2. Preserve at least 8 GiB host `MemAvailable` before starting.
3. Keep host swap use below 50% before starting.
4. Avoid package updates, large builds, browser-heavy sessions, and concurrent
   VMs during the run.
5. Use the gate resource preflight and whole-replay watchdog.
6. Treat any run requiring a hard reset as failed and archive no PASS claim.
7. Preserve `resource-preflight.log`, replay logs, cleanup state, host memory
   telemetry, and the exact commit for the next run.

## Proof Boundary

This postmortem verifies the host resource-exhaustion condition. It does not
verify packet enforcement, daemon leak freedom, verifier acceptance,
load/attach behavior, systemd recovery, or release readiness.
