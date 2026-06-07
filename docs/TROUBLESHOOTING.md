# Troubleshooting

## Installer Fails Before Build

Run:

```bash
sudo ./install.sh --check
```

Required runtime tools are `ip`, `tc`, `mount`, and `uname`. On systemd hosts,
`systemctl` is also required. `bpftool` is strongly recommended for verifier
diagnostics and release validation.

## bpffs Is Missing

Aegis expects bpffs at `/sys/fs/bpf`.

```bash
sudo mount -t bpf bpf /sys/fs/bpf
findmnt /sys/fs/bpf
```

If the mount fails, check kernel BPF support and container restrictions.

## TC Egress Fails

TC is required by default. A startup error that mentions TC means egress
protection did not attach.

Inspect:

```bash
sudo tc qdisc show dev eth0
sudo tc filter show dev eth0 egress
journalctl -u aegis@eth0 --no-pager -n 100
```

Use `--no-tc` only as an explicit ingress-only waiver:

```bash
sudo aegis-cli --iface eth0 --no-tc daemon
```

## XDP Driver Mode Fails

Aegis attempts driver mode first and falls back to SKB/generic mode when
available. Archive both errors when driver and SKB attach fail.

```bash
sudo ip -details link show dev eth0
journalctl -u aegis@eth0 --no-pager -n 100
```

## Emergency Detach (Daemon Crash)

If the userspace daemon is OOM-killed or receives `SIGKILL` (`kill -9`), the eBPF programs (XDP and TC) may remain attached to the interface. This provides fail-closed resilience but requires manual intervention to restore unrestricted connectivity.

To forcibly detach all Aegis programs from an interface (e.g. `eth0`) without the daemon:

```bash
sudo ip link set dev eth0 xdp off
sudo tc qdisc del dev eth0 clsact
```

## Rollback And Cleanup

Stop the service first:

```bash
sudo systemctl stop aegis@eth0
sudo tc qdisc del dev eth0 clsact 2>/dev/null || true
sudo ip link set eth0 xdp off 2>/dev/null || true
```

Inspect pinned Aegis maps before deleting anything:

```bash
sudo find /sys/fs/bpf/aegis -mindepth 1 -maxdepth 1 -print 2>/dev/null || true
```

Only remove `/sys/fs/bpf/aegis` after the Aegis service is stopped and you have
confirmed these pins do not belong to an active production instance. In a
disposable release lab, stale pins are a reason to recreate or clean the lab
before running `privileged-lab`.

## Privileged Lab Refuses Existing bpffs Pins

The release gate intentionally refuses to run if `/sys/fs/bpf/aegis` already
contains pins such as `CONFIG`, `EVENTS`, or `STATS`. Existing pins may belong
to a running Aegis instance, and deleting them blindly can break enforcement or
operator observability.

Use a fresh disposable VM for release evidence. If this is a disposable lab and
you intentionally want to reset it, stop Aegis first, detach XDP/TC, inspect the
pins, and only then remove the stale lab pin directory:

```bash
sudo systemctl stop 'aegis@*' 2>/dev/null || true
sudo tc qdisc del dev aegis-host0 clsact 2>/dev/null || true
sudo ip link set aegis-host0 xdp off 2>/dev/null || true
sudo find /sys/fs/bpf/aegis -mindepth 1 -maxdepth 1 -print 2>/dev/null || true
for pin in \
  BLOCKLIST ALLOWLIST STATS CONFIG BLOCKLIST_IPV6 ALLOWLIST_IPV6 \
  CIDR_BLOCKLIST CIDR_BLOCKLIST_IPV6 DPI_EVENTS EGRESS_BLOCKLIST \
  EGRESS_BLOCKLIST_IPV6 EGRESS_CIDR_BLOCKLIST EGRESS_CIDR_BLOCKLIST_IPV6 \
  EVENTS EVENTS_IPV6 GLOBAL_SYN_CTR PORT_SCAN RATE_LIMIT CONN_TRACK \
  CONN_TRACK_IPV6; do
  sudo rm -f "/sys/fs/bpf/aegis/$pin"
done
sudo rmdir /sys/fs/bpf/aegis 2>/dev/null || true
```

Do not use the lab cleanup command on a shared host unless you own the running
Aegis instance and have accepted the enforcement interruption.

Full uninstall:

```bash
sudo ./install.sh --uninstall
```

## Packet Replay Fails

List required cases:

```bash
python3 scripts/packet-replay-lab.py --list-cases
```

Inspect artifacts:

```bash
find /tmp/aegis-replay -maxdepth 2 -type f -print \
  -exec sh -c 'echo "--- $1"; head -100 "$1"' sh {} \;
```

Every case must have a `.log` with `pass: true`. A pcap-only artifact is not
release evidence.
