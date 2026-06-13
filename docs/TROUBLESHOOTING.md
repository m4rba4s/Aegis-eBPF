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

Do not recursively remove `/sys/fs/bpf/aegis`. Normal cleanup verifies the
instance ownership marker and removes only known pins for the selected
interface.

## Privileged Lab Refuses Existing bpffs Pins

The release gate intentionally refuses to run if the lab instance directory
already contains pins. Existing pins may belong to a running Aegis instance,
and deleting them blindly can break enforcement or operator observability.

Use a fresh disposable VM for release evidence. If this is a disposable lab and
you intentionally want to reset it, stop Aegis first, detach XDP/TC, inspect the
pins, and then use the bounded orphan cleanup command:

```bash
sudo systemctl stop 'aegis@*' 2>/dev/null || true
sudo tc qdisc del dev aegis-host0 clsact 2>/dev/null || true
sudo ip link set aegis-host0 xdp off 2>/dev/null || true
sudo find /sys/fs/bpf/aegis/aegis-host0/abi-v1 -maxdepth 1 -ls
sudo aegis-cli --iface aegis-host0 cleanup-pins --force-orphaned
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

## Orphaned Pinned Maps

Normal shutdown removes only the current interface instance after verifying its
ownership marker under `/run/aegis/instances`. It never recursively removes the
shared `/sys/fs/bpf/aegis` root.

If `/run` metadata was lost after a reboot, inspect the instance directory
before using the explicit recovery command:

```bash
sudo find /sys/fs/bpf/aegis/eth0/abi-v1 -maxdepth 1 -ls
sudo aegis-cli --iface eth0 cleanup-pins --force-orphaned
```

The force command removes only known Aegis pin names. It refuses cleanup when an
unknown entry remains.

## Applying Policy Changes

Live hot reload is disabled for this release candidate. Validate complete TOML
and YAML files and restart the service:

```bash
sudo systemctl restart aegis@eth0
```
