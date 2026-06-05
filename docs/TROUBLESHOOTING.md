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

## Rollback And Cleanup

Stop the service first:

```bash
sudo systemctl stop aegis@eth0
sudo tc qdisc del dev eth0 clsact 2>/dev/null || true
sudo ip link set eth0 xdp off 2>/dev/null || true
sudo rm -rf /sys/fs/bpf/aegis
```

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
