# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Active |
| < 1.0   | ❌ No     |

## Reporting a Vulnerability

If you discover a security vulnerability in Aegis, please report it responsibly:

1. **Do NOT open a public issue**
2. Email: create a private security advisory via [GitHub Security Advisories](https://github.com/m4rba4s/Aegis-Portable-Demo/security/advisories/new)
3. Include: description, reproduction steps, impact assessment
4. Expected response: within 72 hours

## Security Model

Aegis operates with elevated privileges (root/CAP_BPF+CAP_NET_ADMIN) to load eBPF programs. The security design follows:

- **Least privilege**: systemd service restricts capabilities to CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_BPF, CAP_PERFMON
- **Fail-closed**: uninspectable packets (IPv6 extension headers) are dropped, not passed
- **Input validation**: interface names, feed URLs, and download sizes are validated
- **Memory safety**: userspace is 100% Rust, eBPF uses aya-rs with verifier enforcement
- **No secrets in binary**: eBPF bytecode is embedded but contains no credentials

## Hardening Checklist

When deploying Aegis in production:

- [ ] Run via systemd with the provided hardened service file
- [ ] Restrict filesystem access to `/var/log/aegis` and `/sys/fs/bpf`
- [ ] Monitor auto-ban logs for false positives
- [ ] Keep kernel updated (≥ 5.8 recommended for CAP_BPF)
- [ ] Review threat feed sources before enabling
