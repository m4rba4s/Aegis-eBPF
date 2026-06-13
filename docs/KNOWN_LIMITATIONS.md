# Known Limitations

These limitations apply until exact-commit evidence proves otherwise.

## Release Status

- The current release-hardening work is not production or enterprise certified.
- Privileged XDP/TC load, attach, replay, cleanup, stress, and portability
  evidence must be rerun after the final commit.
- Static x86_64-musl linking does not imply universal Linux runtime support.

## Policy Lifecycle

- Live policy hot reload is disabled. Applying policy requires validation of
  complete files followed by controlled service restart.
- Aegis does not claim zero-downtime or atomic policy replacement.

## Pinned Maps

- Pins are scoped by interface identity and map ABI version.
- Ownership metadata is stored under `/run/aegis/instances`, because bpffs
  cannot store a regular JSON marker.
- systemd preserves each interface-scoped marker across automatic service
  restarts, while normal stop removes that instance's runtime directory.
- Normal cleanup refuses missing or mismatched ownership metadata and removes
  only known Aegis pin names.
- After a reboot or other loss of `/run` metadata, an operator may inspect the
  instance directory and explicitly remove known orphaned Aegis pins:

  ```bash
  sudo aegis-cli --iface eth0 cleanup-pins --force-orphaned
  ```

  The command refuses recursive deletion and fails if an unknown entry remains.

## Datapath Scope

- VLAN and QinQ frames are currently documented as fail-closed, not parsed.
- IPv6 exact and CIDR filtering are implemented, but complete extension-header
  portability coverage is not claimed.
- Stateful connection tracking remains experimental.

## Portability

- Fedora, Ubuntu, Debian, Arch, Alpine, RHEL-compatible systems, physical NICs,
  and Kubernetes require current-commit runtime evidence before being marked
  supported.
- aarch64 is unsupported until native build, verifier, attach, replay, cleanup,
  and install evidence is archived.
