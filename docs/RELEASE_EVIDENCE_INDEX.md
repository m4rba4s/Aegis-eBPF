# Release Evidence Index

Evidence is valid only when the raw artifact is retrievable and tied to the
exact commit under assessment. Build success is not runtime enforcement proof.

The release-hardening changes after commit
`e6728391d964e3766d303814089fa86f48e6122a` require a new clean commit and a new
validation set. Earlier local output and historical v4.2.0 claims do not qualify.

| claim | commit | environment | command | artifact | result |
|---|---|---|---|---|---|
| non-privileged release gate | `<release-sha>` | GitHub-hosted Ubuntu and maintainer workstation | `CARGO_HOME=/tmp/aegis-cargo-home ./scripts/release-gates.sh nonpriv` | complete CI log and run URL | requires_rerun |
| formal verification | `<release-sha>` | GitHub-hosted Ubuntu | Kani and TLA jobs from `.github/workflows/ci.yml` | complete CI log and run URL | requires_rerun |
| static x86_64-musl artifact | `<release-sha>` | GitHub-hosted Ubuntu | `portable-static-build` CI job | commit-bound workflow artifact | requires_rerun |
| XDP verifier/load/attach | `<release-sha>` | disposable privileged lab | `./scripts/release-gates.sh privileged-lab` | daemon, attach-state, object hash, and cleanup logs | not_run |
| TC verifier/load/attach | `<release-sha>` | disposable privileged lab | `./scripts/release-gates.sh privileged-lab` | daemon, attach-state, object hash, and cleanup logs | not_run |
| IPv4/IPv6 packet enforcement | `<release-sha>` | disposable privileged lab | packet replay matrix | per-case log, input PCAP, capture PCAP, raw transcript | not_run |
| bounded stress replay | `<release-sha>` | disposable privileged lab | `AEGIS_STRESS_ITERATIONS=25 ./scripts/release-gates.sh stress-lab` | commit-bound `stress-summary.log` and per-case artifacts | not_run |
| install/uninstall/rollback | `<release-sha>` | clean target VM | immutable release bundle install and uninstall | command transcript and before/after state | not_run |
| distribution portability | `<release-sha>` | Fedora, Ubuntu, Debian targets | distro-specific install/load/replay/cleanup | target-specific evidence archive | not_run |
| release bundle checksums/SBOM/provenance | `<release-sha>` | tag workflow | `.github/workflows/release.yml` | `SHA256SUMS`, workspace `*.cdx.json` files, manifest, GitHub attestations | requires_tag_workflow |

## Historical Evidence

| claim | commit | result | reason |
|---|---|---|---|
| v4.2.0 privileged replay | claimed for `0dadb3efb737f7a857548383c4d4eeab859dd732` | historical_unverified | raw archive is not retrievable |
| v4.2.0 stress replay | claimed for `0dadb3efb737f7a857548383c4d4eeab859dd732` | historical_unverified | raw archive is not retrievable |
| June 12 workstation freeze | local incident | host resource exhaustion verified | does not prove Aegis runtime behavior or leak freedom |

Do not authorize production, enterprise, portability, stress-tested, or
leak-free claims until every applicable current-commit row links to its raw
artifact.
