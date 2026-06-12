# Enterprise QA Report v4.2.0 - Retracted

**Original commit:** `a0c71254de318c60b92e0e66f6c05b193def592a`

**Current status:** `INSUFFICIENT_EVIDENCE`

**Enterprise approval:** retracted

The original report claimed `FULL PASS` without linking the raw logs, command
transcripts, memory time series, packet artifacts, or CI run used to reach that
verdict. The referenced archive SHA-256 is not accompanied by an archive path
or release asset in this repository, so the archive cannot be independently
retrieved or verified.

## Invalidated Claims

| original claim | evidence problem | current classification |
|---|---|---|
| 50 stress iterations passed | release validation records 25 iterations; raw replay archive is unavailable here | historical_unverified |
| RSS remained near 81 MB for 25+ minutes | no timestamped RSS samples or collection command are linked | insufficient_evidence |
| verifier and memory limits passed | source inspection and bounded maps do not prove verifier load/attach | insufficient_evidence |
| systemd recovered after `kill -9` | no unit status, journal excerpt, PID, interface state, or cleanup artifact is linked | insufficient_evidence |
| reproducible build passed | no two-build hash comparison or isolated build manifests are linked | insufficient_evidence |
| approved for enterprise deployment | an auditor name or AI persona is not release authority | retracted |

## Release Impact

- Do not cite this document as proof of production or enterprise readiness.
- Treat the v4.2.0 runtime and stress claims as historical and unverified until
  the original raw archive is recovered and matched to commit `8b2184d`, or the
  gates are rerun on the exact target commit.
- Current release status remains governed by
  [RELEASE_VALIDATION.md](RELEASE_VALIDATION.md) and
  [RELEASE_EVIDENCE_INDEX.md](RELEASE_EVIDENCE_INDEX.md).

The June 12, 2026 workstation freeze investigation is documented separately in
[2026-06-12-host-freeze-postmortem.md](release/2026-06-12-host-freeze-postmortem.md).
It confirms host resource exhaustion but does not establish that Aegis caused
the exhaustion.
