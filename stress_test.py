#!/usr/bin/env python3
"""Retired legacy load generator.

The old implementation opened sockets from 100 tight-loop threads and had no
resource guardrails. Keep this path as an explicit refusal so old instructions
cannot accidentally start it.
"""

import sys


def main() -> int:
    print(
        "stress_test.py is retired. Use the isolated bounded stress-lab gate "
        "documented in docs/RELEASE_VALIDATION.md.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
