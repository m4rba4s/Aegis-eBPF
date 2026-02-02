# NEXT SESSION: Heavy Math Verification + BUG FIX

## BUG: TUI Stats/Sparkline disappears over time
- Graphs disappear after running for a while
- Need to check: overflow? memory? render area?
- Debug info in title: n=, sum=, max=

## Priority Tasks:
1. **TLA+** - temporal logic for connection state machine (conntrack)
2. **Coq/Lean** - formal proofs for packet parsing correctness
3. **CBMC** - bounded model checking for eBPF bytecode
4. **Abstract interpretation** - data flow analysis

## Why:
- Critical infrastructure = lives at stake
- Mathematical guarantees > "works on my machine"
- Amazon uses TLA+ for AWS - we should too

## Current state:
- Kani proofs: DONE
- Proptest: DONE (14 tests)
- Fuzz targets: DONE (3 targets)
- CI integration: DONE

## Demo repo: github.com/m4rba4s/Aegis-Portable-Demo
