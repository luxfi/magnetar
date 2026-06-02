# Magnetar v1.1 dudect track --- strict-atom Combine path

The v1.1 dudect track measures the constant-time discipline of the
Magnetar strict-atom Combine path
(`ref/go/pkg/magnetar/thbsse_assemble.go` +
`ref/go/pkg/magnetar/slhdsa_internal.go`).

## What this directory contains

| File | Role |
|---|---|
| `strict_atom_combine_ct.go` | Go-side CT static-analysis harness: pattern-checks the strict-atom Go source for secret-dependent branches and secret-dependent memory accesses. Run via `go test -tags ct`. |
| `combine_ct` | Legacy v1.0 dudect binary (kept for archival reference; the v1.0 dudect harness modelled the abandoned seed-recombine `Combine` path). |
| `dudect_strict_atom_overview.md` | Methodology + threat model for the strict-atom CT track. |

## v1.0 -> v1.1 delta

The v1.0 dudect harness measured `circl/sign/slhdsa.SignDeterministic`
indirectly via the seed-reconstruction Combine path. v1.1 measures the
Magnetar-internal FIPS 205 sec 5/6/7/8 walk DIRECTLY, since the
strict-atom path is the FIPS 205 byte emitter at v1.1 (the call to
circl is bypassed).

## Per-push gate

`scripts/checks/dudect-smoke.sh` runs the Go-side pattern check
(`TestStrictAtom_CT_NoSecretDependentBranch`). This is fast (<5s) and
catches the obvious classes of CT violation:

  - Secret-tagged byte fed into a control-flow branch.
  - Secret-tagged byte used as an array/slice index.
  - Secret-tagged byte fed into a map lookup.

The Go static checker is necessary but not sufficient; the full
dudect statistical test on a compiled C harness (or Go-via-cgo
harness) is a release-time gate.

## Methodology summary

The strict-atom Combine path's CT obligation is BGL leakage-free under
the model:

  - The Lagrange basis depends only on PUBLIC evaluation points.
  - The per-byte Lagrange sum is straight-line modular arithmetic.
  - The SHAKE-256 expansion is constant-time per FIPS 202.
  - The PRF / PRF_msg absorb buffers are constructed by positional
    append; no branch on secret bytes.
  - The Magnetar-internal FIPS 205 walk branches only on PUBLIC values
    (FORS index bits derived from message digest; WOTS+ chain step
    counts; XMSS layer index).

The Go-side harness asserts items 4 + 5 by static AST inspection of
`thbsse_assemble.go` + `slhdsa_internal.go`. The C-side harness (release
gate, not run per-push) asserts items 1 + 2 + 3 by timing distinguishing
attack: fix the public projection of two distinct secret seeds, drive
Combine end-to-end on both, and assert the two execution traces are
indistinguishable above a configurable t-statistic threshold.
