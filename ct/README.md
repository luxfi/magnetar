# Magnetar --- constant-time analysis track

Magnetar v1.0 routes ALL FIPS 205 SLH-DSA operations through
`cloudflare/circl/sign/slhdsa` v1.6.3. CIRCL's slhdsa package is the
upstream CT-audited reference; its constant-time posture is the
constant-time posture inherited by both Magnetar primitives:

- **Per-validator standalone** (`ref/go/pkg/magnetar/standalone.go`)
  --- `ValidatorSign` is a thin wrapper around
  `slhdsa.SignDeterministic`. No Magnetar-side secret-dependent
  branches. The CT property is the CT property of CIRCL slhdsa
  v1.6.3 verbatim.

- **THBS-SE** (`ref/go/pkg/magnetar/thbsse.go` +
  `thbsse_field.go`) --- the share arithmetic surface (commit-bind,
  Lagrange reconstruct over GF(257), mix-to-seed, dispatch to
  CIRCL slhdsa) is straight-line modular arithmetic with no
  secret-dependent branches:
  - `thbsseModInvSmall` / `thbsseModPowSmall` operate on the PUBLIC
    prime exponent `p-2`, not on a secret exponent.
  - The Lagrange basis lambdas are functions of PUBLIC evaluation
    points only.
  - The per-byte share multiplication is one `uint32` mul + one
    `% 257` per byte position --- no branching on share value.
  - The commit re-derivation in `Combine` and `deriveThbsSeCommit`
    is a cSHAKE256 absorb, which is CT by CIRCL's `golang.org/x/
    crypto/sha3` implementation.

## v1.0 ship status

The v0.x dudect harness has been removed --- it modeled the
abandoned seed-recombine `Combine` and `Verify` API surfaces that
no longer exist in the codebase. The v1.0 THBS-SE construction has
a substantially smaller CT-critical surface (no DKG state, no
intermediate Round1Message struct lifetime, no per-party MAC
ladder), and the CIRCL slhdsa upstream covers the heavy SLH-DSA
work.

## v1.1 plan

The v1.1 dudect harness re-lands once the strict-atom-assembly
construction lands (BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11). At that
point a small Magnetar-internal re-implementation of FIPS 205
sec 5/6/7/8 surfaces enters the trusted computing base, and a
dudect harness over the per-atom WOTS+ chain + FORS sign step
becomes the right CT analytical surface. v1.0's CT story is
"inherit CIRCL"; v1.1's CT story is "inherit CIRCL for FIPS 205 sec
0--4 + dudect for the Magnetar-internal sec 5--8 surface".
