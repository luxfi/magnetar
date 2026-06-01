# Magnetar --- machine-checked proof track

Magnetar v1.0 ships two primitives:

- **Per-validator standalone** --- routes through
  `cloudflare/circl/sign/slhdsa` v1.6.3 in production. The
  single-party FIPS 205 functional + constant-time analysis tracks
  the formosa-crypto `libjade-SLH-DSA` upstream when it lands. Until
  then, the trust model relies on CIRCL's upstream review and the
  NIST FIPS 205 reference.

- **THBS-SE (Threshold Hash-Based Signatures with Selected-Element
  Reconstruction)** --- permissionless t-of-n threshold signing that
  produces a byte-identical FIPS 205-shaped signature. See
  `ref/go/pkg/magnetar/thbsse.go` for the construction, and
  `THBS-SPEC.md` for the normative spec.

## What the proof track covers in v1.0

For v1.0 the machine-checked proof effort is **scoped to the
algebraic identities the THBS-SE share arithmetic relies on**, plus
the byte-identity claim that ties THBS-SE Combine output to
single-party FIPS 205 SignDeterministic.

The legacy EasyCrypt scaffolding that modeled the abandoned v0.x
seed-recombine path has been removed (it modeled `combine.go` and
`threshold.go`, files that are no longer in the codebase). The
v1.0 proof track is being rebuilt against the THBS-SE construction
shape (commit-bind, byte-wise Shamir over GF(257), Lagrange
reconstruct, FIPS 205 dispatch) and lands in v1.1 alongside the
strict-atom-assembly construction.

## What ships in v1.0

The Go reference implementation under
`ref/go/pkg/magnetar/thbsse.go` and `thbsse_field.go` is the
load-bearing artifact for v1.0. The 8 test gates listed in the
v1.0 sign-off (TestThbsSE_Wire_FIPS205Verifiable,
TestThbsSE_RejectSeedReveal, TestThbsSE_RejectUnselectedFORS,
TestThbsSE_RejectUnselectedWOTS, TestThbsSE_SlotReuseRejected,
TestThbsSE_OverselectedCommittee,
TestThbsSE_SlotBindingDomainSeparation,
BenchmarkThbsSE_Sign_5of7) pin the byte-identity, slot-binding, and
slashing-evidence properties end-to-end against unmodified
`cloudflare/circl/sign/slhdsa.Verify`. The KAT replay
(`TestKAT_ThbsSe`) pins deterministic vectors at (n=7, t=4) across
all three SLH-DSA modes and three messages.

## What lands in v1.1

The v1.1 proof track plan:

1. **EasyCrypt theory shells** for THBS-SE: the commit-bind ladder,
   the byte-wise Shamir over GF(257), the Lagrange interpolation at
   x=0, and the byte-identity step that ties the final SLH-DSA bytes
   to single-party FIPS 205 SignDeterministic on the reconstructed
   seed (or, in the strict-atom v1.1 path, on the directly-assembled
   FIPS 205 signature atoms).

2. **Lean bridge** for the algebraic content (Shamir reconstruction
   identity, Lagrange basis uniqueness over finite fields, polynomial
   interpolation existence) mirroring Pulsar's
   `~/work/lux/proofs/lean/Crypto/` setup.

3. **Jasmin track** for the strict-atom path (Magnetar-internal FIPS
   205 sec 5/6/7/8 surface), once that construction lands at v1.1.

See `BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11` for the v1.1 roadmap.
