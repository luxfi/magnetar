# NIST MPTC Submission Status — Magnetar

> Honest status of Magnetar's path to NIST Multi-Party Threshold
> Cryptography submission. **Tier B** as of v0.2.0
> (production library + submission scaffold shipped). Mechanized
> refinement + independent audit on the roadmap to Tier A.

## Today (v0.2.0)

**Tier B: production library + submission scaffold landed.**

Specifically:

- **Construction selected.** v0.1 reveal-and-aggregate over the
  SLH-DSA scheme seed (Shamir VSS in GF(257), Lagrange
  reconstruction at sign time). Mirrors Pulsar's v0.1
  reveal-and-aggregate pattern. See `SPEC.md`.
- **Reference implementation shipped.** `ref/go/pkg/magnetar/` —
  pure Go on top of `cloudflare/circl/sign/slhdsa`. Single-party
  + DKG + threshold-sign + Combine. Three parameter sets
  (SHAKE-192s / SHAKE-192f / SHAKE-256s).
- **KAT vectors shipped.** `vectors/{keygen,sign,verify,
  threshold-sign,dkg}.json` — deterministic regeneration via
  `cmd/genkat`.
- **Class-N1-analog evidence shipped.**
  `n1_byte_equality_test.go` — threshold-produced signatures are
  byte-identical to single-party `slhdsa.SignDeterministic` on
  the reconstructed master seed; verifies under unmodified
  FIPS 205.
- **Honest trust-model disclosure shipped.**
  `DEPLOYMENT-RUNBOOK.md` documents the v0.1 reveal-and-aggregate
  aggregator-as-TCB caveat with the same rigor as Pulsar's.

What is **NOT** yet shipped (the Tier B → A gap):

- **Proof artifacts** (EasyCrypt theories, Lean bridges, Jasmin
  sources). See `BLOCKERS.md` BLK-7. This is multi-month research.
- **Constant-time analysis** of the threshold layer under `dudect`
  or formal tooling.
- **ML-KEM-768 wrapping** of DKG Round-1 envelopes (closes
  passive-network-observer channel). v0.1 envelopes are plaintext.
- **Independent cryptographer review.** See `BLOCKERS.md` BLK-9.
- **Full 16-document submission package** mirroring Pulsar's
  layout. See `BLOCKERS.md` BLK-8.

## Why this is not Pulsar (still, at Tier B)

Pulsar v0.1 reached NIST MPTC submission-readiness on three
structural advantages that Magnetar v0.1 partially shares and
partially does not:

1. **Linear-aggregation identity.** SHARED: at the SHARE level,
   Shamir-shares over GF(257) admit linear Lagrange reconstruction
   exactly as Pulsar's do. Magnetar inherits this property.
2. **Fixed FIPS standard to anchor against.** SHARED: Magnetar's
   Class-N1-analog claim is "byte-equal to single-party FIPS 205
   SLH-DSA on the reconstructed seed," directly analogous to
   Pulsar's Class N1 byte-equality claim against FIPS 204 ML-DSA.
3. **Mature academic basis.** PARTIALLY SHARED: the reveal-and-
   aggregate pattern itself has the same security story for SLH-DSA
   as it does for ML-DSA — the aggregator is TCB; this is honest
   v0.1 design space. What's NOT shared: there is no peer-reviewed
   paper specifically targeting threshold-SLH-DSA reveal-and-
   aggregate. Magnetar inherits the construction-equivalence
   argument from Pulsar's v0.1 design rather than citing a fresh
   threshold-SLH-DSA paper. This is acknowledged in `SPEC.md` §6
   and remains an open citation gap.

## Path to NIST MPTC v0.3

Estimated 2-3 months of formal-methods work + 1-2 months of
submission-package authoring + parallel independent review.

### Phase 1 — Construction selection (DONE, v0.2.0)

- ✅ Surveyed candidates (Komlo-style FROST-of-SLH-DSA, full-MPC, reveal-and-aggregate)
- ✅ Selected reveal-and-aggregate (mirrors Pulsar v0.1 pattern; honest TCB caveat)
- ✅ Documented in `SPEC.md`

### Phase 2 — Reference implementation (DONE, v0.2.0)

- ✅ Implemented in Go (`ref/go/pkg/magnetar/`)
- ✅ Three parameter sets (SHAKE-192s, SHAKE-192f, SHAKE-256s)
- ✅ KAT vectors + deterministic regeneration
- ✅ N1 byte-equality test passes across (3,2), (5,3), (7,4) configurations

### Phase 3 — Proof artifacts (OPEN, BLK-7)

- EasyCrypt theories for threshold reconstruction correctness
- Lean bridges (where applicable — SLH-DSA is hash-based, so the bridge story differs from lattice schemes; expect to cite SLH-DSA's existing libjade constant-time analysis for the single-party layer)
- Jasmin constant-time analysis of the threshold layer (DKG / Combine / Round1 / Round2)
- Output target: `proofs/`, `jasmin/`

### Phase 4 — Submission package (OPEN, BLK-8)

Mirror Pulsar's 16-doc structure adapted to Magnetar's specifics:

- `SUBMISSION.md`, `NIST-SUBMISSION.md`, `SPEC.md`
- `PATENTS.md`, `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`,
  `FIPS-TRACEABILITY.md`, `TRUSTED-COMPUTING-BASE.md`
- `CHANGELOG.md`, `DEPLOYMENT-RUNBOOK.md` (✅ landed v0.2.0)
- `docs/{evaluation,nist-mptc-category,design-decisions,
  patent-claims,family-architecture,threat-model,
  ietf-draft-skeleton}.md`
- `scripts/cut-submission.sh` + supporting build/test/bench/vector
  generation scripts

### Phase 5 — Independent cryptographer review (OPEN, BLK-9)

- Same model as Pulsar's `CRYPTOGRAPHER-SIGN-OFF.md`
- Independent reviewer attests construction + impl + proofs + tests
- Output: `CRYPTOGRAPHER-SIGN-OFF.md`

## Target

**NIST MPTC v0.3** — first submission window after Pulsar v0.1
(2026-11-16). Exact NIST date TBA by NIST; Lux internal target is
**2027 Q3**.

## Cross-references

- `SPEC.md` — construction specification (v0.2.0 landed)
- `BLOCKERS.md` — Tier B → A path
- `DEPLOYMENT-RUNBOOK.md` — v0.1 trust-model disclosure (v0.2.0 landed)
- `README.md` — repo purpose + status
- [`luxfi/quasar`](https://github.com/luxfi/quasar) — Polaris cert
  profile depends on Magnetar maturing
- [`luxfi/pulsar`](https://github.com/luxfi/pulsar) — template
  submission package to mirror at Phase 4
- [`luxfi/lps/ROADMAP-CRYPTO-STACK.md`](https://github.com/luxfi/LPs/blob/main/ROADMAP-CRYPTO-STACK.md) — multi-year crypto stack plan

## Honest non-claims (at Tier B)

Magnetar v0.2.0 today is NOT:

- A NIST MPTC submission (won't be until Tier A, target 2027 Q3)
- A production cryptographic primitive **without** the v0.1
  reveal-and-aggregate trust caveat (aggregator is TCB; see
  `DEPLOYMENT-RUNBOOK.md`)
- A formally verified scheme (no EasyCrypt / Lean / Jasmin yet)
- Independently reviewed (no cryptographer sign-off yet)
- A drop-in replacement for Pulsar (Pulsar M-LWE is the
  production cert-profile target; Magnetar is the cross-family
  diversity leg in the Polaris profile)

This repo now exists as a **production library** for v0.1
reveal-and-aggregate threshold SLH-DSA, with the honest trust
caveat documented operationally. The path to Tier A
(formal verification + independent review + full submission
package) is on the NIST MPTC v0.3 roadmap.
