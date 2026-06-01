# NIST MPTC Submission Status --- Magnetar

> **v1.0 framing.** This document is a v0.x archival snapshot. The
> v1.0 submission shape ports to the THBS-SE construction and the
> per-validator standalone primitive; the v0.x reveal-and-aggregate
> path described below has been removed from the codebase. See
> `CHANGELOG.md::[1.0.0]` for the load-bearing deletions and the
> v1.0 construction surface.

> Honest status of Magnetar's path to NIST Multi-Party Threshold
> Cryptography submission. **Tier A documentation shape complete**
> as of v0.3.0. Mechanized refinement, dudect, v0.4 lifecycle
> additions (ML-KEM envelope wrap + reshare), and external audit
> are the remaining gates to **full Tier A**.

## Today (v0.3.0)

**Tier A documentation shape complete; full Tier A formal-methods
+ measurement + lifecycle gates open.**

Specifically (carried forward from v0.2.0 and extended at v0.3.0):

- **Construction selected.** v0.1 reveal-and-aggregate over the
  SLH-DSA scheme seed (Shamir VSS in GF(257), Lagrange
  reconstruction at sign time). Mirrors Pulsar's v0.1
  reveal-and-aggregate pattern. See `SPEC.md`.
- **Reference implementation shipped.** `ref/go/pkg/magnetar/` —
  pure Go on top of `cloudflare/circl/sign/slhdsa`. Single-party
  + DKG + threshold-sign + Combine. Three parameter sets
  (SHAKE-192s / SHAKE-192f / SHAKE-256s). ~2186 LOC production
  Go, 76.8% test coverage.
- **KAT vectors shipped.** `vectors/{keygen,sign,verify,
  threshold-sign,dkg}.json` — deterministic regeneration via
  `ref/go/cmd/genkat`.
- **Class-N1 evidence shipped.**
  `n1_byte_equality_test.go` — threshold-produced signatures are
  byte-identical to single-party `slhdsa.SignDeterministic` on
  the reconstructed master seed across (3,2), (5,3), (7,4)
  configurations; verifies under unmodified FIPS 205.
- **Honest trust-model disclosure shipped.**
  `DEPLOYMENT-RUNBOOK.md` documents the v0.1 reveal-and-aggregate
  aggregator-as-TCB caveat with the same rigor as Pulsar's.
- **Tier A documentation shape complete (v0.3.0).** Full 12-document
  submission package shape, mirroring Pulsar's structure:
  `SUBMISSION.md`, `NIST-SUBMISSION.md`, `SPEC.md`, `PATENTS.md`,
  `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`, `FIPS-TRACEABILITY.md`,
  `TRUSTED-COMPUTING-BASE.md`, `CRYPTOGRAPHER-SIGN-OFF.md`,
  `DEPLOYMENT-RUNBOOK.md`, `BLOCKERS.md`, `SUBMISSION-STATUS.md`.
- **Internal cryptographer sign-off shipped (v0.3.0).**
  `CRYPTOGRAPHER-SIGN-OFF.md` — APPROVED WITH GATES, mirroring
  Pulsar's exact structure. Five open gates tracked.
- **Submission orchestration shipped (v0.3.0).**
  `scripts/cut-submission.sh` (8-step tarball cut with KAT-determinism
  verification) + `scripts/check-high-assurance.sh` (per-push gate).

What is **NOT** yet shipped (the gates to full Tier A — tracked
in `CRYPTOGRAPHER-SIGN-OFF.md` Gates section):

- **GATE-1: EC theory shells for the threshold overlay**. The
  single-party FIPS 205 layer is NIST-anchored; the threshold
  overlay is novel. Cross-citation to Pulsar's Lean ↔ EC bridges
  for the GF(257) Shamir / Lagrange algebraic identities; new EC
  theory shells needed for the cSHAKE256 mix + `KeyFromSeed →
  SignDeterministic` dispatch. **Roadmap v0.5.0; multi-month research.**
- **GATE-2: Lean ↔ EC bridge**. Cross-citation closure to Pulsar's
  bridges. **Roadmap v0.5.0.**
- **GATE-3: dudect 10⁹ samples on the threshold overlay**.
  **Roadmap v0.6.0.**
- **GATE-4: external cryptographer audit**. **Roadmap v0.6.0.**
- **GATE-5: v0.4 lifecycle additions**. ML-KEM-768 wrapping of
  DKG Round-1 envelopes (closes passive-network-observer channel)
  + Reshare protocol (Refresh + ReshareToNewSet) for Class N4-analog
  evidence. **Roadmap v0.4.0.**

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

### Phase 4 — Submission package (CLOSED v0.3.0 for documentation shape; full Tier A formal-methods gates open)

Mirror Pulsar's 12-doc structure adapted to Magnetar's specifics:

- ✅ `SUBMISSION.md`, `NIST-SUBMISSION.md`, `SPEC.md` (landed v0.3.0)
- ✅ `PATENTS.md`, `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`,
  `FIPS-TRACEABILITY.md`, `TRUSTED-COMPUTING-BASE.md` (landed v0.3.0)
- ✅ `CHANGELOG.md` (landed v0.3.0), `DEPLOYMENT-RUNBOOK.md` (landed v0.2.0)
- ✅ `CRYPTOGRAPHER-SIGN-OFF.md` (landed v0.3.0, APPROVED WITH GATES)
- ✅ `scripts/cut-submission.sh` + `scripts/check-high-assurance.sh`
  (landed v0.3.0)
- ⏳ `docs/{evaluation,nist-mptc-category,design-decisions,
  patent-claims,family-architecture,threat-model,
  ietf-draft-skeleton}.md` — supporting docs (parallel to
  Pulsar's `docs/`; deferred to v0.4 — not required for
  Tier A documentation shape)

### Phase 5 — Independent cryptographer review (PARTIAL: internal v0.3.0; external roadmap v0.6.0)

- ✅ **Internal review (v0.3.0)**: `CRYPTOGRAPHER-SIGN-OFF.md`
  signed off by the internal cryptographer agent. Verdict:
  APPROVED WITH GATES. Five gates tracked.
- ⏳ **External engagement (roadmap v0.6.0)**: independent lab
  audit covering construction + implementation + EC theories (when
  they land v0.5.0) + dudect (when it lands v0.6.0).

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

## Honest non-claims (at Tier A documentation shape; v0.3.0)

Magnetar v0.3.0 today is NOT:

- A submitted NIST MPTC entry (the tarball cut tool is in place
  via `scripts/cut-submission.sh`; cut target is the
  `submission-2026-11-16` window; Lux internal target is 2027 Q3)
- A production cryptographic primitive **without** the v0.1
  reveal-and-aggregate trust caveat (aggregator is TCB; see
  `DEPLOYMENT-RUNBOOK.md`)
- A formally verified scheme **at the threshold overlay layer**
  (FIPS 205 single-party is NIST-anchored; threshold overlay
  EC theory shells are roadmap v0.5.0)
- Externally audited (internal cryptographer sign-off only at
  v0.3.0; external lab engagement is roadmap v0.6.0)
- A drop-in replacement for Pulsar (Pulsar M-LWE is the
  production cert-profile target; Magnetar is the cross-family
  diversity leg in the Polaris profile)

This repo now exists as a **production library + Tier A
documentation shape complete** for v0.1 reveal-and-aggregate
threshold SLH-DSA, with the honest trust caveat documented
operationally. The path to **full Tier A** (mechanized refinement
+ dudect + v0.4 lifecycle + external audit) is tracked on the
v0.4 / v0.5 / v0.6 roadmap, with closure plans documented in
`CRYPTOGRAPHER-SIGN-OFF.md` Gates section.
