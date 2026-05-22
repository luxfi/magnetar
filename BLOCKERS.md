# Magnetar — Blockers to NIST MPTC submission

> Honest enumeration of what blocks Magnetar from moving toward
> **full Tier A** (Pulsar-equivalent) on the submission-readiness
> ladder.
>
> **As of v0.5.0**: Tier C → Tier B blockers (BLK-1, BLK-2, BLK-3)
> are **CLOSED** at v0.2.0. BLK-5 (KAT vectors), BLK-8 (submission
> package documentation shape) are **CLOSED** at v0.3.0. BLK-4
> (reference impl + v0.4 lifecycle additions), BLK-6 (cross-validation
> harness), BLK-7 (proof artifacts), BLK-9 (independent
> cryptographer review) are partially or fully open; see status
> below. **MAGNETAR-PUBLIC-DKG-1** (public-DKG threshold HBS) is the
> v0.6+ research-grade open task; the v0.5.0 release ships the PVSS
> skeleton at `ref/go/pkg/thbs/dkg2/` and demotes the threshold form
> to the M-Chain custody / TEE path while promoting per-validator
> standalone SLH-DSA (`magnetar.ValidatorSign` +
> `magnetar.VerifyAggregateCert`) as the public-BFT primary primitive.
> See `SPEC.md` for the selected construction,
> `SUBMISSION-STATUS.md` for tier definitions and the phased plan,
> `CRYPTOGRAPHER-SIGN-OFF.md` Gates section for the full Tier A
> gate inventory.

## Tier C → Tier B blockers (construction-level) — CLOSED v0.2.0

### BLK-1 — Construction not selected → **CLOSED**

**Resolution**: v0.1 reveal-and-aggregate construction selected
(see `SPEC.md` §3-§4). Among the three candidates surveyed:

- ~~Komlo/Goldberg-style FROST-of-SLH-DSA~~ — rejected. SLH-DSA's
  hash-tree traversal has no linear-aggregation identity at the
  signature level, so byte-equal FIPS 205 output from threshold
  Lagrange-of-z is not possible. The Pulsar protocol shape does
  NOT transfer.
- ~~Full-MPC hash-computation~~ — deferred. Per-signature MPC
  ceremony cost dominates deployment economics for the v0.1
  timeline; deferred to v0.2 research.
- ✅ **Threshold seed-DKG + reveal-and-aggregate** — selected.
  Distribute SLH-DSA scheme seed via byte-wise Shamir VSS over
  GF(257). Each Combine reconstructs the seed in aggregator memory,
  calls single-party `slhdsa.SignDeterministic`, zeroizes. Signature
  is byte-identical to centralized FIPS 205.

The honest trust caveat: aggregator process is TCB for the brief
seed-reconstruction window. Same caveat as Pulsar v0.1; documented
in `DEPLOYMENT-RUNBOOK.md`.

### BLK-2 — Reference paper / academic basis → **CLOSED (with caveat)**

**Resolution**: the construction-equivalence argument is inherited
from Pulsar's v0.1 reveal-and-aggregate pattern, which itself
adapts the standard byte-wise Shamir VSS literature (Shamir 1979,
Pedersen VSS, Feldman VSS) to a FIPS 204 / FIPS 205 seed.

**Open citation gap**: there is no peer-reviewed paper specifically
targeting threshold-SLH-DSA reveal-and-aggregate. Magnetar inherits
the security argument from the equivalence to a centralized signer
(aggregator with the master seed). When the v0.2 full-MPC
construction matures, a new peer-reviewed paper SHOULD be authored.

### BLK-3 — Spec definition → **CLOSED**

**Resolution**: `SPEC.md` ships in v0.2.0. Covers notation,
hash domain separation, DKG protocol, threshold signing,
Class-N1-analog byte-equality claim, trust model, identifiable
abort, parameter sets, and honest non-claims.

## Tier B → Tier A blockers (engineering- and formal-methods-level)

### BLK-4 — Reference implementation → **PARTIAL: shipped v0.2.0**

**Status**: `ref/go/pkg/magnetar/` ships in v0.2.0:

- ✅ params.go, types.go, transcript.go, zeroize.go, shamir.go
- ✅ keygen.go, sign.go, verify.go
- ✅ dkg.go (DKG protocol)
- ✅ threshold.go, combine.go (threshold-sign + Combine)
- ✅ Three parameter sets: SHAKE-192s, SHAKE-192f, SHAKE-256s

**What's not yet in v0.2.0** (for v0.3+):

- ML-KEM-768 wrapping of DKG envelopes (closes passive-network
  channel; v0.1 envelopes are plaintext).
- Reshare protocol (zero-secret-refresh rotation of shares).
- Per-pair MACs for the threshold-sign rounds (Pulsar CR-7 analog).
- Large-committee path (n > 256; v0.1 caps at GF(257) party-count
  limit).

### BLK-5 — KAT vectors → **CLOSED**

**Resolution**: `vectors/{keygen,sign,verify,threshold-sign,dkg}.json`
ship in v0.2.0. Deterministic regeneration via `cmd/genkat`.
Re-running on a clean checkout produces byte-identical output.

The KAT replay tests in `kat_test.go` validate that the package
implementation reproduces every KAT entry verbatim. This is the
analog of Pulsar's KAT-determinism gate.

### BLK-6 — Cross-validation harness → **OPEN**

**Status**: the package's `Verify` function dispatches to
`circl/slhdsa.Verify`, which IS the FIPS 205 reference verifier
(cloudflare/circl is the only mainstream Go FIPS 205 implementation).
Threshold-produced signatures verify under unmodified circl
slhdsa.Verify — see `n1_byte_equality_test.go`.

**What remains**:

- A cross-implementation harness that verifies Magnetar-produced
  signatures under an independent FIPS 205 implementation (e.g.,
  the pq-crystals reference C code, or BoringSSL's SLH-DSA when
  available). Pure interop testing with no code shared.
- IETF / NIST ACVP integration would slot here.

### BLK-7 — Proof artifacts → **OPEN (multi-month)**

**Status**: none ship in v0.2.0.

**What's needed**:

- **EasyCrypt theories**: correctness of byte-wise Shamir
  reconstruction over GF(257); equivalence of threshold Combine to
  centralized `KeyFromSeed(reconstructed_seed) → SignDeterministic`.
- **Lean bridges**: TBD. SLH-DSA is hash-based; the bridge story
  differs from lattice schemes. May reuse libjade's SLH-DSA
  formal artifacts for the single-party layer; the threshold
  overlay is novel work.
- **Jasmin constant-time analysis**: of `dkg.go`, `threshold.go`,
  `combine.go`, `shamir.go`. The single-party SLH-DSA CT side is
  upstream-ready via libjade.

Multi-month research. Tier A submission depends on at least the
EasyCrypt correctness theorem.

### BLK-8 — Submission package documentation → **CLOSED v0.3.0 (documentation shape; supporting docs/* deferred)**

**Resolution at v0.3.0**: the full 12-document Tier A submission
package shape mirroring Pulsar's structure now ships:

- ✅ `SUBMISSION.md` (cover sheet)
- ✅ `NIST-SUBMISSION.md` (one-page executive summary)
- ✅ `SPEC.md` (from v0.2.0)
- ✅ `PATENTS.md` (royalty-free grant + defensive termination)
- ✅ `PROOF-CLAIMS.md` (HONEST framing — narrow claim + 7 explicit non-claims)
- ✅ `AXIOM-INVENTORY.md` (construction-level + implementation-level axioms with closure plans)
- ✅ `FIPS-TRACEABILITY.md` (FIPS 205 § → code mapping)
- ✅ `TRUSTED-COMPUTING-BASE.md` (TCB inventory)
- ✅ `CRYPTOGRAPHER-SIGN-OFF.md` (internal review — APPROVED WITH GATES)
- ✅ `CHANGELOG.md` (v0.3.0 entry)
- ✅ `DEPLOYMENT-RUNBOOK.md` (from v0.2.0)
- ✅ `BLOCKERS.md` (this file, v0.3.0 update)
- ✅ `SUBMISSION-STATUS.md` (v0.3.0 update — Tier A doc shape complete)

**What remains deferred to v0.4** (supporting docs/* — not
required for Tier A documentation shape):

- `docs/evaluation.md` — performance + correctness + KAT
  cross-validation evidence
- `docs/ietf-draft-skeleton.md` — IETF draft skeleton
- `docs/nist-mptc-category.md` — Class N1 + N4-analog mapping
- `docs/patent-claims.md` — attorney-prep claim drafts
- `docs/design-decisions.md`, `docs/family-architecture.md`,
  `docs/threat-model.md` — supporting design context

These are tracked for the v0.4 release alongside ML-KEM envelope
wrapping + reshare protocol.

### BLK-9 — Independent cryptographer review → **PARTIAL: internal v0.3.0, external roadmap v0.6.0**

**Resolution at v0.3.0 (internal)**: `CRYPTOGRAPHER-SIGN-OFF.md`
landed. Internal cryptographer agent reviewed all 12 production
Go source files (~2186 LOC) plus the test surface (~1451 LOC),
verified build + vet + tests + coverage (76.8%), conducted real
file:line citation of constant-time discipline + zeroize
discipline + identifiable abort soundness. Verdict: **APPROVED
WITH GATES**. Five open gates tracked (GATE-1 through GATE-5).

**What remains (external, roadmap v0.6.0)**: independent lab
engagement covering construction + implementation + EC theories
(when they land v0.5.0) + dudect (when it lands v0.6.0). Output:
external audit report alongside the internal sign-off.

External engagement is blocked on:
- GATE-1 / GATE-2 (EC theory shells + Lean ↔ EC bridge, v0.5.0)
- GATE-3 (dudect 10⁹ samples, v0.6.0)
- GATE-5 (v0.4 lifecycle additions for the deployment posture)

## Research path: public-DKG threshold HBS

### MAGNETAR-PUBLIC-DKG-1 — Public DKG for threshold HBS → **OPEN (research-grade, v0.6+ candidate)**

**Context**: the `thbs/` subpackage ships true-threshold HBS per
McGrew et al. (IACR ePrint 2019/793) but the v1 setup is
DEALER-BACKED — a single dealer generates the WOTS+ chain heads
and FORS secret leaves at setup, Shamir-shares them, and erases the
master seed. Dealer-backed threshold HBS is **NOT public-BFT-safe**
(the dealer learns every secret element at setup time). The user's
hard architectural position:

> "We can't do a trusted dealer obv. It HAS to be freaking done
> right for public chains bro."
>
> "For HBS, the hard part is that public keys are hashes/Merkle
> roots of many secret values. Hashes are nonlinear... a practical
> public-safe DKG must generate and commit to shared leaf/chain
> material, not merely share a seed."
>
> "DKG = PVSS for secret shares + MPC/public verification for
> derived roots."

**What's needed** (per the user spec):

1. **PVSS layer (Ingredient A)** — each party j ∈ [n] samples a
   contribution `r_{j,e}` for every secret element e, Shamir-shares
   `r_{j,e}` across the committee at threshold t. The joint secret
   is `x_e = Σ_j r_{j,e}`; no single party ever holds `x_e`. **A
   SKELETON of this layer ships at `ref/go/pkg/thbs/dkg2/` in
   v0.5.0** (`pvss.go`, `complaint.go`, `consensus.go`).

2. **MPC-root layer (Ingredient B)** — MPC over SHA-256/SHAKE to
   compute the public chain endpoints `W_e = H^{w-1}(x_e)` from
   secret-shared `x_e` without revealing any `x_e`. **THIS IS THE
   HARD FRONTIER.** Candidate frameworks:
   - SPDZ-style MPC (Damgård-Pastro-Smart-Zakarias CRYPTO 2012)
   - Garbled circuits + OT (Wang-Ranellucci-Katz CCS 2017)
   - Function Secret Sharing (Boyle-Gilboa-Ishai EUROCRYPT 2015)
   - MP-SPDZ integration (https://github.com/data61/MP-SPDZ)

   For SLH-DSA-SHAKE-192s with the v1 thbs parameter set this is
   ~750K SHAKE evaluations per DKG ceremony — multi-hour to
   multi-day per ceremony at current framework performance. The
   cryptographer team selects the production MPC framework when
   integrating; the v0.6+ candidate target is "honest cost
   estimate + working demo at small parameters."

**Status of the skeleton** (`ref/go/pkg/thbs/dkg2/`):

- ✅ `doc.go` — package doc, scope, literature (Schoenmakers PVSS,
  SPDZ, garbled-circuits, function-secret-sharing).
- ✅ `pvss.go` — Deal / Verify wire shape; `ErrSkeletonOnly` stubs
  prevent production consumption.
- ✅ `complaint.go` — Complaint round wire shape (BadShare,
  MissingDelivery, CommitmentMalformed); FileComplaint / DealerDefend
  stubs.
- ✅ `consensus.go` — Qualified-set agreement + Run orchestrator;
  `RootMPC` stub returns `ErrMPCRootNotImpl` with explicit pointer
  to this BLOCKERS entry.
- ✅ `README.md` — public-facing scope + research path.
- ✅ Skeleton tests pin the `ErrSkeletonOnly` / `ErrMPCRootNotImpl`
  sentinels.

**What blocks shipping a working dkg2** (the v0.6+ checklist):

1. Select the production MPC framework (MP-SPDZ, EMP-toolkit,
   custom).
2. Implement the SHAKE-256 chain circuit under the chosen MPC.
3. Benchmark per-element cost; choose parameter set + committee
   size that fits the deployment budget.
4. Write production `root.go` (compute joint W_e + public Merkle
   root from secret-shared x_e).
5. Wire-format spec for the public root computation transcript
   (auditability across re-runs).
6. Integrate with parent `thbs.PublicKey` so the resulting threshold
   HBS public key is BYTE-EQUAL to a dealer-DKG'd public key for
   the same elements.
7. Re-prove the construction (security argument under PVSS + MPC
   composition; the user's "PVSS + MPC/public verification for
   derived roots" framing).
8. Independent cryptographer review (BLK-9-analog gate).
9. Independent MPC engineer review of the SHAKE-circuit
   implementation.

**Until MAGNETAR-PUBLIC-DKG-1 closes**:

- PUBLIC-BFT CONSENSUS uses `magnetar.PerValidatorKeypair` +
  `magnetar.ValidatorSign` + `magnetar.VerifyAggregateCert`
  (per-validator standalone SLH-DSA, no DKG, no dealer, no
  aggregator-as-TCB). See `DEPLOYMENT-RUNBOOK.md` §9.
- M-CHAIN CUSTODY uses `magnetar.CombineWithSeedReconstruction`
  OR `thbs.DealerDKG` inside a TEE-attested host (the dealer/
  aggregator is in the TCB by policy). See `DEPLOYMENT-RUNBOOK.md`
  §1.

## Non-blockers

These are NOT blockers — they are deliberate non-claims that
Magnetar will continue to make at Tier A:

- **Byte-equal across full-MPC and reveal-and-aggregate**:
  Magnetar v0.1 reveal-and-aggregate IS byte-equal to centralized
  FIPS 205. A future v0.2 full-MPC would also be byte-equal IF the
  hash-tree computations under MPC are deterministic, but
  Magnetar will not pretend the two constructions share the same
  security model — the trust caveat differs.
- **Sub-second per-signature**: SLH-DSA single-party signing on
  SHAKE-192s is ~50-100ms on commodity hardware; the threshold
  Combine layer adds ~10-20ms of Shamir reconstruction. Magnetar
  will not pretend to match Pulsar's signing throughput.
- **Production-ready before 2027**: see `SUBMISSION-STATUS.md`
  target window.

## Cross-references

- `README.md` — repo purpose + status (v0.2.0 = Tier B)
- `SPEC.md` — construction specification (v0.2.0 landed)
- `DEPLOYMENT-RUNBOOK.md` — operator-facing trust-model disclosure (v0.2.0 landed)
- `SUBMISSION-STATUS.md` — tier definitions + phased plan
- [`luxfi/pulsar`](https://github.com/luxfi/pulsar) — Tier A template
- [`luxfi/quasar`](https://github.com/luxfi/quasar) — Polaris profile cannot deploy until Magnetar matures to Tier A
