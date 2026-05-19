# Magnetar — Blockers to NIST MPTC submission

> Honest enumeration of what blocks Magnetar from moving Tier B →
> Tier A on the submission-readiness ladder.
>
> **As of v0.2.0**: Tier C → Tier B blockers (BLK-1, BLK-2, BLK-3)
> are **CLOSED**. Tier B → A blockers (BLK-4 through BLK-9) are
> partially or fully open; see status below. See `SPEC.md` for the
> selected construction, `SUBMISSION-STATUS.md` for tier definitions
> and the phased plan.

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

### BLK-8 — Submission package documentation → **OPEN (depends on BLK-7)**

**Status**: `SPEC.md` + `DEPLOYMENT-RUNBOOK.md` + `BLOCKERS.md` +
`SUBMISSION-STATUS.md` ship in v0.2.0. The remaining 12 documents
in the Pulsar template (NIST-SUBMISSION.md, PATENTS.md,
PROOF-CLAIMS.md, AXIOM-INVENTORY.md, FIPS-TRACEABILITY.md,
TRUSTED-COMPUTING-BASE.md, CHANGELOG.md, docs/* mirror) are
deferred to the Tier A submission package. Several depend on
BLK-7 outputs.

### BLK-9 — Independent cryptographer review → **OPEN**

**Status**: no independent review of v0.2.0 has occurred.

**What's needed**: same model as Pulsar's
`CRYPTOGRAPHER-SIGN-OFF.md` — independent reviewer attests
construction + impl + proofs + tests. Output:
`CRYPTOGRAPHER-SIGN-OFF.md` matching Pulsar's structure.

Blocked on BLK-7 and BLK-8 being complete enough for the reviewer
to evaluate the formal correctness + the submission package.

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
