# Magnetar — Blockers to NIST MPTC submission

> Honest enumeration of what blocks Magnetar from moving Tier C →
> Tier B → Tier A on the submission-readiness ladder. This is the
> path-to-production register; see `SUBMISSION-STATUS.md` for the
> tier definitions and phased plan.

## Tier C → Tier B blockers (construction-level)

### BLK-1 — Construction not selected

No fixed threshold-SLH-DSA protocol. Multiple candidates exist
in the literature:

- **Komlo/Goldberg-style FROST-of-SLH-DSA** — would mirror Pulsar's
  protocol shape but SLH-DSA's hash-tree traversal has no linear-
  aggregation identity. Cannot produce byte-equal FIPS 205
  signatures from threshold inputs.
- **Full-MPC hash-computation** — run every SHAKE / SHA-2 inside
  MPC. Slow (per-signature MPC ceremony dominates) but correct.
- **Threshold seed-DKG + batched per-signature ceremony** —
  hybrid: distribute seed via VSS, batch per-signature
  reconstruction.

Each has different security models, performance, and proof
obligations. Selection requires research, not engineering.

### BLK-2 — Reference paper / academic basis

The threshold-SLH-DSA literature is sparse compared to threshold-
Schnorr / threshold-Lattice. Magnetar's construction MUST cite a
peer-reviewed paper as its academic basis (analogous to Pulsar's
ePrint 2024/1113 for the Corona-family). Without this, the
construction risks being unreviewed work.

### BLK-3 — Spec definition

No `SPEC.md` exists. Spec authoring is blocked on BLK-1
(construction selection).

## Tier B → Tier A blockers (engineering-level)

These activate once BLK-1, BLK-2, BLK-3 close.

### BLK-4 — Reference implementation

No Go implementation. Layout: `ref/go/pkg/magnetar/` mirroring
Pulsar. Estimated 4-8 weeks once construction frozen.

### BLK-5 — KAT vectors

Deterministic KAT generator + replay tests. Cannot exist without
implementation.

### BLK-6 — Cross-validation harness

Third-party FIPS 205 verifier integration (cloudflare/circl, pq-
crystals reference) for the threshold-output-verifies-under-
unmodified-FIPS-205 claim (analog of Pulsar's Class N1 evidence).

### BLK-7 — Proof artifacts

- EasyCrypt theories for threshold-SLH-DSA correctness
- Lean bridges for the algebraic identities (TBD — SLH-DSA is hash-
  based, the bridge story is different from lattice schemes)
- Jasmin constant-time analysis of the per-signature MPC ceremony

Hash-based constructions have well-developed CT analysis pipelines
(libjade SLH-DSA exists), so the single-party CT side is upstream-
ready. The threshold MPC overlay is novel work.

### BLK-8 — Submission package documentation

16-doc mirror of Pulsar's structure adapted to Magnetar specifics.
Blocked on BLK-1 + BLK-4.

### BLK-9 — Independent cryptographer review

Independent reviewer must attest construction + impl + proofs +
tests. Blocked on BLK-1 through BLK-8.

## Non-blockers

These are NOT blockers — they are deliberate non-claims that
Magnetar will continue to make even at Tier A:

- **Byte-equal to single-party FIPS 205**: SLH-DSA's hash-tree
  traversal precludes this. Magnetar will instead claim
  "verifies under unmodified FIPS 205 given seed-DKG soundness"
  (a strictly weaker but still well-defined claim).
- **Sub-second per-signature**: per-signature MPC ceremony is
  hash-dominated; production deployment will batch / amortize but
  Magnetar will not pretend to match Pulsar's signing throughput.
- **Production-ready before 2027**: see `SUBMISSION-STATUS.md`
  target window.

## Cross-references

- `README.md` — repo purpose + status
- `DESIGN.md` — research direction
- `SUBMISSION-STATUS.md` — tier definitions + phased plan
- [`luxfi/pulsar`](https://github.com/luxfi/pulsar) — Tier A template
- [`luxfi/quasar`](https://github.com/luxfi/quasar) — Polaris profile
  cannot deploy until Magnetar matures to Tier A
