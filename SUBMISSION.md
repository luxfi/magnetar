# NIST MPTC Submission — Magnetar

This document is the cover sheet for the **Magnetar** submission to the
NIST Multi-Party Threshold Cryptography (MPTC) project. It is written
for NIST reviewers and points at every artifact a reviewer needs.

The `magnetar` repository is the **single canonical home** for the
submission: it carries the Go reference implementation under
`ref/go/pkg/magnetar/`, the cover sheet, the construction
specification, the deterministic KAT generator, the deployment runbook,
and the high-assurance gate orchestration. A NIST reviewer gets a
self-contained checkout that does not require network access.

The repository is **active** (not frozen). The submission tarball is
cut from a tag on `main` at NIST's deadline via
`scripts/cut-submission.sh`; reviewer feedback and post-submission
patches land in this same repository so the artifact chain stays
auditable.

**Date stamp (this revision): 2026-05-18.**

**Maturity stamp**: Tier A documentation shape complete at v0.3.0.
This submission is **not** NIST-ratified, **not** FIPS 140-3
validated, **not** ACVP-validated. It IS FIPS-anchored at the
single-party layer (FIPS 205 SLH-DSA). The threshold-overlay layer
is novel; the byte-equality property to single-party FIPS 205 is the
load-bearing N1 claim.

## At a glance

| Field | Value |
|---|---|
| Submission name | **Magnetar** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold SLH-DSA (FIPS 205) — reveal-and-aggregate over the SLH-DSA scheme seed |
| Target NIST MPTC classes | **N1** (threshold signing, byte-identical to single-party FIPS 205 SLH-DSA on the reconstructed master seed) + **N4-analog** (multi-party key generation; public-key preservation across resharing is on the v0.4 roadmap) |
| Underlying construction | FIPS 205 SLH-DSA (single-party layer); v0.1 reveal-and-aggregate Shamir VSS of the SLH-DSA scheme seed over GF(257) (threshold overlay) |
| Hash family | SHA-3 / SHAKE (FIPS 202) and cSHAKE256 / KMAC256 (SP 800-185) for every Magnetar-specific transcript hash |
| Parameter sets | SLH-DSA-SHAKE-192s (recommended; NIST PQ Cat 3), SLH-DSA-SHAKE-192f (Cat 3 "fast"), SLH-DSA-SHAKE-256s (Cat 5) |
| Round count | DKG = 3 rounds (Round-1 deal; Round-2 transcript digest; Round-3 share assembly). Threshold sign = 2 rounds (commit + reveal). |
| Signature output | **Byte-identical to single-party FIPS 205 `slhdsa.SignDeterministic`** on the reconstructed master seed (the headline N1 claim) |
| Repository | <https://github.com/luxfi/magnetar> (single canonical home: code, spec, KAT, runbook, cut tool) |
| Algorithm source | This repository, `ref/go/pkg/magnetar/`. Latest tagged release at this revision: `v0.2.0` (Tier B); this revision targets `v0.3.0` (Tier A documentation shape complete). |
| Tarball cut tool | `scripts/cut-submission.sh` (tags from `main`, regenerates KATs deterministically, runs the test suite, tars) |
| Submission tag | `submission-YYYY-MM-DD` (cut from `main` at deadline) |
| Spec | `SPEC.md` (in-tree construction specification) |
| License | BSD-3-Clause (code) — see `LICENSE` |
| Patent posture | **Royalty-free grant** — see `PATENTS.md`. Lux Industries grants a worldwide, royalty-free, irrevocable patent license to any implementation conformant to the Magnetar construction released under BSD-3-Clause or compatible OSI license, OR any NIST MPTC / PQC / ACVP submission, validation, or interoperability test. Defensive termination mirrors Apache-2.0 §3. |
| Sibling submissions | **Pulsar** ([`luxfi/pulsar`](https://github.com/luxfi/pulsar)) — M-LWE threshold ML-DSA with FIPS 204 byte-equality (Tier A, sister submission). **Corona** ([`luxfi/corona`](https://github.com/luxfi/corona)) — R-LWE threshold (Tier A documentation shape; no FIPS standard target). Independent submissions; reviewable separately. |

## Headline claim

> Every signature produced by a Magnetar threshold ceremony (DKG →
> Round-1 commit → Round-2 reveal → Combine) is **byte-identical**
> to the signature single-party FIPS 205
> `slhdsa.SignDeterministic(slhdsa.Scheme(ID).DeriveKey(S), m, ctx)`
> would produce on the same reconstructed master seed `S`, message
> `m`, and context `ctx`. Verification under unmodified FIPS 205
> `slhdsa.Verify` therefore accepts Magnetar signatures with **no
> code change**.

This is the Class-N1 byte-equality claim, anchored against FIPS 205
SLH-DSA (NIST PQ category 3 / 5 stateless hash-based signature
standard, 2024).

**Verifier-side story (load-bearing for N1 framing).** Because
FIPS 205 SLH-DSA IS a NIST standard, Magnetar's N1 claim has the
strong form: a Magnetar threshold signature must verify under any
FIPS 205-conformant verifier. The Magnetar `verify.go` is a thin
dispatch over `circl/slhdsa.Verify`, which is the FIPS 205 §10.3
verifier verbatim. A reviewer can — and the test suite does —
cross-check Magnetar threshold-emitted bytes against
`cloudflare/circl`'s FIPS 205 verifier; the byte-identity invariant
is empirically realized by `TestN1_ByteEquality_*` over
(committee, threshold) configurations (3,2), (5,3), (7,4).

## Algorithm scope

The algorithm being submitted is the Magnetar implementation at
`luxfi/magnetar` v0.3.0. The single-party signing primitive is
FIPS 205 SLH-DSA, **unchanged in its math** (via `cloudflare/circl`'s
audited Go reference), plus the following production threshold
lifecycle layers that FIPS 205 does not specify (these are
Magnetar's contribution to the submission package):

1. **Byte-wise Shamir VSS of the SLH-DSA scheme seed over GF(257)** —
   `ref/go/pkg/magnetar/shamir.go`. Distributes the 96-byte (192s/192f)
   or 128-byte (256s) FIPS 205 scheme seed across `n` committee
   members at reconstruction threshold `t`. The choice of GF(257) is
   the smallest prime > 255 (so every byte fits as a distinct field
   element); shares are encoded as one big-endian uint16 per byte
   position, matching the byte-equal property byte-wise.

2. **Three-round DKG over the scheme seed** — `ref/go/pkg/magnetar/dkg.go`.
   Round-1 dealers broadcast per-recipient envelopes carrying that
   recipient's Shamir share plus the dealer's full contribution to
   the joint seed. Round-2 broadcasts a transcript digest binding
   the entire ordered envelope set. Round-3 reconciles digests
   (identifiable abort on equivocation) and computes each party's
   share of the master byte-sum + the group public key. v0.1 ships
   plaintext envelopes for KAT determinism; v0.4 wraps them under
   ML-KEM-768 to recipient identity keys (BLOCKERS.md BLK-4 path,
   matching Pulsar's CR-8 closure).

3. **Two-round threshold sign with commit-bind reveal** —
   `ref/go/pkg/magnetar/threshold.go` + `combine.go`. Round-1 each
   signer commits to `D_i = cSHAKE256(mask || masked_share || tau_1)`
   where `tau_1 = (sid, attempt, quorum, pk, msg)`. Round-2 reveals
   `(mask, masked_share)`. Combine re-derives every `D_i` from the
   reveals, gates each share on `ctEqual32(D'_i, D_i)`, recovers
   each share via `masked XOR mask`, Lagrange-reconstructs the
   master byte-sum, applies the cSHAKE256 mix bit-for-bit identical
   to DKG Round-3, and calls FIPS 205 `SignDeterministic` on the
   reconstructed seed-derived key.

4. **Identifiable abort with attributable evidence** — `dkg.go`
   complaint emission (`ComplaintEquivocation` on DKG Round-3 digest
   mismatch; conflicting digest pair is the evidence blob).
   `ComplaintBadDelivery` on malformed envelopes. `ComplaintMACFailure`
   reserved for v0.2 (per-pair MAC layer, currently omitted —
   reveal-and-aggregate trust model already places the aggregator
   in the TCB; MACs close a session-bind hole that doesn't matter
   under v0.1 trust caveat).

5. **Domain-separated hash suite** — `ref/go/pkg/magnetar/transcript.go`
   centralises every Magnetar cSHAKE256 / KMAC256 call. All cSHAKE
   function-name `"Magnetar"`; customisation tags
   `MAGNETAR-DKG-COMMIT-V1`, `MAGNETAR-DKG-TRANSCRIPT-V1`,
   `MAGNETAR-SIGN-R1-V1`, `MAGNETAR-SIGN-MASK-V1`,
   `MAGNETAR-SEED-SHARE-V1`. Protocol-wide domain-separation context
   `lux-magnetar-v0.1`.

## What to read first

A reviewer with limited time should read in this order:

1. **`SUBMISSION.md`** (this file) — submission metadata and headline
2. **`NIST-SUBMISSION.md`** — one-page executive summary
3. **`SPEC.md`** — standalone construction specification
4. **`PROOF-CLAIMS.md`** — what is claimed vs not (HONEST framing — no
   machine-checked refinement proof at this submission; FIPS-anchored
   byte-equality empirical at the test-vector level)
5. **`TRUSTED-COMPUTING-BASE.md`** — implementation TCB (Go +
   `cloudflare/circl` SLH-DSA + crypto/subtle)
6. **`FIPS-TRACEABILITY.md`** — FIPS 205 § → code mapping
7. **`AXIOM-INVENTORY.md`** — construction-level + implementation-level
   axioms; closure plans for the proof-tier roadmap
8. **`PATENTS.md`** — royalty-free patent grant text
9. **`DEPLOYMENT-RUNBOOK.md`** — operator-facing trust-model disclosure
   (v0.1 reveal-and-aggregate aggregator-as-TCB)
10. **`BLOCKERS.md`** — Tier B → A path; outstanding gates
11. **`CRYPTOGRAPHER-SIGN-OFF.md`** — internal review verdict
12. **`README.md`** — repository layout and how to reproduce

## What to run

The reproducibility gate is `scripts/cut-submission.sh` against the
tarball extract — the entire submission is self-contained, so no
network access is required:

```bash
tar xzf submission-YYYY-MM-DD.tar.gz
cd magnetar
GOWORK=off go build ./...
GOWORK=off go test -count=1 -short -timeout 240s ./ref/go/pkg/magnetar/
GOWORK=off go run ./ref/go/cmd/genkat -out=vectors/   # regenerate KATs deterministically
```

The test suite includes `TestN1_ByteEquality_ThresholdMatchesCentralized`
(across (3,2), (5,3), (7,4) configurations) and
`TestN1_ByteEquality_DifferentQuorumsSameSignature` (the same DKG
output under two distinct signing quorums yields byte-identical
signatures). Both are the load-bearing N1 evidence.

To cut a fresh tarball (maintainer-side):

```bash
scripts/cut-submission.sh                       # dry-run, no tarball
scripts/cut-submission.sh submission-2026-11-16 # production cut + tag
```

The cut script verifies a clean tree, regenerates KATs from the
in-tree canonical implementation, re-runs the test suite (including
N1 byte-equality), tars the entire submission checkout, and prints
the SHA-256.

## Class N1 — Byte-equal to single-party FIPS 205

The N1 claim is asserted at **three** levels of evidence (one fewer
than Pulsar at full Tier A; the missing level is the machine-checked
refinement chain — EC theory shells for the threshold overlay layer
remain a roadmap item, multi-month research):

| Evidence | Where |
|---|---|
| Algorithmic argument | `SPEC.md` §6 (Class-N1-analog byte-equality claim) + the construction-equivalence proof sketch |
| Test harness | `ref/go/pkg/magnetar/n1_byte_equality_test.go` — three (committee, threshold) configurations; byte-identity asserted via `bytes.Equal` |
| KAT determinism | `vectors/{keygen,sign,verify,threshold-sign,dkg}.json` regenerated deterministically by `ref/go/cmd/genkat` |
| Cross-implementation verifier | Magnetar's `Verify` is a thin dispatch over `cloudflare/circl/sign/slhdsa.Verify`, which is the FIPS 205 §10.3 verifier verbatim. Any FIPS 205-conformant verifier accepts Magnetar threshold-emitted bytes. |

**What Magnetar DOES NOT yet provide vs Pulsar Tier A**:

- No EasyCrypt refinement chain for the threshold overlay layer.
  (FIPS 205 SLH-DSA itself has the libjade formal artifacts available
  for the single-party layer; the threshold overlay is novel and
  not yet mechanized. See `AXIOM-INVENTORY.md` §2 closure plan.)
- No Lean ↔ EC algebraic bridge files specific to Magnetar. (Magnetar's
  Shamir / Lagrange operations are algebraically identical to
  Pulsar's GF(257) variant; cross-citation to Pulsar's
  `proofs/lean-easycrypt-bridge.md` is the closure target, see
  `AXIOM-INVENTORY.md` §2.)
- No Jasmin high-assurance implementation of the threshold overlay.
  (libjade covers SLH-DSA single-party; the threshold overlay is
  pure Go.)
- No machine-checked `Class N1 byte-equality` theorem for the
  threshold overlay layer.

The honest framing for Magnetar is: **production-hardened
implementation of a FIPS-anchored single-party primitive with a
novel reveal-and-aggregate threshold overlay**, NOT
**machine-checked refinement against FIPS 205**. The mechanized
proof tier for the threshold overlay remains a roadmap item; see
`PROOF-CLAIMS.md` for the narrow stated claim and the closure path.

## Class N4-analog — Public-key preservation across resharing

Multi-party reshare with public-key preservation is on the v0.4
roadmap (see `BLOCKERS.md` BLK-4 "Reshare protocol"). The v0.1
construction supports DKG → threshold-sign → Combine but does NOT
ship a `Refresh` or `ReshareToNewSet` primitive. Class N4 framing
is therefore "**N4-analog**" at v0.3.0: the construction admits a
reshare protocol with the same byte-equality property to FIPS 205
under the reconstructed seed, but the protocol itself is not yet
implemented.

The N4-equivalent claim, when v0.4 lands, will state: any DKG share
set can be `Refresh`-rotated (same committee, fresh shares) or
`ReshareToNewSet`-rotated (committee rotation) such that any
post-reshare threshold-sign produces signatures verifiable under
the byte-identical unchanged group public key.

## High-assurance track — HONEST DELTA vs Pulsar

Pulsar ships an EasyCrypt + Lean + Jasmin high-assurance track that
mechanically refines its Class N1 byte-equality claim against a
formal model of FIPS 204. **Magnetar does NOT ship that.** The
honest delta:

| Pulsar artifact | Magnetar equivalent | Status |
|---|---|---|
| 13/13 EasyCrypt files compile, 0/0 admits (refinement chain) | none | NOT PRESENT — threshold-overlay EC theory shells are roadmap v0.4+, multi-month research project, see `AXIOM-INVENTORY.md` §2 |
| 5/5 Lean ↔ EC algebraic-bridge files | none specific to Magnetar | NOT PRESENT — Shamir / Lagrange algebraically identical to Pulsar's GF(257) variant; cross-citation closure on roadmap, see `AXIOM-INVENTORY.md` §2 |
| 3/3 jasmin-ct blocking on threshold layer | none for the threshold overlay | NOT PRESENT — libjade covers FIPS 205 SLH-DSA single-party; threshold overlay is pure Go |
| Class N1 byte-equality theorem (mechanized) | empirical byte-equality at the test-vector level only | NOT MECHANIZED — see `PROOF-CLAIMS.md` §3 |
| `cloudflare/circl` FIPS 205 cross-validation | `Verify` dispatches to circl's FIPS 205 verifier; `TestN1_ByteEquality_*` is the load-bearing harness | PRESENT — circl is the canonical Go FIPS 205 implementation |

What Magnetar DOES offer at this submission-time:

1. **Production-hardened reference implementation** in Go
   (`ref/go/pkg/magnetar/`, ~2200 LOC). Single-party + DKG +
   threshold sign + Combine. Three FIPS 205 parameter sets.
2. **KAT-deterministic outputs** under the Magnetar hash suite
   (cSHAKE256 / KMAC256 per FIPS 202 + SP 800-185). Vectors at
   five profiles: keygen, sign, verify, threshold-sign, dkg.
   Deterministic regeneration via `ref/go/cmd/genkat`.
3. **Byte-identity N1 evidence**:
   `TestN1_ByteEquality_ThresholdMatchesCentralized` proves at three
   configurations that threshold-Combine output is byte-equal to
   single-party `slhdsa.SignDeterministic` on the same seed.
4. **Identifiable-abort evidence pipeline** at the DKG layer
   (`ComplaintEquivocation` carries the conflicting digest pair).
5. **Honest gap disclosure** — `PROOF-CLAIMS.md` §3 enumerates every
   property NOT proved; `BLOCKERS.md` enumerates the Tier B → A gates.
6. **Reproducibility commitment** — `scripts/cut-submission.sh` is
   deterministic from fixed seeds; the KAT generator's output is
   byte-stable across runs.

## What this submission does NOT claim

- **No formal mechanized refinement** of the threshold overlay layer
  against FIPS 205. EasyCrypt / Lean / Jasmin theories for the
  Magnetar threshold layer are roadmap items, multi-month research.
  See `PROOF-CLAIMS.md` §3.1 and `AXIOM-INVENTORY.md` §2.
- **No threshold secrecy without aggregator trust.** Magnetar v0.1 is
  reveal-and-aggregate: the aggregator process holds the reconstructed
  master seed in memory for the duration of one Combine call. This is
  the same trust caveat Pulsar v0.1 carries; documented in
  `DEPLOYMENT-RUNBOOK.md` with the TEE / mlock / ptrace-off hardening
  matrix. A v0.2 full-MPC construction (aggregator never sees the seed)
  is on the research path; see `BLOCKERS.md`.
- **No statistical constant-time validation (dudect)** of the threshold
  layer. The Magnetar threshold-layer code paths use constant-time
  primitives (`ctEqual32` / `ctEqualSlice`) for every commit verification
  and key equality check, but no statistical timing harness ships at
  v0.3.0. Roadmap v0.4+. See `PROOF-CLAIMS.md` §3.4.
- **No ML-KEM-768 envelope wrapping** of DKG Round-1 envelopes in
  v0.1 — envelopes are plaintext. A passive network observer can see
  the per-recipient share + dealer contribution. v0.4 closes this
  channel by wrapping envelopes under recipient identity keys (matching
  Pulsar's CR-8 closure). See `BLOCKERS.md` BLK-4.
- **No reshare protocol** in v0.1. Class N4-analog will be claimed at
  v0.4 when `Refresh` and `ReshareToNewSet` primitives land. See
  `BLOCKERS.md` BLK-4.
- **No external cryptographic audit.** Internal cryptographer
  sign-off (`CRYPTOGRAPHER-SIGN-OFF.md`) is the v0.3.0 review; an
  external lab engagement is roadmap, see `BLOCKERS.md` BLK-9.
- **No FIPS 140-3 module validation** — applies to packaged
  cryptographic modules, not this reference implementation. Downstream
  of this submission.
- **No ACVP / CAVP algorithm validation certificate** for the
  threshold layer — no NIST ACVP test vector set exists for
  threshold SLH-DSA. The single-party FIPS 205 layer in `cloudflare/circl`
  is independently ACVP-testable; the threshold overlay is not.
- **No identifiable abort under network partition** — synchronous
  network assumption only; asynchronous identifiable abort is a
  separate problem.
- **No post-quantum hardness claim beyond FIPS 205's analysis.**
  SLH-DSA's security rests on collision/preimage resistance of the
  underlying hash (SHAKE for the Magnetar parameter sets); NIST's
  FIPS 205 analysis is the substrate.

## Comparison to sibling and related submissions

| Submission | Hardness basis | Round count | Output story | NIST class |
|---|---|---|---|---|
| **Magnetar** (this) | Hash-based (FIPS 205 SLH-DSA collision/preimage resistance) | DKG=3 + sign=2 | **Byte-equal to single-party FIPS 205 SLH-DSA on reconstructed seed** | N1 (+ N4-analog at v0.4) |
| **Pulsar** ([`luxfi/pulsar`](https://github.com/luxfi/pulsar)) | Module-LWE (FIPS 204 ML-DSA) | 2 | Byte-equal to FIPS 204 ML-DSA-65 | N1 + N4 |
| **Corona** ([`luxfi/corona`](https://github.com/luxfi/corona)) | Ring-LWE (Boschini et al. ePrint 2024/1113) | 2 | Construction-level interchangeable; no NIST standard target | N1 + N4 |
| FROST (academic upstream) | Discrete log / Schnorr | 2 | EdDSA-compatible | not MPTC |

The hash-based / M-LWE / R-LWE triple is intentional. Lux's Polaris
cert profile MAY combine Magnetar (hash-based) and Pulsar (M-LWE)
and Corona (R-LWE) as a **cross-family** layered defence so a break
in any single family (lattice or hash) does not break finality.
That layered combination is the consumer's design choice and is
not part of this submission. Magnetar stands alone as an MPTC
Class N1 candidate (with N4-analog roadmap).

## Contact

- Primary: <z@lux.network> (Lux Industries, Inc.)
- Submission coordination: <mptc@lux.network>
- Security disclosure: see `SECURITY.md` (when present) or
  `magnetar@lux.network`
- Public discussion: <https://github.com/luxfi/magnetar/discussions>

## Reproducibility commitment

The build, test, and vector-generation scripts are deterministic
from fixed seeds. A reviewer reproducing the submission tarball
from `submission-YYYY-MM-DD` should obtain byte-identical artifacts.
Drift is a build bug; please open an issue.

---

**Document metadata**

- Name: `SUBMISSION.md`
- Version: v0.1 (initial Tier A submission-package scaffolding)
- Date: 2026-05-18
- Submission package version: Magnetar v0.3.0 (Tier A documentation
  shape complete)
- Underlying library version at this revision: `luxfi/magnetar v0.3.0`
