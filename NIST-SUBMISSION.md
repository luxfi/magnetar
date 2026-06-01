# NIST MPTC Submission --- Magnetar (one-page executive summary)

> **v1.0 framing.** Magnetar v1.0 ships TWO primitives:
> per-validator standalone (`standalone.go`) and THBS-SE
> (`thbsse.go` + `thbsse_field.go`). The text below was written
> against the v0.x reveal-and-aggregate construction; v1.0
> superseding language is in `README.md`, `SPEC.md`, `THBS-SPEC.md`,
> `CHANGELOG.md::[1.0.0]`, and `CRYPTOGRAPHER-SIGN-OFF.md`.

> **Executive summary** of the Magnetar package for the NIST Multi-Party
> Threshold Cryptography (MPTC) project. The full cover sheet is in
> `SUBMISSION.md`; the package contents map is below.

## Submission metadata

| Field | Value |
|---|---|
| Submission name | **Magnetar** |
| Submitting organisation | Lux Industries, Inc. |
| Algorithm | Threshold SLH-DSA (FIPS 205) — reveal-and-aggregate over the SLH-DSA scheme seed |
| MPTC classes | **N1** (threshold signing, byte-identical to single-party FIPS 205 SLH-DSA on the reconstructed master seed). N4-analog (reshare with public-key preservation) is on the v0.4 roadmap. |
| Underlying construction | FIPS 205 SLH-DSA (single-party layer); v0.1 reveal-and-aggregate Shamir VSS of the SLH-DSA scheme seed over GF(257) (threshold overlay) |
| Hash family | FIPS 202 SHA-3 / SHAKE; SP 800-185 cSHAKE256 / KMAC256 for Magnetar-specific transcript hashes |
| Parameter sets | SLH-DSA-SHAKE-192s (NIST PQ Cat 3, recommended), SLH-DSA-SHAKE-192f (Cat 3 fast), SLH-DSA-SHAKE-256s (Cat 5) |
| Round count | DKG = 3 rounds; threshold sign = 2 rounds (commit + reveal) |
| Repository | <https://github.com/luxfi/magnetar> |
| Submission tag | `submission-2026-11-16` (planned) |
| Latest tagged release | `v0.2.0` (this revision targets `v0.3.0`) |
| License | BSD-3-Clause (code) + CC-BY-4.0 (PATENTS.md) |

## Headline claim

> Every signature produced by a Magnetar threshold ceremony (DKG →
> Round-1 commit → Round-2 reveal → Combine) is **byte-identical**
> to single-party FIPS 205 `slhdsa.SignDeterministic` on the
> reconstructed master seed. Verification under unmodified FIPS 205
> accepts Magnetar signatures with no code change.

**Theorem framing**: byte-equality to a NIST-standardized
single-party primitive. Magnetar implements FIPS 205 SLH-DSA
**unchanged in its math** (via `cloudflare/circl` audited Go
reference) for the single-party layer; Magnetar's contribution
beyond FIPS 205 is the threshold lifecycle (byte-wise Shamir VSS
over GF(257) of the SLH-DSA scheme seed, three-round DKG,
two-round commit-bind threshold sign, identifiable abort,
KAT-deterministic Magnetar-SHA3 hash suite).

**Verifier-side reality.** FIPS 205 SLH-DSA IS a NIST standard.
Magnetar's `Verify` is a thin dispatch over circl's FIPS 205 §10.3
verifier; a reviewer can cross-check Magnetar threshold-emitted
bytes against any FIPS 205-conformant verifier. The Magnetar test
suite's `TestN1_ByteEquality_*` realizes this property empirically.
This is the strong N1 framing distinction from Corona (which has
no FIPS standard target to anchor against); it is the same N1
framing Pulsar uses against FIPS 204.

## Package contents (mapped to NIST IR 8214C requirements)

| NIST requirement | Magnetar artifact |
|---|---|
| Technical specification | `SPEC.md` |
| Open-source reference implementation | `ref/go/pkg/magnetar/` (BSD-3-Clause) |
| KAT vectors | `vectors/{keygen,sign,verify,threshold-sign,dkg}.json`; deterministic regeneration via `ref/go/cmd/genkat` |
| Security analysis | `SPEC.md` §6 (Class-N1-analog byte-equality claim) + `SPEC.md` §7 (trust model) + FIPS 205 (NIST standard) for the single-party layer |
| Patent / IP statement | `PATENTS.md` (royalty-free grant) |
| Known limitations | `SUBMISSION.md` §"Does NOT claim" + `BLOCKERS.md` |
| Trust model | `DEPLOYMENT-RUNBOOK.md` (operator-facing); `TRUSTED-COMPUTING-BASE.md` (implementation TCB); `PROOF-CLAIMS.md` (proof scope) |
| Axiom inventory | `AXIOM-INVENTORY.md` |
| FIPS traceability | `FIPS-TRACEABILITY.md` (FIPS 205 § → code mapping) |
| Cryptographer review | `CRYPTOGRAPHER-SIGN-OFF.md` (internal review) |
| Contact / maintainers | `SUBMISSION.md` §Contact |

## What makes this submission different

1. **Cross-family PQ diversity** — Magnetar is the hash-based PQ
   threshold leg of the Lux cross-family cert profile. While Pulsar
   (M-LWE) and Corona (R-LWE) provide lattice-based PQ threshold
   signing, Magnetar's hash-based foundation means a complete break
   of the lattice family (M-LWE and R-LWE together) would leave the
   Magnetar leg sound. The hardness assumption is collision/preimage
   resistance of the underlying hash (SHAKE for the Magnetar
   parameter sets), with no lattice dependence.

2. **FIPS-anchored byte equality** — Unlike Corona (which targets a
   2024 academic R-LWE construction with no NIST standard), Magnetar
   anchors byte-equality against FIPS 205 SLH-DSA — a published NIST
   standard. The strong N1 claim form is therefore available;
   verification against any FIPS 205-conformant verifier is a
   property the submission asserts and the test suite empirically
   realizes.

3. **KAT-deterministic Magnetar-SHA3 profile** — Every transcript
   hash routes through cSHAKE256 / KMAC256 per FIPS 202 + SP 800-185.
   Customisation tags are pinned (`MAGNETAR-DKG-COMMIT-V1`,
   `MAGNETAR-DKG-TRANSCRIPT-V1`, `MAGNETAR-SIGN-R1-V1`,
   `MAGNETAR-SIGN-MASK-V1`, `MAGNETAR-SEED-SHARE-V1`). Re-running
   `ref/go/cmd/genkat` on a clean checkout produces byte-identical
   vectors.

4. **Reveal-and-aggregate construction (honest trust caveat)** —
   Magnetar v0.1 reconstructs the master SLH-DSA seed in
   aggregator-process memory during each Combine call. This is the
   same trust model as Pulsar v0.1; documented in
   `DEPLOYMENT-RUNBOOK.md` with the TEE / mlock / ptrace-off
   hardening matrix. A v0.2 full-MPC construction is on the research
   path; the v0.1 byte-equality property is preserved across that
   migration (the math is unchanged; only the trust placement
   differs).

5. **Reproducibility-first** — `scripts/cut-submission.sh` and
   `ref/go/cmd/genkat` are deterministic. KAT regeneration is
   byte-equal across runs; CI enforces drift = build bug.

6. **Honest gap disclosure** — Magnetar does NOT ship a mechanized
   refinement proof for the threshold overlay layer. See
   `PROOF-CLAIMS.md` for the narrow claim and the roadmap. The
   honest framing: production-hardened FIPS-anchored single-party
   primitive with a novel reveal-and-aggregate threshold overlay,
   NOT machine-checked refinement of the threshold overlay against
   FIPS 205.

## Trust footprint (one-screen summary)

After Magnetar v0.3.0:

| Category | Count / Status |
|---|---|
| EasyCrypt files (threshold overlay) | **0** (no mechanized refinement of the overlay layer — see `PROOF-CLAIMS.md` §3.1) |
| Lean ↔ EC bridge files | **0** specific to Magnetar (Shamir / Lagrange algebraically identical to Pulsar's; cross-citation closure on roadmap) |
| Jasmin source files (threshold overlay) | **0** (libjade covers FIPS 205 single-party; threshold overlay is pure Go) |
| Go reference test coverage | single-party + DKG + threshold + Combine + KAT replay; `TestN1_ByteEquality_*` across three configurations |
| KAT determinism | enforced by deterministic `ref/go/cmd/genkat` regeneration |
| Constant-time discipline | `ctEqualSlice` / `ctEqual32` on every commit comparison and public-key equality; secret-dependent branches absent from `verify.go`, `sign.go`, and the Combine commit-verify gate. Statistical CT validation (dudect) is roadmap. |

The trust base for Magnetar at submission time reduces to:

- The FIPS 205 SLH-DSA standard (NIST 2024) and its security analysis.
- The `cloudflare/circl/sign/slhdsa` Go reference implementation
  (community-audited; standard library-style).
- The Go reference implementation correctness of the Magnetar
  threshold overlay (reviewed by code + KATs +
  `TestN1_ByteEquality_*`).
- The `crypto/subtle` standard library constant-time helpers.
- The Go toolchain.

## What this submission does NOT claim

| Out-of-scope claim | Why |
|---|---|
| Mechanized refinement of the threshold overlay | Multi-month research project. See `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`. |
| Threshold secrecy without aggregator trust | v0.1 is reveal-and-aggregate; aggregator process is TCB for the seed-reconstruction window. v0.2 (full-MPC) is research. |
| Statistical constant-time validation (dudect) | Roadmap v0.4+. |
| ML-KEM-768 envelope wrapping of DKG envelopes | v0.1 envelopes are plaintext (KAT-deterministic); v0.4 closes this. See `BLOCKERS.md` BLK-4. |
| Reshare protocol (N4-analog) | v0.4 roadmap. See `BLOCKERS.md` BLK-4. |
| Post-quantum hardness of SLH-DSA itself | Assumed from FIPS 205 + the SHAKE-family analysis. |
| ACVP/CAVP algorithm validation for the threshold overlay | Not applicable — NIST has no ACVP test vector set for threshold SLH-DSA. |
| FIPS 140-3 module validation | Downstream — applies to packaged modules. |
| Asynchronous identifiable abort | Synchronous only. |
| External cryptographic audit | Internal sign-off only at v0.3.0. See `BLOCKERS.md` BLK-9. |

## Reproducibility commitment

```bash
git clone --branch submission-2026-11-16 https://github.com/luxfi/magnetar
cd magnetar
GOWORK=off go build ./...
GOWORK=off go test -count=1 -short -timeout 240s ./ref/go/pkg/magnetar/
GOWORK=off go run ./ref/go/cmd/genkat -out=vectors/  # regenerate KAT vectors
```

Drift between submission tarball and reproduced output is a build
bug — please file at the GitHub issues link above. NIST reviewers
should obtain byte-identical artifacts on reproduction.

## Patent / IP posture (TL;DR)

- **Code**: BSD-3-Clause.
- **Patents**: Royalty-free grant to any implementation of the
  Magnetar construction released under BSD-3-Clause or compatible
  OSI license, OR any NIST MPTC / PQC / ACVP submission /
  validation / interoperability test.
- **Defensive termination**: license terminates against any party
  asserting patents against Magnetar, FIPS 205 SLH-DSA, or any
  other NIST-standardized PQ signature scheme.
- **Full text**: `PATENTS.md` §3.

## Contact

| Purpose | Contact |
|---|---|
| Submission coordination | `mptc@lux.network` |
| Patent / IP inquiries | `legal@lux.network` |
| Security disclosure | `magnetar@lux.network` |
| Public discussion | <https://github.com/luxfi/magnetar/discussions> |
| Primary maintainer | `z@lux.network` (Lux Industries, Inc.) |

## Roadmap (v0.4 and beyond)

| Milestone | Target |
|---|---|
| Tier A documentation shape complete (this revision) | v0.3.0 |
| ML-KEM-768 envelope wrapping of DKG Round-1 envelopes (closes passive-network-observer channel) | v0.4.0 |
| Reshare protocol (Refresh + ReshareToNewSet) — Class N4-analog evidence | v0.4.0 |
| EasyCrypt theory shells for the threshold overlay (refinement of byte-equality to FIPS 205) | v0.5.0 (research; multi-month) |
| Lean ↔ EC bridge (cross-citation to Pulsar's Shamir / Lagrange bridges; or Magnetar-specific entries if needed) | v0.5.0 |
| dudect-style statistical CT validation harness for the threshold overlay | v0.6.0 |
| External cryptographic audit (engaged lab) | v0.6.0 |
| v0.2 full-MPC construction (aggregator never sees the master seed) | research, no committed target |

The roadmap is published at `SUBMISSION.md` "What this submission
does NOT claim" + tracked at the GitHub issues link above.

---

**Document metadata**

- Name: `NIST-SUBMISSION.md`
- Version: v0.1 (initial Tier A submission-package scaffolding)
- Date: 2026-05-18
- Submission package version: Magnetar v0.3.0
