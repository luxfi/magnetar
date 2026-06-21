# AXIOM-INVENTORY --- Magnetar

> **v1.0 framing.** This document is a v0.x archival snapshot.
> v1.0 axioms port to the THBS-SE construction shape. See
> `BLOCKERS.md::MAGNETAR-PROOF-TRACK-V11`.

> Honest enumeration of every cryptographic assumption + residual
> axiom Magnetar depends on. This document is load-bearing for the
> Tier A submission gate: per the project rubric, AXIOM-INVENTORY
> MUST be reviewable by an external cryptographer and MUST close
> every residual axiom with either a closure plan or an explicit
> non-closure rationale.
>
> Status: **there are NO EC/Lean theorems for the threshold overlay,
> present or planned.** The prior ones were vacuous and have been
> deleted (`PROOF-CLAIMS.md` §2). This document enumerates the
> construction-level + implementation-level axioms the code relies on;
> NONE are discharged by machine. The single-party FIPS 205 SLH-DSA
> layer is NIST-anchored (FIPS 205, 2024) and inherits NIST's analysis.

## §1 Construction-level axioms (cryptographic assumptions)

These are the underlying hardness + soundness assumptions of the
Magnetar construction. They are NOT closing in any Lux work —
they are the substrate of the security argument and are inherited
from NIST standards and the academic literature.

| Axiom | Reference | Rationale for non-closure |
|---|---|---|
| **FIPS 205 SLH-DSA security (EUF-CMA)** | NIST FIPS 205 (Stateless Hash-Based Digital Signature Standard, 2024); Bernstein et al. SPHINCS+ submission to NIST PQC | Standard NIST analysis. The single-party signing primitive's unforgeability under chosen-message attack is FIPS 205's security goal; Magnetar inherits it via the `cloudflare/circl/sign/slhdsa` dispatch. Not a Magnetar-specific assumption. |
| **SHAKE256 / cSHAKE256 collision + preimage resistance** | NIST FIPS 202 + SP 800-185 | Used in `transcript.go` for domain-separated hashing across DKG, signing, mix-to-seed. Hash function security is standard NIST assumption. Magnetar's threshold-overlay binding arguments (transcript digest equivocation detection, commit-bind reveal, mix-to-seed) reduce to SHAKE256 collision/preimage resistance. |
| **KMAC256 unforgeability** | NIST SP 800-185 | Reserved for v0.4 envelope-authentication tag (matching Pulsar's `PULSAR-DKG-ENVAUTH-V1` pattern). Not in use at v0.1 (envelopes are plaintext); will be load-bearing once v0.4 ML-KEM wrapping lands. |
| **Byte-wise Shamir VSS soundness over GF(257)** | Shamir 1979 (information-theoretic secret sharing); standard textbook result | The classical Shamir construction is information-theoretically secure: any `t-1` shares reveal zero information about the secret. Magnetar applies the construction byte-by-byte to the SLH-DSA scheme seed; the per-byte independence + GF(257) choice (smallest prime > 255) preserve this property. The Lagrange reconstruction at `x=0` is standard. (No Magnetar EC/Lean mechanization of this exists; the prior "cross-cite Pulsar's bridge once our EC shells land" plan is withdrawn — those shells were vacuous and deleted.) |
| **Identity-key signature unforgeability** | Application-level assumption (consensus layer identity keys; for v0.4 envelope-authenticated DKG, this maps to FIPS 204 ML-DSA-65 or equivalent) | Reserved for v0.4 identifiable-abort evidence-signing pattern. At v0.1 the `AbortEvidence.Signature` field is provisioned but not yet wired (the v0.1 reveal-and-aggregate trust model places the aggregator in TCB, so identifiable-abort attribution at the DKG level via digest pairs is sufficient for v0.1; v0.4 will sign evidence under identity keys for slashing). |
| **Domain-separation soundness of cSHAKE customisation strings** | NIST SP 800-185 §3 | Each Magnetar transcript hash uses a distinct customisation string (`MAGNETAR-DKG-COMMIT-V1`, `MAGNETAR-DKG-TRANSCRIPT-V1`, `MAGNETAR-SIGN-R1-V1`, `MAGNETAR-SIGN-MASK-V1`, `MAGNETAR-SEED-SHARE-V1`) plus function-name `"Magnetar"`. SP 800-185 guarantees no collision across distinct (N, S) tuples for the cSHAKE construction. Standard NIST assumption. |

## §2 Implementation-level axioms (TCB)

These are residual gaps between the FIPS-anchored single-party
primitive + the construction-level argument and the shipped Go
implementation. Each has a closure plan.

> NOTE: the v0.x files this table once cited (`shamir.go`, `dkg.go`,
> `threshold.go`, `combine.go`) were DELETED. The current code is in
> `thbsse.go`, `thbsse_field.go`, `thbsse_assemble.go`,
> `slhdsa_internal.go`, `standalone.go`, `pvss_dkg.go`. The "closure
> plan = EC theory shells" entries below were FALSE: the EC track was
> vacuous and has been deleted (see `PROOF-CLAIMS.md` §2). Nothing here
> is on a credible near-term mechanization path.

| Axiom | Location | Status |
|---|---|---|
| `cloudflare/circl/sign/slhdsa` correctness vs FIPS 205 | indirect via `keygen.go`, `sign.go`, `verify.go`, `slhdsa_internal.go` | Trust the library; community-audited. Cross-implementation check against a non-Go FIPS 205 reference (BoringSSL / pq-crystals) is a tracked gap (OPEN). |
| `golang.org/x/crypto/sha3` cSHAKE256 / KMAC256 correctness vs FIPS 202 / SP 800-185 | indirect via `transcript.go` | Trust the standard library. KAT-determinism (`ref/go/cmd/genkat`) enforces byte-stability. |
| Implementation matches the construction at the protocol level | `thbsse.go`, `pvss_dkg.go`, `thbsse_assemble.go`, `slhdsa_internal.go` | **OPEN, no mechanization.** Evidence is code review + tests only. The prior "EC theory shells at v0.5.0" closure plan was vacuous and is withdrawn. |
| THBS-SE Combine output byte-equals single-party FIPS 205 SignDeterministic on the reconstructed master | `thbsse_assemble.go`; tests `TestSlhdsaInternal_ByteEqualToCirclSign`, `TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl` | ASSERTED by test (correctness/interop). NOT mechanized. NOT a no-leak property — the master IS reconstructed (`ASSEMBLE-INVARIANT.md`). |
| Constant-time of the threshold overlay | `transcript.go` (`ctEqualSlice`, `ctEqual32`) + code review | **OPEN.** No dudect harness. The "CT" AST test is a name lint, not a timing measurement, and CT is moot for a path holding the master in plaintext. |
| PVSS-DKG production transcript hides the master | `pvss_dkg.go` (`RunDKG`); test `TestPVSS_DKG_ProductionTranscriptHidesMaster` | ASSERTED by test. The secrecy reduction to byte-wise Shamir over GF(257) is standard but NOT machine-checked. pk derivation still reconstructs M (inherent). |
| Secret-buffer zeroization | `thbsse_assemble.go`, `pvss_dkg.go`, `zeroize.go` | Defense-in-depth, not a guarantee (GC may copy). In the permissionless THBS-SE path the master IS resident during one Sign call; this is research-grade, not no-leak (`BLOCKERS.md`). |
| Network-observer envelope confidentiality | v0.1: NONE (envelopes are plaintext); v0.4: ML-KEM-768 wrapping under recipient identity key | **OPEN — v0.4 closure plan.** v0.4 wraps each Round-1 envelope as `KEMCiphertext || Sealed` matching Pulsar's `sealEnvelope` pattern (`identity.go:399` in pulsar). See `BLOCKERS.md` BLK-4. |

## §3 Comparison to Pulsar's AXIOM-INVENTORY

Whatever Pulsar's posture, Magnetar has **zero** mechanized artifacts
for the threshold overlay. The prior claim that "the comparable axiom
inventory for Magnetar is the roadmap target of v0.5.0+" implied a
credible path; it was not credible (the EC track that was supposed to
seed it turned out vacuous and is deleted). Treat Magnetar as having NO
mechanized threshold proof, present or planned, until someone writes a
real one.

What is genuinely simpler about Magnetar (if a proof were ever
attempted): SLH-DSA `SignDeterministic` is straight-line (no
rejection-sampling kappa loop), so a hypothetical byte-equality
refinement would be narrower than Pulsar's. But none exists.

## §4 Honest non-claim

This document is NOT a claim of any closed proof, and NOT a roadmap to
one. There are no EC/Lean theorems for the threshold overlay, present
or scheduled; the prior ones were vacuous and removed (`PROOF-CLAIMS.md`
§2).

Magnetar's actual basis is:

1. FIPS 205 SLH-DSA NIST security analysis (single-party layer).
2. Byte-wise Shamir over GF(257) + Lagrange reconstruction (standard,
   not mechanized here).
3. KAT-determinism (`ref/go/cmd/genkat` is reproducible).
4. Byte-identity tests vs single-party FIPS 205
   (`TestSlhdsaInternal_ByteEqualToCirclSign`,
   `TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl`,
   `TestMagnetar_Wire_FIPS205Verifiable`).
5. Cross-validation: `verify.go` dispatches to
   `cloudflare/circl/sign/slhdsa.Verify`; any FIPS 205-conformant
   verifier accepts the output.
6. Code review: secret-dependent branches replaced with constant-time
   helpers (`ctEqualSlice`, `ctEqual32`) where applicable.
7. Test-suite coverage (`go test -count=1 ./ref/go/pkg/magnetar/`
   green; race-mode skip via `raceEnabled` build-tag pattern for
   SLH-DSA-heavy tests that exceed race-detector overhead).

EC mechanization for the threshold overlay is the load-bearing
gap between Tier A documentation shape (achieved v0.3.0) and the
full Tier A cut-readiness Pulsar v1.0.7 holds (admit 0/0 across
13 EC files).

## §5 Cross-references

- `SUBMISSION.md` — submission cover sheet
- `PROOF-CLAIMS.md` — narrow claim + explicit non-claims
- `TRUSTED-COMPUTING-BASE.md` — TCB inventory
- `FIPS-TRACEABILITY.md` — FIPS 205 § → code traceability
- `DEPLOYMENT-RUNBOOK.md` — operator trust-model disclosure (v0.1
  reveal-and-aggregate aggregator-as-TCB)
- `CRYPTOGRAPHER-SIGN-OFF.md` — internal review verdict (standalone
  primitive only)
- `BLOCKERS.md` — sound / open / falsely-closed enumeration
- `PROOF-CLAIMS.md` §2 — the vacuous proof track that was deleted
- `proofs/README.md` — the empty proof track (scaffolds only)

---

**Document metadata**

- Name: `AXIOM-INVENTORY.md`
- Version: v0.1 (initial Tier A submission-package scaffolding)
- Date: 2026-05-18
