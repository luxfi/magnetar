# AXIOM-INVENTORY — Magnetar

> Honest enumeration of every cryptographic assumption + residual
> axiom Magnetar depends on. This document is load-bearing for the
> Tier A submission gate: per the project rubric, AXIOM-INVENTORY
> MUST be reviewable by an external cryptographer and MUST close
> every residual axiom with either a closure plan or an explicit
> non-closure rationale.
>
> Status at v0.3.0: **EC theory artifacts for the threshold overlay
> are roadmap**; this document enumerates the construction-level +
> implementation-level axioms against which the eventual proofs will
> be discharged. The single-party FIPS 205 SLH-DSA layer is NIST-
> anchored (FIPS 205, 2024) and inherits NIST's security analysis.

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
| **Byte-wise Shamir VSS soundness over GF(257)** | Shamir 1979 (information-theoretic secret sharing); standard textbook result | The classical Shamir construction is information-theoretically secure: any `t-1` shares reveal zero information about the secret. Magnetar applies the construction byte-by-byte to the SLH-DSA scheme seed; the per-byte independence + GF(257) choice (smallest prime > 255) preserve this property. The Lagrange reconstruction at `x=0` is algebraically identical to Pulsar's GF(257) variant — Pulsar's Lean ↔ EC bridge files cover the algebraic identity and Magnetar can cross-cite them once its EC theory shells land. |
| **Identity-key signature unforgeability** | Application-level assumption (consensus layer identity keys; for v0.4 envelope-authenticated DKG, this maps to FIPS 204 ML-DSA-65 or equivalent) | Reserved for v0.4 identifiable-abort evidence-signing pattern. At v0.1 the `AbortEvidence.Signature` field is provisioned but not yet wired (the v0.1 reveal-and-aggregate trust model places the aggregator in TCB, so identifiable-abort attribution at the DKG level via digest pairs is sufficient for v0.1; v0.4 will sign evidence under identity keys for slashing). |
| **Domain-separation soundness of cSHAKE customisation strings** | NIST SP 800-185 §3 | Each Magnetar transcript hash uses a distinct customisation string (`MAGNETAR-DKG-COMMIT-V1`, `MAGNETAR-DKG-TRANSCRIPT-V1`, `MAGNETAR-SIGN-R1-V1`, `MAGNETAR-SIGN-MASK-V1`, `MAGNETAR-SEED-SHARE-V1`) plus function-name `"Magnetar"`. SP 800-185 guarantees no collision across distinct (N, S) tuples for the cSHAKE construction. Standard NIST assumption. |

## §2 Implementation-level axioms (TCB)

These are residual gaps between the FIPS-anchored single-party
primitive + the construction-level argument and the shipped Go
implementation. Each has a closure plan.

| Axiom | Location | Closure plan |
|---|---|---|
| `cloudflare/circl/sign/slhdsa` correctness vs FIPS 205 | indirect via `keygen.go`, `sign.go`, `verify.go`, `combine.go` | Trust the library; upstream is community-audited Cloudflare reference. Cross-implementation check against a non-Go FIPS 205 implementation (BoringSSL when SLH-DSA matures, or pq-crystals reference C) is roadmap item; see `BLOCKERS.md` BLK-6. |
| `golang.org/x/crypto/sha3` cSHAKE256 / KMAC256 correctness vs FIPS 202 / SP 800-185 | indirect via `transcript.go` | Trust the standard-library implementation; widely deployed and quickly patched. KAT-determinism (`ref/go/cmd/genkat`) enforces byte-stability across runs. |
| Implementation matches the Magnetar SPEC.md construction at the protocol level | `ref/go/pkg/magnetar/{shamir,dkg,threshold,combine,transcript,zeroize}.go` | **OPEN — gated by EC theory shells.** Roadmap v0.5.0: implement EC theories `Magnetar_N1_Refinement.ec`, `Magnetar_N1_Combine_Refinement.ec`, `Magnetar_DKG_Refinement.ec`. Pulsar got to admit 0/0 over 13 EC iterations; Magnetar will follow the same closure path, with the advantage that the Shamir / Lagrange algebraic identities are identical to Pulsar's (cross-citation to Pulsar's Lean bridges is the closure plan). |
| Threshold-Combine output byte-equals single-party FIPS 205 SignDeterministic on reconstructed seed (Class N1 byte-equality) | `combine.go` end-to-end; empirically `n1_byte_equality_test.go` | **OPEN — empirical-only at v0.3.0.** Closure: the byte-equality refinement theorem extracted from the EC theory shells (v0.5.0) would mechanize the property. Until then the evidence is `TestN1_ByteEquality_*` (3 configs) + KAT determinism + the FIPS 205 verifier dispatch. |
| Constant-time execution of the threshold overlay (commit verify, pubkey equality, share equality) | `transcript.go` (`ctEqualSlice`, `ctEqual32`), `combine.go`, `keygen.go` | **OPEN.** No `dudect` harness yet for the threshold overlay. Roadmap v0.6.0. Single-party FIPS 205 CT inherits `cloudflare/circl` upstream claims; libjade's SLH-DSA formal CT artifacts are available upstream but not redistributed in this submission. |
| Identifiable-abort attribution via DKG Round-3 digest mismatch | `dkg.go` Round3 | Soundness reduces to cSHAKE256 collision resistance (binding the transcript digest) plus identity-key signature unforgeability (when v0.4 signs the evidence). Documented in `SPEC.md` §8 and tested in `dkg_test.go`. Formal proof: roadmap v0.5.0. |
| Secret-buffer zeroization on every Combine return path | `combine.go` (every error and success exit), `zeroize.go` | Go's GC may copy buffers around; zeroize is defense-in-depth, not a guarantee. The v0.1 reveal-and-aggregate trust caveat (master seed reconstructed in aggregator memory for ~100ms during Combine) is documented in `DEPLOYMENT-RUNBOOK.md` with the TEE / mlock / ptrace-off hardening matrix. Closure: v0.2 full-MPC construction would eliminate the brief seed-exposure window; research, no committed target. |
| Network-observer envelope confidentiality | v0.1: NONE (envelopes are plaintext); v0.4: ML-KEM-768 wrapping under recipient identity key | **OPEN — v0.4 closure plan.** v0.4 wraps each Round-1 envelope as `KEMCiphertext || Sealed` matching Pulsar's `sealEnvelope` pattern (`identity.go:399` in pulsar). See `BLOCKERS.md` BLK-4. |

## §3 Comparison to Pulsar's AXIOM-INVENTORY

Pulsar's `~/work/lux/pulsar/AXIOM-INVENTORY.md` enumerates ~36
residual EC axioms remaining after the v4-v13 decomposition cascade
(see Pulsar's "Trust footprint summary (after v8)" table for the
category breakdown). Magnetar v0.3.0 has **zero** EC artifacts for
the threshold overlay; the comparable axiom inventory for Magnetar
is the **roadmap target** of v0.5.0+.

Magnetar is structurally easier than Pulsar in one respect: there
is no rejection-sampling kappa-loop reasoning. FIPS 205 SLH-DSA
signing is deterministic in the `SignDeterministic` mode (no
rejection-restart on the hot path; the WOTS+/FORS hash-tree
construction is straight-line). Pulsar's hot path includes the
ML-DSA rejection-sampling-loop kappa reasoning (an `accept_signing_attempt`
predicate plus per-kappa loop unrolling). Magnetar's Class-N1-analog
byte-equality is a strictly narrower refinement than Pulsar's:
"threshold output equals single-party deterministic FIPS 205 output
on the reconstructed seed" with no per-attempt kappa branching.

Magnetar is structurally harder than Corona in one respect: Corona
has no FIPS standard target, so its byte-equality claim is
"construction-level interchangeability" with its own verifier.
Magnetar's claim is strictly stronger: byte-equality with a NIST
standard primitive (FIPS 205) such that any FIPS 205-conformant
verifier accepts threshold output with no code change.

## §4 Honest non-claim

This document is the **inventory** of axioms Magnetar's proofs
WILL discharge. It is NOT a claim that Magnetar's proofs are
CLOSED. EC theories for the threshold overlay are explicitly
roadmap (see `PROOF-CLAIMS.md` §3 non-claims + this file's §2
closure plans).

At v0.3.0, Magnetar's proof basis is:

1. FIPS 205 SLH-DSA NIST security analysis (single-party layer).
2. Construction soundness inherited from byte-wise Shamir VSS
   over GF(257) + the classical Lagrange reconstruction identity.
3. KAT-determinism (`ref/go/cmd/genkat` is reproducible).
4. `TestN1_ByteEquality_*` empirical byte-equality across
   (committee, threshold) configurations (3,2), (5,3), (7,4).
5. Cross-validation: `verify.go` dispatches to
   `cloudflare/circl/sign/slhdsa.Verify` (the FIPS 205 §10.3
   verifier verbatim); any FIPS 205-conformant verifier accepts
   Magnetar threshold output.
6. Code review: secret-dependent branches identified and replaced
   with constant-time helpers (`ctEqualSlice`, `ctEqual32`).
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
- `CRYPTOGRAPHER-SIGN-OFF.md` — independent review verdict
- `BLOCKERS.md` — Tier B → A path; gates blocking full Tier A
- Roadmap target for EC theory shells: v0.5.0 (see `NIST-SUBMISSION.md`
  §"Roadmap")
- Sibling AXIOM-INVENTORY (Pulsar): `~/work/lux/pulsar/AXIOM-INVENTORY.md`
  — Tier A reference with admit 0/0 closure; Magnetar's eventual
  closure plan mirrors this pattern.

---

**Document metadata**

- Name: `AXIOM-INVENTORY.md`
- Version: v0.1 (initial Tier A submission-package scaffolding)
- Date: 2026-05-18
