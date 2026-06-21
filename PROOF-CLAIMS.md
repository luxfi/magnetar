# PROOF-CLAIMS --- Magnetar (HONEST: proven vs asserted vs open)

This document states, per property, exactly what is PROVEN (mechanized),
what is ASSERTED (tested / by-construction / inherited from a standard),
and what is OPEN. Read it before reading the code.

## §0 One-paragraph truth

Magnetar has **no mechanized proof of any threshold property**. The
per-validator standalone primitive is a thin, sound wrapper over
`cloudflare/circl/sign/slhdsa` FIPS 205. The permissionless THBS-SE
threshold path reconstructs the FIPS 205 master at the public combiner
(research-grade; not no-leak). The dealerless PVSS-DKG production path
hides the master from transcript observers but still reconstructs it to
derive the group public key. The EasyCrypt/Lean "proof track" was
vacuous and has been deleted or reduced to labeled scaffolds. Evidence
is empirical (tests + KAT determinism + FIPS 205 verifier dispatch),
not machine-checked.

## §1 Per-property status

| Property | Status | Basis |
|---|---|---|
| Per-validator standalone emits valid single-party FIPS 205 signatures | ASSERTED (by dispatch + test) | `standalone.go` calls `circl/slhdsa`; `TestMagnetar_Wire_FIPS205Verifiable` across 3 SHAKE modes. Inherits FIPS 205 (NIST 2024) security analysis for the single-party layer. |
| THBS-SE Combine output is byte-identical to `circl/slhdsa.SignDeterministic` on the reconstructed master (valid FIPS 205 signature) | ASSERTED (by test) | `TestSlhdsaInternal_ByteEqualToCirclSign`, `TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl`. This is a CORRECTNESS/INTEROP property. NOT mechanized. |
| THBS-SE Combine is no-leak (master not reconstructed) | **FALSE / OPEN** | The path DOES reconstruct the master at the public combiner (`ASSEMBLE-INVARIANT.md`). There is no no-leak property to prove. RESEARCH-ONLY. |
| PVSS-DKG production transcript hides the master from observers | ASSERTED (by test) | `RunDKG` emits no constant-term reveals; `TestPVSS_DKG_ProductionTranscriptHidesMaster`. NOT mechanized (the secrecy reduction to byte-wise Shamir over GF(257) is a standard result but is not machine-checked here). |
| PVSS-DKG: no party EVER holds the master | **FALSE** | `deriveDKGPublicKey` reconstructs M to compute `pk = SLH-DSA.PK(M)` (inherent; see `BLOCKERS.md`). True only on the TEE / dealer paths. |
| PVSS-DKG robust against malicious dealers (production path) | **NOT DELIVERED** | Hash commitments aren't openable without revealing m_i; production defers malformed-share detection to sign-time commit binding. Robustness holds only on the open-reveal (test) path. |
| Threshold overlay mechanized refinement (EasyCrypt / Lean / Jasmin) | **NONE** | The prior track was vacuous; deleted/scaffolded. See §2. |
| Constant-time of the threshold overlay (statistical / dudect) | OPEN | Only local CT helpers + code review. No dudect harness. The "CT" AST test is a name lint, not a timing measurement. |
| Post-quantum hardness of SLH-DSA | INHERITED | FIPS 205 (NIST 2024); collision/preimage resistance of SHAKE. Nothing Magnetar-specific. |

## §2 The deleted/scaffolded "proof track" (HONEST accounting)

The earlier submission advertised a mechanized EasyCrypt + Lean track
with a small "admit budget". Every result in it was vacuous:

- `Magnetar_N1_StrictAtom.ec` --- headline theorem
  `magnetar_n1_strict_atom_byte_equality` proved by `apply
  combine_assemble_axiom`, where that axiom RESTATED THE THEOREM
  verbatim. Circular. Plus `strict_atom_discipline_satisfied : bool =
  true`. **Reduced to a 0-content scaffold.**
- `proofs/lean/.../StrictAtom.lean` --- theorem body `sorry`;
  `strictAtomDisciplineSatisfied : Prop := True`. **Reduced to a
  0-content scaffold.**
- `Magnetar_N5_PVSS_DKG.ec` --- "secrecy theorem" with conclusion
  `... true` proved by `trivial`; wire-compat `X = X`; composition
  `true`. Doubly false because it claimed secrecy for the open-reveal
  code that PUBLISHES the secret. **Reduced to a 0-content scaffold.**
- `Magnetar_N1_SHAKE_Expand.ec` --- only non-axiom lemma was
  `shake_expand s = shake_expand s` from `s = s`. **DELETED.**
- `Magnetar_N1_Atom_Refinement.ec` --- a single restate-as-axiom.
  **DELETED.**
- `Magnetar_N4_KeyDeriveStable.ec` --- `s = s' => f s = f s'` ("this
  function is a function"). **DELETED.**
- `lemmas/Magnetar_CT.ec` --- `strict_atom_combine_is_ct` discharged by
  `admit`; comment admitted "abstract level vacuous". CT is also the
  wrong property (the master is in plaintext in the buffer). **DELETED.**
- `lemmas/SLHDSA_Functional.ec` --- legitimate black-box FIPS 205
  functional axioms, but fed only the deleted files. **DELETED.**

The remaining `.ec`/`.lean` files declare no `axiom`, `admit`, `lemma`,
`theorem`, or `sorry` — they are prose scaffolds recording that the
properties are NOT proven. See `proofs/README.md`.

## §3 What the trust base reduces to (no mechanization)

For correctness/interop:

- FIPS 205 SLH-DSA standard (NIST 2024).
- `cloudflare/circl/sign/slhdsa` reference (community-audited).
- Go reference review of the threshold overlay.
- KAT determinism (`ref/go/cmd/genkat`).
- `TestSlhdsaInternal_ByteEqualToCirclSign` /
  `TestMagnetar_Wire_FIPS205Verifiable` /
  `TestThbsSE_Wire_FIPS205Verifiable`.

For confidentiality: the ONLY sound posture is the per-validator
standalone path (no reconstruction). The THBS-SE permissionless path is
research-grade; the TEE pool relocates trust into attested hardware.

## §4 What an auditor should do

1. Read this file and `BLOCKERS.md`.
2. Read `ASSEMBLE-INVARIANT.md` (what THBS-SE Combine does).
3. `cd ref/go && GOWORK=off go build ./...` (clean).
4. `GOWORK=off go test -count=1 -short ./pkg/magnetar/` (green),
   including `TestPVSS_DKG_ProductionTranscriptHidesMaster`.
5. Regenerate KATs and diff (determinism):
   `GOWORK=off go run ./ref/go/cmd/genkat -out=vectors/`,
   `diff -qr vectors_backup/ vectors/`.
6. Read the Go reference: `params.go`, `types.go`, `keygen.go`,
   `sign.go`, `verify.go`, `thbsse.go`, `thbsse_field.go`,
   `thbsse_assemble.go`, `slhdsa_internal.go`, `standalone.go`,
   `pvss_dkg.go`, `key.go`, `zeroize.go`. (NOTE: the v0.x files
   `shamir.go`, `dkg.go`, `threshold.go`, `combine.go` were DELETED;
   any doc still referencing them is stale.)
7. Cross-reference FIPS 205 (NIST 2024) §5--§11 and §10.

## §5 Open items (tracked)

| Item | Status |
|---|---|
| Mechanized refinement of the threshold overlay | OPEN (multi-week; prior track was vacuous, now deleted) |
| No-leak THBS-SE (full MPC over SHAKE) | OPEN RESEARCH |
| Robust dealerless DKG (group-homomorphic or PVSS+NIZK commitments) | OPEN (separate construction) |
| dudect statistical CT harness | OPEN |
| External cryptographer audit | OPEN |
| Cross-implementation FIPS 205 byte-equality (non-circl) | OPEN |
