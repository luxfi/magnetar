# Lean -- EasyCrypt bridge (Magnetar v1.1)

This document is the cross-reference table between the Magnetar
EasyCrypt theories and the Lean theorems they cite. The bridge lets
the EasyCrypt side treat algebraic / hash-functional content as
black-box axioms while the Lean side carries the corresponding
proofs (or proof statements) in a dependent type theory.

## Direction

- The EasyCrypt theory shells are AUTHORITATIVE for the protocol-level
  byte-equality statement (the strict-atom Combine output equals the
  FIPS 205 SignDeterministic dispatch).
- The Lean theories are AUTHORITATIVE for the algebraic content
  (byte-wise Shamir over GF(257), Lagrange interpolation at x=0,
  SHAKE-256 functional spec).
- Cross-references are explicit at the axiom-declaration site in
  EasyCrypt.

## Cross-cited axioms

| EasyCrypt axiom | Lean theorem | Lean location |
|---|---|---|
| `lagrange_recovers_master` (Magnetar_N1_StrictAtom.ec) | `byte_wise_shamir_lagrange_at_zero_identity` | `Crypto/Magnetar/StrictAtom.lean` (+ shared with `Crypto/Pulsar/Shamir.lean`) |
| `shake256_functional` (Magnetar_N1_SHAKE_Expand.ec) | `shake256_functional` | `Crypto/Magnetar/StrictAtom.lean` (+ shared with `Crypto/Lux/SHA3.lean`) |
| `slhdsa_correctness` (lemmas/SLHDSA_Functional.ec) | NIST FIPS 205 sec 10 (external reference) | n/a |
| `combine_assemble_axiom` (Magnetar_N1_StrictAtom.ec) | n/a (Go extraction trust boundary) | n/a |
| `magnetar_internal_refines_circl` (Magnetar_N1_Atom_Refinement.ec) | n/a (discharged by Go test `TestSlhdsaInternal_ByteEqualToCirclSign`) | n/a |

## What is shared with Pulsar

Magnetar's byte-wise Shamir over GF(257) is ALGEBRAICALLY IDENTICAL
to Pulsar's; the difference is only what is shared. Magnetar shares
the SLH-DSA scheme seed; Pulsar shares the ML-DSA private key
vector. The Shamir polynomial machinery, the GF(257) modular
arithmetic, the Lagrange basis at x=0, and the Lagrange-recovers-
master identity are the SAME and live in Lean under
`Crypto.Pulsar.Shamir`. Magnetar cross-cites those theorems.

## What is unique to Magnetar v1.1

The strict-atom discipline statement is unique to Magnetar v1.1:

- `strict_atom_byte_equality` (Lean) corresponds to
  `magnetar_n1_strict_atom_byte_equality` (EasyCrypt) corresponds to
  `TestThbsSE_StrictAtom_NoTransientSeed` + `TestSlhdsaInternal_
  ByteEqualToCirclSign` + `TestThbsSE_StrictAtom_Combine_ByteIdentity
  ToCircl` (Go test suite).

- The abstract-model discipline statement
  `strict_atom_discipline_satisfied` (EC) corresponds to
  `strictAtomDisciplineSatisfied` (Lean) corresponds to the AST grep
  check in `TestThbsSE_StrictAtom_NoTransientSeed`.

## v1.0 -> v1.1 delta

- v0.x bridges modelled the abandoned reveal-and-aggregate
  construction; removed at v1.0.
- v1.0 ship state: no proof bridge in repo (the bridge re-lands at
  v1.1 alongside the strict-atom construction; this is the present
  document).
- v1.1: 2 Magnetar-specific cross-cites + 1 shared Pulsar Shamir
  cross-cite + 1 shared Lux SHA3 cross-cite + 2 NIST/Go-extraction
  external references.
