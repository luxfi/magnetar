/-
Copyright (c) 2025-2026 Lux Industries Inc. All rights reserved.
Released under the same license as the rest of Magnetar.
-/

/-!
# Crypto.Magnetar.StrictAtom

SCAFFOLD: 0 mechanized content. This file proves NOTHING.

## Honest status

The earlier revision of this file declared a theorem
`strict_atom_byte_equality` whose proof body was `sorry`, and a
definition `strictAtomDisciplineSatisfied : Prop := True` with a
companion `theorem strict_atom_discipline := trivial`. A `sorry`
discharges nothing, and a `True`-valued "discipline" proves nothing
about the code. Both have been removed.

## What the code actually does

The THBS-SE Combine path
(`ref/go/pkg/magnetar/thbsse_assemble.go::assembleSignatureBytes`)
Lagrange-reconstructs the FIPS 205 master byte vector, SHAKE-expands
it into a single buffer holding `skSeed || skPrf || pkSeed`, and
emits a FIPS 205 signature. The full master is present in the public
combiner's memory for the duration of one Sign call. Renaming the
buffer to avoid the identifier `seed` does NOT establish any no-leak
property. There is nothing here for Lean to certify as confidential.

The only empirically supported property is byte-IDENTITY of the
emitted signature to `circl/slhdsa.SignDeterministic` on the
reconstructed master (a correctness/interop property), witnessed by
the Go tests `TestSlhdsaInternal_ByteEqualToCirclSign` and
`TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl`. No Lean theorem
backs it.

A genuine result would require an abstract Lean model of the FIPS 205
hash-tree signing walk proven equal to the Go implementation — not a
`sorry`, and not a `True`. That work is OPEN and is tracked in
`PROOF-CLAIMS.md`.

This file intentionally declares no `theorem`, no `axiom`, no `sorry`,
and no `def`. It is a documentation stub only.
-/

namespace Crypto.Magnetar.StrictAtom

-- Intentionally empty. See the module banner: this is a 0-content
-- scaffold. It exists only to record, in the proof tree, that the
-- THBS-SE strict-atom byte-equality is NOT mechanized.

end Crypto.Magnetar.StrictAtom
