# Magnetar --- proof track (HONEST: there is no mechanized proof)

There is currently **no mechanized proof** of any Magnetar threshold
property. This directory contains SCAFFOLDS only. Read this before
treating anything here as assurance.

## What is actually here

| File | Content |
|---|---|
| `easycrypt/Magnetar_N1_StrictAtom.ec` | SCAFFOLD. 0 mechanized content. Records that THBS-SE Combine byte-equality is NOT proven and explains why the prior "proof" (a theorem `apply`-ing an axiom that restated it) was circular. |
| `easycrypt/Magnetar_N5_PVSS_DKG.ec` | SCAFFOLD. 0 mechanized content. Records that PVSS-DKG secrecy is NOT proven, and that the prior secrecy "theorem" was both vacuous (`conclusion = true`) and false for the open-reveal code it modeled. |
| `lean/Crypto/Magnetar/StrictAtom.lean` | SCAFFOLD. 0 mechanized content. The prior `sorry`-bodied theorem and `:= True` discipline have been removed. |

Each file declares no `axiom`, no `admit`, no `sorry`, no `theorem`,
and no `lemma`. The only occurrences of those words are inside prose
comments that describe what was removed.

## What was deleted, and why

The following files were deleted because every result in them was
vacuous (`X = X` by `rewrite`, or `conclusion = true` by `trivial`)
or a black-box axiom feeding nothing real. They manufactured the
appearance of a "proof track" with a nonzero theorem count and a
small "admit budget" while proving nothing about the construction:

- `Magnetar_N1_SHAKE_Expand.ec` --- only non-axiom lemma was
  `shake_expand m s = shake_expand m s` rewritten from `s = s`.
- `Magnetar_N1_Atom_Refinement.ec` --- a single restate-as-axiom.
- `Magnetar_N4_KeyDeriveStable.ec` --- `s = s' => f s = f s'`, i.e.
  "this function is a function". Content-free.
- `lemmas/Magnetar_CT.ec` --- `strict_atom_combine_is_ct` discharged
  by `admit`; the comment itself called the abstract level "vacuous".
  Constant-time was also the wrong property to claim: the Combine
  path reconstructs the FIPS 205 master, so there is no secret to
  protect from a timing side-channel that is not already in plaintext
  in the combiner's buffer.
- `lemmas/SLHDSA_Functional.ec` --- legitimate black-box FIPS 205
  functional-spec axioms, but they fed only the deleted files.

## Honest summary of the actual evidence base

Magnetar's correctness/interop evidence is empirical, not mechanized:

- Per-validator standalone (`standalone.go`) emits single-party
  FIPS 205 signatures; `TestMagnetar_Wire_FIPS205Verifiable`.
- THBS-SE Combine emits FIPS 205 signatures byte-identical to
  `circl/slhdsa.SignDeterministic` on the reconstructed master;
  `TestSlhdsaInternal_ByteEqualToCirclSign`,
  `TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl`.
- KAT determinism via `ref/go/cmd/genkat`.

These are tests. They establish that the threshold output is a valid
FIPS 205 signature. They do NOT establish any confidentiality / no-leak
property, and there is no mechanized refinement.

See `PROOF-CLAIMS.md` for the per-property proven/asserted/open
breakdown.

## Open work (tracked, not done)

A genuine mechanized result would require an abstract `slh_sign`
model (EasyCrypt or Lean) of the FIPS 205 sec 5--sec 8 hash-tree
signing walk, proven equal to the Go implementation — not to circl,
and not to a restatement of the conclusion. That is multi-week work
and is OPEN.

There is no mechanized no-leak result to target for THBS-SE, because
THBS-SE in the permissionless model reconstructs the master at the
public combiner (research-grade; see `BLOCKERS.md`).
