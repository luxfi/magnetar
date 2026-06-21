# Lean -- EasyCrypt bridge (HONEST: there is no bridge)

There is **no Lean<->EasyCrypt proof bridge** for Magnetar. This
document previously presented a cross-reference table mapping
EasyCrypt axioms to Lean theorems, but:

- The EasyCrypt "theorems" it pointed at were vacuous (a theorem
  whose proof was `apply` of an axiom restating it; lemmas of the
  form `X = X`) and have been deleted or reduced to scaffolds.
- The Lean "theorems" it pointed at (`strict_atom_byte_equality`,
  `strictAtomDisciplineSatisfied`) were a `sorry`-bodied theorem and
  a `Prop := True` definition. Both have been removed.

A "bridge" between two sides that each prove nothing is not a bridge.

## What would a real bridge be

If Magnetar's GF(257) byte-wise Shamir / Lagrange-at-zero algebra
were mechanized in Lean (as Pulsar's reportedly is under
`Crypto.Pulsar.Shamir`), an EasyCrypt protocol proof could cite those
Lean lemmas as discharged algebraic facts. That cross-citation does
NOT exist for Magnetar today: there is no EasyCrypt protocol proof to
cite into, and the cross-citation was never machine-checked.

See `proofs/README.md` and `PROOF-CLAIMS.md` for the honest state.
