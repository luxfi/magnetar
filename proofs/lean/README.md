# Magnetar Lean bridge (HONEST: empty)

This directory contains **no mechanized Lean proof** for Magnetar.

`Crypto/Magnetar/StrictAtom.lean` is a 0-content scaffold. Its prior
`strict_atom_byte_equality` theorem had a `sorry` body, and its
`strictAtomDisciplineSatisfied : Prop := True` proved nothing about
the code; both were removed.

The file now declares no `theorem`, no `axiom`, no `def`, and no
`sorry`. It exists only to record, in the proof tree, that THBS-SE
strict-atom byte-equality is NOT mechanized in Lean.

There is no Magnetar-specific Lean algebra here. If the GF(257)
byte-wise Shamir / Lagrange-at-zero identity were needed as a
discharged fact, it would have to be cited from a real
`Crypto.Pulsar.Shamir` development; no such cross-citation is
machine-checked for Magnetar today.

See `../README.md` and `../../PROOF-CLAIMS.md` for the honest state.
