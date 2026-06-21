# Magnetar EasyCrypt track (HONEST: empty)

This directory contains **no mechanized EasyCrypt proof**. It holds
two SCAFFOLD files only:

| File | Content |
|---|---|
| `Magnetar_N1_StrictAtom.ec` | 0-content scaffold. Records that THBS-SE Combine byte-equality is NOT proven; explains the prior circular "proof". |
| `Magnetar_N5_PVSS_DKG.ec` | 0-content scaffold. Records that PVSS-DKG secrecy is NOT proven, and that the prior secrecy "theorem" was vacuous AND false for the open-reveal code it modeled. |

Neither file declares an `axiom`, `admit`, `lemma`, or `theorem`.

## Why the rest was deleted

The earlier EC track (`Magnetar_N1_SHAKE_Expand.ec`,
`Magnetar_N1_Atom_Refinement.ec`, `Magnetar_N4_KeyDeriveStable.ec`,
`lemmas/SLHDSA_Functional.ec`, `lemmas/Magnetar_CT.ec`) advertised a
small "admit budget" (5--6 admits) over a set of theorems that proved
nothing: `X = X` rewrites, `conclusion = true` discharged by
`trivial`, a CT lemma discharged by `admit`, and a headline
byte-equality theorem discharged by `apply`-ing an axiom that restated
it verbatim. A nonzero theorem count with a tidy admit budget is not
evidence when the theorems are vacuous. The files were removed rather
than left to imply a proof track exists.

See `../README.md` (proof-track overview) and `../../PROOF-CLAIMS.md`
(per-property breakdown).
