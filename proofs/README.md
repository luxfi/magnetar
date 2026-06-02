# Magnetar --- machine-checked proof track

Magnetar v1.1 closes `MAGNETAR-STRICT-ATOM-V11` and lands the
mechanised proof track for the strict-atom Combine path. Both
primitives (per-validator standalone + THBS-SE strict-atom) are
covered.

## What ships at v1.1

| Layer | Path |
|---|---|
| EasyCrypt theory shells | `proofs/easycrypt/` |
| Lean bridge (algebraic) | `proofs/lean/Crypto/Magnetar/` |
| Bridge doc | `proofs/lean-easycrypt-bridge.md` |

The construction shape covered by the proof track:

- The strict-atom emitter `assembleSignatureBytes`
  (`ref/go/pkg/magnetar/thbsse_assemble.go`).
- The Magnetar-internal FIPS 205 sec 5/6/7/8 walk `slhSignAtom`
  (`ref/go/pkg/magnetar/slhdsa_internal.go`).
- The byte-wise Shamir over GF(257) + Lagrange interpolation at x=0
  (`ref/go/pkg/magnetar/thbsse_field.go`).
- The byte-identity claim that ties the strict-atom Combine output to
  `cloudflare/circl/sign/slhdsa.SignDeterministic` on the same input.

## Axiom budget

The strict-atom theory has 5 admits across the dependency cone:

| Axiom | File | Discharge mechanism |
|---|---|---|
| `combine_assemble_axiom` | `Magnetar_N1_StrictAtom.ec` | Go extraction trust boundary; audit reads `assembleSignatureBytes` line-for-line against the abstract `AssembleAbs` model. |
| `shake256_functional` | `Magnetar_N1_SHAKE_Expand.ec` | FIPS 202 functional spec. Cross-cited from Lean `Crypto.Lux.SHA3`. |
| `magnetar_internal_refines_circl` | `Magnetar_N1_Atom_Refinement.ec` | Discharged by Go test `TestSlhdsaInternal_ByteEqualToCirclSign` per SHAKE mode. |
| `slhdsa_correctness` | `lemmas/SLHDSA_Functional.ec` | FIPS 205 sec 10 NIST verification. |
| `lagrange_recovers_master` | `Magnetar_N1_StrictAtom.ec` | Algebraic; Lean-bridged to `Crypto.Magnetar.StrictAtom.byte_wise_shamir_lagrange_at_zero_identity`. |
| (CT) abstract-level vacuous | `lemmas/Magnetar_CT.ec` | Concrete CT discharged by direct audit of strict-atom Combine path Go source. |

Total: 6 admits (5 substantive + 1 abstract-vacuous), corresponding to
the trust footprint enumerated in `proofs/easycrypt/README.md`. This is
the same shape as the v0.4 EC track (1 byte-walk + 1 codec + 3
protocol-level + 1 FIPS 205) but specialised to the strict-atom
construction.

## v1.0 -> v1.1 delta

The v0.x EC scaffolding (modelled the abandoned reveal-and-aggregate
construction) was removed at v1.0; the v1.1 track is built directly
against the strict-atom Combine path.

The Lean side carries the abstract-model discipline statement
`strict_atom_discipline` (vacuous at the abstract level; the concrete
discipline is enforced by the Go test
`TestThbsSE_StrictAtom_NoTransientSeed`).

## Per-push gate

The `scripts/check-high-assurance.sh` orchestrator runs:

- `scripts/checks/go-tests.sh` (v1.0 scope; carries forward unchanged).
- `scripts/checks/strict-atom-ast.sh` (NEW at v1.1): runs the
  `TestThbsSE_StrictAtom_NoTransientSeed` AST + grep invariant gate
  per-push. The AST gate is a fast check that the strict-atom
  discipline holds on the file.
- `scripts/checks/easycrypt.sh` (NEW at v1.1): smoke-checks the EC
  theory shells for syntax / require / import consistency. Full
  EasyCrypt re-run is a release-time gate, not per-push, because
  EC is heavy to bring up (the per-push gate runs in <60s; full EC
  takes the EC project's standard hour to run).
