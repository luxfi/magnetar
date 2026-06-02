# Magnetar v1.1 EasyCrypt theory track

Magnetar v1.1 closes `MAGNETAR-STRICT-ATOM-V11` by ripping out the
v1.0 transient seed reconstruction at the public combiner and routing
the Combine output through a Magnetar-internal FIPS 205 §5--§8
implementation that assembles the wire-form signature byte stream
directly from per-byte Lagrange shares. The mechanised proof track
catches up.

## Theory files

| File | Role | Admit budget |
|---|---|---|
| `Magnetar_N1_StrictAtom.ec` | Class N1-analog byte-equality for the strict-atom Combine path. Asserts byte-identity between `assembleSignatureBytes` (the Go strict-atom emitter) and `slh_sign_deterministic(sk_from_seed(S), m, ctx)`. | 1 |
| `Magnetar_N1_SHAKE_Expand.ec` | The FIPS 205 §10.1 SHAKE expansion that lifts the byte-shared master `S` into `(skSeed, skPrf, pkSeed)`. The Lagrange-sum-then-SHAKE composition is byte-equal to circl's `scheme.DeriveKey` on the same input. | 1 |
| `Magnetar_N1_Atom_Refinement.ec` | The strict-atom refinement: the FIPS 205 §5--§8 byte stream emitted by `slhSignAtom` (the Go internal engine) is byte-equal to the byte stream emitted by `circl/slhdsa.SignDeterministic` when both are fed the same `(skSeed, skPrf, pkSeed, pkRoot, msg, ctx)`. | 1 |
| `Magnetar_N4_KeyDeriveStable.ec` | The same-master-yields-same-pk lemma used downstream by reshare/rotation analysis. | 0 |
| `lemmas/SLHDSA_Functional.ec` | The FIPS 205 single-party correctness axiom and the SHAKE-256 PRF/PRF_msg/F/H/T_l/H_msg functional definitions (per FIPS 205 §11.2 SHAKE family). | 4 |
| `lemmas/Magnetar_CT.ec` | Bernstein-Garcia-Levy leakage-model CT lemmas: the strict-atom Combine path has no secret-dependent branch and emits no secret-dependent timing through the `prfAbsorb` / `prfMsgAbsorb` scratch buffers. | 1 |

## Axiom inventory (v1.1)

The trust footprint:

1. `lagrange_inverse_eval` (algebraic; byte-wise Lagrange@0 identity in
   GF(257)). Cross-cited from `Crypto.Pulsar.Shamir` Lean. Magnetar
   shares the same byte-wise Shamir construction as Pulsar.
2. `shake256_functional` (FIPS 202 SHAKE-256 functional spec; the
   sponge construction is treated as a black-box H : bytes -> bytes
   with the absorb-then-squeeze interface). Cross-cited from
   `Crypto.Lux.SHA3` Lean.
3. `slhdsa_correctness` (FIPS 205 single-party correctness; from FIPS
   205 §10 / NIST verification). Treated as a black-box
   functional spec.
4. `combine_assemble_axiom` (the Go extraction trust boundary: the
   extracted `assembleSignatureBytes` function refines the abstract
   `AssembleAbs` model on which `magnetar_n1_strict_atom_byte_equality`
   is discharged). This is the single line of code the audit
   reads byte-for-byte against the proof's abstract model.
5. `magnetar_internal_refines_circl` (the Magnetar-internal §5--§8
   walk refines circl's FIPS 205 dispatch for the SHAKE families;
   discharged via the headline byte-identity gate
   `TestSlhdsaInternal_ByteEqualToCirclSign` per-mode).

## Cross-reference to Lean

The Lean side ships `Crypto.Magnetar.StrictAtom` carrying:

- The byte-wise Shamir identity (shared with Pulsar's `Shamir.lean`).
- The Lagrange-at-zero composition lemma.
- The `assembleSignatureBytes` -> `slh_sign_deterministic` abstract
  refinement bridge.

See `~/work/lux/magnetar/proofs/lean/Crypto/Magnetar/` for the Lean
source.

## v1.0 -> v1.1 delta

The v1.0 (deleted) theories modeled the seed-reconstruction
`combine.go` and the `slhSignDeterministic` dispatch. The v1.1
theories model:

- `thbsse_assemble.go::assembleSignatureBytes` (the strict-atom emit
  path).
- `slhdsa_internal.go::slhSignAtom` (the Magnetar-internal FIPS 205
  §5--§8 walk that the strict-atom path drives).

The byte-identity claim is the SAME (Magnetar emits FIPS 205
wire-format signature bytes any unmodified verifier accepts), but the
abstract model now has the additional constraint that the FIPS 205
master byte material flows through positional slices of a single
SHAKE-output buffer, never through a free-standing named variable.

The mechanised statement of the strict-atom discipline is in
`Magnetar_N1_StrictAtom.ec`'s top-level theorem:

```
theorem magnetar_n1_strict_atom_byte_equality :
  forall pkBytes msg ctx picks lambdas,
    valid_quorum picks =>
    lagrange_basis_at_zero picks = lambdas =>
    assemble_signature_bytes pkBytes msg ctx picks lambdas
      = slh_sign_deterministic (sk_from_seed (lagrange_sum picks)) msg ctx.
```

The discipline is reflected in the abstract model `AssembleAbs`,
which mediates the Lagrange reconstruction through the SHAKE absorb
buffers ONLY at the FIPS 205 §11.2 PRF and PRF_msg call sites.
