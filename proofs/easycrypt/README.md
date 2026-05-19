# Magnetar — EasyCrypt theories

This directory holds the **EasyCrypt** theories for Magnetar's
high-assurance track. EasyCrypt
(https://github.com/EasyCrypt/easycrypt) is the machine-checked
proof assistant for cryptographic protocols. Jasmin sources live at
`../../jasmin/`. The single-party FIPS 205 SLH-DSA functional spec
is in-house at `lemmas/SLHDSA_Functional.ec`.

## Headline

The Class-N1-analog byte-equality theorem `magnetar_n1_byte_equality`
is proved against the protocol-level Magnetar_Threshold abstract
module. The concrete extracted corollary
`magnetar_n1_byte_equality_extracted` composes the two wrapper-bridge
lemmas; the entire dependency cone is **admit 0/0**.

The structural simplification vs Pulsar's analogue (FIPS 204 ML-DSA):
SLH-DSA SignDeterministic is straight-line (no rejection-sampling
loop). So Magnetar's Combine-side byte-walk has ONE atomic axiom
instead of Pulsar's per-stage (c_tilde, z, h) decomposition.

## Status — current trust boundary

| Item | Count |
|---|---|
| Section-local module-contract axioms in extracted N1 corollary | **0** |
| Localized implementation-refinement axioms in dependency cone | **2** |
| Lean-bridged algebraic axioms (Lagrange/Shamir) | **5** (cross-cited from Pulsar) |
| EasyCrypt `admit` budget | **0 / 0** |
| EC files in the per-push gate | **9** |
| `declare axiom` in refinement scaffolds | **0** |

The 2 implementation-refinement axioms are atomic byte-walks over
the extracted Go body:

- `Magnetar_N1_Combine_Refinement.combine_body_compute_sig_spec`
  (covers `ref/go/pkg/magnetar/combine.go` lines 47-206: Round-2
  commit-bind loop, Lagrange reconstruct, cSHAKE256 mix, KeyFromSeed,
  SignDeterministic dispatch — all monolithic since SLH-DSA is
  straight-line)
- `Magnetar_N1_Sign_Refinement.sign_body_compute_sig_spec`
  (covers `ref/go/pkg/magnetar/sign.go::slhSign` — pure dispatch to
  `cloudflare/circl/sign/slhdsa.SignDeterministic`)

The 5 Lean-bridged axioms are the same Shamir / Lagrange algebraic
identities that EasyCrypt's first-order theory does not natively
cover. They are CROSS-CITED from Pulsar's
`~/work/lux/pulsar/proofs/lean-easycrypt-bridge.md` because the
byte-wise Shamir over GF(257) construction is **algebraically
identical** between Pulsar and Magnetar; only the post-Lagrange
mix-and-derive step differs (cSHAKE256 mix + `slhdsa.DeriveKey`
instead of cSHAKE256 mix + `mldsa.DeriveKey`).

## Files

Layered structure (each file owns one concern; the dependency
graph is acyclic and explicit):

| File | Concern |
|---|---|
| `Magnetar_N1.ec` | Class N1-analog protocol-level spec: abstract types, Magnetar_Threshold + SLHDSA_Sign module types, FIPS205Sign + CombineAbs modules, generic `magnetar_n1_byte_equality` theorem inside `section ClassN1` |
| `Magnetar_N4.ec` | Class N4-analog: public-key preservation across proactive resharing (committee rotation). Discharged against concrete `ReshareHonest` module |
| `Magnetar_N1_Memory.ec` | Byte-memory model: `mem_t`, load/store primitives + proved frame laws. No axioms |
| `Magnetar_N1_Signature_Codec.ec` | FIPS 205 §10.2 signature codec: `signature_t`, encode/decode/length, memory read/write + proved frame lemmas |
| `Magnetar_N1_Combine_Layout.ec` | Combine wire layout: ptrs + abstract args + layout predicate + disjointness + read_signature_at/write_signature_at |
| `Magnetar_N1_Sign_Layout.ec` | Single-party Sign wire layout: ptrs + abstract args + layout predicate + disjointness |
| `Magnetar_N1_Combine_Refinement.ec` | Combine refinement scaffold: `combine_full_args_t` ghost args, `combine_abs_op` definition, the ONE atomic byte-walk axiom, derived lemmas |
| `Magnetar_N1_Sign_Refinement.ec` | Sign refinement scaffold: `sign_full_args_t`, `sign_abs_op` definition, the ONE atomic byte-walk axiom, derived lemmas |
| `Magnetar_N1_Combine_Wrapper.ec` | Combine wrapper module + bridge lemma + procedure-level equiv against `CombineAbs` |
| `Magnetar_N1_Sign_Wrapper.ec` | Sign wrapper module + bridge lemma + procedure-level equiv against `FIPS205Sign` |
| `Magnetar_N1_Extracted.ec` | Composition: the concrete extracted N1 byte-equality corollary |
| `lemmas/SLHDSA_Functional.ec` | FIPS 205 §10 in-house functional spec: params, types, slhdsa_key_from_seed, slhdsa_sign_deterministic, slhdsa_verify, correctness axiom (NIST-anchored) |
| `lemmas/Magnetar_CT.ec` | Constant-time obligations under the Barthe–Grégoire–Laporte leakage model |

Dependency layering:

```
Magnetar_N1 ──┐
              │
Memory ── Signature_Codec ── SLHDSA_Functional
   │              │                  │
   ├── Combine_Layout              Sign_Layout
   │      │                          │
   │      Combine_Refinement         Sign_Refinement
   │          │                      │
   │      Combine_Wrapper             Sign_Wrapper
   │          │_________ Extracted ___│
   │
   └── (Magnetar_N1: protocol types + module types + generic theorem)
```

## Conventions

- `admit` is banned (budget 0/0; enforced by
  `../../scripts/checks/ec-admits.sh`).
- `declare axiom` is banned in refinement scaffolds (enforced by
  `../../scripts/checks/ec-refinement-scaffold.sh`).
- Lean-bridged axioms carry an inline citation comment naming the
  Lean theorem and file (enforced by
  `../../scripts/check-lean-bridge.sh`).
- Per-push gate is real-budget:
  `../../scripts/check-high-assurance.sh` runs every check at
  budget that matters.

## How to check

Per-push:

```bash
../../scripts/check-high-assurance.sh    # proof gate
../../scripts/test.sh                    # Go test gate
```

Per-check (independently runnable):

```bash
bash ../../scripts/checks/ec-compile.sh
bash ../../scripts/checks/jasmin.sh
bash ../../scripts/checks/ec-admits.sh
bash ../../scripts/check-lean-bridge.sh
```

## Citations

- NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard
  (2024).
- Bernstein et al. — SPHINCS+ submission to NIST PQC.
- Shamir, A. — *How to share a secret*. Communications of the ACM,
  1979.
- Barthe, Grégoire, Laporte. *Secure compilation of side-channel
  countermeasures: The case of cryptographic constant-time.* CSF 2018.
- Almeida et al. *Formally verifying Kyber.* CRYPTO 2024.
- Pulsar Tier A reference: `~/work/lux/pulsar/proofs/easycrypt/`
  (Magnetar's Shamir / Lagrange axioms are CROSS-CITED from
  Pulsar's Lean ↔ EC bridges).

## Cross-references

- `../lean-easycrypt-bridge.md` — Magnetar-specific Lean↔EC axiom
  correspondence + cross-citation to Pulsar's shared Shamir bridges
- `~/work/lux/proofs/lean/Crypto/Magnetar/OutputInterchange.lean` —
  Lean output-interchangeability theorem
- `~/work/lux/proofs/lean/Crypto/Magnetar/Unforgeability.lean` —
  Lean threshold-strong-unforgeability theorem (reduction-statement
  form)
- `~/work/lux/proofs/lean/Crypto/Pulsar/Shamir.lean` — shared Shamir
  correctness theorem (Magnetar reuses verbatim)
- `~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean` — shared
  Lagrange interpolation theorems
- `../../ct/dudect/` — empirical constant-time validation harness
