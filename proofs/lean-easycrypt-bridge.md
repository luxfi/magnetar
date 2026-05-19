# Lean ↔ EasyCrypt Shamir/Lagrange bridge (Magnetar)

## Why this document exists

Magnetar's machine-checked proof stack uses **two complementary
provers**:

* **EasyCrypt** drives the procedure-level refinement / equiv proofs
  for the threshold layer (`proofs/easycrypt/Magnetar_N1.ec`,
  `Magnetar_N4.ec`, the two `*_Refinement.ec` files, the two
  `*_Layout.ec` files, the two `*_Wrapper.ec` files, and
  `Magnetar_N1_Extracted.ec`). EasyCrypt is the right tool for
  procedural Hoare/equiv goals with side-channel-aware semantics —
  but its first-order theory of finite fields and polynomial
  interpolation is comparatively thin.
* **Lean 4 + Mathlib** carries the algebraic content: Shamir
  reconstruction, Lagrange interpolation linearity, finite-field
  polynomial uniqueness. Mathlib has the field theory we'd
  otherwise have to re-axiomatize in EC.

The bridge between them is currently **conceptual** — the EC side
states the algebraic identities it needs as **named axioms** that
correspond 1:1 to **proved Lean theorems** in the sibling repo
`~/work/lux/proofs/lean/Crypto/`.

**Key simplification**: Magnetar's byte-wise Shamir over GF(257) is
**algebraically identical** to Pulsar's GF(257) variant. The four
Shamir / Lagrange axioms Pulsar's bridge enumerates apply VERBATIM
to Magnetar; this document cross-cites them rather than duplicating
the bridge entries.

Magnetar adds ONE Magnetar-specific bridge entry: the cSHAKE256
mix-to-seed first-argument injectivity, which is NIST SP 800-185
content (not Mathlib content).

## Repository pin-points

* EasyCrypt side: `~/work/lux/magnetar/proofs/easycrypt/`.
* Lean side: `~/work/lux/proofs/lean/Crypto/`.

## Axiom-to-theorem mapping

### Cross-cited from Pulsar (algebraically identical byte-wise GF(257))

The following 4 EC axioms exist in `Magnetar_N4.ec` and Magnetar's
threshold layer; the algebraic content is identical to Pulsar and
cross-cited:

#### Axiom 1: `add_share_zeroR`

**EasyCrypt statement** (`proofs/easycrypt/Magnetar_N4.ec`):

```ec
axiom add_share_zeroR : forall (s : share_t), add_share s zero_share = s.
```

**Lean bridge**: `AddCommMonoid` instance fact. Same as Pulsar
`add_share_zeroR` — see
`~/work/lux/pulsar/proofs/lean-easycrypt-bridge.md` § "Axiom 4".

#### Axiom 2: `reconstruct_linear`

**EasyCrypt statement** (`proofs/easycrypt/Magnetar_N4.ec`):

```ec
axiom reconstruct_linear :
  forall (q : int list) (a b : share_t list),
    size a = size q => size b = size q =>
    reconstruct q (zip_add a b) =
      add_share (reconstruct q a) (reconstruct q b).
```

**Lean proof**
(`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:81`,
theorem `combine_distributes_over_sum`):

Same as Pulsar `reconstruct_linear` — see
`~/work/lux/pulsar/proofs/lean-easycrypt-bridge.md` § "Axiom 2".

#### Axiom 3: `shamir_correct`

**EasyCrypt statement** (`proofs/easycrypt/Magnetar_N4.ec`):

```ec
axiom shamir_correct :
  forall (q : int list) (s : share_t),
    uniq q => 1 <= size q =>
    reconstruct q (fresh_sharing q s) = s.
```

**Lean proof**
(`~/work/lux/proofs/lean/Crypto/Pulsar/Shamir.lean:76`,
theorem `shamir_correct_at_target`):

Same as Pulsar `shamir_correct` — see
`~/work/lux/pulsar/proofs/lean-easycrypt-bridge.md` § "Axiom 3".

#### Axiom 4: `lagrange_inverse_eval`

**EasyCrypt statement** (`proofs/easycrypt/Magnetar_N1.ec`):

```ec
axiom lagrange_inverse_eval (s : share_t) (Q : int list) :
  uniq Q =>
  poly_degree s < size Q =>
  reconstruct Q (List.map (poly_eval s) Q) = s.
```

**Lean proof**
(`~/work/lux/proofs/lean/Crypto/Pulsar/Shamir.lean:76`,
theorem `shamir_correct_at_target`) specialized at evaluation 0 via
`Crypto.Threshold.Lagrange.secret_recovery_at_zero`
(`~/work/lux/proofs/lean/Crypto/Threshold_Lagrange.lean:62`).

Same as Pulsar `lagrange_inverse_eval` — see
`~/work/lux/pulsar/proofs/lean-easycrypt-bridge.md` § "Axiom 1".

### Magnetar-specific

#### Axiom 5: `mix_to_seed_injective_byteSum`

**EasyCrypt statement** (`proofs/easycrypt/Magnetar_N1.ec`):

```ec
axiom mix_to_seed_injective_byteSum
        (b1 b2 : share_t) (cr : committee_root_t) :
    mix_to_seed b1 cr = mix_to_seed b2 cr => b1 = b2.
```

**Lean counterpart**
(`~/work/lux/proofs/lean/Crypto/Magnetar/OutputInterchange.lean`,
theorem `mix_to_seed_first_arg_injective`):

The cSHAKE256(input || cr, N="Magnetar", S="MAGNETAR-SEED-SHARE-V1",
seed_size bytes) operation is collision-resistant on its first
argument under the FIPS 202 collision-resistance assumption on
SHAKE256 (and by extension cSHAKE256). At the algebraic level this
gives "different inputs → different outputs with overwhelming
probability"; at the EC level we surface it as an `axiom` because
EasyCrypt's first-order theory of SHAKE is comparatively thin.

This is NOT a Mathlib content axiom (Mathlib does not natively
mechanize SHAKE collision resistance); it is a NIST SP 800-185 content
axiom that the Lean side states identically.

#### Axiom 6: `derive_pk_is_slhdsa_pk_from_seed`

**EasyCrypt statement** (`proofs/easycrypt/Magnetar_N1.ec`):

```ec
axiom derive_pk_is_slhdsa_pk_from_seed (s : seed_t) :
  derive_pk s = SLHDSA_Functional.slhdsa_pk_from_seed s.
```

**Lean counterpart**: This is a pure DEFINITION pin — it asserts the
protocol-level `derive_pk` IS the FIPS 205 §10.1 Algorithm 21 DeriveKey
public projection. In the Lean side this is satisfied by direct
definition (no separate theorem required); the EC side states it as
an axiom because of EC's two-step approach to type aliasing.

## What this bridge does NOT do

It does **not** provide a mechanical proof-object exchange. The EC
axioms are still trusted in the EC dependency cone — the bridge
is a code-review-level mapping, not a formal-method-level one.

The honest closure path is the same as Pulsar's: either mechanize
the Shamir/Lagrange axioms inside EasyCrypt (would require
importing or rebuilding a finite-field polynomial-interpolation
library in EC; multi-week project), or keep the conceptual bridge
and pin the Lean commit in the EC file headers. Option 2 is what
we do.

## Citation comments

Each of the Magnetar EC axioms has an inline comment immediately
preceding it that names the Lean theorem and file. Updating the EC
axiom statement without updating the Lean side (or vice versa)
trips the per-push test for "axiom signature change without bridge
comment update" — the same CI grep gate `scripts/check-lean-bridge.sh`
that Pulsar uses.

## Honest summary

The trust footprint of the extracted Magnetar N1-analog
byte-equality theorem, including the bridge (v0.4.0):

* Implementation-refinement axioms (EC, byte-walks): **2 monolithic**
  (combine + sign). No per-stage decomposition because SLH-DSA
  SignDeterministic is straight-line (no rejection-sampling loop).
* Algebraic-content axioms bridged to Lean: **6** (4 cross-cited from
  Pulsar's Shamir/Lagrange bridge, 1 Magnetar-specific cSHAKE256
  injectivity, 1 derive_pk pin).
* Module-contract axioms in the extracted N1 corollary: **0**.

The full per-version axiom inventory lives in
`AXIOM-INVENTORY.md`.

## Structural comparison

| Pulsar (FIPS 204 ML-DSA) | Magnetar (FIPS 205 SLH-DSA) |
|---|---|
| Rejection-sampling kappa loop | Straight-line (no loop) |
| (c_tilde, z, h) packed signature | Monolithic R || FORS_sig || HT_sig blob |
| 14 residual EC axioms at v8 | 8 residual EC axioms at v0.4.0 (incl. 6 cross-cited) |
| FIPS 204 §3.5.5 codec decomposition | FIPS 205 §10.2 single-blob codec |
| 13 EC files | 9 EC files (including SLHDSA_Functional lemma) |
| MLWE/MSIS lattice algebra | SHAKE collision/preimage resistance |
| 6-month closure path estimate | Comparable (Magnetar reuses 5/6 Pulsar bridges) |

The structural simplification is the value SLH-DSA's hash-based
primitive buys over Dilithium's lattice rejection-sampling primitive.
