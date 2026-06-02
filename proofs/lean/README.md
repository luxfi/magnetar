# Magnetar v1.1 Lean bridge

The Lean bridge carries the algebraic invariants that the EasyCrypt
theories cross-cite. Two top-level claims live here:

1. `byte_wise_shamir_lagrange_at_zero_identity` --- byte-wise Shamir
   + Lagrange-at-zero over GF(257) is the left inverse of polynomial
   evaluation at distinct non-zero points. Shared with
   `Crypto.Pulsar.Shamir`.

2. `shake256_functional` --- the FIPS 202 SHAKE-256 functional spec
   (same input + output length yields the same byte stream). Shared
   with `Crypto.Lux.SHA3`.

## Files

| File | Role |
|---|---|
| `Crypto/Magnetar/StrictAtom.lean` | The strict-atom byte-equality theorem statement + the discipline statement (abstract-level no-op). |

## Build

The Lean bridge requires Lean 4 (>= v4.5.0). It is intended to be
loaded as part of the broader `Crypto.Lux` Lean library; build
configuration in this checkout is minimal (the bridge is text-only
verification surface, not an executable). Cross-citations to
`Crypto.Pulsar.Shamir` and `Crypto.Lux.SHA3` are RESOLVED in the
sibling `~/work/lux/proofs/lean/Crypto/` checkout.

## v1.0 -> v1.1 delta

The v1.0 Lean bridge modeled the byte-wise Shamir layer shared with
Pulsar. v1.1 adds the strict-atom byte-equality theorem with the
abstract-model discipline statement. The shared Shamir layer is
unchanged (the byte-wise GF(257) construction is algebraically
identical between Magnetar and Pulsar).
