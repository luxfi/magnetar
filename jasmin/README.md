# Magnetar --- Jasmin high-assurance track

This directory holds the **Jasmin** sources for the Magnetar v1.0
single-party SLH-DSA core. Jasmin
(https://github.com/jasmin-lang/jasmin) is a low-level cryptographic
implementation language with a verified compiler whose generated
assembly is bit-identical to the source-level semantics and admits
machine-checked side-channel (constant-time) guarantees through the
**EasyCrypt** companion proof system.

## Magnetar v1.0 Jasmin scope

Magnetar v1.0 ships TWO primitives:

| Primitive | Jasmin coverage |
|---|---|
| **Per-validator standalone** (`ref/go/pkg/magnetar/standalone.go`) | Routes through `cloudflare/circl/sign/slhdsa` v1.6.3 in production. Single-party FIPS 205 functional + constant-time analysis tracks the formosa-crypto `libjade-SLH-DSA` upstream when it lands (see `slh-dsa/`). |
| **THBS-SE** (`ref/go/pkg/magnetar/thbsse.go` + `thbsse_field.go`) | Pure-Go reference; the field-arithmetic surface (GF(257) byte-wise Shamir + Lagrange interpolation) is small enough that the analysis lives in EasyCrypt directly. No standalone Jasmin track for v1.0. |

The Magnetar v1.0 Jasmin track is therefore **single-party SLH-DSA
only** --- the layer where formosa-crypto upstream provides verified
sources. THBS-SE byte-equality to FIPS 205 SignDeterministic falls
out of the construction (the public combiner routes through the SAME
single-party `slhdsa.SignDeterministic` call), so the single-party
verified track transitively covers the THBS-SE output path.

The THBS-SE share-arithmetic surface (`thbsse_field.go`) is
straight-line GF(257) modular arithmetic with constant-time intent:
no secret-dependent branches in `thbsseModInvSmall` /
`thbsseModPowSmall` / Lagrange basis computation; the share VALUES
flow into the multiplications as inputs, but the exponent in Fermat's
little theorem is the PUBLIC prime p-2. The EasyCrypt theory at
`../proofs/easycrypt/` carries the share-arithmetic claims; no
separate Jasmin lift is required for v1.0.

## When the strict-atom-assembly path lands (v1.1)

The `BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11` work item lifts the
THBS-SE public combiner from "transient seed reconstruction" to
"strict per-atom FORS/WOTS reconstruction". At that point a small
Magnetar-internal re-implementation of FIPS 205 sec 5/6/7/8 enters
the trusted computing base: the per-atom WOTS+ chain compute and
FORS sign step become the new CT-critical surfaces, and a Magnetar-
specific Jasmin track becomes the right tool to gate them.

That track is scoped at v1.1; for v1.0 the libjade-SLH-DSA upstream
trace (when it lands) is the canonical single-party CT story.

## Directory layout

- `slh-dsa/` --- placeholder for the upstream libjade-SLH-DSA tree
  (Jasmin sources + EasyCrypt extracted proofs). The README there
  documents the upstream status and the future routing. `fetch.sh`
  is the future on-demand pull script.

The legacy v0.x `threshold/` and `lib/` subtrees that modeled the
seed-recombine path have been removed for v1.0 (they corresponded to
the abandoned reveal-and-aggregate variant). THBS-SE has no Jasmin-
internal threshold layer --- the share math lives in pure Go
(`thbsse_field.go`) and is covered by the EasyCrypt theory above.

## How to check

```bash
../scripts/check-high-assurance.sh
```

The script is **skip-friendly**: if `jasminc` or `easycrypt` is not
on the system PATH it prints a clear skip message and exits 0.

## Tool installation

- **Jasmin compiler** --- https://github.com/jasmin-lang/jasmin#installation
  (OPAM: `opam install jasmin`). The reference platform is OCaml
  4.14 with Coq 8.18.
- **EasyCrypt** --- https://github.com/EasyCrypt/easycrypt#installation
  (OPAM: `opam install easycrypt`). Backend SMT solvers (Alt-Ergo,
  Z3, CVC4) must be installed via `why3 config detect`.

## Citations

- Almeida, Barbosa, Barthe, Blot, Gregoire, Laporte, Oliveira,
  Pacheco, Schwabe, Strub. *The last mile: High-assurance and
  high-speed cryptographic implementations.* IEEE S&P 2020.
- NIST FIPS 205 --- Stateless Hash-Based Digital Signature Standard
  (2024).
- Bernstein et al. --- SPHINCS+ submission to NIST PQC.
- Shamir, A. --- *How to share a secret.* Communications of the ACM,
  1979.
- Schoenmakers, B. --- *A simple publicly verifiable secret sharing
  scheme and its application to electronic voting.* CRYPTO 1999.
