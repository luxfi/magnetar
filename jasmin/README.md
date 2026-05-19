# Magnetar — Jasmin high-assurance track

This directory holds the **Jasmin** sources for the Magnetar threshold
layer. Jasmin (https://github.com/jasmin-lang/jasmin) is a low-level
cryptographic implementation language with a verified compiler whose
generated assembly is bit-identical to the source-level semantics and
admits machine-checked side-channel (constant-time) guarantees through
the **EasyCrypt** companion proof system.

## Track layout

For Magnetar, the high-assurance plan splits along the SLH-DSA
single-party / threshold layer boundary:

| Layer | What Jasmin verifies | Source of truth |
|---|---|---|
| **Single-party SLH-DSA-SHAKE-192s core** | Functional equivalence to FIPS 205 + constant-time over secret key paths | Reference Jasmin source under `slh-dsa/` (advisory). Production routes through `cloudflare/circl/sign/slhdsa` |
| **Threshold layer** (Round-1 commit, Round-2 reveal, Combine) | Functional correctness of the byte-wise Shamir VSS over GF(257) + constant-time over each party's secret share | new (`threshold/`, this submission) |

The Class N1-analog byte-equality claim composes the two: a Magnetar
threshold signature is a single-party FIPS 205 signature whose
underlying byte-string has been produced by `SignDeterministic` on
the master seed reconstructed from t shares.

So the Magnetar Jasmin proof chain is:

    SLH-DSA-SHAKE-192s (functional ≡ FIPS 205)
      ∘ Magnetar threshold (functional ≡ single-party computation
                               under honest quorum + byte-wise
                               Shamir secret-recovery identity)
      ⇒ Magnetar output ≡ FIPS 205 output (Class N1-analog)

with constant-time taken as a side condition on every secret-dependent
control- and memory-access path.

## Structural simplification vs Pulsar

Pulsar's Jasmin threshold layer is large (3 files, ~1500 LOC total)
because it operates on FIPS 204 ML-DSA polynomial vectors in R_q^l
(R_q = Z_q[X]/(X^256+1), q = 8380417). The Lagrange coefficient
computation alone is 242 LOC (`lib/lagrange.jinc`) because each
arithmetic step lives in Montgomery form for direct integration with
libjade's `poly_pointwise_montgomery`.

Magnetar's Jasmin threshold layer is structurally simpler because:

1. Shares live in **GF(257)**, not R_q^l. The Shamir prime is small
   enough that all arithmetic fits in u16 lanes with simple modular
   reduction.
2. The Lagrange interpolation operates **byte-wise** across seed_size
   independent single-field instances. No NTT, no polynomial
   multiplication, no Montgomery domain juggling.
3. No rejection-sampling kappa loop. The Combine path is straight-
   line.

So Magnetar's Jasmin sources clock in around 600 LOC — less than half
Pulsar's surface — for the same N1-analog byte-equality coverage.

## Files

- `lib/magnetar_params.jinc` — protocol-layer parameter set (Shamir
  prime, seed size, quorum cap).
- `lib/lagrange_gf257.jinc` — byte-wise Lagrange coefficient
  computation over GF(257). Constant-time over the (public)
  eval-point set.
- `lib/transcript.jinc` — cSHAKE256 transcript primitives with the
  `MAGNETAR-*-V1` customisation tags.
- `lib/seed.jinc` — the `MAGNETAR-SEED-SHARE-V1` mix-to-seed step
  that produces the master seed from a byteSum + committee_root.
- `threshold/round1.jazz` — per-party Round-1 commit message.
- `threshold/round2.jazz` — per-party Round-2 reveal message.
- `threshold/combine.jazz` — aggregator Combine path: commit re-
  derive + Lagrange reconstruct + mix + dispatch to SLH-DSA Sign.
- `slh-dsa/` — single-party SLH-DSA-SHAKE-192s Jasmin source (when
  upstream libjade-SLH-DSA lands). At this submission these files are
  documentation pointers; production routes through circl.

## Status — initial track

This is the **initial** high-assurance scaffolding for the
submission. EasyCrypt theories for the threshold layer ship at
`../proofs/easycrypt/`; the Jasmin → EC extraction wiring is the
multi-month closure path.

What we commit at submission time:

1. Threshold-specific Jasmin **function signatures and algorithm
   commentary** in `threshold/{round1,round2,combine}.jazz`. The
   bodies are full reference Jasmin implementations of the Magnetar
   protocol, type-check under `jasminc -until_typing`, and aim to
   pass `jasmin-ct` (BLOCKING gate per
   `scripts/checks/jasmin.sh`).
2. EasyCrypt **theory shells** in `../proofs/easycrypt/`. The
   Class N1-analog lemma is stated and proved (admit 0/0).

## How to check

```bash
../scripts/check-high-assurance.sh
```

The script is **skip-friendly**: if `jasminc` or `easycrypt` is not
on the system PATH it prints a clear skip message and exits 0.

## Tool installation

- **Jasmin compiler** — https://github.com/jasmin-lang/jasmin#installation
  (OPAM: `opam install jasmin`). The reference platform is OCaml
  4.14 with Coq 8.18.
- **EasyCrypt** — https://github.com/EasyCrypt/easycrypt#installation
  (OPAM: `opam install easycrypt`). Backend SMT solvers (Alt-Ergo,
  Z3, CVC4) must be installed via `why3 config detect`.

## Citations

- Almeida, Barbosa, Barthe, Blot, Grégoire, Laporte, Oliveira,
  Pacheco, Schwabe, Strub. *The last mile: High-assurance and
  high-speed cryptographic implementations.* IEEE S&P 2020.
- NIST FIPS 205 — Stateless Hash-Based Digital Signature Standard
  (2024).
- Bernstein et al. — SPHINCS+ submission to NIST PQC.
- Shamir, A. — *How to share a secret*. Communications of the ACM,
  1979.
