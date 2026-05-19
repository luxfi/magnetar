# SLH-DSA single-party Jasmin source (placeholder)

Magnetar's single-party path routes through
`cloudflare/circl/sign/slhdsa` in production. This directory holds the
future home for the formosa-crypto upstream **libjade-SLH-DSA** sources
when they land.

## Current upstream status (as of 2026-05)

The formosa-crypto `libjade` project (https://github.com/formosa-crypto/libjade)
ships Jasmin sources and EasyCrypt proofs for:

- ML-KEM (Kyber, NIST PQC ML-KEM standard)
- ML-DSA (Dilithium, FIPS 204 — used by Pulsar)
- Curve25519 + Poly1305 (classical)

SLH-DSA (FIPS 205, SPHINCS+) Jasmin sources are **not yet upstream**.
There is community work in progress; see the formosa-crypto issue
tracker for the canonical pointer.

## What ships in this directory

- This README pointing at upstream.
- A `fetch.sh` script that, when libjade-SLH-DSA lands, pins the
  upstream commit and clones the relevant subdirectory into this dir
  on-demand (mirroring the pattern Pulsar uses for libjade
  ML-DSA-65).

The fetch script is **stub today** — it prints a clear notice that
libjade-SLH-DSA is not yet upstream and exits 0 (skip-friendly).

## Long-term plan

When libjade-SLH-DSA lands:

1. `fetch.sh` pins the upstream commit and pulls the subtree.
2. `../proofs/easycrypt/lemmas/SLHDSA_Functional.ec` becomes a
   `require import` against the libjade EasyCrypt theory.
3. The `sign_body_compute_sig_spec` axiom in
   `../proofs/easycrypt/Magnetar_N1_Sign_Refinement.ec` becomes a
   discharged lemma against the libjade-extracted Jasmin.

The constant-time gate (`scripts/checks/jasmin.sh`) currently treats
this directory as advisory: any .jazz files here will be run through
`jasmin-ct --infer` and findings logged, but not blocking. The
threshold-layer .jazz files in `../threshold/` are the BLOCKING CT
gate.

## Why this matters (production)

The current production routing is via `cloudflare/circl/sign/slhdsa` —
the standard Go FIPS 205 reference, NIST-validated and
community-audited. Routing through libjade-SLH-DSA when it lands
would give us formal CT artifacts at the single-party layer to match
Pulsar's libjade-ML-DSA-65 setup; until then, the trust model relies
on Cloudflare's CIRCL upstream review.
