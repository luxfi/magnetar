# Magnetar --- design

Magnetar is the hash-based (FIPS 205 SLH-DSA) PQ leg of the Lux
cross-family signature suite. This document states the architecture and
why each path exists.

## The fundamental constraint

SLH-DSA is a tree of hash computations: the secret is a SHAKE seed and
signing traverses a hypertree of one-time / few-time signatures keyed
by that seed. There is NO linear-aggregation identity (unlike
FROST/Schnorr or the Raccoon-style ML-DSA threshold). The literature is
explicit:

- Cozzo & Smart, EUROCRYPT 2019, *Sharing the LUOV*: every internal
  SHAKE/SHA-2 evaluation is a non-linear function of the secret seed.
- Bonte, Smart & Tan, 2023, *Threshold SPHINCS+*: there is no efficient
  t-of-n SLH-DSA scheme producing one FIPS 205-shaped signature without
  either (a) reconstructing the seed in some combiner process, or (b)
  full MPC over the SHAKE hash tree (multi-second, multi-megabyte per
  signature).
- NIST IR 8214: SLH-DSA is the highest threshold-MPC cost among FIPS
  20{3,4,5}.

True no-reconstruction threshold SLH-DSA is OPEN RESEARCH. Magnetar
does not pretend otherwise. Instead it offers three paths chosen by
deployment model.

## The three paths

### 1. Per-validator standalone --- PRODUCTION DEFAULT (sound)

`standalone.go`. Each validator holds its own FIPS 205 keypair, signs
the message independently, and the consensus layer collects N
single-party signatures into a `ValidatorAggregateCert`. Verification
counts valid signatures against the validator-set registry; the quorum
decision lives at the consumer.

This is the sound primitive: there is no shared seed, no DKG, no
dealer, and no reconstruction anywhere. It sidesteps both (a) and (b)
by emitting N independent signatures. Wire size is N x |sigma| (a
Z-Chain Groth16 rollup compresses it; separate primitive).

THIS IS THE DOCUMENTED PRODUCTION PRIMITIVE for public-BFT post-quantum
consensus.

### 2. TEE-attested combiner pool --- OPT-IN PRODUCTION (sound under attested-hardware trust)

`luxfi/threshold/protocols/slhdsa-tee`. For deployments that genuinely
need a SINGLE FIPS 205-shaped signature from a committee (custody,
bridge signing), Magnetar routes Combine through a t-of-n
attested-combiner pool, gated by the single profile function
`magnetarRefuseUnderStrictPQ`.

Honest trust model: the seed is reconstructed in full, but INSIDE a
measured enclave whose binary + firmware chain-validate to a vendor
root (AMD KDS today; Intel TDX / NVIDIA NRAS are stubs). This is
TRUST-RELOCATION --- it moves the reconstruction into attested hardware
and ADDS that hardware (plus the attestation chain and the t hosts) to
the TCB. It is NOT MPC and does NOT keep the seed secret from every
party; the enclave sees it.

### 3. Permissionless THBS-SE --- RESEARCH-ONLY

`thbsse.go` + `thbsse_field.go` + `thbsse_assemble.go` +
`slhdsa_internal.go`. A t-of-n committee, slot-bound commit-and-reveal,
and an anyone-can-combine public combiner. The public combiner
RECONSTRUCTS the full FIPS 205 master into one buffer every signature
(`ASSEMBLE-INVARIANT.md`) and emits a byte-identical FIPS 205
signature.

Because whoever runs Combine sees the seed, there is effectively a host
in the TCB at sign time. This path is RESEARCH-GRADE. It must not be
presented as production or as "no host in the TCB". The earlier "strict
-atom Combine closed the no-leak gap" claim was proof by rename (it
avoids the variable name `seed`, not the reconstruction). See
`BLOCKERS.md::MAGNETAR-STRICT-ATOM` (OPEN).

## Setup: dealer, dealerless, or TEE

- **Dealer (`NewThbsSeKey`)**: one machine samples the master,
  byte-shares it over GF(257), and zeroizes it. The dealer is in the
  TCB for setup only. KAT-reproducible; recommended for foundation-HSM
  bootstrap.
- **Dealerless production (`RunDKG`)**: per-party PVSS with hash
  commitments; the transcript carries NO constant-term reveals, so the
  master is not reconstructible from the wire. BUT pk derivation
  reconstructs the master transiently (inherent: `pk = SLH-DSA.PK(M)`
  is a hash tree over M), and the path does NOT robustly exclude
  malicious dealers at DKG time (hash commitments aren't openable
  without revealing m_i). See `RunDKG` HONEST LIMITATIONS in
  `pvss_dkg.go`.
- **TEE**: routes both pk derivation and Combine through attested
  hardware (trust-relocated).

A leaking open-reveal DKG (`RunDKGSimulationOpenRevealTestOnly`) exists
for KAT replay only, behind an explicit hazard acknowledgement; its
transcript reveals the master.

## Parameter sets (FIPS 205 SHAKE)

| Mode | NIST Category | sig bytes |
|---|---|---|
| SHAKE-192s | 3 | 16224 (recommended) |
| SHAKE-192f | 3 fast | larger sig, faster sign |
| SHAKE-256s | 5 | 29792 |

SLH-DSA signatures are large (16-30 KB) vs ML-DSA (2-5 KB); the
per-signature cost dominates economics, which is another reason the
standalone path (no MPC ceremony) is the production default.

## What is NOT claimed

- No mechanized proof of any threshold property (the prior EC/Lean
  track was vacuous; see `PROOF-CLAIMS.md`).
- No no-leak property for THBS-SE.
- No robust-against-malicious-dealers property for the production DKG.
- No external audit.

Use the per-validator standalone path for production public-BFT
signing. Use the TEE pool when you are willing to trust attested
hardware. Treat THBS-SE as research.
