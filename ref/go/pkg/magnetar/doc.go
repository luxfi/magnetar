// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package magnetar implements two threshold-style modes over the
// FIPS 205 SLH-DSA primitive. Pick the mode based on your trust
// model — see DEPLOYMENT-RUNBOOK.md §0 for the decision tree.
//
// ## Mode 1: AggregateSignatures (public-BFT-safe, the default
// recommendation)
//
// Each validator i holds its OWN SLH-DSA keypair (sk_i, pk_i)
// generated independently (no DKG, no shared seed). To sign a
// message m, each validator produces a single-party FIPS 205
// signature σ_i and broadcasts a SignedBundle envelope carrying
// (ValidatorID_i, pk_i, σ_i). The consensus layer collects N
// bundles via AggregateSignatures, and a relying party calls
// VerifyAggregated which returns the COUNT of valid signers
// (compared to a consensus-layer threshold to make the quorum
// policy decision).
//
// Properties:
//   - No aggregator-in-TCB. No single host ever holds N validators'
//     secret material together.
//   - Wire size = N × |σ| (compressible via Z-Chain Groth16 rollup
//     to ~192 bytes; that's a separate primitive).
//   - Per-validator slashing is attributable.
//   - The SOTA answer for "public-BFT post-quantum finality on
//     SLH-DSA".
//
// This is the path almost every Magnetar deployment should use.
//
// ## Mode 2: CombineWithSeedReconstruction (custody, REQUIRES TEE)
//
// Construction summary:
//
//   - Threshold DKG: each party contributes a random scheme-seed.
//     Contributions are byte-wise Shamir-shared via GF(257) (n
//     parties, t threshold) and broadcast in per-recipient
//     envelopes. Each envelope ALSO carries the full contribution
//     so every party can sum the contributions to compute the
//     joint master public key locally. The party's KeyShare is
//     the sum of received shares (one per dealer).
//
//   - Threshold sign: each signer commits to a mask + masked-share
//     in Round 1, reveals (mask, masked_share) in Round 2. The
//     aggregator gathers t reveals, XORs to recover the underlying
//     share, Lagrange-interpolates the byte-sum, applies the same
//     cSHAKE256 mix as the DKG to recover the master seed, and
//     calls single-party FIPS 205 SignDeterministic. The resulting
//     signature is byte-identical to single-party SLH-DSA on the
//     same (master_seed, message, ctx) — the Magnetar analog of
//     Pulsar's Class N1 byte-equality claim.
//
//   - Verify: a thin dispatch over circl/slhdsa.Verify. Threshold
//     signatures verify under unmodified FIPS 205 verifiers.
//
// HONEST TRUST CAVEAT: the aggregator process is in the trusted
// computing base for the brief window the master seed is
// reconstructed in memory. This is the same trust model as
// Pulsar's v0.1 reveal-and-aggregate (BLOCKERS.md). REQUIRES TEE
// for public deployment. Operational mitigations: run the
// aggregator inside a TEE (Intel TDX / SEV-SNP / SGX), mlock the
// seed buffer, disable ptrace, and use a short-lived signer
// process. See DEPLOYMENT-RUNBOOK.md for the deployment-time
// mitigations matrix and SPEC.md for the full trust-model
// disclosure.
//
// Why this caveat is fundamental, not a Magnetar choice:
// SLH-DSA is hash-based — WOTS+ / FORS / Merkle trees over a
// secret seed. The literature establishes there is no efficient
// threshold MPC that produces a single FIPS 205-shaped signature
// without reconstructing the seed:
//
//   - Cozzo & Smart, "Sharing the LUOV" (EUROCRYPT 2019)
//   - Bonte, Smart, Tan, "Threshold SPHINCS+" (2023)
//   - NIST IR 8214 / MPTC submission notes
//   - FIPS 205 §6 SLH-DSA-Sign-Internal (direct inspection)
//
// A v0.2 instantiation that gives true threshold secrecy
// (aggregator never sees the seed) requires full MPC over
// SLH-DSA's hash tree — see BLOCKERS.md BLK-1.
//
// USE THIS MODE ONLY when an aggregator host is in your TCB (e.g.
// M-Chain custody hosts with TDX/SEV-SNP/SGX attestation, the
// LP-134 thresholdvm M-Chain mode). For public BFT, use
// AggregateSignatures instead.
package magnetar
