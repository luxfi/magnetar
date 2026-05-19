// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package magnetar implements the Magnetar v0.1 threshold FIPS 205
// SLH-DSA primitive. It mirrors Pulsar's reveal-and-aggregate
// pattern but over SLH-DSA's scheme seed instead of ML-DSA's.
//
// Construction summary (v0.1):
//
//   - Threshold DKG: each party contributes a random scheme-seed.
//     Contributions are byte-wise Shamir-shared via GF(257) (n
//     parties, t threshold) and broadcast in per-recipient
//     envelopes. Each envelope ALSO carries the full
//     contribution so every party can sum the contributions to
//     compute the joint master public key locally. The party's
//     KeyShare is the sum of received shares (one per dealer).
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
// HONEST TRUST CAVEAT (v0.1): the aggregator process is in the
// trusted computing base for the brief window the master seed is
// reconstructed in memory. This is the same trust model as
// Pulsar's v0.1 reveal-and-aggregate (BLOCKERS.md). Operational
// mitigations: run the aggregator in a TEE, mlock the seed
// buffer, disable ptrace, and use a short-lived signer process.
// See DEPLOYMENT-RUNBOOK.md for the deployment-time mitigations
// matrix and SPEC.md for the full trust-model disclosure.
//
// A v0.2 instantiation that gives true threshold secrecy
// (aggregator never sees the seed) is on the research path — full
// MPC over SLH-DSA's hash tree is the candidate construction; see
// BLOCKERS.md BLK-1.
package magnetar
