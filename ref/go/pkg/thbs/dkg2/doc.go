// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package dkg2 is the RESEARCH-GRADE SKELETON of a public DKG for
// threshold HBS. v1 in this directory ships the PVSS layer; the
// MPC-root layer is OPEN RESEARCH and tracked in BLOCKERS.md::
// MAGNETAR-PUBLIC-DKG-1.
//
// =====================================================================
// !!  SKELETON / RESEARCH ONLY  —  DO NOT USE IN PRODUCTION         !!
// =====================================================================
//
// HBS schemes (LMS, XMSS, SLH-DSA) commit to public keys via Merkle
// roots over many WOTS+ chain endpoints (one per slot, per chain).
// Each chain endpoint W_{slot, j} = H^{w-1}(x_{slot, j}) is derived
// from a SECRET chain head x_{slot, j} by repeated hashing.
//
// A truly PUBLIC DKG (no trusted dealer, no TEE) for threshold HBS
// therefore needs TWO ingredients:
//
//   (A) PVSS distribution of per-element entropy. For every secret
//       element x_e (WOTS+ chain head or FORS leaf), the protocol
//       collects randomness contributions r_{j,e} from each party
//       j ∈ [n] and SHAMIR-SHARES each r_{j,e} across the committee
//       at threshold t. The secret element is x_e = Σ_j r_{j,e};
//       NO single party ever holds x_e in cleartext.
//
//       This file implements (A) as a SKELETON: see pvss.go.
//
//   (B) MPC over the SHA-256 / SHAKE hash function to compute the
//       PUBLIC chain endpoint W_e = H^{w-1}(x_e) from the SECRET-
//       SHARED x_e — WITHOUT REVEALING x_e.
//
//       This is the HARD FRONTIER. Hash functions are non-linear:
//       evaluating one SHA-256 / SHAKE block on a secret-shared input
//       requires either (i) garbled circuits + oblivious transfer
//       (multi-second, multi-megabyte per evaluation) or (ii) SPDZ-
//       style arithmetic MPC (similar cost, plus offline triples) or
//       (iii) function secret sharing for the specific hash circuit
//       (open research). For a single SLH-DSA-SHAKE-192s public key
//       we need O(2^h × WOTSChains × (w-1)) hash evaluations, where
//       h=10, WOTSChains=51, w=16 → ~750 thousand SHAKE evaluations.
//       Multi-hour at current MPC frameworks (MP-SPDZ, EMP, etc.).
//
//       (B) IS NOT IMPLEMENTED. See pvss.go's TODO + the SkeletonOnly
//       sentinel returned by RootMPC.
//
// LITERATURE
// ==========
//
// On PVSS (the layer this skeleton implements):
//
//   - Schoenmakers, "A Simple Publicly Verifiable Secret Sharing
//     Scheme and its Application to Electronic Voting" (CRYPTO 1999)
//   - Heidarvand, Villar, "Public Verifiability from Pairings in
//     Secret Sharing Schemes" (SAC 2008)
//   - Gurkan et al., "Aggregatable Distributed Key Generation"
//     (EUROCRYPT 2021)
//
// On the MPC layer for the public root computation (the layer this
// skeleton does NOT yet implement):
//
//   - Damgård, Pastro, Smart, Zakarias, "Multiparty Computation from
//     Somewhat Homomorphic Encryption" (CRYPTO 2012) — SPDZ
//   - Wang, Ranellucci, Katz, "Global-Scale Secure Multiparty
//     Computation" (CCS 2017)
//   - Boyle, Gilboa, Ishai, "Function Secret Sharing" (EUROCRYPT 2015)
//   - The MP-SPDZ implementation (https://github.com/data61/MP-SPDZ)
//     ships SHA-256 over MASCOT/SPDZ at multi-hundred-ms per block
//     across 3-party LANs.
//
// On threshold HBS overall (the McGrew et al. line of work that
// motivates the entire thbs package):
//
//   - McGrew, Fluhrer, Gazdag, Kampanakis, Morton, Westerbaan,
//     "Coalition and Threshold Hash-Based Signatures" (IACR ePrint
//     2019/793) — the v1 dealer-backed setup, with a v2 public-DKG
//     discussion that leaves the MPC layer unspecified.
//   - Bonte, Smart, Tan, "Threshold SPHINCS+" (2023) — infeasibility
//     analysis confirming the per-signature MPC cost dominates.
//
// SCOPE OF THIS SKELETON
// ======================
//
// What ships in dkg2/ v1:
//
//   - pvss.go: per-element Shamir VSS over GF(257), per-recipient
//     PEdersen-style commitment + share. Each party deals their
//     contribution r_{j,e} to every element e via verifiable shares.
//   - complaint.go: complaint round + dealer disqualification
//     mechanics. A party that fails to deliver a valid share or
//     that delivers an inconsistent share is identifiably aborted.
//   - consensus.go: agreement on the qualified set Q ⊆ [n] of
//     parties whose contributions survive the complaint round. The
//     joint secret is x_e = Σ_{j ∈ Q} r_{j,e} (per element).
//
// What does NOT ship:
//
//   - root.go: STUB. The MPC-root computation that would derive
//     the public chain endpoints W_e from the secret-shared x_e
//     WITHOUT REVEALING any x_e. RootMPC returns ErrMPCRootNotImpl.
//     This is the v0.6+ candidate work; see BLOCKERS.md::
//     MAGNETAR-PUBLIC-DKG-1.
//
// USAGE
// =====
//
// This package is a STUB. Callers should NOT attempt to use it for
// production signing. The intended use is:
//
//   1. The PVSS layer is exercised by the cryptographer team to
//      validate the wire shape against future MPC-root integration.
//   2. The README.md in this directory documents the open research
//      path and serves as a placeholder for the v0.6+ implementation.
//
// For a working THRESHOLD HBS construction TODAY, see the parent
// package (github.com/luxfi/magnetar/ref/go/pkg/thbs) which ships
// the DEALER-BACKED v1 path.
//
// For a working PUBLIC-BFT-SAFE SLH-DSA primitive TODAY, see
// github.com/luxfi/magnetar.ValidatorSign +
// VerifyAggregateCert (per-validator standalone SLH-DSA, no DKG).
package dkg2
