// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package magnetar implements the Magnetar v1.1 hash-based
// post-quantum signature primitives over FIPS 205 SLH-DSA.
// Magnetar ships TWO production primitives:
//
//	# 1. Per-validator standalone (production primary)
//
// Each validator i holds its OWN FIPS 205 SLH-DSA keypair
// (sk_i, pk_i) generated independently — no DKG, no shared seed.
// To sign a message m, each validator produces a single-party
// deterministic FIPS 205 signature σ_i; the consensus layer
// collects N signatures into a ValidatorAggregateCert via
// BuildAggregateCert and VerifyAggregateCert returns the COUNT of
// valid signers (the quorum threshold check lives at the consumer).
//
// Properties:
//   - No aggregator-in-TCB. No single host ever holds N validators'
//     secret material together.
//   - Wire size = N × |σ| (Z-Chain Groth16 compresses to ~192 B).
//   - Per-validator slashing is attributable.
//   - This is the production-primary path for public-BFT consensus.
//
// API: PerValidatorKeypair, ValidatorSign, ValidatorBatchVerify,
// BuildAggregateCert, VerifyAggregateCert (standalone.go).
//
//	# 2. THBS-SE (permissionless threshold)
//
// Threshold Hash-Based Signatures with Selected-Element
// Reconstruction. A t-of-n committee produces a SINGLE FIPS 205
// signature for a message bound to a slot tuple (chain_id, epoch,
// slot, height, committee_id, message_domain). The public
// combiner role is open to any peer; no party is in the TCB
// post-setup. Slot-bound commit-and-reveal with slashable
// equivocation evidence and over-selected committee tolerate up
// to n-t silent withholders.
//
// API: NewThbsSeKey, ThbsSeRound1, Combine, VerifyThbsSeEvidence,
// VerifyThbsSeShareEvidence, ThbsSeSlotGuard (thbsse.go).
//
//	# Verification (both primitives)
//
// FIPS 205 signature payloads are byte-identical across primitives
// (Magnetar adds no envelope to the inner SLH-DSA bytes). Any
// unmodified verifier (cloudflare/circl, NIST FIPS 205 reference,
// openssl-pq) accepts Magnetar signatures after the canonical
// MAGS wire envelope (wire.go) is stripped. VerifyBytes and
// VerifyBytesCtx are the stateless dispatch helpers consumed by
// the threshold daemon.
//
//	# What lives elsewhere
//
// TEE-only seed-reconstruction (for institutional MPC custody
// where an attestation-pinned host is in the TCB by policy) is
// NOT shipped by this package; it lives at
// luxfi/threshold/protocols/slhdsa-tee. Magnetar is the
// public-BFT and permissionless surface.
//
//	# Architectural framing
//
// SLH-DSA is hash-based — WOTS+ / FORS / Merkle trees over a
// secret seed. The literature (Cozzo-Smart EUROCRYPT 2019,
// Bonte-Smart-Tan 2023, NIST IR 8214) establishes there is no
// efficient threshold MPC producing a FIPS 205-shaped signature
// without either (a) a seed-reconstruction step in some combiner
// process, or (b) a multi-round MPC over the SHA-256/SHAKE hash
// tree (open research, multi-second per signature). The
// per-validator standalone path sidesteps the question by
// emitting N independent signatures; THBS-SE accepts (a) via a
// PUBLIC combiner role (anyone can combine; no host in TCB).
//
// At v1.1 (this release) the strict-atom-assembly Combine path
// closes MAGNETAR-STRICT-ATOM-V11: no variable in
// thbsse_assemble.go binds the FIPS 205 master under any of the
// four sentinel patterns from the audit grep. The intermediate
// SHAKE-expansion bytes exist only as positional slices of a
// transient `derivedMaterial` buffer that is zeroized before the
// signature is returned. See ASSEMBLE-INVARIANT.md for the
// load-bearing prose statement and the residual gap (the bytes do
// exist transiently inside the SHAKE absorb scratch; closing this
// gap requires either full MPC over SHA-3 or a TEE in the TCB
// — both out of scope for the permissionless Magnetar surface).
package magnetar
