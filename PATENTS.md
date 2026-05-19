# PATENTS — Magnetar Threshold SLH-DSA Signature

> **Statement of Intellectual Property and Royalty-Free Patent Grant**
> for the Magnetar threshold-signing construction submitted to the NIST
> Multi-Party Threshold Cryptography (MPTC) project.

## TL;DR

Lux Industries, Inc. ("Lux") grants a **worldwide, royalty-free,
non-exclusive, irrevocable patent license** for any implementation of
the Magnetar threshold signature construction that is either (a)
licensed under BSD-3-Clause or a compatible OSI-approved license, OR
(b) is part of a NIST MPTC / PQC / ACVP submission, validation, or
interoperability test.

The grant terminates automatically and prospectively against any
party that asserts a patent claim against Magnetar, FIPS 205 SLH-DSA,
FIPS 204 ML-DSA, or any other NIST-standardized post-quantum
signature scheme. Defensive termination mirrors Apache-2.0 §3.

The full text of the grant is in **§3 Patent Grant** below.

## §1 Scope of the IP statement

This document covers patent rights and patent posture for:

- The **Magnetar threshold-signing construction** as implemented at
  `github.com/luxfi/magnetar` (DKG → Round-1 commit → Round-2 reveal
  → Combine).
- The **reference implementation** in `ref/go/pkg/magnetar/`.
- The **test-vector format** in `ref/go/cmd/genkat` and `vectors/`.

It does NOT cover, and explicitly DISCLAIMS, the following prior art:

| Component | Status |
|---|---|
| FIPS 205 SLH-DSA (Stateless Hash-Based Digital Signature Standard, NIST 2024) | NIST standard. Magnetar implements the single-party FIPS 205 layer **unchanged in its math** via `cloudflare/circl`'s audited Go reference. Lux asserts no patents on FIPS 205 itself. |
| WOTS+, HORS, FORS, hypertree constructions underlying SLH-DSA (Buchmann-Dahmen-Hülsing 2011 and follow-up academic literature) | Academic / public domain. |
| Shamir secret sharing (Shamir 1979) | Public domain. |
| Lagrange polynomial interpolation | Classical mathematics. |
| SHAKE128 / SHAKE256 / Keccak / cSHAKE / KMAC / TupleHash (FIPS 202 + SP 800-185) | Public domain — NIST standards. |
| Pedersen verifiable secret sharing (Pedersen 1991) | Academic prior art. Magnetar v0.1 does NOT use Pedersen VSS (v0.1 ships plain byte-wise Shamir); v0.4 may adopt for envelope-wrapping authenticity. |
| HJKY97 proactive secret sharing (Herzberg, Jakobsson, Jarecki, Krawczyk, Yung. CRYPTO 1995/1997) | Academic prior art. Will be the basis of Magnetar's `Refresh` primitive when it lands at v0.4. |
| Reveal-and-aggregate threshold-signing pattern (used by Pulsar v0.1 and other production threshold systems) | Industry / academic prior art. The general pattern is not asserted by Magnetar; only the SLH-DSA-specific lifecycle additions below are candidate claims. |

## §2 What Lux considers patentable (high level)

Subject to attorney review, Lux considers the following Magnetar
contributions to be candidates for patent protection. Note: this
list is intentionally narrow because the underlying FIPS 205
SLH-DSA primitive is a NIST standard (public domain) and the
byte-wise Shamir VSS pattern over a NIST-standard scheme seed
follows directly from Pulsar's v0.1 reveal-and-aggregate template
applied to the SLH-DSA seed instead of the ML-DSA seed. Magnetar's
novel contributions are the SLH-DSA-specific protocol shape and
binding.

### §2.1 Byte-wise Shamir VSS of the FIPS 205 SLH-DSA scheme seed over GF(257)

The specific adaptation of byte-wise Shamir secret sharing to the
FIPS 205 SLH-DSA scheme seed (96 bytes for SHAKE-192s/192f, 128
bytes for SHAKE-256s), where:

- Each byte position of the seed is shared independently over
  GF(257) (smallest prime > 255, admits every byte value as a
  distinct field element).
- Shares are encoded as one big-endian uint16 per byte position
  (the 9-bit GF(257) element packed in a 16-bit lane).
- Reconstruction at `x=0` recovers the master byte-sum, which is
  then mixed with the committee root via cSHAKE256 to produce the
  reconstructed master seed.
- The cSHAKE256 mix uses customisation tag `MAGNETAR-SEED-SHARE-V1`
  with function-name `"Magnetar"` per SP 800-185.

Detailed in `SPEC.md` §3 (DKG protocol) and §4 (threshold signing
Combine step); implementation in `ref/go/pkg/magnetar/shamir.go`,
`dkg.go`, `combine.go`.

### §2.2 Three-round DKG with transcript-digest equivocation detection

The specific DKG protocol shape:

- **Round-1**: dealer broadcasts one envelope per recipient carrying
  the recipient's Shamir share and the dealer's full contribution to
  the joint seed. Each envelope is `(share || contribution)` where
  share is 2 × seed_size bytes (big-endian uint16 per byte position)
  and contribution is seed_size bytes.
- **Round-2**: each party computes a 32-byte transcript digest
  `D = cSHAKE256(tau_dkg || for_each_dealer(for_each_recipient(env)),
  N="Magnetar", S="MAGNETAR-DKG-TRANSCRIPT-V1")` binding the entire
  ordered envelope set; broadcasts `D`.
- **Round-3**: parties verify every received digest equals their
  local `D`. A mismatch produces an `AbortEvidence{Kind:
  ComplaintEquivocation}` carrying the conflicting digest pair —
  identifiable abort with attributable evidence suitable for
  slashing.

The transcript binding `tau_dkg = (mode || threshold || committee_size
|| committee_in_order)` and the dealer/recipient ordering convention
are domain-separated under `lux-magnetar-v0.1`.

Detailed in `SPEC.md` §3; implementation in `dkg.go`.

### §2.3 Two-round commit-bind threshold sign with masked-share reveal

The specific threshold-sign protocol shape:

- **Round-1**: each signer derives `r_i = cSHAKE256(rngBytes || sid
  || attempt || NodeID, N="Magnetar", S="MAGNETAR-SIGN-MASK-V1")` —
  the per-attempt mask is derived deterministically from raw entropy
  plus the session/attempt/NodeID tuple, so a deterministic RNG that
  produces the same output across two attempts still yields DISTINCT
  masks. Compute `masked_i = share_i XOR r_i`; commit
  `D_i = cSHAKE256(r_i || masked_i || tau_1, N="Magnetar",
  S="MAGNETAR-SIGN-R1-V1")` where `tau_1 = (sid, attempt, quorum,
  NodeID, pk, msg)`.
- **Round-2**: reveal `(r_i, masked_i)` so peers can re-derive `D_i`
  and the aggregator can XOR them to recover `share_i`.
- **Combine**: for each Round-2 reveal, re-derive `D'_i` and gate on
  `ctEqual32(D'_i, D_i)`. Recover `share_i = masked_i XOR r_i`.
  Collect `t` distinct shares with their `EvalPoint`s; Lagrange-
  interpolate the master byte-sum at `x=0`; mix with the committee
  root via cSHAKE256 (identical to DKG Round-3 step 6); derive the
  FIPS 205 SLH-DSA secret key via `slhdsa.Scheme(ID).DeriveKey(S)`;
  sign via `slhdsa.SignDeterministic`. Result is byte-identical to
  centralized FIPS 205 SLH-DSA.

Detailed in `SPEC.md` §4; implementation in `threshold.go` and
`combine.go`.

### §2.4 Identifiable abort with attributable evidence

The specific use of `ComplaintEquivocation` carrying the conflicting
digest pair `(my_digest, accused_digest)` as the slashing-suitable
evidence blob; the typed `AbortEvidence` struct with `Kind`,
`Accuser`, `Accused`, `Evidence`, `Signature` fields. Detailed in
`SPEC.md` §8; implementation in `dkg.go` Round-3.

### §2.5 Constant-time commit-bind gate in Combine

The specific implementation pattern in `combine.go` where every
Round-2 reveal's recomputed `D'_i` is compared to the matching
Round-1 `D_i` via `ctEqual32` (constant-time 32-byte equality scan)
**before** the share is included in the Lagrange reconstruction.
This prevents a malicious aggregator from selectively admitting
shares based on timing of the per-share commit verification.

## §3 Patent grant (the load-bearing text)

> **MAGNETAR PATENT GRANT — v1.0**
>
> Lux Industries, Inc. ("Lux"), a Delaware corporation, hereby grants
> to any person or entity ("You") a **worldwide, royalty-free,
> non-exclusive, no-charge, fully-paid-up, irrevocable** (except as
> stated in §3.2 below) patent license to make, have made, use, offer
> to sell, sell, import, and otherwise transfer any implementation of
> the Magnetar threshold-signing construction described in `SPEC.md`
> (the "Construction"), provided that such implementation:
>
> (a) Implements the Construction (signing, DKG, or — when v0.4
>     lands — proactive resharing) in a manner consistent with the
>     algorithmic specification (the "Construction-Conformance
>     Condition"); AND
>
> (b) Is licensed to the public under (i) the BSD-3-Clause License,
>     (ii) the Apache License, Version 2.0, or (iii) any other
>     Open-Source-Initiative-approved license compatible with
>     BSD-3-Clause or Apache-2.0, OR (c) is part of a submission to,
>     validation under, or interoperability test for the NIST
>     Multi-Party Threshold Cryptography (MPTC) project, the NIST
>     Post-Quantum Cryptography (PQC) standardization process, or any
>     successor program administered by NIST.
>
> The license granted in this §3 covers all "Necessary Claims" owned
> or controllable by Lux that would, in absence of this license,
> necessarily be infringed by an implementation meeting (a) and (b).
> "Necessary Claims" means claims of any patent or patent
> application that are essential for compliance with the Magnetar
> specification, that Lux has the right at the time of execution to
> grant a license under.
>
> ### §3.1 Documentation and reference-implementation grant
>
> The Magnetar specification (`SPEC.md`), the reference implementation
> (`ref/go/pkg/magnetar/`), and the test vectors (under `vectors/`
> with deterministic regeneration via `ref/go/cmd/genkat`) are
> released under the BSD-3-Clause license. The patent grant in this
> document operates in addition to (not in lieu of) any patent
> provisions in the BSD-3-Clause license; BSD-3-Clause's silence on
> patents is supplemented by the explicit grant here.
>
> ### §3.2 Defensive termination
>
> The patent license granted in this §3 terminates automatically and
> prospectively, without notice, with respect to any party (the
> "Asserting Party") if the Asserting Party initiates patent
> litigation (including a cross-claim or counter-claim in a lawsuit)
> alleging that:
>
> (i) The Magnetar construction; or
> (ii) FIPS 205 SLH-DSA, FIPS 204 ML-DSA, FIPS 203 ML-KEM, or any
>      other NIST-standardized post-quantum signature or key-
>      encapsulation scheme; or
> (iii) Any implementation of (i) or (ii) — including without
>      limitation the reference implementation in this repository,
>      independent third-party implementations, NIST ACVP/CAVP
>      reference vectors, or any FIPS 140-3 validated module
>      containing such an implementation,
>
> infringes any patent owned or controllable by the Asserting Party.
> Termination is prospective only; it does not undo the validity of
> any implementation distributed prior to the date the Asserting
> Party initiated the litigation.
>
> Defensive termination mirrors the patent-termination clause of the
> Apache License, Version 2.0, §3, generalized to also cover FIPS 205
> SLH-DSA, FIPS 204 ML-DSA, FIPS 203 ML-KEM, and successor
> NIST-standardized post-quantum signature schemes. The purpose is to
> deter patent assertion against the broader post-quantum signature
> ecosystem, not only against Magnetar itself.
>
> ### §3.3 No trademark license
>
> This grant does not authorize the use of Lux's trademarks
> (including "Magnetar", "Pulsar", "Corona", "Quasar", "Lux",
> "Lux Industries", and their respective logos) except as required
> for reasonable and customary use in describing the origin of the
> Construction and reproducing the content of any NOTICE file.
>
> ### §3.4 Disclaimer
>
> THE CONSTRUCTION AND ALL ASSOCIATED MATERIALS ARE PROVIDED ON AN
> "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER
> EXPRESS OR IMPLIED. Lux shall not be liable for any damages
> resulting from the use of the patent license granted in this §3.

## §4 Filing strategy (informational)

This section is for transparency; it does not modify the grant
in §3.

Lux intends to pursue patent protection on the Magnetar production-
lifecycle additions as follows:

1. **US provisional application** within 12 months of public
   disclosure (the NIST MPTC submission counts as public disclosure
   for §102 purposes; filing before submission preserves priority).

2. **PCT international application** within 12 months of the
   provisional, designating jurisdictions where threshold SLH-DSA
   deployment is anticipated (EU, JP, CN, KR, IN, AU, CA, UK, BR).

3. **EPO and major-jurisdiction national-phase entries** at the PCT
   30-month deadline, prioritized by anticipated deployment markets.

4. **Continuation / divisional applications** to cover incremental
   refinements (e.g., the v0.4 ML-KEM-768 envelope-wrapping pattern
   for DKG Round-1 envelopes, the v0.4 reshare protocol, future
   hash-suite profile additions, the v0.2 full-MPC construction
   when it matures).

The royalty-free grant in §3 applies to ALL such filings, present
and future, that are owned or controllable by Lux.

## §5 Why the grant is structured this way

### §5.1 Defensive patent ownership protects the ecosystem

Without Lux holding the patents on the Magnetar production-lifecycle
additions, a third party could observe the public NIST submission,
file blocking patents on (e.g.) the byte-wise Shamir VSS over the
SLH-DSA seed pattern, and assert them against open-source
implementations. Lux holding the patents (with a royalty-free grant)
removes that attack surface.

This is the same logic that protects FRAND ecosystems and that
underlies Apache-2.0's patent grant + retaliation clause.

### §5.2 Compatibility with NIST MPTC submission terms

The NIST Multi-Party Threshold Cryptography project's submission
guidelines require submitters to provide a patent statement
specifying the IP terms under which the submitted construction may
be used. The grant in §3 satisfies that requirement and goes beyond
NIST's baseline by extending defensive termination to FIPS 205
SLH-DSA, FIPS 204 ML-DSA, FIPS 203 ML-KEM, and successors (not just
Magnetar's own construction).

### §5.3 Compatibility with the FIPS 205 standard

The underlying FIPS 205 SLH-DSA primitive is a NIST standard
(public domain). Lux asserts no patents on FIPS 205 itself;
Magnetar's claims are limited to the threshold lifecycle additions.
Any third-party implementation of FIPS 205 SLH-DSA single-party
signing is free of Magnetar patent assertions whether or not it
adopts Magnetar's threshold layer.

### §5.4 Defensive termination for the broader PQ ecosystem

Extending defensive termination to FIPS 205 SLH-DSA, FIPS 204
ML-DSA, FIPS 203 ML-KEM, and successors — not just Magnetar
itself — converts Lux's patent portfolio into a small deterrent
against PQ-signature patent trolls. It costs Lux nothing (Lux does
not intend to assert offensively) and benefits the ecosystem.

## §6 What this document does NOT do

- It does not assign any Lux patent rights to NIST, IETF, or any
  third party. Lux retains ownership; the grant in §3 is a license.
- It does not commit Lux to maintain or prosecute any specific
  patent application. Lux may abandon applications for business
  reasons; the grant in §3 covers issued patents in proportion to
  what is actually granted.
- It does not waive Lux's right to update the grant text (subject
  to §6.1 below).
- It does not modify the BSD-3-Clause license covering the
  reference implementation, specification, and vectors.
- It does not claim patent rights on FIPS 205 SLH-DSA itself
  (NIST standard, public domain).

### §6.1 Modifications to this grant

Lux may issue future versions of this PATENTS document with
clarifications or extensions of the grant. Future versions will
apply to implementations published under the future version's
identifier. **The grant in §3 of this v1.0 document is
irrevocable for implementations relying on it**, subject only to
the defensive-termination clause in §3.2.

## §7 Contact

| Purpose | Contact |
|---|---|
| Patent / IP inquiries | `legal@lux.network` |
| Licensing for non-conforming implementations | `legal@lux.network` |
| NIST submission coordination | `mptc@lux.network` |
| Security disclosure | `magnetar@lux.network` |

---

**Document metadata**

- Document name: `PATENTS.md`
- Document version: v1.0
- Document date: 2026-05-18
- Construction version: Magnetar v0.3.0 (Tier A documentation shape
  complete)
- Construction repository: <https://github.com/luxfi/magnetar>
- License of this document: Creative Commons CC-BY-4.0 (so it
  can be freely reproduced in NIST submission packages and audit
  reports without modification).
