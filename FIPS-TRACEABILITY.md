# FIPS-TRACEABILITY — Magnetar

> **FIPS 205 § → Magnetar code map.** Magnetar IS FIPS-anchored
> at the single-party layer. This document maps the NIST FIPS 205
> (Stateless Hash-Based Digital Signature Standard, 2024) sections
> to the corresponding code paths in `~/work/lux/magnetar/ref/go/`.
> The threshold-overlay layer is documented as a Magnetar-specific
> overlay traceable to `SPEC.md` sections, not FIPS 205 (no NIST
> standard exists for threshold SLH-DSA at submission time).
>
> Equivalent role to Pulsar's `FIPS-TRACEABILITY.md` (which maps
> FIPS 204 § → code) and Corona's (which maps Boschini ePrint
> 2024/1113 § → code).

## §1 Reference

- **NIST FIPS 205** — *Stateless Hash-Based Digital Signature
  Standard* (Federal Information Processing Standards Publication
  205, U.S. Department of Commerce / NIST, August 2024).
- **NIST FIPS 202** — *SHA-3 Standard: Permutation-Based Hash and
  Extendable-Output Functions* (August 2015).
- **NIST SP 800-185** — *SHA-3 Derived Functions: cSHAKE, KMAC,
  TupleHash, and ParallelHash* (December 2016).

FIPS 205 is the construction-level normative reference for
Magnetar's **single-party layer**. The Magnetar threshold overlay
(byte-wise Shamir VSS, DKG, two-round commit-bind sign, Combine)
is novel work documented in `SPEC.md`; it traces to Shamir 1979 +
the classical Lagrange reconstruction identity, not FIPS 205.

## §2 FIPS 205 section → Magnetar code mapping

### §2.1 Parameter sets (FIPS 205 §10.1 Table 2)

Magnetar ships the SHAKE-family small and fast parameter sets at
NIST PQ Category 3 (≥192-bit security) and Category 5 (≥256-bit).
The SHA-2 family is excluded because Magnetar's transcript-hash
suite is uniformly FIPS 202 SHA-3 / SHAKE.

| FIPS 205 § | Parameter set | Magnetar Mode | Code | Wire sizes |
|---|---|---|---|---|
| §10.1 Table 2 | SLH-DSA-SHAKE-192s | `ModeM192s` (recommended) | `params.go:124` (`ParamsM192s`) | pk=48 B, sk=96 B, sig=16224 B, seed=96 B |
| §10.1 Table 2 | SLH-DSA-SHAKE-192f | `ModeM192f` | `params.go:136` (`ParamsM192f`) | pk=48 B, sk=96 B, sig=35664 B, seed=96 B |
| §10.1 Table 2 | SLH-DSA-SHAKE-256s | `ModeM256s` | `params.go:148` (`ParamsM256s`) | pk=64 B, sk=128 B, sig=29792 B, seed=128 B |

The byte sizes are pinned in `params.go` and validated against the
canonical FIPS 205 sizes via `Params.Validate()`; mismatches return
`ErrParamsTampered`.

### §2.2 Key generation (FIPS 205 §10.1 Algorithm 21 — `slh_keygen`)

| FIPS 205 § | Topic | Magnetar code |
|---|---|---|
| §10.1 Algorithm 21 (`slh_keygen`) | Sample (`SK.seed`, `SK.prf`, `PK.seed`) randomly; derive `PK.root` from FORS / hypertree | dispatched via `cloudflare/circl/sign/slhdsa.Scheme.DeriveKey` in `keygen.go:90` (`slhDSAKeyFromSeed`) |
| §10.1 (key encoding) | `SK` = (SK.seed || SK.prf || PK.seed || PK.root); `PK` = (PK.seed || PK.root) | `keygen.go:64-83` (`KeyFromSeed`); `PrivateKey.Bytes` / `PublicKey.Bytes` carry the byte-equal layout via circl's `MarshalBinary` |

Magnetar's `GenerateKey(params, rng)` samples a fresh
`params.SeedSize`-byte scheme seed from `rng` and dispatches to
`KeyFromSeed`. The KAT generator (`ref/go/cmd/genkat`) uses fixed
seeds for byte-stable output.

### §2.3 Sign (FIPS 205 §10.2 Algorithm 22 — `slh_sign`)

| FIPS 205 § | Topic | Magnetar code |
|---|---|---|
| §10.2 Algorithm 22 (`slh_sign`) | Compute SK.seed → FORS leaves; hypertree → root signature; pack (FORS sig || hypertree sig) | dispatched via `cloudflare/circl/sign/slhdsa.SignDeterministic` (or `SignRandomized`) in `sign.go:82-92` (`slhSign`) |
| §10.2 (context string) | `ctx` ≤ 255 bytes; bound into the hash chain alongside the message | `sign.go:52-54` validates `len(ctx) > 255` → `ErrCtxTooLong`; circl's `SignDeterministic`/`SignRandomized` consume the ctx per FIPS 205 |
| §10.2 (deterministic mode) | `slh_sign` is deterministic given (SK, M, ctx) | Magnetar's `Sign(params, sk, msg, ctx, randomized=false, rng)` produces byte-deterministic output; this is the load-bearing property that the threshold Combine path preserves |

Magnetar's threshold-Combine path uses `randomized=false` to
guarantee byte-identical output to single-party Sign on the
reconstructed seed (the Class-N1-analog byte-equality theorem,
`SPEC.md` §6).

### §2.4 Verify (FIPS 205 §10.3 Algorithm 23 — `slh_verify`)

| FIPS 205 § | Topic | Magnetar code |
|---|---|---|
| §10.3 Algorithm 23 (`slh_verify`) | Parse signature; recompute hypertree root from signature + PK.seed; compare to PK.root | dispatched via `cloudflare/circl/sign/slhdsa.Verify` in `verify.go:104-109` (`slhVerify`) |
| §10.3 (input validation) | Reject sigs/keys of wrong size; reject context > 255 | `verify.go:84-92` validates pk/sig sizes against `params.PublicKeySize` / `params.SignatureSize`; `len(ctx) > 255` returns `ErrCtxTooLong` |

Magnetar's `Verify` is intentionally minimal — a thin dispatch over
circl's FIPS 205 `slhdsa.Verify`. This is the **Class-N1-analog
manifesto in code**: any FIPS 205-conformant verifier accepts
Magnetar threshold-emitted signatures with no code change. Adding
logic to `Verify` would break output interchangeability with
single-party FIPS 205 — the whole point of the Magnetar threshold
variant.

### §2.5 Hash family (FIPS 202 + SP 800-185)

Magnetar's transcript-hash suite is uniformly FIPS 202 SHA-3 /
SHAKE plus SP 800-185 cSHAKE256 / KMAC256. The function-name `N`
is pinned to `"Magnetar"`; the customisation strings `S` are
distinct per protocol round.

| FIPS 202 / SP 800-185 § | Primitive | Magnetar code |
|---|---|---|
| FIPS 202 §6.3 (cSHAKE256) | Customisable SHAKE256 with function-name `N` and customisation `S` | `transcript.go:46-52` (`cshake256(input, outLen, customisation)`) |
| SP 800-185 §3 (cSHAKE algorithm) | `cSHAKE256(X, N, S, L) = SHAKE256(bytepad(encode_string(N) ‖ encode_string(S), 136) ‖ X, L)` | Implemented via `golang.org/x/crypto/sha3.NewCShake256` |
| SP 800-185 §4 (KMAC256) | Keyed MAC over Keccak; output length specified | `transcript.go:56-65` (`kmac256(key, msg, outLen, customisation)`); reserved for v0.4 envelope auth |
| SP 800-185 §2.3 (encoders) | `left_encode`, `right_encode`, `encode_string`, `bytepad` | `transcript.go:72-124` |
| SP 800-185 §5 (TupleHash256) | Domain-separated tuple hash | Magnetar uses the TupleHash256-style construction inline via `transcriptHash` / `transcriptHash32` in `transcript.go:132-156` |

The customisation tags used in Magnetar:

| Tag | Purpose | Defined at |
|---|---|---|
| `MAGNETAR-DKG-COMMIT-V1` | committee-root digest | `transcript.go:29` (`tagDKGCommit`) |
| `MAGNETAR-DKG-TRANSCRIPT-V1` | DKG transcript digest | `transcript.go:30` (`tagDKGTranscript`) |
| `MAGNETAR-SIGN-R1-V1` | threshold-sign Round-1 commit `D_i` | `transcript.go:31` (`tagSignR1`) |
| `MAGNETAR-SIGN-R1-MAC-V1` | (reserved for v0.4 MAC envelope) | `transcript.go:32` (`tagSignR1MAC`) |
| `MAGNETAR-SIGN-MASK-V1` | per-attempt mask derivation | `transcript.go:33` (`tagSignMask`) |
| `MAGNETAR-SEED-SHARE-V1` | Shamir coefficient stream + seed mix | `transcript.go:34` (`tagSeedShare`) |
| `lux-magnetar-v0.1` | protocol-wide domain-separation context | `transcript.go:35` (`tagDomainSep`) |

## §3 Magnetar threshold overlay traceability (SPEC.md → code)

The threshold overlay layer is novel work; it does not trace to
FIPS 205 (no NIST standard exists for threshold SLH-DSA). It
traces to `SPEC.md` and to the classical literature it cites.

### §3.1 Byte-wise Shamir VSS over GF(257)

| `SPEC.md` § | Topic | Magnetar code | Classical reference |
|---|---|---|---|
| §3 Round-1 | Dealer Shamir-shares contribution byte-by-byte | `shamir.go:70-120` (`shamirDealRandomGF`) | Shamir 1979 (information-theoretic secret sharing) |
| §4 Combine step 3 | Aggregator Lagrange-interpolates byte-sum at `x=0` over GF(257) | `shamir.go:127-174` (`shamirReconstructGF`) | Classical Lagrange interpolation |
| §3 wire layout | Share encoded as 1 big-endian uint16 per byte position (GF(257) packed in 16-bit lane) | `shamir.go:198-206` (`shareToBytes`); `shamir.go:208-216` (`shareFromBytes`) | — |

### §3.2 Three-round DKG

| `SPEC.md` § | Topic | Magnetar code |
|---|---|---|
| §3 Round-1 | Dealer samples contribution `c_i`, Shamir-shares it, broadcasts per-recipient envelopes (`share || contribution`) | `dkg.go:137-181` (`DKGSession.Round1`) |
| §3 Round-2 | Each party validates envelope set; computes transcript digest binding ordered envelope set; broadcasts digest | `dkg.go:185-240` (`DKGSession.Round2`) + `dkg.go:244-269` (`computeR2Digest`) |
| §3 Round-3 | Each party verifies digests; sums per-byte shares; sums contributions; mixes byte-sum + committee root via cSHAKE256 to recover master seed; derives group public key via `KeyFromSeed`; outputs `KeyShare` | `dkg.go:278-418` (`DKGSession.Round3`) |
| §3 identifiable abort (equivocation) | Digest mismatch produces `AbortEvidence{Kind: ComplaintEquivocation, Evidence: my_digest || accused_digest}` | `dkg.go:304-317` |

### §3.3 Two-round threshold sign + Combine

| `SPEC.md` § | Topic | Magnetar code |
|---|---|---|
| §4 Round-1 | Signer samples `rngBytes`; derives `r_i = cSHAKE256(rngBytes || sid || attempt || NodeID, tagSignMask)`; computes `masked_i = share_i XOR r_i`; commits `D_i = cSHAKE256(r_i || masked_i || tau_1, tagSignR1)` | `threshold.go:150-194` (`ThresholdSigner.Round1`) |
| §4 Round-2 | Reveal `(r_i, masked_i)` packed as `PartialSig = r_i || masked_i` | `threshold.go:198-223` (`ThresholdSigner.Round2`) |
| §4 Combine step 1 | Re-derive `D'_i` from reveals; gate on `ctEqual32(D'_i, D_i)`; reject on mismatch | `combine.go:75-116` |
| §4 Combine step 2 | Recover `share_i = masked_i XOR r_i` | `combine.go:110-114` |
| §4 Combine step 3 | Collect `t` distinct shares; Lagrange-interpolate at `x=0` over GF(257) | `combine.go:118-150` |
| §4 Combine step 4-5 | Compute committee root; mix byte-sum + committee_root via cSHAKE256 (identical to DKG Round-3 step 6) | `combine.go:151-158` |
| §4 Combine step 6-7 | Derive SLH-DSA secret key via `KeyFromSeed`; sanity-check pk matches `groupPubkey`; sign via FIPS 205 `slhdsa.SignDeterministic` | `combine.go:163-195` |
| §4 Combine step 8 | Zeroize every secret-bearing buffer on every return path | `combine.go:164-203` (explicit, no `defer`) |
| §6 byte-equality claim | Threshold output byte-equals `slhdsa.SignDeterministic(KeyFromSeed(S), msg, ctx)` | empirically `n1_byte_equality_test.go:TestN1_ByteEquality_*` |

### §3.4 Domain separation + transcript binding

| Topic | Magnetar code |
|---|---|
| Per-protocol-round customisation strings | `transcript.go:28-36` (all tags constant; rotating a tag invalidates KATs pinned at that tag) |
| TupleHash256-style binding (length-prefixed parts) | `transcript.go:126-156` (`transcriptHash`, `transcriptHash32`) |
| Constant-time byte equality | `transcript.go:158-179` (`ctEqualSlice`, `ctEqual32`) |
| Canonical committee ordering (big-endian byte order) | `transcript.go:181-190` (`nodeIDLess`); used to sort committee for `committeeRoot` |

## §4 What this document is NOT

- NOT a NIST FIPS 140-3 module-validation reference (FIPS 140-3
  applies to packaged cryptographic modules, not the algorithm
  reference).
- NOT an ACVP test-vector specification (NIST has no ACVP test
  vector set for threshold SLH-DSA; the single-party FIPS 205 layer
  in `cloudflare/circl/sign/slhdsa` is independently ACVP-testable).
- NOT a security proof. FIPS 205's security is NIST's analysis;
  Magnetar's threshold-overlay security argument lives in
  `SPEC.md` §6 (byte-equality claim) and is empirically validated
  by `TestN1_ByteEquality_*`. EC theories that mechanize this
  mapping for the threshold overlay are roadmap v0.5.0 (see
  `AXIOM-INVENTORY.md` §2 + `PROOF-CLAIMS.md` §3).
- NOT a mechanized refinement against FIPS 205. The single-party
  FIPS 205 layer is NIST-anchored; the threshold overlay is novel.

This document is the **citation discipline**: every operation in
the shipped code traces to a specific FIPS 205 / FIPS 202 /
SP 800-185 section (for the single-party + hash layer), or to a
specific `SPEC.md` section (for the Magnetar threshold overlay).

## §5 Cross-references

- `SUBMISSION.md` — submission cover sheet
- `SPEC.md` — protocol specification (single-party + threshold overlay)
- `AXIOM-INVENTORY.md` — residual axiom inventory
- `PROOF-CLAIMS.md` — narrow claim + non-claims
- `TRUSTED-COMPUTING-BASE.md` — TCB
- NIST FIPS 205 — single-party SLH-DSA normative reference
- NIST FIPS 202 — SHA-3 / SHAKE normative reference
- NIST SP 800-185 — cSHAKE / KMAC normative reference

---

**Document metadata**

- Name: `FIPS-TRACEABILITY.md`
- Version: v0.1 (initial Tier A submission-package scaffolding)
- Date: 2026-05-18
