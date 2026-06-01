# Magnetar THBS-SE v1.0 --- Threshold Hash-Based Signatures with Selected-Element Reconstruction

> Subpackage: `github.com/luxfi/magnetar/ref/go/pkg/magnetar`
> Status: v1.0.0 normative spec.

## What this is

THBS-SE is the ONE permissionless threshold construction shipped by
Magnetar v1.0. A t-of-n committee produces a SINGLE FIPS 205-shaped
signature on a slot-bound message; the public combiner role is open
to any peer (anyone can run Combine); no host is in the TCB at sign
time.

THBS-SE is the architectural counterpart of the per-validator
standalone primitive (`standalone.go`): both produce FIPS 205 wire
bytes that any unmodified verifier accepts. The per-validator
standalone path is the public-BFT primary; THBS-SE is the
permissionless threshold companion for deployments that need a single
FIPS 205-shaped signature from a committee instead of N independent
signatures.

## Hard invariant (verbatim from user spec)

```
A revealed value is allowed only if it is also present in the final
SLH-DSA signature.
```

| Reveal type | Allowed? | Notes |
|---|---|---|
| Per-round mask `r_i` | YES | Part of Round-2 PartialSig payload; legitimately public. |
| Masked share `s'_i = share_i XOR r_i` | YES | Part of Round-2 PartialSig payload; legitimately public. Combined with `r_i` recovers `share_i`, which is information-theoretically uniform-random with fewer than t leaves under GF(257) Shamir. |
| Round-1 commit hash `D_i` | YES | Public domain-separated hash. |
| Final FIPS 205 signature bytes | YES | The PUBLIC output of Combine. |
| `SK.seed` | NO | Forbidden in any party-local persistent form. Each party holds ONLY its Shamir leaf, never the seed. |
| `SK.prf` | NO | Derived from `SK.seed`. |
| Future-slot share material | NO | The slot guard refuses any same-slot re-emission. The share envelope is per-slot. |
| WOTS+ chain bases for unused chains | NO | (v1.1 strict-atom invariant.) |
| FORS leaves not selected by message digest | NO | (v1.1 strict-atom invariant.) |
| Public auth-path nodes | YES | Part of every SLH-DSA signature. |

## v1.0 ship state (honest open item)

The strictest formulation of the invariant --- "no party or combiner
EVER reconstructs SK.seed, even transiently in memory" --- requires
the v1.1 strict-atom-assembly path tracked at
`BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11`.

Magnetar v1.0 routes the final FIPS 205 byte production via
`circl/slhdsa.SignDeterministic` on a seed reconstructed by the
PUBLIC COMBINER. The seed is briefly present in the public combiner's
memory for one Sign call and is zeroized before return. The combiner
role is PUBLIC --- anyone can be the combiner --- and there is no
long-lived secret material outside party-local Shamir leaves.

This is materially stronger than a TEE-attested privileged-aggregator
model (no host is in the TCB) and materially weaker than the strict
invariant (a peer-local memory-disclosure adversary at exactly the
combine moment could observe the seed).

## Construction (v1.0 wire)

### Setup

```
1. Sample SLH-DSA seed S.
2. Derive (PK, SK) = slhdsa.Scheme().DeriveKey(S).
3. Byte-wise Shamir-share S across (n, t) committee via GF(257).
4. Publish PK + committee + (n, t).
5. Erase S. The dealer is in the TCB FOR SETUP ONLY; once setup
   returns, no party including the dealer holds S.
```

Production deployments run the leaderless PVSS-DKG path via the
sibling `luxfi/threshold` DKG package and feed the result into the
same wire-shape share envelope. v1.0 reference ships a
deterministic-dealer setup (`NewThbsSeKey`) for KAT determinism.

### Sign Round 1 (party p_i, in parallel)

```
1. Sample per-round mask r_i.
2. Compute D_i = cSHAKE256(r_i || s'_i || tau)
   where s'_i = share_i XOR r_i
     and tau = SlotBinding.Encode() || msg || party_id.
3. Broadcast (party_id, slot_id, D_i, availability_bit).
4. Persist (slot_id, H(slot_id || msg)) in local SlotGuard.
   Refuse if the same slot_id is already used for a different digest.
```

### Sign Round 2 (party p_i, after Round-1 quorum is observable)

```
1. Reveal PartialSig = r_i || s'_i.
2. Idempotent replay: re-issuing Round 1+2 for the same
   (slot_id, msg) returns the persisted (R1, R2). A genuine
   equivocation attempt (same slot_id, different msg) raises
   *ThbsSeEquivocationError without emitting the second R1.
```

### Combine (anyone, public)

```
1. Collect >= t Round-2 reveals.
2. For each, re-derive D_i from PartialSig + slot_binding + msg + party_id.
   Mismatch produces ThbsSeShareEvidence with reason=ThbsSeShareCommitMismatch.
3. Recover share_i = mask XOR masked_share via byte-wise XOR.
4. Lagrange-interpolate the seed via thbsseReconstructGF over GF(257).
5. Bind to slot via FIPS 205 ctx = tagThbsSeCtxPrefix || slot_id (32 bytes);
   total <= 255B per FIPS 205 sec 10.2.
6. Call slhdsa.SignDeterministic(seed, msg, ctx).
7. Zeroize seed + intermediate buffers.
8. Return Signature{Mode, FIPS 205 wire bytes}.
```

### Verify (anyone, public)

Standard FIPS 205 `slhdsa.Verify(pk, msg, sig, ctx)`. The v1.0
reference exposes this as `VerifyBytesCtx` (wire.go) for stateless
dispatch --- no Magnetar code path on the verifier side.

## Slot binding

Every signature is bound to the slot tuple
`(chain_id, epoch, slot, height, committee_id, message_domain)`. The
binding flows into:

1. The cSHAKE256 commit transcript (so the same committee cannot
   reuse the same share material on a different message).
2. The FIPS 205 ctx string at sign time (so any verifier holding the
   slot tuple can derive ctx independently).

Wire layout (canonical, big-endian):

```
chain_id_len(4) || chain_id ||
epoch(8) || slot(8) || height(8) ||
committee_id_len(4) || committee_id ||
message_domain_len(4) || message_domain
```

The 32-byte `slot_id = cSHAKE256(encode(binding), 32, "MAGNETAR-THBSSE-SLOT-V1")`
is the canonical key in the local slot guard and the payload of the
FIPS 205 ctx string.

## Slashing evidence

### Equivocation

A party that signs two distinct messages at the same slot binding
raises `*ThbsSeEquivocationError` carrying:

```
SlotID, PartyID,
PriorDigest, PriorR1, PriorR2,
NewDigest, NewR1, NewR2
```

The wire-shaped `ThbsSeEvidence` blob is the on-chain transmission
shape. `VerifyThbsSeEvidence` is the canonical third-party verifier:
pure function with no committee state required.

### Malformed share

Combine emits typed `ThbsSeShareEvidence` for the following
malformations:

- `ThbsSeShareSlotMismatch` --- the Round-2 reveal carries a slot
  ID that does not match the binding.
- `ThbsSeShareWireSize` --- the PartialSig is the wrong number of
  bytes for the SLH-DSA mode.
- `ThbsSeShareCommitMismatch` --- the Round-1 commit does not
  re-derive from the Round-2 reveal under the slot binding and
  message.

`VerifyThbsSeShareEvidence` is the third-party verifier; pure
function.

## Over-selected committee

With `(n, t)` and `n > t`, up to `n - t` silent withholders are
tolerated. The Lagrange basis is determined by ANY t evaluation
points, so disjoint sub-quora of size t produce byte-equal final
signatures (the public combiner is a PURE function of its
inputs). The 8-th test gate
`TestThbsSE_PublicCombiner_Determinism` pins this.

## API surface

- `NewThbsSeKey(params, threshold, committee, rng) -> (*ThbsSeKey, error)`
- `ThbsSeRound1(params, share, binding, msg, guard, rng) -> (r1, r2, error)`
- `Combine(input ThbsSeCombineInput) -> (*Signature, []ThbsSeShareEvidence, error)`
- `ThbsSeSlotGuard` + `NewThbsSeSlotGuard`, `Record`, `Has`
- `VerifyThbsSeEvidence(params, ev, msgPrior, msgNew, bindingPrior, bindingNew) -> bool`
- `VerifyThbsSeShareEvidence(params, ev, binding, msg) -> bool`

Stateless wire dispatch (consumed by `luxfi/threshold/pkg/thresholdd`):

- `VerifyBytes(gpkBytes, message, sigBytes) -> bool`
- `VerifyBytesCtx(gpkBytes, message, ctx, sigBytes) -> bool`

## Test gates

The 8 mandated test gates plus 2 bonus correctness checks:

| Gate | Test | Status |
|---|---|---|
| 1 | `TestThbsSE_Wire_FIPS205Verifiable` (3 modes) | PASS |
| 2 | `TestThbsSE_RejectSeedReveal` | PASS |
| 3 | `TestThbsSE_RejectUnselectedFORS` | PASS |
| 4 | `TestThbsSE_RejectUnselectedWOTS` | PASS |
| 5 | `TestThbsSE_SlotReuseRejected` | PASS |
| 6 | `TestThbsSE_OverselectedCommittee` | PASS |
| 7 | `TestThbsSE_SlotBindingDomainSeparation` | PASS |
| 8 | `BenchmarkThbsSE_Sign_5of7` (192f < 100 ms/op) | PASS |
| bonus | `TestThbsSE_PublicCombiner_Determinism` | PASS |
| KAT | `TestKAT_ThbsSe` (n=7, t=4, 3 modes, 3 messages) | PASS |

## Citations

- McGrew, D., Wallace, C. and Whyte, W. (2019). *Threshold Hash-Based
  Signatures.* IACR ePrint 2019/793.
- Cozzo, D. and Smart, N. P. (2019). *Sharing the LUOV.* EUROCRYPT.
- Bonte, C., Smart, N. P. and Tan, T. (2023). *Threshold SPHINCS+.*
- Schoenmakers, B. (1999). *A simple publicly verifiable secret
  sharing scheme and its application to electronic voting.* CRYPTO.
- Shamir, A. (1979). *How to share a secret.* CACM.
- NIST FIPS 205 (2024). *Stateless Hash-Based Digital Signature
  Standard.*
