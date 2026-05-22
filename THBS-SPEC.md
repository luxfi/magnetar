# Magnetar-THBS v1 — True Threshold Hash-Based Signatures

> Subpackage: `github.com/luxfi/magnetar/ref/go/pkg/thbs`
> Status: v1 dealer-backed reference implementation.

## What this is

A reference implementation of **true threshold hash-based signing** in the McGrew et al. sense: parties hold secret-shared FORS/WOTS+ elements; for each message, parties release shares ONLY for the SELECTED elements determined by the message digest; the combiner reconstructs the final signature elements and ships an ordinary HBS-style signature.

**Critical distinction from `magnetar/CombineWithSeedReconstruction`:**

| Property | `magnetar.CombineWithSeedReconstruction` (v0.1 reveal-and-aggregate) | `thbs.Aggregate` (v1 true threshold) |
| --- | --- | --- |
| What is shared | The whole SLH-DSA scheme seed | Individual WOTS+ chain values + FORS leaves |
| Aggregator sees | Reconstructed master seed | Reconstructed selected elements only |
| Aggregator can sign future messages? | YES (it has the seed) | NO (only the elements selected by this digest) |
| Verifier | FIPS 205 SLH-DSA (byte-equal) | Custom HBS verifier (v1); FIPS 205 (v3 target) |
| Trust model | Aggregator-as-TCB / TEE custody only | Public-BFT acceptable (no party holds the seed) |

## v1 scope — honest

| Concern | v1 (this release) |
| --- | --- |
| Setup | **Dealer-backed.** A trusted dealer generates shared WOTS+/FORS material and distributes shares. (Public DKG = v2.) |
| Helper data | Shipped alongside the public key (McGrew et al. permit this). The dealer's pre-computed authentication paths are public; only the leaf/chain values are secret-shared. |
| Verifier | A **custom HBS verifier** in `thbs.Verify`. Bit-equality with FIPS 205 SLH-DSA wire format is a v3 goal, not v1. |
| Anti-equivocation | Each party stores `slot_id -> message_digest`. Same slot, different digest -> `ErrEquivocation` + `Evidence{...}` for slashing. |
| Parameter set | Lightweight reference parameters (WOTS+ Winternitz w=16, FORS k=14, a=12, height=10). NOT FIPS 205 wire-compatible. |

## What v1 explicitly does NOT do

1. No public-DKG: setup is dealer-backed. The dealer learns the secret elements at setup and must erase them before going live. v2 ports the BB-PEEDA-style PVSS-based DKG from the literature.
2. No FIPS 205 wire compatibility: a FIPS 205 verifier will NOT accept these signatures. v3 maps to the FIPS 205 parameter set and produces byte-identical signatures (the cost is significantly larger helper data and a more complex DKG).
3. No public-coin sponge stateless construction: v1 is stateful in the sense that each `Slot` must be used at most once. A double-use is identifiable abort (same-slot-different-digest evidence emitted).

## v2 / v3 roadmap

- **v2: Public DKG.** Replace the dealer with a coalition-DKG (Pedersen-VSS adapted for hash chains, or the PVSS variant in McGrew et al.). No single party learns the secret elements at any point.
- **v3: FIPS 205 wire compatibility.** Map the threshold elements onto the FIPS 205 hypertree (XMSS_MT) and produce byte-identical SLH-DSA signatures. Helper data grows to ~30 KiB but verifier code is unchanged FIPS 205.
- **v4: Stateless re-randomisation.** Address the stateful-slot constraint via the FIPS 205 `opt_rand` re-randomisation channel for randomised mode.

## Reference

McGrew, Fluhrer, Gazdag, Kampanakis, Morton, Westerbaan — "Hash-Based Signatures: An Outline for a New Standard" / "State Management for Hash-Based Signatures" — and the follow-on threshold extension treated in:

- McGrew et al., "Coalition and Threshold Hash-Based Signatures", IACR ePrint 2019/793 (and IRTF draft `draft-mcgrew-hash-sigs-15` line of work).
- Bonte, Smart, Tan, "Threshold SPHINCS+", PKC 2024 (the negative result confirming that bytewise FIPS 205 threshold without seed reconstruction is hard — informs our v1 scope choice to ship a *custom* HBS verifier).

## Invariant (verbatim)

```
OK:        ReconstructElement(slot, elementID, shares)
Forbidden: ReconstructSeed, ReconstructPrivateKey,
           ExpandPrivateKey, DeriveAllFutureElements
```

The thbs subpackage *enforces* this invariant: there is no API path that returns a future-signing key. The only `Reconstruct*` symbol in thbs/*.go is `reconstructElement` (file-scope, unexported, used by `Aggregate`). The dealer's secret elements are zeroised after `DKG` returns. Tests `TestTHBS_DKG_NoSeedExposure` and `TestTHBS_Aggregate_NoFutureSigningMaterial` pin this.

## Anti-equivocation

```
For each (party_id, slot_id):
   first call:   record digest_a, share_a; return PartialSignature
   second call:  if msg_digest_b == digest_a: idempotent re-emit
                 if msg_digest_b != digest_a: return ErrEquivocation
                                              + Evidence{party_id, slot_id,
                                                         digest_a, share_a,
                                                         digest_b, share_b}
```

The `Evidence` payload is sufficient for an external slashing layer to verify the equivocation (both shares were validly produced by the same party against the same slot under different messages) without re-running the protocol.
