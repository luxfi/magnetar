# Magnetar v0.1 — Construction specification

> Threshold FIPS 205 SLH-DSA via reveal-and-aggregate. Mirrors
> Pulsar's v0.1 reveal-and-aggregate pattern, ported to SLH-DSA's
> scheme-seed-as-secret model.
>
> Status: v0.1 implementation specification. **NOT yet
> independently reviewed.** See `BLOCKERS.md` BLK-7 and BLK-9 for
> the proof-and-review path to Tier A.

## 1. Notation

| Symbol | Meaning |
|---|---|
| `n` | committee size |
| `t` | reconstruction threshold (1 ≤ t ≤ n ≤ 256) |
| `q` | Shamir prime, fixed at 257 (smallest prime > 255) |
| `seed_size` | SLH-DSA scheme-seed length: 96 bytes for SHAKE-192s/192f, 128 bytes for SHAKE-256s |
| `P_i` | party `i`, `1 ≤ i ≤ n` |
| `x_i` | Shamir x-coordinate of `P_i`, `1 ≤ x_i ≤ 256`, distinct per party |
| `c_i` | `P_i`'s contribution to the joint seed, `c_i ∈ {0,1}^{8·seed_size}` |
| `S` | joint master seed, `S ∈ {0,1}^{8·seed_size}` |
| `share_i` | `P_i`'s Shamir share of the byte-sum used to mix to `S` |
| `pk`, `sk` | FIPS 205 SLH-DSA group public / private keypair derived from `S` |

## 2. Hash domain separation

All cSHAKE / KMAC calls use function-name `"Magnetar"` and one of
the following customisation tags:

| Tag | Purpose |
|---|---|
| `MAGNETAR-DKG-COMMIT-V1` | committee-root digest |
| `MAGNETAR-DKG-TRANSCRIPT-V1` | DKG transcript digest |
| `MAGNETAR-SIGN-R1-V1` | threshold-sign Round-1 commit `D_i` |
| `MAGNETAR-SIGN-R1-MAC-V1` | (reserved for v0.2 MAC envelope) |
| `MAGNETAR-SIGN-MASK-V1` | per-attempt mask derivation |
| `MAGNETAR-SEED-SHARE-V1` | Shamir coefficient stream + seed mix |

The protocol-wide domain-separation context is the ASCII string
`"lux-magnetar-v0.1"` (`tagDomainSep`).

## 3. DKG protocol

### Round 1 (dealer P_i)

1. Sample `c_i ←$ {0,1}^{8·seed_size}` from `rng`.
2. Sample `seed_size · 2 · (t-1)` bytes of coefficient material from `rng` (the random Shamir polynomial coefficients).
3. Run byte-wise Shamir-share-deal over GF(257):
   - For each byte position `b ∈ [0, seed_size)`, define a polynomial `f_b(x) = c_i[b] + a_{b,1}·x + ... + a_{b,t-1}·x^{t-1} (mod 257)` where `a_{b,j}` are derived from the coefficient stream.
   - For each recipient `P_j`, compute `share_{i→j}[b] = f_b(x_j) (mod 257)` for every byte `b`. The result is a 2·seed_size-byte big-endian uint16 vector.
4. Construct one envelope per recipient:
   ```
   Envelope_{i→j} := (share_{i→j} || c_i)
   ```
   The full `c_i` is duplicated into every envelope so that at Round 2 each `P_j` can sum contributions to compute the joint master public key locally.
5. Broadcast `DKGRound1Msg{NodeID = P_i, Envelopes = { P_j ↦ Envelope_{i→j} }_{j∈[n]}}`.

### Round 2 (party P_i)

1. Receive Round-1 broadcasts from every dealer in committee.
2. Validate: every broadcast contains an envelope for every recipient (no omissions); every envelope has the expected wire sizes; sender is in committee.
3. Compute the transcript digest binding the entire ordered envelope set:
   ```
   τ_dkg := lux-magnetar-v0.1 ‖ Mode ‖ t ‖ n ‖ committee_in_order
   D := cSHAKE256( τ_dkg ‖ for_each_dealer_in_order(for_each_recipient_in_order(share || contribution)),
                   N="Magnetar", S="MAGNETAR-DKG-TRANSCRIPT-V1", 32 bytes )
   ```
4. Broadcast `DKGRound2Msg{NodeID = P_i, Digest = D}`.

### Round 3 (party P_i)

1. Receive Round-2 digests from every party.
2. Verify every received digest equals `D` (computed locally). A mismatch is identifiable abort with `ComplaintKind = ComplaintEquivocation`; the conflicting digest pair is the evidence blob.
3. Sum per-byte Shamir shares received from each dealer:
   ```
   my_share_sum[b] := Σ_{j∈[n]} share_{j→i}[b] (mod 257)  for b ∈ [0, seed_size)
   ```
4. Sum dealer contributions byte-by-byte over GF(257):
   ```
   master_byteSum[b] := Σ_{j∈[n]} c_j[b] (mod 257)  for b ∈ [0, seed_size)
   ```
5. Compute the committee root:
   ```
   committee_root := cSHAKE256( "MAGNETAR-COMMITTEE-V1" ‖ sorted_committee,
                                 N="Magnetar", S="MAGNETAR-DKG-COMMIT-V1", 32 bytes )
   ```
6. Mix to the master seed:
   ```
   mix := (master_byteSum encoded as 2·seed_size big-endian uint16) ‖ committee_root
   S := cSHAKE256( mix, N="Magnetar", S="MAGNETAR-SEED-SHARE-V1", seed_size bytes )
   ```
7. Derive the group public key via FIPS 205:
   ```
   (pk, sk) := slhdsa.Scheme(SLH-DSA-SHAKE-{192s,192f,256s}).DeriveKey(S)
   ```
   Discard `sk`; publish `pk` as the joint group public key. (Each party can compute the same `pk` because every party has identical `master_byteSum` and `committee_root` inputs.)
8. Output: `KeyShare{NodeID = P_i, EvalPoint = x_i = i, Share = my_share_sum, Pub = pk}`.

### DKG correctness

For any quorum `Q ⊆ [n]` with `|Q| ≥ t`:
```
Lagrange-interpolate({(x_i, my_share_sum_i) : i ∈ Q}) = master_byteSum
```
because `my_share_sum_i = Σ_j share_{j→i} = Σ_j f_{j,b}(x_i)` and the Lagrange interpolation at `x=0` over GF(257) of the polynomial sums `Σ_j f_{j,b}` recovers `Σ_j c_j[b] = master_byteSum[b]`.

Therefore any quorum's reconstructed seed `S` is identical to the one computed at Round 3.

## 4. Threshold signing

### Round 1 (signer P_i, i ∈ T ⊆ [n], |T| = t)

1. Sample `rngBytes ←$ {0,1}^{8·2·seed_size}` from `rng`.
2. Derive per-attempt mask:
   ```
   maskMix := rngBytes ‖ session_id ‖ attempt(BE 4 bytes) ‖ NodeID
   r_i := cSHAKE256( maskMix, N="Magnetar", S="MAGNETAR-SIGN-MASK-V1", 2·seed_size bytes )
   ```
3. Mask the share byte-by-byte XOR:
   ```
   masked_i[b] := share_i[b] XOR r_i[b]  for b ∈ [0, 2·seed_size)
   ```
4. Compute Round-1 transcript binding:
   ```
   τ_1 := SP800-185-encode( session_id, attempt, quorum, NodeID, pk, message )
   ```
5. Compute commit:
   ```
   D_i := cSHAKE256( r_i ‖ masked_i ‖ τ_1, N="Magnetar", S="MAGNETAR-SIGN-R1-V1", 32 bytes )
   ```
6. Broadcast `Round1Message{NodeID, SessionID, Attempt, Commit = D_i}`.

### Round 2 (signer P_i)

1. Validate Round-1 broadcasts (consistent session/attempt).
2. Reveal:
   ```
   Round2Message{NodeID, SessionID, Attempt, PartialSig = r_i ‖ masked_i}
   ```

### Combine (aggregator)

1. For each Round-2 reveal `(r_i, masked_i)`:
   a. Recompute `D'_i = cSHAKE256(r_i ‖ masked_i ‖ τ_1_i, ...)` and check `D'_i == Round1Message.Commit`. Reject on mismatch.
   b. Recover `share_i = masked_i XOR r_i`.
2. Collect `t` distinct shares. Pair each with its `KeyShare.EvalPoint` from the directory.
3. Run Lagrange interpolation over GF(257) at `x=0`:
   ```
   reconstructed_byteSum[b] := Σ_{i∈Q} λ_i · share_i[b] (mod 257)
   ```
   where `λ_i = Π_{j≠i} (-x_j) / (x_i - x_j) (mod 257)`.
4. Compute committee_root from `allShares` (same definition as Round 3 step 5).
5. Mix to recover the master seed (identical to DKG Round 3 step 6):
   ```
   S := cSHAKE256( reconstructed_byteSum_BE ‖ committee_root, N="Magnetar", S="MAGNETAR-SEED-SHARE-V1", seed_size bytes )
   ```
6. Derive the SLH-DSA secret key:
   ```
   (pk_rec, sk_rec) := slhdsa.Scheme(...).DeriveKey(S)
   ```
   If `pk_rec ≠ groupPubkey`: abort with `ErrPubkeyMismatch`.
7. Sign:
   ```
   sig := slhdsa.SignDeterministic(sk_rec, message, ctx)
   ```
   (When `randomized=true`, `SignRandomized` is used with the caller's `rng`.)
8. Zeroize `S, sk_rec, mix, reconstructed_byteSum`.
9. Return `Signature{Mode, Bytes = sig}`.

## 5. Verify

`Verify` is a thin dispatch to `slhdsa.Verify(pk, NewMessage(message), sig, ctx)`. **No Magnetar-specific envelope.** This is the Class-N1-analog property: any unmodified FIPS 205 verifier accepts Magnetar signatures.

## 6. Class-N1-analog byte-equality claim

**Claim (Magnetar reveal-and-aggregate byte-equality).** For any honest threshold-sign session over committee `[n]` with threshold `t`, any quorum `Q` of size `t`, message `m`, context `ctx`, session_id `sid`, attempt `κ`:

> `Combine(...) = slhdsa.SignDeterministic(slhdsa.DeriveKey(S), NewMessage(m), ctx)`

where `S` is the master seed computed at DKG Round 3.

**Proof sketch.** Combine reconstructs `master_byteSum` from `Q`'s shares via Lagrange interpolation (correct by Shamir's secret sharing over GF(257) for any quorum of size ≥ t). It then computes `committee_root` from the same `allShares` set that fixed it at DKG time, and applies the identical cSHAKE256 mix → produces the identical `S`. Sign on `DeriveKey(S)` is byte-deterministic over `(S, m, ctx)`. ∎

**Empirical validation.** See `n1_byte_equality_test.go`: `TestN1_ByteEquality_ThresholdMatchesCentralized` and `TestN1_ByteEquality_DifferentQuorumsSameSignature` exercise the claim across three configurations and across distinct quorums.

## 7. Trust model — the v0.1 reveal-and-aggregate caveat

**The aggregator process is in the trusted computing base (TCB) for the brief window the master seed is reconstructed in memory.**

This is the same trust caveat Pulsar's v0.1 reveal-and-aggregate carries; it is documented honestly in Pulsar's `DEPLOYMENT-RUNBOOK.md` and is inherited verbatim by Magnetar.

Specifically:

- At step 6 of `Combine` (§4), the master SLH-DSA seed `S` is recomputed in aggregator memory.
- At step 7, FIPS 205 `SignDeterministic` consumes `S` to produce the signature.
- At step 8, all secret-bearing buffers (`S, sk_rec, mix, reconstructed_byteSum`) are explicitly zeroized.

During steps 6–7, an adversary with arbitrary code-execution on the aggregator host can extract `S` via:
- `/proc/<pid>/mem`
- a coredump
- a swap-file or hibernation image
- `ptrace`
- a malicious kernel/hypervisor

Operational mitigations are described in `DEPLOYMENT-RUNBOOK.md` "Aggregator hardening".

**What this caveat does NOT cover:**

- A passive **network observer** never sees `S`. Round-1 commits and Round-2 reveals collectively carry `share_i` values (masked + revealed), but reconstruction requires combining `t` of them with the matching `EvalPoint` directory. v0.1 v1 envelopes are plaintext (a passive observer can see committee shares); v0.2 will wrap them under ML-KEM-768 to the recipient's long-term identity public key, matching Pulsar's BLOCKERS.md CR-8 pattern.
- A **single Byzantine committee member** cannot forge a signature: forging requires reconstructing `S`, which requires `t` shares.
- A **single Byzantine aggregator** cannot forge a signature for a message it did not receive valid Round-2 reveals on: Combine's commit-bind check (step 1a) rejects tampered reveals.

## 8. Identifiable abort

The protocol commits to identifiable abort: every detected deviation produces verifiable evidence suitable for slashing.

| Complaint | Detected at | Evidence |
|---|---|---|
| `ComplaintEquivocation` | DKG Round 3 | Conflicting `Digest` from accused; honest party's local `Digest` |
| `ComplaintBadDelivery` | DKG Round 2 (envelope shape check) | Malformed envelope |

The v0.1 protocol omits the per-pair MAC layer that Pulsar uses (BLOCKERS.md CR-7). This is documented; v0.2 adds MACs once the trust model tightens.

## 9. Parameter sets

| Mode | NIST PQ Cat | Pub key | Priv key | Signature | Seed |
|---|---|---|---|---|---|
| `Magnetar-SHAKE-192s` | 3 | 48 B | 96 B | 16,224 B | 96 B |
| `Magnetar-SHAKE-192f` | 3 | 48 B | 96 B | 35,664 B | 96 B |
| `Magnetar-SHAKE-256s` | 5 | 64 B | 128 B | 29,792 B | 128 B |

**Recommended production target: `Magnetar-SHAKE-192s`** (matches NIST Cat 3, smallest signature in its category).

## 10. Honest non-claims

Magnetar v0.1 does NOT claim:

- **Full MPC threshold signing.** v0.1 is reveal-and-aggregate; the aggregator process is TCB.
- **Network-observer secrecy of envelopes** in v0.1. Plaintext envelopes are visible to a passive observer; v0.2 closes this with ML-KEM-768 wrapping.
- **Sub-second signing.** SLH-DSA single-party signing on SHAKE-192s is ~10–50ms depending on hardware; race-detector runs are 5–10× slower.
- **Formal verification.** No EasyCrypt, Lean, or Jasmin artifacts ship in v0.1. See `BLOCKERS.md` BLK-7.

## 11. References

- FIPS 205: Stateless Hash-Based Digital Signature Standard (2024).
- Shamir, A. *How to share a secret*. Communications of the ACM, 1979.
- Pulsar v0.1 `SPEC.md` — reveal-and-aggregate pattern adapted from there.
- `BLOCKERS.md` — outstanding Tier B → A path.
- `DEPLOYMENT-RUNBOOK.md` — operator-facing trust-model disclosure.

---

**Document metadata**

- File: `SPEC.md`
- Version: v0.1
- Date: 2026-05-18
- Status: implementation specification; **not yet independently reviewed** (see BLK-9).
