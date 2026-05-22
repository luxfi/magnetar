# Magnetar — Deployment runbook

> Operator-facing trust-model disclosure and hardening guidance for
> Magnetar. **READ THIS BEFORE DEPLOYING.**

## 0. Choose your mode — the most important decision

Magnetar ships **three distinct signing surfaces** with different trust
models. Picking the wrong one is the single largest deployment risk.

| Surface | Trust model | Public-BFT safe | Use case |
|---|---|---|---|
| `ValidatorSign` + `VerifyAggregateCert` | Per-validator standalone keys | **YES** | **Lux public-BFT validator quorum (PRIMARY)** |
| `AggregateSignatures` (SignedBundle form) | Per-validator standalone keys | YES | Same as above, SDK-friendly bundle shape |
| `CombineWithSeedReconstruction` | Aggregator-as-TCB (TEE required) | NO | M-Chain custody w/ TEE attestation |
| `thbs.DealerDKG` + `thbs.SignShare` + `thbs.Aggregate` | Trusted-dealer-as-TCB (TEE required) | NO | M-Chain bridge custody w/ TEE attestation |
| `thbs/dkg2/` | Public PVSS + MPC (research) | YES (when complete) | Future research; v0.6+ candidate |

### TL;DR

- **PUBLIC BFT CONSENSUS** (validator quorum, untrusted aggregator
  host) → `magnetar.PerValidatorKeypair` + `magnetar.ValidatorSign` +
  `magnetar.VerifyAggregateCert` (`ref/go/pkg/magnetar/standalone.go`).
  This is the **CANONICAL primary primitive for Lux public-BFT
  post-quantum consensus**. Per-validator standalone SLH-DSA keypairs;
  no DKG; no dealer; no aggregator-as-TCB. The consensus layer
  collects N validator signatures and a relying party calls
  `VerifyAggregateCert` to obtain the count of valid signers. Wire
  cost is N × |σ|; Z-Chain Groth16 rollup compresses to ~192 bytes.
  See §10.

- **PUBLIC BFT, SDK SHAPE** (same model as above, but the
  consumer prefers the nested-bundle wire format) →
  `magnetar.AggregateSignatures` + `magnetar.VerifyAggregated`
  (`ref/go/pkg/magnetar/aggregate.go`). Byte-equivalent to the
  standalone form; differs only in wire encoding shape.

- **M-CHAIN CUSTODY with TEE** (M-Chain thresholdvm host with
  TDX/SEV-SNP/SGX attestation, the LP-134 thresholdvm M-Chain mode)
  → EITHER:
    * `magnetar.CombineWithSeedReconstruction` (reveal-and-aggregate;
      master seed reconstructed in aggregator memory; trust caveat in
      §1 applies), OR
    * `thbs.DealerDKG` + `thbs.SignShare` + `thbs.Aggregate` (true
      threshold HBS per McGrew et al.; dealer learns secrets at
      setup time; per-signature reveals only the SELECTED elements).
  Both REQUIRE TEE attestation of the dealer/aggregator host.

- **RESEARCH / FUTURE** (public-DKG threshold HBS, no dealer, no
  TEE) → `thbs/dkg2/` ships the PVSS layer as a skeleton. The
  MPC-root layer is OPEN RESEARCH; see `BLOCKERS.md::MAGNETAR-PUBLIC-
  DKG-1`. Will be the public-BFT-safe THRESHOLD path in v0.6+
  once an MPC framework or MPC-friendly hash is selected.

- **Anything else** → `magnetar.ValidatorSign`. The reveal-and-
  aggregate and dealer-backed-threshold paths are NOT safe for
  public deployments.

### Decision tree

```
              ┌────────────────────────────────────────────────┐
              │  WHO NEEDS TO VERIFY THIS SIGNATURE?           │
              └────────────────────────────────────────────────┘
                                  │
              ┌───────────────────┴───────────────────┐
              │                                       │
        PUBLIC,                                INTERNAL,
        untrusted verifiers                    pre-attested TCB
        (BFT chain,                            (M-Chain custody,
        external relayers)                     thresholdvm)
              │                                       │
              ▼                                       ▼
   ┌─────────────────────────┐          ┌─────────────────────────────┐
   │   magnetar.             │          │ Is an aggregator/dealer host│
   │   ValidatorSign +       │          │ attested by TEE             │
   │   VerifyAggregateCert   │          │ (TDX/SEV-SNP/SGX)?          │
   │                         │          └─────────────────────────────┘
   │   (PRIMARY public-BFT-  │                       │
   │    safe primitive;      │           ┌───────────┴───────────┐
   │    per-validator        │           │                       │
   │    standalone keys)     │          YES                     NO
   │                         │           │                       │
   │ + Z-Chain Groth16       │           ▼                       ▼
   │   rollup compresses     │  ┌─────────────────────┐  ┌──────────────────────┐
   │   N × |σ| → ~192 B      │  │ Pick one of:        │  │ magnetar.ValidatorSign│
   └─────────────────────────┘  │ - magnetar.Combine- │  │ — DO NOT use the     │
                                │   WithSeedReconstr. │  │ dealer / reveal-and- │
                                │ - thbs.DealerDKG +  │  │ aggregate paths      │
                                │   thbs.SignShare    │  │ outside TEE!         │
                                └─────────────────────┘  └──────────────────────┘
```

## 1. `CombineWithSeedReconstruction` (v0.1 reveal-and-aggregate) trust caveat

**The Magnetar `CombineWithSeedReconstruction` aggregator process holds the reconstructed master SLH-DSA seed in memory for the duration of one call.**

This is the v0.1 reveal-and-aggregate trust model. It is identical to Pulsar's v0.1 reveal-and-aggregate trust model. The construction is **honest** about this: the security properties below are precisely what `CombineWithSeedReconstruction` delivers, and the path to v0.2 (true MPC, aggregator never sees the seed) is in `BLOCKERS.md`.

**Why this is fundamental, not a Magnetar choice:**

SLH-DSA (FIPS 205) is hash-based. The literature confirms there is *no efficient threshold MPC* that produces a single FIPS 205-shaped signature without reconstructing the master seed:

- Cozzo & Smart, "Sharing the LUOV" (EUROCRYPT 2019) — establishes that hash-based signatures are MPC-hard.
- Bonte, Smart, Tan, "Threshold SPHINCS+" (2023) — exhaustive infeasibility analysis.
- NIST IR 8214 / MPTC submission notes — SLH-DSA classified as "highest threshold-MPC cost" among the FIPS 20{3,4,5} family.
- FIPS 205 §6 SLH-DSA-Sign-Internal — direct inspection confirms no Lagrange-aggregatable response in the algorithm.

If you cannot trust the aggregator host as TCB, use `AggregateSignatures` instead (see §0 and §10). That mode replaces "reconstruct the seed" with "collect N separate signatures" and is the SOTA answer for public-BFT post-quantum finality on SLH-DSA.

### What this means operationally

During a `CombineWithSeedReconstruction` call (typically ≤100 ms for SHAKE-192s on commodity hardware), the following secret material is live in the aggregator process's address space:

| Buffer | Lifetime | Wiped by |
|---|---|---|
| `master_seed` (96 / 128 bytes) | ~ duration of one `slhdsa.SignDeterministic` call | `zeroizeBytes` at every return path in `combine.go` |
| `sk_rec` (96 / 128 bytes) | ~ duration of one `slhdsa.SignDeterministic` call | `zeroizePrivateKey` |
| `byteSum_bytes` (2×seed_size bytes) | from share Lagrange reconstruction to mix completion | `zeroizeBytes` |
| `mixInput` (2×seed_size + 32 bytes) | from mix construction to cSHAKE output | `zeroizeBytes` |

During this window, an adversary with one of the capabilities below can extract `master_seed` (and therefore forge arbitrary future signatures under the group key):

- arbitrary-code-execution on the aggregator host
- `/proc/<pid>/mem` read of the aggregator process
- a coredump triggered during a Sign call
- a swap-file or hibernation image written to disk
- `ptrace` attached to the aggregator process
- a malicious kernel or hypervisor

### Hardening matrix

| Mitigation | What it protects against | How to enable |
|---|---|---|
| **TEE (SGX / SEV-SNP / TDX)** | malicious kernel/hypervisor, /proc/<pid>/mem from outside the enclave | run aggregator inside a confidential VM or enclave |
| `mlock` the secret buffers | swap / hibernation | the Go runtime does not expose `mlock`; deploy with `vm.swappiness=0` + `swapoff` |
| `prctl(PR_SET_DUMPABLE, 0)` | coredumps | set ulimit core 0 (`ulimit -c 0`), set `/proc/sys/kernel/core_pattern` to disable cores, or run inside a container with `--security-opt no-new-privileges` |
| ptrace-off (Yama LSM `kernel.yama.ptrace_scope=3`) | local ptrace attach | sysctl on the aggregator host |
| Aggregator is a **short-lived process** (one Sign per process invocation, then exit) | post-mortem analysis of the long-lived process | wrap aggregator behind a per-Sign exec spawn |
| Hardware HSM-backed aggregator | host compromise | offload `slhdsa.SignDeterministic` to an HSM — note: most commodity HSMs do not yet ship SLH-DSA |

The Pulsar v0.1 deployment runbook mandates **TEE + mlock + ptrace-off** as the baseline; Magnetar v0.1 inherits the same requirement.

### What this caveat does NOT cover (safe by construction)

- A **single Byzantine committee member** cannot forge a signature. Forging requires `t` valid Round-2 reveals, which requires `t` honest signers to participate.
- A **single Byzantine aggregator** cannot forge a signature for a message that did not receive `t` Round-2 reveals. `Combine`'s commit-bind check (re-derives each `D'_i` from the reveal and compares to the Round-1 broadcast `D_i`) rejects tampered reveals at constant-time check.
- A **passive network observer** does NOT see the reconstructed seed. v0.1 envelopes are plaintext, so a passive observer can collect Shamir shares (one per committee member, but at most one share value per dealer-recipient pair); reconstructing the seed requires the EvalPoint directory + at least `t` distinct envelopes from a single dealer. v0.2 closes this with ML-KEM-768 envelope wrapping.
- The **wire signature** is byte-equal to single-party FIPS 205. Any unmodified FIPS 205 verifier (including stock SLH-DSA validators in standard libraries) accepts Magnetar signatures with no code change.

## 2. Aggregator role assignment

Any party in the quorum (or an external third-party aggregator) can call `CombineWithSeedReconstruction`. The protocol does not assume a specific aggregator; the aggregator's identity is not bound into the signature.

**Recommendation:** rotate aggregator role across signing requests to minimise the seed-exposure window on any single host. A leader-rotation pattern over committee members (round-robin keyed by `session_id`) is a reasonable v0.1 default.

## 3. DKG ceremony procedure

1. **Committee membership freeze.** All `n` committee members must agree on the committee NodeID set BEFORE Round 1. Committee membership is bound into the transcript digest at DKG Round 2; mid-ceremony additions are rejected.
2. **Per-party entropy.** Each party MUST use a cryptographically secure RNG for `NewDKGSession.rng`. Reusing entropy across DKG ceremonies leaks contributions.
3. **Round-1 envelope authenticity.** v0.1 envelopes are NOT KEM-wrapped — the network layer MUST authenticate dealers (TLS, sigs, gossip auth) to prevent forged envelopes. v0.2 adds ML-KEM-768 wrapping.
4. **Round-2 digest agreement.** Honest parties detect dealer equivocation when their Round-3 local digest disagrees with any received Round-2 digest. The `ComplaintEquivocation` AbortEvidence is produced; protocol-layer drivers MUST broadcast this for slashing.

## 4. Threshold-sign ceremony procedure

1. **Quorum freeze.** All `t` quorum members must agree on the quorum NodeID set BEFORE Round 1. Quorum is bound into the `τ_1` transcript; mid-ceremony quorum changes are rejected.
2. **Per-attempt RNG.** Each `ThresholdSigner` MUST use a fresh RNG state per (session_id, attempt) pair. Reusing RNG across attempts gives the same mask, which leaks the share to anyone observing the Round-2 reveal.
3. **Round-2 timing.** Round-2 messages SHOULD be released only after every quorum member's Round-1 commit is in hand. This is a protocol invariant; if Round-2 is released early, an attacker can fork the session at Round 1 and extract two distinct shares from the same party (a forgery vector).
4. **Aggregator hardening.** The aggregator host MUST follow §1 hardening (TEE + mlock + ptrace-off baseline).

## 5. Key-share storage

`KeyShare` is a long-lived secret. Storage requirements:

- Encrypt-at-rest with a host-bound key (TPM-sealed, or KMS-wrapped under the host's identity attestation).
- NEVER write `KeyShare.Share` to disk in plaintext.
- Recommended: hold `KeyShare` in a TEE that performs the Round-1/Round-2 computation; the host process never touches the share bytes.

## 6. Quorum rotation / resharing

Magnetar v0.1 does NOT ship resharing. Once a committee is bootstrapped via DKG, the only way to rotate is to run a fresh DKG (producing a new group public key).

v0.2 will ship zero-secret-refresh resharing matching Pulsar's resharing pattern.

## 7. Honest non-warranties

Magnetar v0.1 is shipped under the BSD-3-Clause license with NO WARRANTY. In particular:

- **No independent cryptographic review** of the v0.1 protocol has occurred. See `BLOCKERS.md` BLK-9.
- **No EasyCrypt / Lean / Jasmin proofs** ship in v0.1. See `BLOCKERS.md` BLK-7.
- **No constant-time analysis** of the threshold layer has been conducted under `dudect` or formal tooling.
- **No NIST MPTC submission** has been made.
- **No production Lux deployment** uses Magnetar v0.1. The Polaris profile in `luxfi/quasar` references Magnetar at Tier A; v0.1 reaches Tier B only.

Operators deploying Magnetar v0.1 do so at their own risk and SHOULD layer it with Pulsar (Tier A production primitive) under a cross-family cert profile rather than as the sole signing scheme.

## 8. Cross-references

- `SPEC.md` — full protocol specification
- `BLOCKERS.md` — Tier B → A path (incl. `MAGNETAR-PUBLIC-DKG-1` for the public-DKG research path)
- `SUBMISSION-STATUS.md` — NIST MPTC submission status
- `THBS-SPEC.md` — true threshold HBS subpackage scope and v1/v2/v3 roadmap
- `ref/go/pkg/thbs/dkg2/README.md` — public-DKG skeleton + research path
- [`luxfi/pulsar/DEPLOYMENT-RUNBOOK.md`](https://github.com/luxfi/pulsar/blob/main/DEPLOYMENT-RUNBOOK.md) — sibling runbook for the threshold M-LWE primitive

## 9. Public-BFT primary primitive: `ValidatorSign` + `VerifyAggregateCert`

This is the **CANONICAL primary primitive** for using Magnetar in a
Lux public-BFT validator quorum. It does NOT require an aggregator
or dealer in the TCB. **This is the path you SHOULD pick** unless
§0's decision tree points elsewhere.

### Construction summary

1. **Per-validator keygen** (one-time, off-chain): each validator `i`
   independently runs `magnetar.PerValidatorKeypair(params, rng)` to
   produce its own (sk_i, pk_i). **No DKG.** **No shared seed.** **No
   resharing ceremony.** The validator-set registry binds
   `(ValidatorID_i, pk_i)` so peers can verify this validator's
   signatures.

2. **Per-validator sign** (one signature per block): each validator
   `i` calls `magnetar.ValidatorSign(sk_i, nil, message)` to produce
   the raw FIPS 205 signature bytes (length = params.SignatureSize).
   The signature is byte-identical to single-party FIPS 205
   SignDeterministic and verifies under unmodified `slhdsa.Verify`.
   Bind chain-id / block-height into `message` upstream of this call
   (the consensus layer's transcript-hash pattern handles this; see
   `luxfi/consensus` `QuasarCert`).

3. **Build aggregate cert** (consensus layer): collect N
   per-validator signatures and assemble into a
   `ValidatorAggregateCert{Mode, Signers, PubKeys, Sigs}` via
   `magnetar.BuildAggregateCert(params, signers, pubKeys, sigs)`.
   The cert's parallel-slice shape maps directly onto a Z-Chain
   Groth16 rollup witness — N parallel signatures become N parallel
   circuit inputs.

4. **Verify aggregate cert** (relying party): a verifier calls
   `magnetar.VerifyAggregateCert(cert, message, knownValidators)`
   which returns the COUNT of valid signers. The verifier compares
   the count against its quorum threshold to make the policy
   decision. Unknown / pubkey-mismatched signers are counted as
   INVALID but are NOT fatal — the cert may carry a stale-registry
   tail that the verifier should not abort on.

### Security model

| Property | `ValidatorSign` + `VerifyAggregateCert` | Notes |
|---|---|---|
| **Unforgeability** | FIPS 205-grade per signer | Each σ_i is a standard FIPS 205 signature; forgery reduces to the FIPS 205 EUF-CMA assumption per signer. |
| **No single-host TCB** | YES | No party ever holds N validators' secret material together. Compromising one validator host leaks ONE sk_i, not the group key. |
| **No dealer-in-TCB** | YES | Each validator generates its keypair INDEPENDENTLY; no party ever sees another validator's secret material. |
| **No aggregator-in-TCB** | YES | The aggregator is a pure-public-data shape-checker; the cert's Verify step does not require the aggregator to be trusted. |
| **Quorum byzantine tolerance** | Yes (consensus-layer policy) | The count returned by `VerifyAggregateCert` is compared against the consensus threshold (e.g. 2f+1 for f Byzantine faults). |
| **Per-validator slashing** | YES | Each σ_i is independently attributable to ValidatorID_i; the consensus layer can publish proof-of-double-sign on (ValidatorID_i, σ_a, σ_b, m_a, m_b). |
| **Post-quantum hardness** | FIPS 205 (~192-bit at SHAKE-192s) | All N signatures use the SAME FIPS 205 parameter set; no hybrid weakening. |
| **Replay resistance** | Caller-bound message | Bind chain-id / block-height into `message` upstream. |

### Why this is the right primary primitive for SLH-DSA in public BFT

SLH-DSA is HASH-BASED. It has no algebraic structure that admits
FROST-style threshold aggregation. The literature confirms this is
fundamental (Cozzo-Smart EUROCRYPT 2019; Bonte-Smart-Tan 2023; NIST
IR 8214). Any true-threshold SLH-DSA construction requires either:

- A **dealer-in-TCB** (the v1 `CombineWithSeedReconstruction` and
  `thbs.DealerDKG` paths — REQUIRES TEE), or
- A **full MPC over the SHA-256/SHAKE hash tree** (research-grade,
  multi-second to multi-hour per signature; tracked at
  `BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1`).

For PUBLIC BFT consensus, the correct architecture is "N separate
signatures, count valid ones, apply policy threshold". The
`ValidatorSign` + `VerifyAggregateCert` path expresses exactly this.
The wire cost is N × |σ|; this is the irreducible cost of being
TCB-free on a hash-based signature scheme.

The Z-Chain Groth16 rollup compresses N × |σ| to ~192 bytes when the
relying party cannot consume the raw N-bundle envelope. The rollup
is a separate primitive (lux-zchain spec); Magnetar produces its
input but does NOT consume or verify the proof.

### Operational checklist

- [ ] Generate each validator's keypair on the validator host with a
      hardware RNG. NEVER share sk_i across hosts.
- [ ] Encrypt sk_i at rest with a host-bound key (TPM-sealed or
      KMS-wrapped). NEVER write sk_i to disk in plaintext.
- [ ] Publish (ValidatorID_i, pk_i) to the validator-set registry
      via the same on-chain registration flow you'd use for
      classical BLS validators.
- [ ] The consensus layer SHOULD parallelize verify by routing
      `cert` bytes through `luxfi/crypto/slhdsa.VerifyBatch` for GPU
      substrate acceleration (see `crypto/slhdsa/gpu.go`). Magnetar's
      goroutine-parallel CPU path is the floor; the upstream GPU
      substrate is the ceiling.
- [ ] On Byzantine fault detection (double-sign), produce slashing
      evidence at the consensus layer.

### Honest non-warranties

- **No formal proof** of the aggregate construction beyond FIPS
  205's per-signature security. The construction is a thin layer
  over N independent FIPS 205 signatures — its security argument is
  "N × FIPS 205 EUF-CMA", which is sufficient but not separately
  formalized in EasyCrypt/Lean.
- **No dudect on `VerifyAggregateCert`.** The function dispatches
  over per-validator data which is public (NodeID + PublicKey are
  network-observable). The signature verify call inherits the
  dudect coverage of single-party FIPS 205 verify.
- **No Groth16 verifier ships in this package.** The Z-Chain rollup
  is a separate primitive — Magnetar produces the input to it but
  does not consume or verify the proof.

## 10. Public-BFT aggregate mode (`AggregateSignatures`)

The aggregate mode is the **public-BFT-safe path** for using Magnetar in a validator quorum. It does NOT require the aggregator to be in the TCB and does NOT rely on the reveal-and-aggregate construction. This is the path you SHOULD pick unless §0's decision tree points elsewhere.

### Construction summary

1. **Per-validator keygen** (one-time, off-chain): each validator `i` independently runs `GenerateValidatorKey(params, rng)` to produce its own (sk_i, pk_i). No DKG, no shared seed, no resharing ceremony. The validator-set registry binds `(ValidatorID_i, pk_i)` so peers can verify this validator's signatures.

2. **Per-validator sign** (one signature per block): each validator `i` calls `SignBundle(params, sk_i, ValidatorID_i, message)` to produce a `SignedBundle{ValidatorID, PublicKey, Signature}`. The signature is FIPS 205-byte-identical (no envelope) and verifies under unmodified `slhdsa.Verify`.

3. **Aggregate** (consensus layer): the consensus layer collects N `SignedBundle` envelopes from the network, then calls `AggregateSignatures(params, bundles, message)` to dedupe + shape-check and produce a wire-stable `AggregatedSignature{Message, Bundles}`.

4. **Verify** (relying party): a verifier calls `VerifyAggregated(params, agg, knownValidators)` which returns the COUNT of valid signers. The verifier compares the count against its quorum threshold to make the policy decision.

### Honest trade-offs

- **Wire size grows linearly with N.** At SLH-DSA-SHAKE-192s (16,224 byte signature) a 21-validator quorum is 336 KiB; a 64-validator quorum is 1 MiB. This is the cost of being TCB-free.
- **Verification cost grows linearly with N.** Each bundle requires one full FIPS 205 verify (~50ms per signature on M1 Max for SHAKE-192s). For N=21 that's ~1s in the serial path. `VerifyAggregated` automatically forks to `GOMAXPROCS` goroutines above `verifyAggregatedConcurrentThreshold=2` (mirrors `luxfi/crypto/slhdsa.VerifyBatch` parallel path), reducing wall-clock to ~125ms on an 8-core machine. The GPU substrate at `luxfi/crypto/slhdsa.VerifyBatch` brings this further down when an accel device is loaded — embed magnetar bundles in that path for upper-bound throughput.
- **Z-Chain Groth16 rollup is a separate primitive.** A Groth16 SNARK over the FIPS 205 verify circuit can compress the N-signature bundle to ~192 bytes. This is NOT part of the magnetar API; see `lux-zchain` for the rollup spec. The rollup does NOT change Magnetar's correctness — it's a post-hoc compression layer that the relying party can choose to consume instead of the raw N-bundle envelope.

### Security model

| Property | `AggregateSignatures` | Notes |
|---|---|---|
| **Unforgeability** | FIPS 205-grade per signer | Each σ_i is a standard FIPS 205 signature; forgery reduces to the FIPS 205 EUF-CMA assumption per signer. |
| **No single-host TCB** | Yes | No party ever holds N validators' secret material together. Compromising one validator host leaks ONE sk_i, not the group key. |
| **Quorum byzantine tolerance** | Yes (consensus-layer policy) | The count returned by `VerifyAggregated` is compared against the consensus threshold (e.g. 2f+1 for f Byzantine faults). |
| **Per-validator slashing** | Yes | Each σ_i is independently attributable to ValidatorID_i; the consensus layer can publish proof-of-double-sign on (ValidatorID_i, σ_a, σ_b, m_a, m_b). |
| **Post-quantum hardness** | FIPS 205 (~192-bit at SHAKE-192s) | All N signatures use the SAME FIPS 205 parameter set; no hybrid weakening. |
| **Replay resistance** | Per-signer ctx string | Use the `ctx` argument to bind chain-id / block-height into each σ_i (currently `SignBundle` passes nil; v0.4.3 will add a ctx parameter). |

### Operational checklist

- [ ] Generate each validator's keypair on the validator host with a hardware RNG. NEVER share sk_i across hosts.
- [ ] Encrypt sk_i at rest with a host-bound key (TPM-sealed or KMS-wrapped). NEVER write sk_i to disk in plaintext.
- [ ] Publish (ValidatorID_i, pk_i) to the validator-set registry via the same on-chain registration flow you'd use for classical BLS validators.
- [ ] The consensus layer SHOULD parallelize verify by routing `AggregatedSignature.Bundles` through `luxfi/crypto/slhdsa.VerifyBatch` for GPU substrate acceleration (see `crypto/slhdsa/gpu.go`).
- [ ] On Byzantine fault detection (double-sign, ValidatorID-pk mismatch via `ErrValidatorPubkeyMismatch`), produce slashing evidence at the consensus layer. `VerifyAggregated` returns typed errors so the slashing decision can be made deterministically.

### Honest non-warranties

- **No formal proof** of the aggregate construction beyond FIPS 205's per-signature security. The aggregate construction is a thin layer over N independent FIPS 205 signatures — its security argument is "N × FIPS 205 EUF-CMA", which is sufficient but not separately formalized in EasyCrypt/Lean.
- **No dudect on `VerifyAggregated`.** The function dispatches over per-validator data which is public (NodeID + PublicKey are network-observable). The signature verify call inherits the dudect coverage of single-party FIPS 205 verify (covered by upstream `slhdsa.Verify` constant-time analysis where applicable; CT is NOT a load-bearing property here since all inputs are public).
- **No Groth16 verifier ships in this package.** The Z-Chain rollup is a separate primitive — magnetar produces the input to it but does not consume or verify the proof.

---

**Document metadata**

- File: `DEPLOYMENT-RUNBOOK.md`
- Version: v0.5.0 (rewrites §0 mode chooser to direct PUBLIC BFT users to `ValidatorSign` + `VerifyAggregateCert`; adds §9 documenting the new primary primitive; honestly demotes `CombineWithSeedReconstruction` and `thbs.DealerDKG` to the M-Chain custody / TEE-attested path; cites `thbs/dkg2/` skeleton + `BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1` as the public-DKG research path)
- Date: 2026-05-21
- Status: operator-facing trust-model disclosure
