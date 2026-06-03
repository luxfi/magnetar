# Magnetar --- TEE integration specification

This document is the canonical design + integration story for
Magnetar's TEE-attested production surface. It is the load-bearing
prose for the `strict-PQ` chain profile at deployment time.

> **Decomplecting discipline.** The TEE integration is the
> SIBLING package at `luxfi/threshold/protocols/slhdsa-tee` ---
> NOT a new field on the magnetar primitive. Magnetar stays the
> hash-tree arithmetic; slhdsa-tee composes the trust root +
> attestation + HSM + approval flow. The two compose by function
> composition, not by inheritance.

---

## 1. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Caller (RPC / EVM precompile)         │
└──────────────┬──────────────────────────────────┬───────────┘
               │ Sign / Sign_Ctx                  │ Sign_TEE / Combine_TEE
               │ (legacy-compat)                  │ (strict-PQ)
               ▼                                  ▼
   ┌───────────────────────┐         ┌──────────────────────────────────┐
   │ magnetar.ValidatorSign│         │ slhdsa-tee.Signer.Sign           │
   │  (per-validator)      │         │  • approval.ApproveIntent         │
   └───────────────────────┘         │  • gate.Issue (nonce+epoch)       │
                                      │  • gate.Release (attest+RIM)     │
   ┌───────────────────────┐         │  • hsm.Provider.GetKey            │
   │ magnetar.Combine      │         │  • magnetar.Sign (inside TEE)    │
   │  (strict-atom Combine)│         │  • zeroize on return              │
   │  (THBS-SE public)     │         └──────────────────────────────────┘
   └───────────────────────┘                       │
                                                   ▼
                                      ┌──────────────────────────────────┐
                                      │ slhdsa-tee.CombinerPool.Combine  │
                                      │  • snapshot members under RLock  │
                                      │  • freshness gate (RotationWindow)│
                                      │  • drive each member's Sign      │
                                      │  • byte-equality across quorum   │
                                      │  • refuse divergence             │
                                      └──────────────────────────────────┘
                                                   │
                                                   ▼
                                      ┌──────────────────────────────────┐
                                      │ cc/attest/{sev,tdx,nras}.go      │
                                      │  • SEV-SNP: PRODUCTION           │
                                      │  • TDX:     STUB (#222 stage 2)  │
                                      │  • NRAS:    STUB (#222 stage 3)  │
                                      └──────────────────────────────────┘
```

---

## 2. Component contracts

### 2.1 Magnetar (this repo)

- **Lane**: FIPS 205 hash-tree arithmetic (FORS, WOTS+, XMSS,
  hypertree). Pure functions.
- **Inputs (sign path)**: `Params, *PrivateKey, msg, ctx,
  randomized, rng`.
- **Output**: `Signature` (FIPS 205 wire bytes).
- **No knowledge of**: TEE, HSM, approval, gate, attestation.
  Pure crypto.

### 2.2 slhdsa-tee.Signer (sibling, `luxfi/threshold/protocols/slhdsa-tee`)

- **Lane**: institutional-custody composition. The full
  attested-release flow that ends in a magnetar.Sign call.
- **Inputs**: `Envelope (attestation, RIM, hardware, TEEPub),
  jobID, msg, signCtx`.
- **Output**: `(wireBytes, *SignReceipt, error)`.
- **Composes**: `kms.ReleaseGate + hsm.Provider +
  approval.ApprovalProvider + Config`.
- **Does NOT compose** magnetar itself --- the Signer holds an
  `hsm.Provider` reference and unwraps the master seed inside the
  TEE, then calls `magnetar.KeyFromSeed + magnetar.Sign` on the
  unwrapped seed.

### 2.3 slhdsa-tee.CombinerPool (sibling)

- **Lane**: t-of-n attested-combiner agreement. The strict-PQ
  Sign surface.
- **Inputs**: `map[memberName]*Envelope, jobID, msg, signCtx`.
- **Output**: `(wireBytes, []*SignReceipt, error)` --- one
  consolidated wire signature byte-equal across the quorum, plus
  per-member audit signatures.
- **Composes**: N `*slhdsa-tee.Signer` instances (one per attested
  host) + freshness state (`LastIssuedAt` per member).
- **Refusal sentinels**: `ErrMagnetarNoTEEAttestation`,
  `ErrMagnetarStaleAttestation`, `ErrMagnetarInsufficientQuorum`,
  `ErrMagnetarSignatureDivergence`.

### 2.4 cc/attest (sibling, `luxfi/mpc/cc/attest`)

- **Lane**: vendor evidence chain validation. Maps from
  vendor-framed quote bytes to `VerifiedReport`
  (Vendor + IssuedAt + ReportData).
- **Status**: SEV-SNP PRODUCTION; TDX + NRAS STUB.

### 2.5 hsm.Provider (sibling, `luxfi/mpc/pkg/hsm`)

- **Lane**: at-rest seed wrap. Implementations include file
  (dev), AWS KMS, Azure Key Vault, GCP Cloud KMS.
- **Inputs**: `keyID, ctx`.
- **Output**: wrapped (or AEAD-sealed) bytes.

### 2.6 kms.ReleaseGate (sibling, `luxfi/mpc/pkg/kms`)

- **Lane**: fresh-nonce + policy-bound release decision.
- **Issue**: returns `(nonce, epoch)` for a job; must be presented
  in the subsequent Release call.
- **Release**: takes `ReleaseRequest{JobID, Epoch, Nonce,
  Attestation, Ctx}` and returns a `SealedSessionKey` if
  policy + attestation pass.

### 2.7 approval.ApprovalProvider (sibling, `luxfi/mpc/pkg/approval`)

- **Lane**: out-of-band human / programmatic approval of a sign
  intent. Used when `Config.ApprovalRequired = true`.
- **Inputs**: `SignIntent` (jobID, msg, env-bound).
- **Output**: `ApprovalSignature`.

---

## 3. Profile gate (one function, one place)

The profile gate is **the only** decomplecting point between the
permissionless and strict-PQ paths. The function is
`magnetarRefuseUnderStrictPQ` at
`luxfi/threshold/pkg/thresholdd/magnetar.go:242`. It mirrors:

- `RefuseUnderStrictPQ` at
  `luxfi/precompile/contract/strict_pq.go` (precompile-side gate
  consulted at the top of every classical precompile's `Run`).
- `RefuseUnderStrictPQ` at `luxfi/threshold/pkg/thresholdd/
  profile.go` (per-request chain-ID resolver gate for HTTP
  503 mapping).

### Discipline

1. **ONE function**. No duplication across schemes (every PQ
   primitive that has a strict-PQ-only path consults its own gate
   function with this exact shape).
2. **ONE place**. Called at the top of `Sign` and `Sign_Ctx` ---
   the permissionless paths. Never called from `Sign_TEE` /
   `Combine_TEE` (which are the strict-PQ-permitted paths).
3. **ONE canonical refusal sentinel**.
   `slhdsatee.ErrMagnetarNoTEEAttestation` with wire identifier
   `ERR_MAGNETAR_NO_TEE_ATTESTATION`.

### Cascade on chain profile flip

Operators rotating a chain into strict-PQ MUST follow:

1. Flip the chain profile in `luxfi/node` ChainConfig.
2. Flip the magnetar dispatcher's profile via
   `magnetarScheme.SetChainSecurityProfile(ProfileStrictPQ)`.
3. Wire a `CombinerPool` via `SetCombinerPool` with at least
   `Threshold` attested members already provisioned.

Until all three steps complete, the dispatcher fail-closes:
`Sign` / `Sign_Ctx` refuse; `Combine_TEE` refuses with
`errMagnetarPoolUnwired`. No silent fallback.

---

## 4. Production deployment matrix

| Chain profile | Sign primitive | TEE substrate | KnownIssuers map |
|---|---|---|---|
| `legacy-compat` (default) | per-validator standalone | none | --- |
| `legacy-compat` (THBS-SE) | public combiner | none | --- |
| `legacy-compat` (custody opt-in) | `Combine_TEE` (1-of-1) | SEV-SNP | `{"amd.sev.snp": {}}` |
| `strict-PQ` (production today) | `Combine_TEE` (t-of-n) | SEV-SNP | `{"amd.sev.snp": {}}` |
| `strict-PQ` (post-#222 stage 2) | `Combine_TEE` (t-of-n) | SEV-SNP + TDX | `{"amd.sev.snp": {}, "intel.tdx": {}}` |
| `strict-PQ` (post-#222 stage 3) | `Combine_TEE` (t-of-n) | + NVIDIA NRAS | `{"amd.sev.snp": {}, "intel.tdx": {}, "nvidia.nras.v1": {}}` |

### 4.1 NVIDIA Confidential Computing (H100 / H200 / B200) integration

When `luxfi/mpc/cc/attest/nras.go` ships its production chain
validator (NVIDIA Remote Attestation Service, `nvtrust` SDK
integration), the operator's CombinerPool config adds
`"nvidia.nras.v1": {}` to KnownIssuers. Each attested member's
slhdsa-tee.Signer runs inside a NVIDIA Confidential Compute VM on
H100/H200/B200. The CC VM's measurement (firmware + UEFI + VBS +
TEE workload) is chain-validated against NRAS's JWKS. No
magnetar-side code change.

For the **deployment-time** Apple SE / Apple Silicon story, see
the v1.4 work item `MAGNETAR-APPLE-SE-HSM-V14` --- the Apple SE
is layered BELOW the attestation as the `hsm.Provider`, not as a
substitute for the attestation chain.

---

## 5. Wire compatibility

The TEE integration is **completely opaque to verifiers**. Any
party holding the canonical MAGG-framed group public key
validates a TEE-emitted signature via stock
`magnetar.VerifyBytes(gkBytes, msg, sigBytes)` --- no special
casing, no TEE-aware verifier, no extra round-trips.

This is the load-bearing property: the TEE substrate provides
custody discipline, NOT verification discipline. The on-chain
verifier (the EVM precompile at slot `0x012207`) does NOT know
or care whether the signature came from:

- a per-validator standalone keypair on a commodity host,
- a public combiner on a commodity host running THBS-SE,
- a 1-of-1 attested-host TEE,
- a t-of-n attested-combiner pool spanning SEV-SNP + TDX + NRAS.

All four paths emit byte-identical FIPS 205 wire bytes.

---

## 6. Stub Go integration code (operator-side reference)

The following is a minimal operator-side reference for wiring a
`strict-PQ` chain into the magnetar dispatcher with NVIDIA
Confidential Compute. It is NOT in this repo (the TEE primitives
live at `luxfi/threshold/protocols/slhdsa-tee`); reproduced here
for the spec's completeness.

```go
package main

import (
    "context"
    "time"

    "github.com/luxfi/mpc/cc/attest"
    "github.com/luxfi/mpc/pkg/approval"
    "github.com/luxfi/mpc/pkg/hsm"
    "github.com/luxfi/mpc/pkg/kms"
    magnetar "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
    slhdsatee "github.com/luxfi/threshold/protocols/slhdsa-tee"
    "github.com/luxfi/threshold/pkg/thresholdd"
)

// configureMagnetarStrictPQ wires a strict-PQ Magnetar dispatcher
// with a 2-of-3 attested-combiner pool across AMD SEV-SNP +
// NVIDIA NRAS. Called once at operator boot.
func configureMagnetarStrictPQ(
    ctx context.Context,
    dispatcher *thresholdd.MagnetarScheme,
    gate kms.ReleaseGate,
    hsmP hsm.Provider,
    approver approval.ApprovalProvider,
) error {
    // 1. Flip the dispatcher into strict-PQ. From this point on,
    //    Sign / Sign_Ctx refuse with ErrMagnetarNoTEEAttestation.
    //    Only Sign_TEE / Combine_TEE can produce signatures.
    dispatcher.SetChainSecurityProfile(slhdsatee.ProfileStrictPQ)

    // 2. Build the attested-combiner pool. KnownIssuers includes
    //    both AMD SEV-SNP (production today) AND NVIDIA NRAS
    //    (post-#222 stage 3).
    pool, err := slhdsatee.NewCombinerPool(slhdsatee.CombinerPoolConfig{
        Threshold:      2,                  // 2-of-3, no single-host quorum
        RotationWindow: 60 * time.Second,   // 60 blocks of slack
        KnownIssuers: map[string]struct{}{
            "amd.sev.snp":     {},
            "nvidia.nras.v1": {},   // assumes cc/attest/nras.go has shipped
        },
    })
    if err != nil {
        return err
    }

    // 3. Register the three attested signers. Each signer has its
    //    own wrapped seed in its own HSM key slot; the pool drives
    //    each member's full slhdsa-tee.Signer.Sign machinery.
    for _, m := range []struct {
        name  string
        keyID string
        mode  magnetar.Mode
    }{
        {name: "us-east-1a-snp-01", keyID: "magnetar/east/snp01", mode: magnetar.ModeM192s},
        {name: "us-west-2b-snp-02", keyID: "magnetar/west/snp02", mode: magnetar.ModeM192s},
        {name: "eu-central-1a-nras-01", keyID: "magnetar/eu/nras01", mode: magnetar.ModeM192s},
    } {
        signer, err := slhdsatee.New(gate, hsmP, approver, slhdsatee.Config{
            Mode:               m.mode,
            WrappedSeedKeyID:   m.keyID,
            ApprovalRequired:   true,    // require human sign-off per call
            ApproverID:         "operator@example.com",
            RequireSEV:         false,   // accept any KnownIssuer
            RequireTDX:         false,
            RequireNRAS:        false,
        })
        if err != nil {
            return err
        }
        if _, err := pool.AddMember(m.name, signer); err != nil {
            return err
        }
    }

    // 4. Wire the pool into the dispatcher. From this point on,
    //    Combine_TEE drives the pool; Sign_TEE drives a single
    //    attested host.
    dispatcher.SetCombinerPool(pool)

    // 5. Initial attestation tick. Production deployments would
    //    re-attest every block (~1s); the 60s RotationWindow
    //    absorbs ~60 blocks of control-plane latency before any
    //    sign would refuse.
    for _, name := range []string{
        "us-east-1a-snp-01",
        "us-west-2b-snp-02",
        "eu-central-1a-nras-01",
    } {
        // The operator's control-plane captures fresh attestation
        // evidence from the named TEE and submits it.
        env := captureFreshAttestation(name)  // operator-side hook
        if err := pool.Attest(ctx, name, env); err != nil {
            return err
        }
    }
    return nil
}

// captureFreshAttestation is the operator's control-plane hook.
// For SEV-SNP: capture SNP_GUEST_REQUEST quote via the in-VM agent.
// For TDX:     capture TDREPORT via the in-VM agent.
// For NRAS:    capture NRAS-JWT via nvidia-attest agent + NRAS API.
// Each returns an *slhdsatee.Envelope wrapping the vendor quote.
func captureFreshAttestation(name string) *slhdsatee.Envelope {
    // ... vendor-specific quote capture ...
    return &slhdsatee.Envelope{
        Kind: attest.Kind{
            Vendor:   "amd.sev.snp", // or "nvidia.nras.v1"
            Format:   "snp.v1",      // or "nras.jwt.v1"
        },
        EvidenceBytes: nil, // populate from quote
        RIM:           [32]byte{},   // operator-asserted RIM digest
        Hardware:      [32]byte{},   // hardware fingerprint
        TEEPub:        [32]byte{},   // X25519 TEE pubkey
    }
}
```

The above is the operator-side wiring; the magnetar reference
package itself stays pure.

---

## 7. Verification end-to-end

Pinned by `magnetar_tee_gate_test.go` in
`luxfi/threshold/pkg/thresholdd/`:

- `TestMagnetarCombine_StrictPQProfile_RequiresTEE` --- strict-PQ
  refuses `Sign` and `Sign_Ctx`; permits `Combine_TEE` only when
  pool is wired; profile flip is reversible + idempotent.
- `TestMagnetarCombine_AttestationVerified_AllowsSign` ---
  end-to-end pool drive against committed AMD Milan SEV-SNP
  fixture; output verifies under `magnetar.VerifyBytes` (no
  caller awareness of the pool's existence).
- `TestMagnetarCombine_StaleAttestation_RejectsSign` --- members
  outside rotation window refused; partial re-attestation
  recovers.
- `TestMagnetarCombine_TwoOfThreeAttestedCombiners_MatchSig` ---
  2-of-3 quorum surfaces signature; 1-of-3 stops.
- `TestMagnetarCombine_SignatureDivergence_HardRefusal` --- pool
  refuses byte-divergent quorum output (no silent winner-picking).

All five tests pass under `-race` against the committed Milan
SEV-SNP fixture (`pkg/thresholdd/testdata/sev_snp_attestation_milan.bin`,
`sev_snp_vcek_milan.cer`) replayed via `dispatchKDSReplay()`.

---

**Document metadata**

- Name: `TEE-INTEGRATION.md`
- Date: 2026-06-03
- Pin: Magnetar v1.2 + slhdsa-tee at commit b1c0..f8d
