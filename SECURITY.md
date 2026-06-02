# Magnetar --- Security Posture by Chain Profile

This document is the honest threat-model statement for Magnetar's two
canonical Combine paths, parameterised by the chain-security profile
the embedding consensus layer publishes.

It is the load-bearing prose for the strict-PQ profile gate landed at
2026-06-01 in `luxfi/threshold/pkg/thresholdd/magnetar.go` (Combine
gate + t-of-n attested-combiner pool).

---

## 1. Two profiles, two threat models

Magnetar exposes ONE wire format (MAGS / MAGG, byte-identical to
single-party FIPS 205) and exactly TWO Combine paths whose acceptance
is gated by the chain-security profile in effect:

| Profile             | Combine path                          | TCB                                |
|---------------------|---------------------------------------|------------------------------------|
| `legacy-compat`     | strict-atom commodity-host (v1.1)     | public combiner host (microseconds)|
| `strict-PQ`         | TEE-attested t-of-n pool              | measured enclave (only)            |

Wire bytes are identical across both paths. The distinction is
entirely in **where the FIPS 205 master bytes are allowed to
transiently exist** during the SHAKE absorb step that emits the
signature.

---

## 2. Residual gap closed by `strict-PQ`

### 2.1 Commodity-host Combine (legacy-compat)

Magnetar v1.1's strict-atom Combine path is implemented at
`ref/go/pkg/magnetar/thbsse_assemble.go::assembleSignatureBytes`
backed by `slhdsa_internal.go::slhSignAtom`. The discipline pins:

```
grep -rE "SK\.seed|SK\.prf|sk_seed|sk_prf" thbsse_assemble.go
```

returns zero matches. There is no named transient seed binder; the
master is decomposed into per-atom positional slices of a SHAKE
expansion buffer.

**Residual gap.** The bytes of the FIPS 205 master DO exist
transiently inside `derivedMaterial` (the SHAKE-expansion output
buffer) and `derivedExpandInput` (the Lagrange-reconstructed input to
SHAKE) for the duration of the SHAKE absorb --- approximately a few
microseconds on a modern host. A coredump or `/proc/self/mem` dump at
exactly the right wall-clock instant would observe them. This is the
strictest discipline available **without crossing into either**
(a) MPC-over-SHAKE (open research; multi-second per signature) or
(b) a TEE-attested host inside the TCB.

For the **legacy-compat profile**, this residency window is acceptable.
The combiner role is PUBLIC --- any peer can run the strict-atom
Combine on its own substrate. No host is privileged. The strict-atom
discipline is materially stronger than the v1.0
reveal-and-aggregate model and is the recommended commodity-host
posture.

### 2.2 TEE-attested Combine (strict-PQ)

For deployments that cannot tolerate the microsecond residency
window --- regulated custody, sovereign settlement, high-value
bridge --- the `strict-PQ` profile requires that every Combine route
through the `luxfi/threshold/protocols/slhdsa-tee` package. In this
path:

1. The wrapped master seed lives at-rest in an HSM
   (`luxfi/mpc/pkg/hsm.Provider` --- file, AWS KMS, Azure Key Vault,
   GCP Cloud KMS).
2. The seed is **only** unwrapped inside a hardware-attested TEE
   (SEV-SNP / TDX / NRAS) whose binary + firmware chain-validate to
   the vendor root (AMD KDS / Intel PCS / NVIDIA NRAS JWKS) and whose
   measurement matches the operator-asserted RIM digest.
3. Each sign call is gated by `luxfi/mpc/pkg/kms.ReleaseGate.Issue`
   (fresh single-use nonce + epoch) and `Release` (RIM allowlist +
   hardware allowlist + Require* issuers).
4. The FIPS 205 master bytes only ever exist inside the measured
   enclave. The host process never sees plaintext --- it sees only
   the AEAD-sealed session key, the wrapped seed ciphertext, and the
   resulting wire signature.

Output bytes are byte-identical to single-party FIPS 205
`SignDeterministic` on the same `(seed, msg, ctx)` tuple. Any
verifier holding the canonical MAGG group public key validates
without any awareness of the TEE substrate.

---

## 3. Profile gate (one function, one place)

The dispatcher-side gate is the single function
`magnetarRefuseUnderStrictPQ` at
`luxfi/threshold/pkg/thresholdd/magnetar.go`. It mirrors the
precompile-side gate `contract.RefuseUnderStrictPQ` in
`luxfi/precompile/contract/strict_pq.go` and follows the same
discipline:

- ONE function (no duplication across schemes).
- ONE place (called at the top of `Sign` and `Sign_Ctx`).
- ONE canonical refusal sentinel
  (`slhdsatee.ErrMagnetarNoTEEAttestation`, wire-stable identifier
  `ERR_MAGNETAR_NO_TEE_ATTESTATION`).

Under `ProfileStrictPQ`:

- `Sign` → refuses with `ErrMagnetarNoTEEAttestation`.
- `Sign_Ctx` → refuses with `ErrMagnetarNoTEEAttestation`.
- `Sign_TEE` → allowed (single-host attested-release sign).
- `Combine_TEE` → allowed (t-of-n attested-combiner pool sign).

Under `ProfileLegacyCompat` (default):

- All four paths allowed.
- `Combine_TEE` still works when a pool is wired --- the strict-PQ
  posture is opt-in even on legacy-compat chains.

---

## 4. T-of-n attested-combiner pool

The strict-PQ Combine path is **not single-host**. The pool at
`luxfi/threshold/protocols/slhdsa-tee/pool.go` registers `n` attested
combiner endpoints; each holds an independently provisioned
`slhdsa-tee.Signer` (independent wrapped seed). Combine selects the
first `t` members whose attestation freshness is inside the rotation
window, drives each member's full Sign machinery, and **refuses if
the produced bytes are not byte-identical**.

SLH-DSA `SignDeterministic` is byte-stable: same `(seed, msg, ctx)`
→ same bytes. Two attested combiners holding the same wrapped seed
under the same RIM MUST produce identical output. Divergence indicates
a misconfigured or compromised combiner; the pool refuses with
`ErrMagnetarSignatureDivergence` --- no silent winner-picking.

### 4.1 Threshold-of-attested-combiners policy

The default deployment posture is **t = 2, n = 3**. Operator policy
may pin higher `t` for higher-value deployments. The constructor
refuses `t < 2` (no single-attested-host quorum):

```go
slhdsatee.NewCombinerPool(slhdsatee.CombinerPoolConfig{
    Threshold:      2,                        // t-of-n, t >= 2
    RotationWindow: 60 * time.Second,         // per-member attestation TTL
    KnownIssuers:   map[string]struct{}{      // vendor root pin
        "amd.sev.snp": {},
    },
})
```

### 4.2 Rotation window

Each pool member's attestation freshness is bounded by
`RotationWindow`. Outside the window, the member is treated as
**stale** and not eligible for the quorum. Combine refuses with
`ErrMagnetarStaleAttestation` when insufficient fresh members exist.

Re-attestation is the operator control-plane's responsibility: a
periodic tick captures fresh `SNP_GUEST_REQUEST` / `TDREPORT` /
NRAS-JWT bytes from each combiner and submits via
`CombinerPool.Attest`. The Combine path is then a freshness **read**
--- it never blocks on KDS / PCS / NRAS network roundtrips.

**Recommended cadence**: every Lux block (`~1s`), with a 60s
`RotationWindow`. This absorbs ~60 blocks of control-plane latency
between attestation capture and the next sign request. Latency-
sensitive deployments may shrink to 5s rotation; long-lived custody
deployments may extend to 5min with periodic compensating audits.

---

## 5. Attestation kinds in production

The strict-PQ profile accepts evidence whose `Vendor` lies in the
operator-configured `KnownIssuers` set. Today the three supported
kinds are:

| Kind        | Vendor string       | Verifier status                                    |
|-------------|---------------------|----------------------------------------------------|
| `sev_snp`   | `amd.sev.snp`       | PRODUCTION (`luxfi/mpc/cc/attest/sev.go` + go-sev-guest) |
| `tdx`       | `intel.tdx`         | STUB (`luxfi/mpc/cc/attest/tdx.go`, ErrNotImplemented; tracked #222 stage 2) |
| `nras`      | `nvidia.nras.v1`    | STUB (`luxfi/mpc/cc/attest/nras.go`, ErrNotImplemented; tracked #222 stage 3) |

**Production today:** strict-PQ deployments MUST use SEV-SNP. TDX and
NRAS chain-validators are stubs that return `ErrNotImplemented` ---
the pool refuses any Attest call routing through them. When the
upstream verifiers ship, no code changes are required at the magnetar
dispatcher --- the pool's `KnownIssuers` set is the only knob.

---

## 6. Defence in depth: each layer is independently complete

Composition: each step in the strict-PQ Combine path is independently
complete and refuses on its own without relying on later steps:

| Step | Responsibility | Refusal sentinel |
|------|----------------|------------------|
| Profile gate | `Sign` / `Sign_Ctx` on strict-PQ | `ErrMagnetarNoTEEAttestation` |
| Pool wired | `Combine_TEE` requires pool | `errMagnetarPoolUnwired` |
| Freshness | Attestation < rotation window | `ErrMagnetarStaleAttestation` |
| Quorum | At least `t` fresh members | `ErrMagnetarInsufficientQuorum` |
| Vendor pin | KnownIssuers ∋ report.Vendor | `slhdsa-tee: vendor not in KnownIssuers` |
| Approval | (if ApprovalRequired) signed intent | `slhdsatee.ErrApprovalDenied` |
| Chain | `attest.Dispatch` validates evidence | `attest.ErrChainInvalid` / `ErrSignatureInvalid` |
| RIM/HW | gate.Release checks allowlists | `slhdsatee.ErrPolicyRefused` |
| HSM | wrapped seed unsealable inside TEE | `slhdsatee.ErrCorruptWrappedSeed` |
| Divergence | byte-equality across quorum | `ErrMagnetarSignatureDivergence` |

**No silent fallback.** A failure at any step is hard refusal at the
pool level --- the strict-PQ profile cannot silently drop a member
mid-flight.

---

## 7. Threat model summary

### 7.1 Adversary capabilities (strict-PQ)

We model an adversary that controls:

- the operator's host process outside the TEE (compromised binary,
  malicious operator);
- the operator's at-rest HSM ciphertext (compromised HSM admin,
  stolen volume snapshot);
- the network between the operator and the chain (replay,
  reordering, drop).

We do NOT model an adversary that:

- has compromised AMD / Intel / NVIDIA's vendor signing keys
  (assumed-out, defence-in-depth via vendor key rotation);
- has physical access to the TEE die during sign (assumed-out for
  CSP-hosted deployments; mitigated by chassis-attest for on-prem);
- has compromised the wall-clock or RotationWindow policy (assumed
  honest; the rotation is operator policy, not a cryptographic
  guarantee --- monitor for skew).

### 7.2 Adversary capabilities (legacy-compat)

Same as strict-PQ, MINUS the explicit acceptance that the master
bytes transiently exist in the public combiner's SHAKE-expansion
buffers for ~microseconds. This window is exposed to:

- a coredump / `/proc/self/mem` snapshot fired during the Combine
  window;
- a kernel exploit that reads user-space process memory while the
  Combine goroutine is suspended.

Neither is exploitable without root-equivalent access to the host
running the public combiner. The combiner is public --- any peer can
run it on its own substrate. The window IS finite microseconds. We
ship this with full disclosure rather than hide it.

### 7.3 Why strict-PQ closes residual #1 fully

In strict-PQ mode the host running the Sign / Combine routine is a
measured enclave. The kernel running on the enclave is the vendor-
signed enclave runtime. There is no `/proc/self/mem` from the host
side that observes enclave RAM --- the hardware encrypts pages
in-place against a chip-rooted key the host CPU cannot read. The
microsecond residency window still exists, but it exists inside the
enclave's address space, which is cryptographically opaque to every
party except the enclave itself.

This is the standard guarantee SEV-SNP / TDX provide and is the
basis on which institutional-custody platforms (AWS Nitro,
Google Cloud Confidential Computing, Azure Confidential VMs) build.
Strict-PQ Magnetar is no more, and no less, secure than the
underlying CSP enclave guarantee.

---

## 8. Verification

The gate is exercised end-to-end at
`luxfi/threshold/pkg/thresholdd/magnetar_tee_gate_test.go`:

- `TestMagnetarCombine_StrictPQProfile_RequiresTEE` --- strict-PQ
  refuses `Sign` / `Sign_Ctx`; permits `Combine_TEE` only when pool
  is wired.
- `TestMagnetarCombine_AttestationVerified_AllowsSign` --- end-to-end
  pool drive against committed AMD Milan SEV-SNP fixture; output
  verifies under `magnetar.VerifyBytes`.
- `TestMagnetarCombine_StaleAttestation_RejectsSign` --- members
  outside rotation window refused; partial re-attestation recovers.
- `TestMagnetarCombine_TwoOfThreeAttestedCombiners_MatchSig` ---
  2-of-3 quorum surfaces signature; 1-of-3 refuses.
- `TestMagnetarCombine_SignatureDivergence_HardRefusal` ---
  pool refuses byte-divergent quorum output.

All five tests pass under `-race` against the committed Milan
SEV-SNP fixture (`pkg/thresholdd/testdata/sev_snp_attestation_milan.bin`,
`sev_snp_vcek_milan.cer`) replayed via `dispatchKDSReplay()`.

---

## 9. Cross-references

- Strict-atom Combine load-bearing prose: `ASSEMBLE-INVARIANT.md`.
- Strict-atom KAT: `TestSlhdsaInternal_ByteEqualToCirclSign`.
- Profile sentinel value: `slhdsatee.ProfileStrictPQ`
  (`luxfi/threshold/protocols/slhdsa-tee/profile.go`).
- Precompile-side strict-PQ gate (analogous):
  `luxfi/precompile/contract/strict_pq.go`.
- Pool implementation:
  `luxfi/threshold/protocols/slhdsa-tee/pool.go`.
- Chain attestation verifiers:
  `luxfi/mpc/cc/attest/{sev,tdx,nras}.go`.
- Magnetar v1.0 → v1.1 strict-atom closure: `CHANGELOG.md` v1.1.0.
