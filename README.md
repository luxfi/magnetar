# Magnetar — Threshold SLH-DSA (FIPS 205)

> **Tier A documentation shape complete at v0.3.0; public-BFT-safe aggregate mode + THBS v1 added at v0.4.2.**
> Threshold hash-based PQ signature primitive over FIPS 205 SLH-DSA
> shipping **three modes**: `pkg/thbs.Aggregate` (TRUE threshold —
> McGrew et al., selected-elements reconstruction, no aggregator-in-TCB;
> v1 dealer-backed, see `THBS-SPEC.md`), `AggregateSignatures`
> (public-BFT-safe N-of-N collected signatures), and
> `CombineWithSeedReconstruction` (reveal-and-aggregate; requires TEE).
> The full 12-document Tier A submission package shape (mirroring
> Pulsar's structure) is now in-tree; mechanized refinement, dudect
> statistical CT validation, v0.4 lifecycle additions (ML-KEM
> envelope wrap + reshare), and external audit are the remaining
> gates to full Tier A — see `CRYPTOGRAPHER-SIGN-OFF.md` "Gates"
> section.
>
> See `SUBMISSION.md` for the NIST MPTC cover sheet,
> `SPEC.md` for the construction specification,
> `DEPLOYMENT-RUNBOOK.md` for the v0.1 trust-model disclosure,
> `BLOCKERS.md` for the remaining gates to full Tier A, and
> `SUBMISSION-STATUS.md` for the NIST MPTC roadmap.

## Status

| Field | Value |
|---|---|
| Standard | FIPS 205 SLH-DSA (single-party + aggregate + reveal-and-aggregate threshold) |
| Construction | **Two modes**: (1) `AggregateSignatures` — N independent per-validator FIPS 205 signatures, public-BFT-safe; (2) `CombineWithSeedReconstruction` — Shamir VSS over the SLH-DSA scheme seed (v0.1 reveal-and-aggregate), requires TEE |
| Reference implementation | `ref/go/pkg/magnetar/` — pure Go, depends on `cloudflare/circl/sign/slhdsa` |
| KAT vectors | `vectors/{keygen,sign,verify,threshold-sign,dkg}.json` (deterministic regeneration) |
| Class-N1 claim | threshold signature is byte-identical to single-party `slhdsa.SignDeterministic` on the same reconstructed seed |
| Submission package | **Tier A documentation shape complete (v0.3.0)** — `SUBMISSION.md`, `NIST-SUBMISSION.md`, `SPEC.md`, `PATENTS.md`, `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`, `FIPS-TRACEABILITY.md`, `TRUSTED-COMPUTING-BASE.md`, `CRYPTOGRAPHER-SIGN-OFF.md`, `DEPLOYMENT-RUNBOOK.md`, `BLOCKERS.md`, `SUBMISSION-STATUS.md`. See `scripts/cut-submission.sh`. |
| Cert-profile role | Polaris profile in `luxfi/quasar` (cross-family PQ diversity) |
| Proof artifacts | None yet for the threshold overlay — roadmap v0.5.0 (multi-month research). See `AXIOM-INVENTORY.md` §2. |
| Independent review | Internal cryptographer sign-off at v0.3.0 (`CRYPTOGRAPHER-SIGN-OFF.md`); external audit roadmap v0.6.0. See `BLOCKERS.md` BLK-9. |

## What v0.3.0 ships (Tier A documentation shape complete)

- **Reference implementation** (`ref/go/pkg/magnetar/`, ~2186 LOC): single-party + DKG + threshold-sign + Combine over the SLH-DSA scheme seed.
- **Parameter sets**: SHAKE-192s (recommended), SHAKE-192f, SHAKE-256s.
- **KAT generator** (`ref/go/cmd/genkat`): deterministic vectors at five profiles (keygen, sign, verify, threshold-sign, dkg). Re-running on a clean checkout produces byte-identical output.
- **Headline test** (`n1_byte_equality_test.go`): threshold-produced signatures are byte-identical to single-party FIPS 205 `SignDeterministic` on the reconstructed master seed across (3,2), (5,3), (7,4) configurations.
- **Honest trust-model disclosure**: `DEPLOYMENT-RUNBOOK.md` documents the v0.1 reveal-and-aggregate aggregator-as-TCB caveat with the same rigor as Pulsar's.
- **Full Tier A documentation shape**: `SUBMISSION.md`, `NIST-SUBMISSION.md`, `PATENTS.md`, `PROOF-CLAIMS.md`, `AXIOM-INVENTORY.md`, `FIPS-TRACEABILITY.md`, `TRUSTED-COMPUTING-BASE.md`, `CRYPTOGRAPHER-SIGN-OFF.md` (mirroring Pulsar's 12-doc structure).
- **Submission orchestration**: `scripts/cut-submission.sh` + `scripts/check-high-assurance.sh`.

## What v0.3.0 does NOT yet ship (open gates to full Tier A)

- Formal proofs (EasyCrypt theory shells for the threshold overlay, Lean ↔ EC bridges) — see `BLOCKERS.md` BLK-7 + `CRYPTOGRAPHER-SIGN-OFF.md` GATE-1 / GATE-2. **Roadmap v0.5.0; multi-month research.**
- Constant-time analysis under `dudect` of the threshold layer — see `CRYPTOGRAPHER-SIGN-OFF.md` GATE-3. **Roadmap v0.6.0.**
- ML-KEM-768 wrapping of DKG Round-1 envelopes (closes passive-network-observer channel) — see `BLOCKERS.md` BLK-4. **Roadmap v0.4.0.**
- Reshare protocol (Refresh + ReshareToNewSet) for Class N4-analog evidence — see `BLOCKERS.md` BLK-4. **Roadmap v0.4.0.**
- External cryptographer audit — see `BLOCKERS.md` BLK-9 + `CRYPTOGRAPHER-SIGN-OFF.md` GATE-4. **Roadmap v0.6.0.**

## Where this is used

The `Magnetar` leg of the **Polaris** cert profile in
[`luxfi/quasar`](https://github.com/luxfi/quasar) — the
maximum-assurance cross-family profile that pairs lattice PQ
(Pulsar M-LWE + Corona R-LWE) with hash-based PQ (Magnetar
SLH-DSA). Polaris is the production migration target for when
Magnetar matures to Tier A.

At v0.2.0 Tier B, Magnetar is **available as a library** but not
yet the production cert-profile target. Production chains run
the **Pulsar** profile; Polaris remains reserved.

## Why hash-based threshold matters

SLH-DSA's security rests on collision/preimage resistance of the
underlying hash (SHA-2 or SHAKE), with no lattice assumption.
A threshold profile of SLH-DSA gives cross-family defense in depth:
even if a future cryptanalytic break hits the entire lattice family
(both M-LWE and R-LWE), Magnetar's hash-based threshold leg keeps
the cert sound.

## The v0.1 trust caveat (READ THIS)

The v0.1 reveal-and-aggregate construction reconstructs the master
SLH-DSA seed in **aggregator-process memory** during each `Combine`
call. The aggregator process is in the trusted computing base for
this brief window. This is the same trust model as Pulsar's v0.1
reveal-and-aggregate.

**Mitigations** (see `DEPLOYMENT-RUNBOOK.md` for the full matrix):
- TEE (SGX / SEV-SNP / TDX) is the recommended deployment posture.
- `mlock`, ptrace-off (`kernel.yama.ptrace_scope=3`), `ulimit -c 0` are mandatory.
- Aggregator role SHOULD rotate per signing request.

A v0.2 instantiation that gives true threshold secrecy (aggregator
never sees the seed) is on the research path — full MPC over
SLH-DSA's hash tree is the candidate construction; see
`BLOCKERS.md` BLK-1 follow-on work.

## Quick start

```go
import (
    "github.com/luxfi/magnetar/ref/go/pkg/magnetar"
)

// Single-party usage (single-instance signer).
params := magnetar.MustParamsFor(magnetar.ModeM192s)
sk, _ := magnetar.GenerateKey(params, nil) // crypto/rand
sig, _ := magnetar.Sign(params, sk, msg, ctx, false /* deterministic */, nil)
err := magnetar.Verify(params, sk.Pub, msg, sig)
```

For DKG + threshold signing, see the `n1_byte_equality_test.go`
end-to-end example.

## Cross-references

- [`luxfi/quasar`](https://github.com/luxfi/quasar) — Quasar, the Lux PQ-finality singularity; Magnetar is `PRIMITIVES.md` row
- [`luxfi/pulsar`](https://github.com/luxfi/pulsar) — sibling threshold M-LWE primitive (Tier A production)
- [`luxfi/corona`](https://github.com/luxfi/corona) — sibling threshold R-LWE primitive (Tier A submission)

## License

BSD-3-Clause. See `LICENSE`.

## Maintainer

`magnetar@lux.network` — Lux Industries, Inc.
