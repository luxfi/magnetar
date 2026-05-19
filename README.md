# Magnetar — Threshold SLH-DSA (FIPS 205)

> **Tier B: production library + submission scaffold landed v0.2.0.**
> Threshold hash-based PQ signature primitive over FIPS 205 SLH-DSA
> implementing the **v0.1 reveal-and-aggregate** construction.
> Mechanized refinement + independent audit on the roadmap to Tier A.
>
> See `SPEC.md` for the construction specification,
> `DEPLOYMENT-RUNBOOK.md` for the v0.1 trust-model disclosure,
> `BLOCKERS.md` for the remaining Tier B → A path, and
> `SUBMISSION-STATUS.md` for the NIST MPTC roadmap.

## Status

| Field | Value |
|---|---|
| Standard | FIPS 205 SLH-DSA (single-party + reveal-and-aggregate threshold) |
| Construction | v0.1 reveal-and-aggregate (Shamir VSS over the SLH-DSA scheme seed) |
| Reference implementation | `ref/go/pkg/magnetar/` — pure Go, depends on `cloudflare/circl/sign/slhdsa` |
| KAT vectors | `vectors/{keygen,sign,verify,threshold-sign,dkg}.json` (deterministic regeneration) |
| Class-N1-analog claim | threshold signature is byte-equal to single-party `slhdsa.SignDeterministic` on the same reconstructed seed |
| Submission package | NIST MPTC roadmap — see `SUBMISSION-STATUS.md` for the v0.3 target window |
| Cert-profile role | Polaris profile in `luxfi/quasar` (cross-family PQ diversity) |
| Proof artifacts | None yet — see `BLOCKERS.md` BLK-7 |
| Independent review | None yet — see `BLOCKERS.md` BLK-9 |

## What v0.2.0 ships

- **Reference implementation** (`ref/go/pkg/magnetar/`): single-party + DKG + threshold-sign + Combine over the SLH-DSA scheme seed.
- **Parameter sets**: SHAKE-192s (recommended), SHAKE-192f, SHAKE-256s.
- **KAT generator** (`ref/go/cmd/genkat`): deterministic vectors at five profiles (keygen, sign, verify, threshold-sign, dkg). Re-running on a clean checkout produces byte-identical output.
- **Headline test** (`n1_byte_equality_test.go`): threshold-produced signatures are byte-identical to single-party FIPS 205 `SignDeterministic` on the reconstructed master seed.
- **Honest trust-model disclosure**: `DEPLOYMENT-RUNBOOK.md` documents the v0.1 reveal-and-aggregate aggregator-as-TCB caveat with the same rigor as Pulsar's.

## What v0.2.0 does NOT yet ship

- Formal proofs (EasyCrypt theories, Lean bridges, Jasmin sources) — see `BLOCKERS.md` BLK-7.
- Constant-time analysis under `dudect` of the threshold layer — see `BLOCKERS.md` BLK-7.
- ML-KEM-768 wrapping of DKG Round-1 envelopes (closes passive-network-observer channel) — planned for v0.3 / Pulsar parity.
- Independent cryptographer sign-off — see `BLOCKERS.md` BLK-9.
- Full 16-document submission package — see `BLOCKERS.md` BLK-8.

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

- [`luxfi/quasar`](https://github.com/luxfi/quasar) — umbrella spec; Magnetar is `PRIMITIVES.md` row
- [`luxfi/pulsar`](https://github.com/luxfi/pulsar) — sibling threshold M-LWE primitive (Tier A production)
- [`luxfi/corona`](https://github.com/luxfi/corona) — sibling threshold R-LWE primitive (Tier A submission)

## License

BSD-3-Clause. See `LICENSE`.

## Maintainer

`magnetar@lux.network` — Lux Industries, Inc.
