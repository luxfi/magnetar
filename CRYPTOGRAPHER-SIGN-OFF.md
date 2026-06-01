# Cryptographer sign-off --- luxfi/magnetar v1.0.0

Independent review of the Magnetar SLH-DSA implementation at `main`
of `github.com/luxfi/magnetar` at tag `v1.0.0`. Date of review:
2026-05-31. Reviewer: cryptographer agent (internal review).

## Summary

**APPROVED WITH OPEN ITEMS** for production deployment of the
per-validator standalone primitive and for the THBS-SE
permissionless threshold construction under the threat model
documented in `DEPLOYMENT-RUNBOOK.md` sec 2.1. The v1.0.0 review
covers:

- **Per-validator standalone**
  (`ref/go/pkg/magnetar/standalone.go`) --- the public-BFT primary
  primitive. APPROVED for production. The construction is a thin
  wrapper around `cloudflare/circl/sign/slhdsa` v1.6.3 FIPS 205
  SignDeterministic; the wire-identity claim
  (TestMagnetar_Wire_FIPS205Verifiable) passes across all 3 SHAKE
  modes. The aggregate-cert verifier has explicit
  unknown-validator + pubkey-mismatch handling and parallel-CPU
  dispatch with observable provenance via
  `LastValidatorBatchTier`.

- **THBS-SE** (`ref/go/pkg/magnetar/thbsse.go` + `thbsse_field.go`)
  --- the permissionless threshold companion. APPROVED for the
  documented threat model (public combiner, anyone-can-combine,
  no host in TCB at sign time). The 8 mandated test gates pass:
  TestThbsSE_Wire_FIPS205Verifiable (3 modes),
  TestThbsSE_RejectSeedReveal, TestThbsSE_RejectUnselectedFORS,
  TestThbsSE_RejectUnselectedWOTS, TestThbsSE_SlotReuseRejected,
  TestThbsSE_OverselectedCommittee,
  TestThbsSE_SlotBindingDomainSeparation, and
  BenchmarkThbsSE_Sign_5of7 (192f at < 100 ms/op on Apple M1 Max).
  The KAT replay (TestKAT_ThbsSe) is deterministic at
  (n=7, t=4) x 3 modes x 3 messages.

## Honest open items (v1.1)

1. **MAGNETAR-STRICT-ATOM-V11** --- The strictest formulation of
   the THBS-SE invariant ("no party or combiner EVER reconstructs
   SK.seed, even transiently in memory") requires a v1.1
   strict-atom-assembly path. v1.0 ships a PUBLIC COMBINER that
   holds the seed for the duration of one
   `slhdsa.SignDeterministic` call and zeroizes. This is materially
   stronger than a TEE-attested privileged-aggregator model (no host
   in TCB) and materially weaker than the strict invariant (a
   peer-local memory-disclosure adversary at the precise sub-second
   combine moment could observe the seed). See
   `BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11`.

2. **MAGNETAR-PVSS-DKG-V11** --- v1.0 ships a deterministic-dealer
   setup (`NewThbsSeKey`). Production deployments needing the
   leaderless PVSS-DKG variant route through the sibling
   `luxfi/threshold` DKG package; the share envelope is
   wire-equivalent. See
   `BLOCKERS.md::MAGNETAR-PVSS-DKG-V11`.

3. **MAGNETAR-PROOF-TRACK-V11** --- The legacy EasyCrypt
   scaffolding modeling the abandoned v0.x seed-recombine path has
   been removed. The v1.0 proof track ports to the THBS-SE
   construction shape; full EC + Lean coverage lands at v1.1. See
   `BLOCKERS.md::MAGNETAR-PROOF-TRACK-V11`.

4. **MAGNETAR-DUDECT-V11** --- v1.0's CT story is "inherit CIRCL"
   (`ct/README.md`). The v1.1 dudect harness lands alongside the
   strict-atom-assembly path. See
   `BLOCKERS.md::MAGNETAR-DUDECT-V11`.

5. **MAGNETAR-EXTERNAL-AUDIT-V11** --- The v0.x internal sign-off
   applied to the v0.x construction surface, much of which has been
   removed at v1.0. The v1.1 external audit should target the
   THBS-SE construction shape, the strict-atom-assembly path, and
   the leaderless PVSS-DKG setup. See
   `BLOCKERS.md::MAGNETAR-EXTERNAL-AUDIT-V11`.

## What changed since v0.5.x

The full v1.0 changeset is in `CHANGELOG.md::[1.0.0]`. The
load-bearing deletions:

- `threshold.go`, `aggregate.go`, `combine.go`, `shamir.go`,
  `dkg.go` and their tests --- the legacy seed-recombine threshold
  path.
- `pkg/thbs/` (entire subtree) --- the legacy true-HBS path
  including the `dkg2/` PVSS skeleton.
- `vectors/threshold-sign.json`, `vectors/dkg.json` --- legacy KATs.
- `jasmin/threshold/`, `jasmin/lib/` --- legacy Jasmin model.
- `proofs/easycrypt/` (entire tree) --- legacy EC theories.
- `ct/dudect/` (entire tree) --- legacy dudect harness.

The load-bearing additions:

- `ref/go/pkg/magnetar/thbsse.go` + `thbsse_field.go` --- the
  THBS-SE construction.
- `ref/go/pkg/magnetar/thbsse_test.go` --- the 8 mandated test
  gates plus 2 bonus correctness checks.
- `vectors/thbsse-sign.json` --- deterministic KAT vectors at
  (n=7, t=4) x 3 modes x 3 messages.

## Verification commands

```bash
cd ref/go && GOWORK=off go build ./...
cd ref/go && GOWORK=off go vet ./...
cd ref/go && GOWORK=off go test -count=1 -short -timeout 600s ./pkg/magnetar/...
cd ref/go && GOWORK=off go test -count=1 -race -short -timeout 600s ./pkg/magnetar/...
cd ref/go && GOWORK=off go test -bench=BenchmarkThbsSE_Sign_5of7 -benchtime=2x ./pkg/magnetar/...
```

All clean as of v1.0.0 sign-off.

## Recommendation

**TAG `v1.0.0`** for the per-validator standalone primitive and for
THBS-SE under the documented threat model. Track the 5 open items
above against the v1.1 milestone. Operator-controlled MPC custody
(M-Chain bridge, A-Chain confidential compute) remains the domain of
the sibling `luxfi/threshold` package's TEE-attested variants and is
explicitly out of scope for this primitive.
