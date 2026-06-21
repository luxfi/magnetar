# Cryptographer sign-off --- luxfi/magnetar

Internal review of the Magnetar SLH-DSA implementation at `main` of
`github.com/luxfi/magnetar`. Reviewer: cryptographer agent (internal).

## Summary

**APPROVED for the per-validator standalone primitive only.** The
threshold paths are NOT blessed as no-leak.

- **Per-validator standalone** (`standalone.go`): **APPROVED for
  production.** A thin, sound wrapper over
  `cloudflare/circl/sign/slhdsa` FIPS 205 SignDeterministic. No shared
  seed, no DKG, no reconstruction. Wire identity
  (`TestMagnetar_Wire_FIPS205Verifiable`) passes across all 3 SHAKE
  modes. The aggregate-cert verifier handles unknown-validator +
  pubkey-mismatch and parallel-CPU dispatch with observable provenance.

- **TEE-attested combiner pool** (`luxfi/threshold/protocols/slhdsa-tee`):
  **APPROVED under an explicit attested-hardware trust model.** The
  seed is reconstructed inside a measured enclave on t hosts that must
  agree. This is trust-relocation (adds a host to the TCB), NOT MPC.
  The five `TestMagnetarCombine_*` gates build and pass under `-race`
  after the `luxfi/zap` v0.3.1 bump in `luxfi/threshold`.

- **Permissionless THBS-SE** (`thbsse.go`, `thbsse_assemble.go`): **NOT
  APPROVED as a no-leak / no-host-in-TCB primitive.** The public
  combiner RECONSTRUCTS the full FIPS 205 master every signature
  (`ASSEMBLE-INVARIANT.md`). It is RESEARCH-GRADE. It may be used where
  the combiner host is trusted by deployment policy, but it must not be
  presented as keeping the seed secret from the combiner. The byte
  identity to single-party FIPS 205 is a correctness/interop property,
  not a confidentiality one.

## Open items (corrected)

1. **MAGNETAR-STRICT-ATOM --- OPEN (was falsely marked CLOSED).** The
   "strict-atom" Combine does NOT eliminate seed reconstruction; it
   renames the buffer. The earlier sign-off's claim that v1.0/v1.1 was
   "materially stronger than a TEE-attested model (no host in TCB)" was
   wrong: whoever runs the public combiner sees the seed, so there IS a
   host in the TCB at sign time. Closing this needs full MPC over the
   SHAKE hash tree (open research) or the TEE pool. See `BLOCKERS.md`.

2. **PVSS-DKG open-reveal leak --- FIXED.** The earlier DKG published
   every party's constant term, making the master reconstructible by
   any observer. The production path (`RunDKG`) now publishes no
   reveals; `TestPVSS_DKG_ProductionTranscriptHidesMaster` gates it.
   Honest residual limits: pk derivation still reconstructs the master
   (inherent), and the production path does not robustly exclude
   malicious dealers at DKG time. See `BLOCKERS.md` (P2).

3. **Mechanized proofs --- NONE.** The earlier EC/Lean track was
   vacuous (a headline theorem proved by `apply`-ing an axiom that
   restated it; `X = X` lemmas; a CT lemma by `admit`; a PVSS secrecy
   "theorem" with conclusion `true`). It has been deleted or reduced to
   labeled scaffolds. There is no mechanized refinement, present or on
   a credible near-term path. See `PROOF-CLAIMS.md` §2.

4. **dudect / statistical CT --- OPEN.** Only local CT helpers + code
   review. The "CT" AST test is a name lint, not a timing measurement
   (and CT is moot for a path holding the master in plaintext).

5. **External audit --- OPEN.**

## What changed since v0.x

The load-bearing v1.0 deletions (recorded for provenance): the v0.x
seed-recombine threshold files `threshold.go`, `aggregate.go`,
`combine.go`, `shamir.go`, `dkg.go` and their tests; `pkg/thbs/`; the
legacy KATs; the legacy Jasmin model; the legacy EC tree; the legacy
dudect harness. The current code lives in `thbsse.go`,
`thbsse_field.go`, `thbsse_assemble.go`, `slhdsa_internal.go`,
`standalone.go`, `pvss_dkg.go`, `key.go`.

The THBS-SE gates are `TestThbsSE_Wire_FIPS205Verifiable`,
`TestThbsSE_RejectSeedReveal`, `TestThbsSE_RejectOversizedShareWireSize`,
`TestThbsSE_RejectTamperedShareCommitMismatch`,
`TestThbsSE_SlotReuseRejected`, `TestThbsSE_OverselectedCommittee`,
`TestThbsSE_SlotBindingDomainSeparation`. (The last two reject-tests
were formerly mis-named ...UnselectedFORS / ...WOTS; THBS-SE shares the
whole seed, so they test commit binding, not atom selection.)

## Verification commands

```bash
cd ref/go && GOWORK=off go build ./...
cd ref/go && GOWORK=off go vet ./...
cd ref/go && export PATH="$(go env GOPATH)/bin:$PATH" && staticcheck ./...
cd ref/go && GOWORK=off go test -count=1 -short -timeout 600s ./pkg/magnetar/...
```

## Recommendation

Ship the per-validator standalone primitive as the production default.
Ship the TEE pool as opt-in for trusted-hardware custody, under the
honest trust-relocation framing. Keep THBS-SE labeled RESEARCH-ONLY; do
not present it as no-leak. Track the open items in `BLOCKERS.md`.
