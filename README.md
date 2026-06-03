# Magnetar v1.2 --- SLH-DSA (FIPS 205) for Lux

Magnetar v1.2 ships ONE construction surface to each of the two
deployment regimes Lux ecosystem chains need, with the strict-atom
Combine path closing `MAGNETAR-STRICT-ATOM-V11` and the dealerless
PVSS-DKG closing `MAGNETAR-PVSS-DKG-V11`:

| Regime | Construction | Where it lives |
|---|---|---|
| Public-BFT consensus on Lux L1/L2 (mainnet, testnet, devnet, white-label) | **Per-validator standalone** --- each validator holds its own FIPS 205 keypair, signs independently, consensus collects N signatures into a `ValidatorAggregateCert` | `ref/go/pkg/magnetar/standalone.go` |
| Permissionless t-of-n threshold for verifier-side single-signature certificates | **THBS-SE (strict-atom Combine)** --- t-of-n committee, slot-bound commit-and-reveal, anyone-can-combine public combiner, Magnetar-internal FIPS 205 sec 5--sec 8 walk with no named transient seed binder | `ref/go/pkg/magnetar/thbsse.go` + `thbsse_field.go` + `thbsse_assemble.go` + `slhdsa_internal.go` |

Both produce FIPS 205 wire bytes that an unmodified verifier accepts.

## Per-validator standalone (public-BFT primary)

```go
sk, pk, _ := magnetar.PerValidatorKeypair(params, rng)
sig, _    := magnetar.ValidatorSign(sk, rng, message)
// ... collected at the consensus layer ...
cert, _   := magnetar.BuildAggregateCert(params, signers, pubkeys, sigs)
valid, _  := magnetar.VerifyAggregateCert(cert, message, knownValidators)
```

No DKG, no shared seed, no aggregator-in-TCB. Wire size grows
linearly with the quorum (`N x |sigma|`). The Z-Chain Groth16 rollup
compresses the cert to ~192 bytes for long-term storage; the rollup
is a separate primitive (lux-zchain spec).

## THBS-SE (permissionless threshold)

```go
key, _   := magnetar.NewThbsSeKey(params, t, committee, setupRng)
// Per-party Round-1 / Round-2 over the slot binding ...
r1i, r2i, _ := magnetar.ThbsSeRound1(params, key.Shares[i], binding, msg, guard, rng)
// ... any peer (the "public combiner") collects t valid r1/r2 pairs ...
sig, ev, _  := magnetar.Combine(magnetar.ThbsSeCombineInput{
    Key: key, Binding: binding, Message: msg, Round1: r1s, Round2: r2s,
})
// sig.Bytes is canonical FIPS 205; verifies under unmodified circl.slhdsa.Verify.
```

### Setup --- two equivalent paths

**Dealer setup (KAT-reproducible).** `NewThbsSeKey` samples a master,
byte-shares it via Shamir over GF(257), and zeroizes the master
before return. The dealer machine is in the TCB FOR SETUP ONLY; once
the function returns, no party (including the dealer) holds the
master. Recommended for foundation-HSM single-host bootstrap and
KAT replay.

**Dealerless PVSS-DKG setup (no trusted dealer).** Each committee
party runs `NewPVSSPartyState` independently, publishes a
`PublicContribution` (per-coefficient hash commitments only),
distributes private share rows over authenticated channels, and
publishes a `RevealMsg` at Round 2. Any third party collates the
public payloads into a `PVSSTranscript` and invokes
`NewThbsSeKeyFromDealerlessDKG` to assemble the canonical
`ThbsSeKey`:

```go
// Each party i runs in its own process.
state_i, _ := magnetar.NewPVSSPartyState(params, t, committee, uint32(i+1), rng)
contrib_i  := state_i.PublicContribution()  // broadcast publicly
share_to_j, _ := state_i.ShareTo(uint32(j+1))  // send privately to j
reveal_i := state_i.RevealMsg()              // broadcast publicly at Round 2

// Any auditor (or any party) collates the public-form transcript
// and assembles the canonical ThbsSeKey.
transcript := &magnetar.PVSSTranscript{
    Params: params, Committee: committee, Threshold: t,
    Contributions: contribs, Reveals: reveals,
    ReceivedShares: receivedShares, SetupTr: setupTr,
}
key, _ := magnetar.NewThbsSeKeyFromDealerlessDKG(transcript)
// key is byte-shape identical to the dealer-path output for the
// implicit master M = sum_{i in Q} m_i mod 257 byte-wise.
```

The dealerless path enforces the hard invariant: **no party (and no
transient dealer) ever holds the master byte vector at any time
during setup**. The implicit master is only materialised inside the
`deriveDKGPublicKey` closure (named `lagrangeScratch`, zeroized at
closure exit) when an auditor invokes `VerifyDKGTranscript` to
derive the public key.

For reference, the `RunDKGSimulation` helper runs the full n-party
protocol in a single test process (every party's state in one heap)
for KAT replay and benchmark purposes; production deployments should
run each party in its own process.

**Hard invariant** (THBS-SE construction): a revealed value is allowed
ONLY if it is also present in the final SLH-DSA signature.

- ALLOWED reveals: the per-round mask `r_i`, the masked share
  `s'_i = share_i XOR r_i`, the public commit hash, the final FIPS
  205 signature bytes.
- FORBIDDEN reveals: `SK.seed` in any party-local persistent form;
  `SK.prf`; future-slot share material. The slot guard refuses any
  same-slot re-emission, and the share envelope is per-slot.

**No-aggregator property**: The public combiner is a PURE function of
its inputs. Any peer --- validator, block proposer, RPC node, passive
watcher --- can run Combine. There is no privileged aggregator role
and no host in the TCB at sign time. (The strict-atom Combine path
at v1.1 closed the residual transient-seed-at-combiner gap; see
`BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11` for the closure summary.)

**No-trusted-dealer property**: The PVSS-DKG setup path
(`NewThbsSeKeyFromDealerlessDKG`, v1.2) eliminates the trusted
dealer from setup. No party (and no transient dealer) ever holds
the master byte vector at any time during setup. See
`BLOCKERS.md::MAGNETAR-PVSS-DKG-V11` for the closure summary and
`pvss_dkg.go` for the construction.

**Slot binding**: every signature is bound to
`(chain_id, epoch, slot, height, committee_id, message_domain)`. The
binding flows into the cSHAKE256 commit transcript AND into the FIPS
205 ctx string at sign time, so a verifier holding the slot tuple
derives ctx independently and routes through unmodified
`slhdsa.Verify`.

**Slashing evidence**: a party that signs two distinct messages at
the same slot emits a `ThbsSeEquivocationError` carrying a wire-
shaped `ThbsSeEvidence` blob that any third party can verify via
`VerifyThbsSeEvidence` --- pure function, no committee state
required. Malformed shares produce typed `ThbsSeShareEvidence` blobs
verified via `VerifyThbsSeShareEvidence`.

**Over-selected committee**: with `(n, t)` and `n > t`, up to `n - t`
silent withholders are tolerated. Any t valid Round-2 reveals produce
byte-equal final signatures.

## Why per-validator standalone is the public-BFT default

SLH-DSA is hash-based; it has no algebraic structure that admits
FROST-style linear share-aggregation. The literature confirms:

- Cozzo and Smart, EUROCRYPT 2019 *Sharing the LUOV*: every internal
  SHAKE/SHA-2 evaluation in an HBS scheme is a non-linear function
  of the secret seed.
- Bonte, Smart and Tan 2023 *Threshold SPHINCS+*: exhaustive
  infeasibility analysis. There is no efficient t-of-n SLH-DSA
  scheme producing a single FIPS 205-shaped signature without either
  (a) reconstructing the seed in some combiner process or (b) running
  full MPC over the SHA-256/SHAKE hash tree (multi-second per
  signature, multi-megabyte of comms).

THBS-SE chooses (a) with a PUBLIC COMBINER --- anyone-can-combine,
no host in TCB. The per-validator standalone path sidesteps (a) and
(b) entirely by emitting N independent signatures.

## Status

| Field | Value |
|---|---|
| Standard | FIPS 205 SLH-DSA (single-party + per-validator standalone aggregate + THBS-SE permissionless threshold) |
| Constructions | 2 (per-validator standalone, THBS-SE) |
| Reference implementation | `ref/go/pkg/magnetar/` --- pure Go, depends on `cloudflare/circl/sign/slhdsa` v1.6.3 |
| KAT vectors | `vectors/{keygen,sign,verify,thbsse-sign}.json` (deterministic regeneration) |
| Wire identity | Both Magnetar primitives emit byte-identical FIPS 205 signatures; any unmodified slhdsa verifier accepts |
| Tag | `v1.2.0` |
| Cert-profile role | Polaris profile in `luxfi/quasar` (hash-based leg of the maximum-assurance cross-family PQ profile) |
| Sibling primitives | Pulsar (FIPS 204 M-LWE), Corona (R-LWE) --- algorithmically distinct families |

## Headline tests

```bash
cd ref/go && GOWORK=off go test -count=1 -short -timeout 600s ./pkg/magnetar/...
```

- `TestMagnetar_Wire_FIPS205Verifiable` (wire_test.go) --- pins
  byte-identity between `ValidatorSign` output and unmodified
  `cloudflare/circl/sign/slhdsa.Verify` across all 3 SHAKE modes.
- `TestThbsSE_Wire_FIPS205Verifiable` (thbsse_test.go) --- pins the
  same identity for the THBS-SE public combiner output.
- `TestThbsSE_RejectSeedReveal`, `TestThbsSE_RejectUnselectedFORS`,
  `TestThbsSE_RejectUnselectedWOTS`, `TestThbsSE_SlotReuseRejected`,
  `TestThbsSE_OverselectedCommittee`,
  `TestThbsSE_SlotBindingDomainSeparation` --- the 6 invariant gates
  for the THBS-SE construction.
- `TestPVSS_DKG_NoSinglePartyHoldsMaster`,
  `TestPVSS_DKG_ByteCompatWithDealerPath`,
  `TestPVSS_DKG_AdversarialReveals`,
  `TestPVSS_DKG_RobustnessAgainstMaliciousCommitments`,
  `TestPVSS_DKG_EndToEnd_SignAndVerify` --- the 5 invariant gates
  for the dealerless PVSS-DKG setup path (v1.2).
- `BenchmarkThbsSE_Sign_5of7/Magnetar-SHAKE-192f` --- end-to-end
  per-signature wall-clock at < 100 ms/op on Apple M1.
- `TestKAT_ThbsSe` --- deterministic vector replay at (n=7, t=4) x 3
  modes x 3 messages.

## Operator-controlled MPC custody

For deployments where an HSM-attested host is in the TCB by
deployment policy (e.g. M-Chain bridge custody, A-Chain confidential
compute), TEE-attestation-gated variants ship under
`luxfi/threshold/protocols/{slhdsa,mldsa,rlwe}-tee` via the
`lux/mpc` sibling tree --- NOT in this package. Magnetar's role is
the public-BFT and permissionless-threshold surface; the operator-
controlled variants are decomplected into their own primitive slot.

## Where this is used

The hash-based leg of the **Polaris** cert profile in
[`luxfi/quasar`](https://github.com/luxfi/quasar) --- the
maximum-assurance cross-family profile pairing lattice PQ (Pulsar
M-LWE + Corona R-LWE) with hash-based PQ (Magnetar SLH-DSA).

## Documents

- `SPEC.md` --- normative construction specification.
- `THBS-SPEC.md` --- THBS-SE normative spec (slot binding,
  commit-reveal, public-combiner, evidence).
- `CHANGELOG.md` --- release-by-release framing.
- `DEPLOYMENT-RUNBOOK.md` --- public-BFT default + the v1.0 honest
  open item (transient seed reconstruction at the public combiner).
- `BLOCKERS.md` --- the v1.1 roadmap (strict-atom-assembly path).
- `CRYPTOGRAPHER-SIGN-OFF.md` --- internal review trail.
- `TRUSTED-COMPUTING-BASE.md` --- TCB enumeration.
- `PROOF-CLAIMS.md` --- proof-roadmap inventory.
- `AXIOM-INVENTORY.md` --- assumed-axiom enumeration.
- `FIPS-TRACEABILITY.md` --- line-by-line FIPS 205 conformance trace.
- `PATENTS.md` --- patent-status notes.
- `LICENSING.md` --- license terms.
- `SUBMISSION.md` / `NIST-SUBMISSION.md` / `SUBMISSION-STATUS.md` ---
  NIST MPTC submission framework.
- `AUDIT-2026-06.md` --- 2026-06 production-readiness audit
  (public-permissionless-chain safety, TEE integration story,
  GPU acceleration story, canonical-name positioning).
- `TEE-INTEGRATION.md` --- TEE-attested production surface spec
  (SEV-SNP today, TDX + NRAS post-#222, operator-side wiring).
- `GPU-PORT-PLAN.md` --- v1.3 GPU acceleration port plan (four
  batched FIPS 205 hash-tree kernels at
  `lux-private/gpu-kernels/ops/crypto/slhdsa/`).
- `SECURITY.md` --- threat model + strict-PQ profile closure.
- `ASSEMBLE-INVARIANT.md` --- strict-atom Combine invariant.

## Build

```bash
cd ref/go && GOWORK=off go build ./...
cd ref/go && GOWORK=off go test -count=1 -short -timeout 600s ./pkg/magnetar/...
cd ref/go && GOWORK=off go test -count=1 -race -short -timeout 600s ./pkg/magnetar/...
```

## Citations

- NIST FIPS 205 (2024). *Stateless Hash-Based Digital Signature
  Standard.*
- Cozzo, D. and Smart, N. P. (2019). *Sharing the LUOV.* EUROCRYPT.
- Bonte, C., Smart, N. P. and Tan, T. (2023). *Threshold SPHINCS+:
  Practical Threshold Signatures from a Stateless Hash-Based
  Signature.*
- McGrew, D., Wallace, C. and Whyte, W. (2019). *Threshold Hash-Based
  Signatures.* IACR ePrint 2019/793.
- Schoenmakers, B. (1999). *A simple publicly verifiable secret
  sharing scheme and its application to electronic voting.* CRYPTO.
- Shamir, A. (1979). *How to share a secret.* Communications of the
  ACM.
