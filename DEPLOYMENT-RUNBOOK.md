# Magnetar --- Deployment runbook

Operator-facing deployment guidance for Magnetar v1.0. **READ THIS
BEFORE DEPLOYING.**

## 0. Choose your primitive

Magnetar v1.0 ships **TWO distinct signing primitives** with
different trust models. Picking the wrong one is the single largest
deployment risk.

| Primitive | Trust model | No-leak / sound | Use case |
|---|---|---|---|
| `ValidatorSign` + `VerifyAggregateCert` (per-validator standalone, `standalone.go`) | Per-validator standalone keys, no shared seed, NO reconstruction | YES (SOUND) | **Lux public-BFT validator quorum (PRODUCTION DEFAULT)** |
| TEE-attested combiner pool (`luxfi/threshold/protocols/slhdsa-tee`) | Seed reconstructed INSIDE a measured enclave on t hosts; trust-relocation (adds a host to the TCB), NOT MPC | YES under attested-hardware trust | Opt-in custody / single-signature certificates |
| `NewThbsSeKey` + `ThbsSeRound1` + `Combine` (THBS-SE, `thbsse.go`) | t-of-n committee, public combiner that **RECONSTRUCTS the full FIPS 205 master every signature** | NO --- RESEARCH-GRADE; whoever runs Combine sees the seed (a host IS effectively in the TCB) | Permissionless threshold ONLY where the combiner host is trusted by policy. NOT no-leak. |

### Quick decision

- **Public-BFT consensus on a Lux chain** (mainnet, testnet, devnet,
  white-label) --> per-validator standalone. The consensus layer
  collects N validator signatures into a `ValidatorAggregateCert`
  and counts valid signers; the quorum policy decision lives at the
  consumer. Wire cost is `N x |sigma|`; Z-Chain Groth16 rollup
  compresses to ~192 bytes.

- **Permissionless threshold signing for verifier-side
  single-signature certificates** --> THBS-SE. Read sec 2 below for
  the v1.0 honest open item on transient seed reconstruction at the
  public combiner.

- **HSM-attested MPC custody** (M-Chain bridge custody, A-Chain
  confidential compute) --> NOT in this package. Operator-controlled
  MPC custody uses TEE-attestation-gated variants shipped under
  `luxfi/threshold/protocols/{slhdsa,mldsa,rlwe}-tee` via the
  `lux/mpc` sibling tree.

## 1. Per-validator standalone (production primary)

### 1.1 Keygen

Each validator runs `PerValidatorKeypair` ONCE on its own host:

```go
sk, pk, err := magnetar.PerValidatorKeypair(params, rng)
```

- `params` SHOULD be `magnetar.ParamsM192s` (smallest signatures at
  NIST PQ category 3, >=192-bit classical security). Use
  `ParamsM192f` only if signing latency is the dominant constraint
  and you can absorb the 2.2x larger signature; use `ParamsM256s`
  only if you need category 5 (>=256-bit classical security).
- `rng` SHOULD be `crypto/rand.Reader` (nil also works; the function
  defaults to `crypto/rand.Reader`). Pass a deterministic reader
  ONLY for KAT reproducibility.

Persist `(sk, pk)` durably. Losing `sk` means dropping out of the
quorum until rotating to a fresh keypair. Standard HSM-backed key
storage applies; CIRCL slhdsa private keys are ~96 bytes at
ModeM192s.

Register `pk` in the validator-set commitment via the consensus
layer's normal key-registration ceremony.

### 1.2 Signing

```go
sig, err := magnetar.ValidatorSign(sk, nil, message)
```

Pass `nil` for the RNG to get the deterministic variant (FIPS 205
SignDeterministic). The output is the raw `params.SignatureSize`
bytes; the consensus layer's wire format wraps them.

Bind chain-id / block-height / consensus epoch into the message
upstream of this call --- the consensus layer's transcript-hash
pattern handles this (see `luxfi/consensus` QuasarCert).

### 1.3 Verification

```go
cert, _ := magnetar.BuildAggregateCert(params, signers, pubKeys, sigs)
count, err := magnetar.VerifyAggregateCert(cert, message, knownValidators)
if count >= quorumThreshold { ... }
```

- `knownValidators` is the consensus layer's authoritative
  `NodeID -> pubkey` map.
- The function returns the COUNT of valid signers. Unknown /
  pubkey-mismatched signers are counted as INVALID (not fatal --- a
  defense against impersonation that does not abort the entire
  batch).
- The quorum decision lives at the consumer.

## 2. THBS-SE (permissionless threshold)

### 2.1 v1.0 honest open item

THBS-SE v1.0 routes the final FIPS 205 byte production via a PUBLIC
COMBINER that holds the seed for the duration of one
`slhdsa.SignDeterministic` call and zeroizes. The combiner role is
PUBLIC --- anyone can be the combiner --- and there is no
long-lived secret material outside party-local Shamir leaves.

This is materially stronger than a TEE-attested
privileged-aggregator model (no host is in the TCB; the combiner
is a pure function any peer can run on its own substrate).

This is materially weaker than the strict invariant "no party or
combiner EVER reconstructs SK.seed, even transiently in memory" ---
a peer-local memory-disclosure adversary at exactly the combine
moment could observe the seed. The strict-atom-assembly path is the
v1.1 work item tracked at
`BLOCKERS.md::MAGNETAR-STRICT-ATOM-V11`.

**Operational implications.** If your threat model includes
"peer-local memory-disclosure adversary at the precise sub-second
combine moment," do NOT deploy THBS-SE v1.0 for new committee
ceremonies. Either:

1. Wait for v1.1 strict-atom-assembly.
2. Route the threshold signing via the TEE-attested variants at
   `luxfi/threshold/protocols/slhdsa-tee` (operator-controlled MPC
   custody, host in TCB by policy).
3. Use per-validator standalone instead --- the public-BFT primary
   has no seed reconstruction at any point.

### 2.2 Setup

```go
key, err := magnetar.NewThbsSeKey(params, threshold, committee, setupRng)
```

- `params` and the threshold `t` are the same shape as
  per-validator standalone.
- `committee` MUST be sorted ascending by `NodeID` with distinct
  non-zero IDs.
- `setupRng` defaults to `crypto/rand.Reader`.

v1.0 reference uses a deterministic-dealer setup. The dealer is in
the TCB FOR SETUP ONLY; once `NewThbsSeKey` returns, no party
(including the dealer) holds the master seed. The returned
`*ThbsSeKey` carries: the public key `PublicKey`, the per-party
shares `Shares[]`, the setup transcript `SetupTranscript`, and
metadata `(Threshold, N, Params)`.

Production deployments needing the leaderless PVSS-DKG variant
route through the sibling `luxfi/threshold` DKG package; that
DKG produces shares in the SAME wire-shape envelope. See
`BLOCKERS.md::MAGNETAR-PVSS-DKG-V11` for the v1.1 closure path.

### 2.3 Signing rounds

Each party runs:

```go
r1, r2, err := magnetar.ThbsSeRound1(params, share, binding, msg, guard, rng)
```

- `binding` is the slot tuple
  `(chain_id, epoch, slot, height, committee_id, message_domain)`.
- `guard` is a `*ThbsSeSlotGuard` the party persists across calls.
- Idempotent replay: re-calling with the same `(binding, msg)`
  returns the persisted `(r1, r2)`. A genuine equivocation attempt
  (same slot, different message) returns
  `*ThbsSeEquivocationError` carrying slashable evidence.

The party broadcasts `r1` (the commit) and, after the Round-1
quorum is observable, `r2` (the reveal).

### 2.4 Combine

Any peer (validator, block proposer, RPC node, passive watcher) can
run:

```go
sig, evidences, err := magnetar.Combine(magnetar.ThbsSeCombineInput{
    Key: key, Binding: binding, Message: msg,
    Round1: r1s, Round2: r2s,
})
```

- `err == nil` and `evidences` empty: the signature was produced
  from `>=t` honest reveals.
- `err == nil` and `evidences` non-empty: the signature was
  produced from `>=t` honest reveals, AND some malformed reveals
  were observed; the consensus layer can slash the named parties
  via `VerifyThbsSeShareEvidence`.
- `err == ErrInsufficientQuor`: fewer than `t` valid reveals were
  observed. `evidences` carries the malformed-share evidence the
  consensus layer can act on before retrying.

### 2.5 Verification

```go
ok := magnetar.VerifyBytesCtx(gpkBytes, message, ctxFromSlot(binding), sigBytes)
```

The `VerifyBytesCtx` helper is bytes-in, bool-out: it strips the
MAGS/MAGG envelopes and routes through the FIPS 205 verifier
verbatim. Any unmodified slhdsa verifier accepts the inner FIPS 205
bytes.

## 3. Operational hardening

### 3.1 RNG sourcing

`crypto/rand.Reader` on Linux/macOS reads from `getrandom(2)` /
`/dev/urandom`. On non-trivial deployments, additionally:

- Use the OS kernel's hardware-RNG entropy when available
  (`/dev/hwrng` on Linux with a HW source like RDRAND, the TPM, or
  a Yubikey-Bio).
- For HSM-backed keys, route keygen through the HSM's FIPS
  140-validated RNG.

### 3.2 Slot-guard persistence

The `ThbsSeSlotGuard` is in-memory only. For production deployments
that must survive restarts, persist the guard's state to disk
between Round-1 broadcasts (mirrored from
`SlotGuard.Record(slotID, digest, r1, r2)` --- ALL four fields are
required to verify slashing evidence after restart).

### 3.3 Equivocation slashing

`VerifyThbsSeEvidence` is a pure function. The consensus layer's
slashing pipeline:

1. Receive `ThbsSeEvidence` blob via gossip / on-chain submission.
2. Verify via `VerifyThbsSeEvidence(params, ev, msgPrior, msgNew,
   bindingPrior, bindingNew)`.
3. If valid, slash the party named in `ev.PartyID`.

The evidence blob is sufficient on its own --- no committee state,
no re-running of the protocol, no membership-proof gymnastics
required.

### 3.4 Mode-mixing prevention

Magnetar's wire codec rejects mode-mismatch at parse time. A
`Signature` parsed under `ModeM192s` cannot be cross-verified
against a `GroupKey` parsed under `ModeM256s` --- `VerifyBytesCtx`
returns false on mismatch.

### 3.5 Race detector

The Magnetar test suite passes under `go test -race`. SLH-DSA-heavy
tests self-skip via the `raceEnabled` build tag pattern (race-on
overhead is 5-10x and the tests carry no inter-goroutine
concurrency that would benefit from race coverage); race-on runs
cover the cheap unit tests (transcript, types, wire codec).

## 4. Migration from Magnetar v0.x

The v0.x `CombineWithSeedReconstruction` and `AggregateSignatures`
API surfaces have been removed. v0.x consumers migrate as follows:

| v0.x | v1.0 |
|---|---|
| `magnetar.GenerateValidatorKey` | `magnetar.PerValidatorKeypair` |
| `magnetar.AggregateSignatures` + `SignedBundle` | `magnetar.BuildAggregateCert` + `ValidatorAggregateCert` |
| `magnetar.VerifyAggregated` | `magnetar.VerifyAggregateCert` |
| `magnetar.CombineWithSeedReconstruction` | `magnetar.Combine` (THBS-SE, different semantics --- see THBS-SPEC.md) |
| `pkg/thbs` (legacy true-HBS) | DELETED. THBS-SE in `pkg/magnetar` is the v1.0 threshold construction. |

The signature payload bytes are byte-equal across primitives: a v0.x
`AggregateSignatures` output and a v1.0 `BuildAggregateCert` output
carry identical FIPS 205 signature bytes per validator. The only
difference is the envelope shape.
