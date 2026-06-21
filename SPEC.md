# Magnetar v1.0 --- Normative specification

This document is the normative specification of the two primitives
shipped by `luxfi/magnetar` v1.0.

Companion documents:

- `README.md` --- introduction and headline tests.
- `THBS-SPEC.md` --- detailed THBS-SE construction spec.
- `DEPLOYMENT-RUNBOOK.md` --- operator runbook.
- `BLOCKERS.md` --- v1.1 roadmap.

## 1. Primitives

Magnetar v1.0 ships TWO primitives. Both produce FIPS 205 wire bytes
that an unmodified verifier accepts.

### 1.0 Threshold SLH-DSA status (normative)

Magnetar does NOT claim an efficient oracle-respecting thresholdization of
SLH-DSA. Known theoretical barriers for extractable hash-based signatures
(Kondi-Kumar-Vanegas, MPTS '26) imply that, in the no-dealer / no-preprocessing
setting a public, leaderless, permissionless chain requires, threshold signing
CANNOT be achieved by merely making black-box use of the random-oracle / hash
function. A true threshold SLH-DSA signer would have to evaluate the FIPS 205
signing algorithm inside an active-secure MPC -- including the SHAKE/SHA-2/Keccak
computations that derive `R`, the FORS secrets, the WOTS+ chains, and the
authentication paths -- which is non-black-box use of the hash: research-grade
and expected to be expensive (the **T-SLH-DSA-MPC** research track).

Production Magnetar therefore implements threshold **CERTIFICATION** over
**INDEPENDENT** FIPS 205 SLH-DSA signatures -- never threshold signing:

- **Permissionless (production default):** the weighted quorum certificate in
  `luxfi/consensus` (`protocol/quasar/quorum_cert.go`). A quorum-weight subset
  of the validator set sign independently (1.1 below); a verifier checks the
  quorum predicate directly, or via a post-quantum STARK/FRI proof of those
  verifications (P3Q, `luxfi/p3q`). No key material is shared, reconstructed,
  or combined.
- **Trusted-hardware / custody (opt-in production):** the TEE-attested combiner
  pool -- honest trust-relocation (a host enters the TCB), NOT MPC. See
  `BLOCKERS.md`.
- **THBS-SE (1.2): RESEARCH-ONLY.** It reconstructs the FIPS 205 master at the
  public combiner every signature; it MUST NOT be presented as a
  no-reconstruction production threshold. See
  `BLOCKERS.md::MAGNETAR-STRICT-ATOM` (OPEN).

### 1.1 Per-validator standalone (public-BFT primary)

API at `ref/go/pkg/magnetar/standalone.go`:

```
PerValidatorKeypair(params, rng) -> (sk, pk, error)
ValidatorSign(sk, rng, message)  -> ([]byte, error)
ValidatorBatchVerify(params, pubs, msgs, sigs) -> ([]bool, error)
BuildAggregateCert(params, signers, pubKeys, sigs) -> (*ValidatorAggregateCert, error)
VerifyAggregateCert(cert, message, knownValidators) -> (count, error)
```

Semantics:

- Each validator runs `PerValidatorKeypair` ONCE on its own host with
  its own RNG; persists `(sk_i, pk_i)`; registers `pk_i` in the
  validator-set commitment.
- To sign message `m`: validator `i` computes
  `sigma_i = ValidatorSign(sk_i, nil, m)`. Output is the raw FIPS 205
  signature bytes; deterministic when `rng` is nil (FIPS 205
  SignDeterministic).
- The consensus layer collects N `(sigma_i, pk_i, ValidatorID_i)`
  triples into a `ValidatorAggregateCert` via `BuildAggregateCert`.
- `VerifyAggregateCert` returns the COUNT of valid signers. The
  quorum policy decision (count >= threshold) lives at the CONSUMER,
  NOT in the primitive.

Trust model:

- No DKG, no shared seed, no aggregator-in-TCB.
- Per-validator slashing is attributable.
- A post-quantum P3Q STARK/FRI proof (`luxfi/p3q`) compresses the N
  independent signatures plus the weighted-quorum predicate into one
  succinct quorum certificate; the rollup is a separate primitive
  (`luxfi/consensus` quorum_cert + `luxfi/p3q`). The earlier Groth16/bn254
  rollup is classical (pairing-based) and is superseded for PQ finality.

### 1.2 THBS-SE (permissionless threshold)

API at `ref/go/pkg/magnetar/thbsse.go`:

```
NewThbsSeKey(params, threshold, committee, rng) -> (*ThbsSeKey, error)
ThbsSeRound1(params, share, binding, msg, guard, rng) -> (r1, r2, error)
Combine(input ThbsSeCombineInput) -> (*Signature, []ThbsSeShareEvidence, error)
NewThbsSeSlotGuard() -> *ThbsSeSlotGuard
VerifyThbsSeEvidence(params, ev, msgPrior, msgNew, bindingPrior, bindingNew) -> bool
VerifyThbsSeShareEvidence(params, ev, binding, msg) -> bool
```

Semantics: see `THBS-SPEC.md` for the full construction. Highlights:

- t-of-n committee with `n > t` over-selection.
- Slot binding flows into the cSHAKE256 commit transcript AND into
  the FIPS 205 ctx string.
- PUBLIC COMBINER role; anyone with the public ThbsSeKey, the slot
  binding, the message, and >= t valid Round-1/Round-2 pairs can
  produce the FIPS 205 signature.
- Equivocation and malformed-share evidence are wire-shaped typed
  blobs; pure-function third-party verifiers.

## 2. Parameter sets

Per FIPS 205 sec 10.1 Table 2:

| Mode | n (WOTS+ msg len) | PK | SK | Sig | Seed |
|---|---|---|---|---|---|
| `ModeM192s` (Magnetar-SHAKE-192s) | 24 | 48 | 96 | 16224 | 96 |
| `ModeM192f` (Magnetar-SHAKE-192f) | 24 | 48 | 96 | 35664 | 96 |
| `ModeM256s` (Magnetar-SHAKE-256s) | 32 | 64 | 128 | 29792 | 128 |

Recommended production target: `ModeM192s` (smallest signatures at
NIST PQ category 3, >=192-bit classical security).

## 3. Hash domain separation

All cSHAKE calls use function-name `"Magnetar"` and one of the
following customisation tags:

| Tag | Purpose | Defined in |
|---|---|---|
| `MAGNETAR-THBSSE-SHARE-DEAL-V1` | Shamir coefficient stream + EvalPointFromID hash | `transcript.go` |
| `MAGNETAR-THBSSE-SLOT-V1` | Slot binding -> 32-byte slot_id; message digest | `thbsse.go` |
| `MAGNETAR-THBSSE-R1-COMMIT-V1` | Round-1 commit D_i; setup transcript | `thbsse.go` |
| `MAGNETAR-THBSSE-SHARE-MAC-V1` | (reserved for share-MAC envelope) | `thbsse.go` |

The protocol-wide domain-separation context is the ASCII string
`"lux-magnetar-v1"` (`tagDomainSep`).

The FIPS 205 ctx prefix for THBS-SE signatures is `"lux-magnetar-thbsse-v1"`
followed by the 32-byte slot_id; total length 56 bytes, well under
the FIPS 205 sec 10.2 limit of 255 bytes.

## 4. Byte-identity claims

### 4.1 Per-validator standalone

`TestMagnetar_Wire_FIPS205Verifiable` pins:

For any `(sk, message)` pair: stripping the canonical 11-byte MAGS
wire header from `MarshalBinary(ValidatorSign(sk, nil, message))`
recovers the unmodified FIPS 205 bytes that
`cloudflare/circl/sign/slhdsa.Verify` accepts under
`(sk.Pub, message, nil_ctx)`.

### 4.2 THBS-SE

`TestThbsSE_Wire_FIPS205Verifiable` pins:

For any `(key, binding, message)` triple and any `t` valid
Round-1/Round-2 pairs: `Combine(...)` emits a `*Signature` whose
`Bytes` field, fed DIRECTLY to `cloudflare/circl/sign/slhdsa.Verify`
under `(key.PublicKey, message, ctxFromSlot(binding))`, is accepted.

Additionally, `TestThbsSE_PublicCombiner_Determinism` pins that any
two disjoint t-sized sub-quora of valid Round-2 reveals produce
byte-equal final signatures. The public combiner is a PURE function
of its inputs.

## 5. Slashing evidence wire shape

### 5.1 Equivocation evidence (ThbsSeEvidence)

```
type ThbsSeEvidence struct {
    SlotID      [32]byte
    PartyID     NodeID  // [32]byte
    PriorDigest [32]byte
    PriorR1     ThbsSeRound1Msg
    PriorR2     ThbsSeRound2Msg
    NewDigest   [32]byte
    NewR1       ThbsSeRound1Msg
    NewR2       ThbsSeRound2Msg
}
```

Third-party verifier:
`VerifyThbsSeEvidence(params, ev, msgPrior, msgNew, bindingPrior, bindingNew) -> bool`.

### 5.2 Malformed-share evidence (ThbsSeShareEvidence)

```
type ThbsSeShareEvidence struct {
    PartyID    NodeID
    Reason     ThbsSeShareEvidenceReason  // {slot-mismatch, wire-size, commit-mismatch}
    ExpectedD  [32]byte                   // for commit-mismatch
    ObservedD  [32]byte                   // for commit-mismatch
    PartialSig []byte                     // for commit-mismatch / wire-size
}
```

Third-party verifier:
`VerifyThbsSeShareEvidence(params, ev, binding, msg) -> bool`.

## 6. Wire codec

Magnetar v1.0 ships canonical MAGS (signature) and MAGG (group key)
frames per `wire.go`:

```
Signature:                       GroupKey:
  magic(4) = 'M' 'A' 'G' 'S'       magic(4) = 'M' 'A' 'G' 'G'
  version(2) = 0x0001              version(2) = 0x0001
  mode(1)    = {0x01..0x03}        mode(1)    = {0x01..0x03}
  len(4)     = FIPS 205 sig size   len(4)     = FIPS 205 pk size
  payload    = FIPS 205 sigEncode  payload    = FIPS 205 (seed||root)
```

Magic bytes are distinct from sibling protocols (pulsar PULS/PULG,
corona CORS/CORG) so cross-protocol frames fail at the first
dispatch. Stripping the 11-byte header recovers the unmodified FIPS
205 bytes any verifier accepts.

## 7. v1.0 open items

See `BLOCKERS.md`:

- `MAGNETAR-STRICT-ATOM-V11` --- the strict-invariant lift (no seed
  reconstruction even transiently).
- `MAGNETAR-PVSS-DKG-V11` --- the leaderless PVSS-DKG setup variant
  (v1.0 ships deterministic-dealer reference; production routes
  through sibling `luxfi/threshold` DKG).
- `MAGNETAR-PROOF-TRACK-V11` --- EasyCrypt + Lean track for the
  THBS-SE construction shape.
- `MAGNETAR-DUDECT-V11` --- v1.1 dudect harness.
- `MAGNETAR-EXTERNAL-AUDIT-V11` --- external cryptographer review.
