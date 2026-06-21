# Magnetar --- Blockers

Honest enumeration of what is sound, what is open, and what was
falsely marked closed.

## Deployment model (the product decision)

Magnetar ships ONE construction to each of three deployment regimes:

| Regime | Construction | Posture |
|---|---|---|
| **Permissionless public-BFT (DEFAULT, production)** | Per-validator standalone (`standalone.go`) | SOUND. Each validator holds its own FIPS 205 keypair, signs independently; consensus collects N signatures into a `ValidatorAggregateCert`. No DKG, no dealer, no reconstruction anywhere. |
| **Trusted-hardware / custody (opt-in, production)** | TEE-attested combiner pool (`luxfi/threshold/protocols/slhdsa-tee`) | SOUND under an explicit, honest trust model: the whole seed is reconstructed INSIDE a measured enclave on t hosts that must agree. This is TRUST-RELOCATION (it adds a host to the TCB), NOT MPC. |
| **Permissionless threshold THBS-SE (RESEARCH-ONLY)** | `thbsse.go` + `thbsse_assemble.go` + PVSS-DKG | RESEARCH-GRADE. The public combiner reconstructs the full FIPS 205 master every signature. Do NOT present as production or "no host in the TCB at sign time". |

The hash-based-signature literature is unambiguous that this is
fundamental (Cozzo-Smart EUROCRYPT 2019; Bonte-Smart-Tan 2023; NIST IR
8214): SLH-DSA has no aggregatable structure, so one FIPS 205-shaped
signature from shares requires either reconstructing the seed at some
party or full MPC over the SHAKE hash tree. Magnetar's PRIMARY
production answer (per-validator standalone) sidesteps the dilemma by
emitting N independent signatures.

## OPEN --- MAGNETAR-STRICT-ATOM --- THBS-SE reconstructs the master

**Status: OPEN. (Previously, and falsely, marked CLOSED.)**

`assembleSignatureBytes` (`thbsse_assemble.go`) reconstructs the full
FIPS 205 master at the public combiner: it Lagrange-interpolates the
shares into `derivedExpandInput`, SHAKE-expands them into
`derivedMaterial` (= skSeed || skPrf || pkSeed), and drives the FIPS
205 §5--§8 walk reading positional slices of that buffer
(`ASSEMBLE-INVARIANT.md`). The whole private key is resident in the
combiner's memory for one Sign call.

The earlier "strict-atom" closure was PROOF BY RENAME: the path avoids
*spelling* a variable `seed`, and a name-grep test/lint
(`TestThbsSE_AssembleIdentHygiene`, `scripts/checks/strict-atom-ast.sh`)
enforces the spelling. Renaming the buffer does not change the data.
The "CT" gate (`ct/dudect/strict_atom_combine_ct_test.go`) is likewise
a name lint, not a timing measurement — and constant-time is the wrong
property to claim for a path that holds the master in plaintext.

**What IS true:** the emitted signature is byte-identical to
`circl/slhdsa.SignDeterministic` on the reconstructed master (a
correctness/interop property, pinned by
`TestSlhdsaInternal_ByteEqualToCirclSign` and
`TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl`). That is the only
property the path delivers. It is NOT a no-leak property.

**Closing it** requires full MPC over the SHAKE hash tree (open
research; multi-second, multi-megabyte per signature) or a TEE-attested
host in the TCB (the opt-in pool below). The permissionless THBS-SE
path stays RESEARCH-ONLY.

## SOUND (with an honest trust model) --- TEE-attested combiner pool

The strict-PQ / custody regime routes Combine through a t-of-n
attested-combiner pool in
`luxfi/threshold/protocols/slhdsa-tee/pool.go`, gated by the single
profile function `magnetarRefuseUnderStrictPQ` in
`luxfi/threshold/pkg/thresholdd/magnetar.go` (mirrors the precompile
`contract.RefuseUnderStrictPQ` discipline: ONE function, ONE place, ONE
refusal sentinel `slhdsatee.ErrMagnetarNoTEEAttestation`).

**Honest trust model.** The seed is still RECONSTRUCTED in full — but
inside a MEASURED ENCLAVE whose binary + firmware chain-validate to the
vendor root (AMD KDS / Intel PCS / NVIDIA NRAS). t hosts must agree on
the output. This is TRUST-RELOCATION: it moves the reconstruction from
an untrusted public combiner into attested hardware, ADDING that
hardware (and the attestation chain, and the t hosts) to the TCB. It is
NOT MPC; no party is prevented from seeing the seed — the enclave sees
it. Use it when you are willing to trust attested hardware; do not call
it threshold cryptography that keeps the seed secret from every party.

**Production attestation kinds.** SEV-SNP is the only `cc/attest`
verifier currently production-implemented. TDX / NRAS verifiers are
stubs returning `ErrNotImplemented` (tracked at #222 stages 2--3); they
wire through the same pool contract once shipped (an addition to
`CombinerPoolConfig.KnownIssuers`, no magnetar-side change).

**Pool policy defaults:** `Threshold = 2` (2-of-3 attested combiners),
`RotationWindow = 60s` (per-member attestation freshness),
`KnownIssuers = {"amd.sev.snp"}`.

**Verification gates (BUILD + PASS under `-race`).** As of the
`luxfi/zap` bump to v0.3.1 in `luxfi/threshold` (which restores the
`NodeConfig.TLS` field that `pkg/thresholdd` needs to build), the five
gates build and pass under `-race`:

- `TestMagnetarCombine_StrictPQProfile_RequiresTEE` --- PASS (~77s)
- `TestMagnetarCombine_AttestationVerified_AllowsSign` --- PASS (~95s)
- `TestMagnetarCombine_StaleAttestation_RejectsSign` --- PASS (~128s)
- `TestMagnetarCombine_TwoOfThreeAttestedCombiners_MatchSig` --- PASS (~94s)
- `TestMagnetarCombine_SignatureDivergence_HardRefusal` --- PASS (~91s)

(`ok github.com/luxfi/threshold/pkg/thresholdd` ~487s under `-race`.)
These gates exercise the profile refusal, attestation freshness, t-of-n
agreement, and divergence-refusal logic. They do NOT change the trust
model: the seed is reconstructed inside the enclave.

## FIXED --- PVSS-DKG open-reveal leak (P2)

**Status: FIXED for the production default; honest limits documented.**

The earlier DKG ran in OPEN-REVEAL mode: `RunDKGSimulation` called
`RevealMsg()` for EVERY party, and `RevealMsg()` publishes
`PolyCoeffs[b][0] = m_i`. With every constant term public, the master
M = Σ m_i was reconstructible by ANY observer of the transcript — not
merely by t-1 colluding insiders. The "complaint-conditional reveal"
was prose only.

**The fix (`pvss_dkg.go`):**

- Production entry `RunDKG` emits a transcript with `Reveals == nil`:
  no constant terms are published, so M is NOT reconstructible from the
  transcript. `tr.RevealsMaster()` is false. Regression-gated by
  `TestPVSS_DKG_ProductionTranscriptHidesMaster` (asserts production
  hides M, open-reveal reveals M, and the open-reveal path refuses
  without an explicit hazard ack).
- `VerifyDKGTranscript` dispatches on transcript type: the production
  (no-reveal) path verifies commitment shape + setup binding and
  qualifies well-shaped parties; the open-reveal path additionally
  verifies shares against published reveals.
- The leaking open-reveal simulation is renamed
  `RunDKGSimulationOpenRevealTestOnly` and gated behind a required
  `AckOpenRevealRevealsMaster` barrier (greppable, impossible to call
  by accident). It is TEST/KAT only.

**Honest limits of the fixed production path (`RunDKG` HONEST
LIMITATIONS in code):**

1. **PK derivation still reconstructs M.** `pk = SLH-DSA.PK(M)` is a
   hash tree over M; there is no way to derive it from shares without
   reconstructing M somewhere (or TEE/MPC). `deriveDKGPublicKey`
   reconstructs M transiently to compute pk and zeroizes it. M is not
   published, but SOME party (whoever derives pk) holds it for an
   instant. "No party EVER holds M" is achievable only via the TEE or
   dealer paths. The earlier banner's "NO-MASTER-IN-MEMORY DISCIPLINE"
   (naming a buffer `lagrangeScratch`) was the same proof-by-rename and
   is corrected.

2. **No robust malicious-dealer exclusion at DKG time.** Hash
   commitments are not openable without revealing m_i, so a recipient
   cannot non-interactively verify a received share. The production
   path therefore does NOT exclude malicious dealers at setup;
   malformed shares are caught later at THBS-SE sign time (commit
   binding; `TestThbsSE_RejectOversizedShareWireSize`,
   `TestThbsSE_RejectTamperedShareCommitMismatch`) and via a complaint
   that reveals only the disputed recipient's share value. For
   adversarial committees, prefer the dealer path or the TEE pool.

Sound robust dealerless DKG would need group-homomorphic (Feldman /
Pedersen) commitments or encrypted-shares + NIZK (proper Schoenmakers
PVSS) — a separate construction, not attempted here.

## OPEN --- Mechanized proofs (there are none)

There is NO mechanized proof of any Magnetar threshold property. The
EasyCrypt/Lean "proof track" was vacuous (a headline theorem proved by
`apply`-ing an axiom that restated it; lemmas of the form `X = X`; a CT
lemma discharged by `admit`; a PVSS secrecy "theorem" with conclusion
`true`) and has been deleted or reduced to explicitly-labeled scaffolds
that prove nothing. See `proofs/README.md` and `PROOF-CLAIMS.md`. A
genuine result (an abstract `slh_sign` model proven equal to the Go
implementation) is multi-week work and is OPEN.

## OPEN --- External cryptographer audit

No external audit. The internal sign-off
(`CRYPTOGRAPHER-SIGN-OFF.md`) covers only the per-validator standalone
primitive (sound) and explicitly does NOT bless the permissionless
THBS-SE path as no-leak.

## OPEN --- Cross-implementation FIPS 205 byte-equality

Byte-equality is checked only against `cloudflare/circl`. A cross-check
against an independent FIPS 205 reference (pq-crystals C, BoringSSL
when SLH-DSA lands) is a tracked gap (not yet done).

## Cross-references

- `README.md`, `DESIGN.md` --- construction overview.
- `ASSEMBLE-INVARIANT.md` --- what the THBS-SE Combine path does.
- `PROOF-CLAIMS.md` --- per-property proven/asserted/open breakdown.
- `TEE-INTEGRATION.md` --- TEE-attested production surface spec.
- `CHANGELOG.md` --- release history.
