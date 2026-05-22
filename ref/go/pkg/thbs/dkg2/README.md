# thbs/dkg2 — Public DKG for Threshold HBS (research skeleton)

> **DO NOT USE IN PRODUCTION.** This subpackage is a research-grade
> skeleton. The PVSS layer ships; the MPC-root layer is **open research**
> and tracked in `BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1`. Ship a working
> public DKG in v0.6+ once an MPC-friendly hash is selected OR an MPC
> framework (MP-SPDZ, EMP, etc.) is integrated.

## What this is

`dkg2` is the **public-DKG** counterpart to the dealer-backed v1 DKG
in the parent `thbs` package. The two paths are:

| Path | Setup | Public-BFT safe | Status |
|---|---|---|---|
| `thbs.DealerDKG` | Trusted dealer | No (dealer learns secrets) | Ships, v1 stable |
| `dkg2` (this dir) | PVSS + MPC | Yes (no party learns secrets) | Skeleton only |

For the **public-BFT-safe primary primitive** today, use
**per-validator standalone SLH-DSA**: `magnetar.PerValidatorKeypair` +
`magnetar.ValidatorSign` + `magnetar.VerifyAggregateCert`
(`ref/go/pkg/magnetar/standalone.go`). That path needs no DKG and is
the correct primitive for public consensus.

`dkg2` is the future path for **threshold** HBS (one signature, not N
collected) **without** a trusted dealer.

## Why this is hard

Hash-Based Signatures (LMS, XMSS, SLH-DSA) commit public keys to
**Merkle roots over many WOTS+ chain endpoints**. Each endpoint
`W_{slot, j} = H^{w-1}(x_{slot, j})` is derived from a SECRET chain head
`x_{slot, j}` by repeated hashing.

A truly **public** DKG (no trusted dealer, no TEE) needs TWO ingredients:

### (A) PVSS distribution of per-element entropy

For every secret element `x_e`, the protocol collects randomness
contributions `r_{j,e}` from each party `j ∈ [n]` and Shamir-shares each
`r_{j,e}` across the committee at threshold `t`. The secret element is
`x_e = Σ_j r_{j,e}`; **no single party** ever holds `x_e` in cleartext.

**Status: this is what the skeleton implements** in `pvss.go`,
`complaint.go`, `consensus.go`.

### (B) MPC over the SHA-256 / SHAKE hash function

To produce a PUBLIC chain endpoint `W_e = H^{w-1}(x_e)` from a SECRET-
SHARED `x_e`, every party participates in an MPC that evaluates the hash
function on the shared input WITHOUT revealing it. Hash functions are
**non-linear**, so this is one of:

- **SPDZ-style arithmetic MPC**
  (Damgård-Pastro-Smart-Zakarias, "Multiparty Computation from Somewhat
  Homomorphic Encryption", CRYPTO 2012)
- **Garbled circuits + OT**
  (Wang-Ranellucci-Katz, "Global-Scale Secure Multiparty Computation",
  CCS 2017)
- **Function Secret Sharing**
  (Boyle-Gilboa-Ishai, "Function Secret Sharing", EUROCRYPT 2015)

For SLH-DSA-SHAKE-192s with the v1 thbs parameter set this is
**~750k SHAKE evaluations per DKG ceremony**. At current MPC framework
performance (MP-SPDZ, EMP-toolkit, SCALE-MAMBA) that's **multi-hour to
multi-day** per ceremony.

**Status: NOT IMPLEMENTED.** `RootMPC` returns `ErrMPCRootNotImpl`.

## Literature

### PVSS (the layer this skeleton implements)

- Schoenmakers, "A Simple Publicly Verifiable Secret Sharing Scheme and
  its Application to Electronic Voting" (CRYPTO 1999)
- Heidarvand, Villar, "Public Verifiability from Pairings in Secret
  Sharing Schemes" (SAC 2008)
- Gurkan et al., "Aggregatable Distributed Key Generation"
  (EUROCRYPT 2021)

### MPC over hash functions (the layer not yet implemented)

- Damgård, Pastro, Smart, Zakarias, "Multiparty Computation from Somewhat
  Homomorphic Encryption" (CRYPTO 2012) — SPDZ
- Wang, Ranellucci, Katz, "Global-Scale Secure Multiparty Computation"
  (CCS 2017)
- Boyle, Gilboa, Ishai, "Function Secret Sharing" (EUROCRYPT 2015)
- MP-SPDZ implementation: <https://github.com/data61/MP-SPDZ>

### Threshold HBS context

- McGrew, Fluhrer, Gazdag, Kampanakis, Morton, Westerbaan, "Coalition
  and Threshold Hash-Based Signatures" (IACR ePrint 2019/793)
- Bonte, Smart, Tan, "Threshold SPHINCS+" (2023)

## What ships in v1

```
dkg2/
├── doc.go         — package doc, scope, literature
├── pvss.go        — PVSS deal/verify wire shape, ErrSkeletonOnly stub
├── complaint.go   — Complaint round wire shape, ErrSkeletonOnly stub
├── consensus.go   — Qualified-set agreement + orchestrator + ErrMPCRootNotImpl
└── README.md      — this file
```

Every public function returns `ErrSkeletonOnly` (orchestration) or
`ErrMPCRootNotImpl` (the MPC root step). This makes it **impossible**
for a production caller to accidentally consume the unfinished pipeline.

## What blocks shipping a working dkg2

See `BLOCKERS.md::MAGNETAR-PUBLIC-DKG-1` in the magnetar repo root.

In short:

1. Select the MPC framework (MP-SPDZ, EMP, custom).
2. Implement the SHAKE-256 chain circuit under the chosen MPC.
3. Benchmark per-element cost; choose the parameter set + committee
   size that fits the deployment budget.
4. Write the production root.go.
5. Wire-format spec the public root computation transcript.
6. Integrate with the parent `thbs` `PublicKey` shape so the resulting
   threshold HBS public key is **byte-equal** to a dealer-DKG'd public
   key for the same elements (auditability).
7. Re-prove the construction (security argument under PVSS + MPC
   composition).
8. Independent cryptographer review (BLK-9-analog gate).
9. Independent MPC engineer review of the SHAKE-circuit implementation.

## When to use the dealer-backed v1 instead

The dealer-backed `thbs.DealerDKG` is the **right primitive** when:

- The deployment is **M-Chain bridge custody** (`thresholdvm` M-Chain
  mode per LP-134) and a TEE-attested host runs the dealer.
- The TCB explicitly includes the dealer process (Intel TDX / AMD
  SEV-SNP / Intel SGX attestation).
- The operator has performed the §1 hardening from
  `DEPLOYMENT-RUNBOOK.md` (mlock, ptrace-off, short-lived process).

It is the **wrong primitive** for:

- Public-BFT consensus (validator quorum, external relayers).
- Settings where the dealer cannot be in the TCB.

For those, use `magnetar.ValidatorSign` + `VerifyAggregateCert`
(per-validator standalone SLH-DSA).
