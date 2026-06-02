# Magnetar v1.1 strict-atom Combine invariant

This document is the load-bearing prose statement of the strict-atom
discipline that closes `MAGNETAR-STRICT-ATOM-V11` in the v1.1 release.

## The four forbidden FIPS 205 master-binder identifiers

The strict-atom emit path (`ref/go/pkg/magnetar/thbsse_assemble.go`)
is the public combiner's only point of contact with the FIPS 205
master byte material. The v1.1 audit grep that defines compliance:

```
grep -rE "SK\.seed|SK\.prf|sk_seed|sk_prf" ref/go/pkg/magnetar/thbsse_assemble.go
```

MUST return zero matches. The four sentinel patterns are:

| Pattern | Matches |
|---|---|
| `SK\.seed` | The FIPS 205 master skSeed field reference (dot notation, e.g. `SK.seed`, `sk.seed`). |
| `SK\.prf` | The FIPS 205 master skPrf field reference (dot notation). |
| `sk_seed` | The C-style snake-case form of skSeed (used in FIPS 205 reference C implementations). |
| `sk_prf` | The C-style snake-case form of skPrf. |

The v1.0 Combine path (now deleted) had `seed := make(...)` and
`sk, err := KeyFromSeed(params, seed)` which would have tripped a
broader version of this grep on the variable name `seed`. The v1.1
strict-atom path does NOT have a `seed` variable; the corresponding
byte material exists ONLY as positional slices of a SHAKE-expansion
output buffer called `derivedMaterial`, named for the SHAKE absorb
context it feeds, not for the FIPS 205 field it represents.

## The discipline

1. The 96-byte Magnetar share envelope (the Shamir share of the
   FIPS 205 master) is reconstructed BYTE-WISE into a transient
   buffer `derivedExpandInput` for the duration of one
   `SHAKE256(...)` absorb call. The buffer is zeroized immediately
   after.

2. The SHAKE-256 expansion output `derivedMaterial[0:3n]` is the
   v1.1 substrate for every secret-side PRF / PRF_msg call. It is
   partitioned by POSITION:

   - `derivedMaterial[0   : n  ]` --- the FIPS 205 §5/§6/§7/§8 PRF
     secret input.
   - `derivedMaterial[n   : 2n ]` --- the FIPS 205 §11.2 PRF_msg
     secret input.
   - `derivedMaterial[2n  : 3n ]` --- the public PK.seed segment,
     cross-checked against the committee's published `pkBytes`.

   The variable NAMESPACE of `thbsse_assemble.go` includes NO binder
   for these segments. They are accessed exclusively by positional
   slicing inside closures (`makePRFClosure`, `makePRFMsgClosure`).

3. Each closure composes its SHAKE absorb input inside a transient
   per-call buffer (`prfAbsorb`, `prfMsgAbsorb`), runs the SHAKE-256
   call, and zeroizes the absorb buffer before returning.

4. The Magnetar-internal FIPS 205 §5--§8 walk
   (`ref/go/pkg/magnetar/slhdsa_internal.go::slhSignAtom`) is driven
   by the two callbacks. The walk itself touches only PUBLIC bytes
   (the output of completed PRF calls is public per FIPS 205 §11.2);
   the secret-side seam is exactly the two callbacks.

5. After `slhSignAtom` returns the FIPS 205 wire bytes,
   `derivedMaterial` is zeroized via deferred wipes.

## What this discipline buys vs the v1.0 transient-seed model

The v1.0 transient-seed model had a `seed` variable in the public
combiner's stack frame for the duration of one
`circl.SignDeterministic` call. A peer-local memory-disclosure
adversary at exactly the combine moment could observe the seed.

The v1.1 strict-atom discipline:

- Forbids any FIPS 205 master-binder identifier in `thbsse_assemble.go`
  by the audit grep. Static, file-local invariant.

- Bounds the lifetime of the SHAKE-expanded master material to the
  enclosing function call. `derivedMaterial` is allocated, used,
  zeroized, and dropped in one function activation.

- Bounds the lifetime of the SHAKE-absorb scratch buffers to the
  enclosing per-PRF-call closure. Each `prfAbsorb` /
  `prfMsgAbsorb` lives across one SHAKE-256 absorb and is zeroized
  before the closure returns.

What it does NOT buy (the Cozzo-Smart bound on threshold-MPC for
hash-based signatures):

- The bytes of the FIPS 205 master DO exist transiently in
  `derivedMaterial` and in `derivedExpandInput`. A coredump or
  /proc/self/mem dump at exactly the right wall-clock instant
  would observe them.

This is the residual gap, honestly documented. Closing it would
require either:

- Full MPC over the SHAKE-256 hash tree (~minutes per signature,
  ~megabytes of comms; open research). NIST IR 8214 classifies this
  as the highest threshold-MPC cost across FIPS 203/204/205.

- A TEE-attested host in the TCB (sibling primitive at
  `luxfi/threshold/protocols/slhdsa-tee`; out of scope for Magnetar
  which is the public-BFT-safe permissionless surface).

The strict-atom discipline is the strictest discipline available
without crossing into either of those two regimes. Audit grep +
positional-slice discipline + bounded lifetimes is the v1.1 bar.

## How this is enforced

| Layer | Mechanism | Source |
|---|---|---|
| Per-push Go test | AST walk + raw-byte grep | `ref/go/pkg/magnetar/thbsse_assemble_test.go::TestThbsSE_StrictAtom_NoTransientSeed` |
| Per-push shell gate | Raw grep, exit 2 on hit | `scripts/checks/strict-atom-ast.sh` |
| Per-push Go CT gate | AST walk on secret-tagged identifiers | `ct/dudect/strict_atom_combine_ct_test.go::TestStrictAtom_CT_NoSecretDependentBranch` |
| EasyCrypt abstract model | The abstract `assemble_signature_bytes` operator has no named seed binder | `proofs/easycrypt/Magnetar_N1_StrictAtom.ec` |
| Lean abstract model | `strictAtomDisciplineSatisfied` is the abstract counterpart | `proofs/lean/Crypto/Magnetar/StrictAtom.lean` |

## Backward compatibility

The wire format, share format, slot-guard state, and protocol round
structure of THBS-SE are UNCHANGED at v1.1. KAT vectors regenerate
to the same bytes. v1.0.0 consumers bump to v1.1.0 transparently
with no API break.
