# Magnetar THBS-SE Combine: what the assemble path actually does

This document used to be the "load-bearing prose statement of the
strict-atom discipline that closes MAGNETAR-STRICT-ATOM-V11". That
framing was wrong. MAGNETAR-STRICT-ATOM-V11 is **NOT closed** (see
`BLOCKERS.md`). This document now states plainly what
`ref/go/pkg/magnetar/thbsse_assemble.go` does.

## The fact

`assembleSignatureBytes` RECONSTRUCTS the full FIPS 205 master at the
public combiner, every signature:

1. It Lagrange-interpolates the t share envelopes byte-by-byte into a
   buffer `derivedExpandInput`.
2. It SHAKE-expands that into a single buffer `derivedMaterial`
   = `skSeed || skPrf || pkSeed` (FIPS 205 §10.1).
3. It drives a FIPS 205 §5--§8 signing walk that reads positional
   slices of `derivedMaterial` (the §5/§6/§7/§8 PRF input and the
   §11.2 PRF_msg key).

For the duration of one Sign call, the entire private key is resident
in the combiner's process memory. The combiner is PUBLIC (any peer can
run it), so this is a reconstruction at an untrusted party.

## The "strict-atom" naming convention is not a security property

The earlier revision avoided the identifier `seed` (and `skSeed`,
`skPrf`, ...) and routed access through closures over positional
slices of `derivedMaterial`. It then claimed this "secures" something
that a `seed []byte` local did not, and called it a discipline that
"closes" the no-leak gap.

That is false. Renaming the buffer changes the spelling, not the data.
`derivedMaterial` holds `skSeed || skPrf || pkSeed` exactly as a
variable named `seed` would. A memory-disclosure adversary (coredump,
`/proc/self/mem`, a compromised combiner process) observes the master
during the Sign call either way. There is no confidentiality property
to rely on, and the "strict-atom invariant" buys none.

This is a fundamental property of hash-based signatures, not a fixable
implementation detail: there is no algebraic structure to aggregate,
so producing one FIPS 205-shaped signature from shares requires either
reconstructing the seed at some party (this path) or full MPC over the
SHAKE hash tree (open research; multi-second, multi-megabyte per
signature). See `standalone.go`'s banner for the literature
(Cozzo-Smart 2019, Bonte-Smart-Tan 2023, NIST IR 8214).

## What the path actually gives

ONE property, and it is a CORRECTNESS/INTEROP property, not a
confidentiality one:

> The emitted signature is byte-identical to
> `circl/slhdsa.SignDeterministic` on the reconstructed master, so any
> unmodified FIPS 205 verifier accepts it.

Pinned by `TestSlhdsaInternal_ByteEqualToCirclSign` and
`TestThbsSE_StrictAtom_Combine_ByteIdentityToCircl`.

The scratch buffers (`prfAbsorb`, `prfMsgAbsorb`) and the derived
buffers (`derivedExpandInput`, `derivedMaterial`) are zeroized after
use. That is defense-in-depth against lingering heap copies, NOT a
guarantee the master was never resident — it was.

## Deployment positioning (see BLOCKERS.md and the product decision)

- **Permissionless THBS-SE (this path): RESEARCH-GRADE.** Master is
  reconstructed at an untrusted public combiner. Do not present as
  production or as "no host in the TCB at sign time".
- **Production default:** per-validator standalone (`standalone.go`) —
  N independent FIPS 205 signatures, no reconstruction anywhere.
- **Opt-in trusted-hardware:** the TEE-attested combiner pool in
  `luxfi/threshold/protocols/slhdsa-tee`. That relocates the
  reconstruction into a measured enclave; it ADDS a host to the TCB
  (trust-relocation), it is not MPC.

## The lint

`TestThbsSE_AssembleIdentHygiene` (Go) and `scripts/checks/strict-atom-ast.sh`
are an IDENTIFIER-HYGIENE LINT over `thbsse_assemble.go`. They assert
no variable is *spelled* `seed`/`skSeed`/... . That is a style/naming
check. It is not, and does not claim to be, a no-leak proof.
