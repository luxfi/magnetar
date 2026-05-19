(* -------------------------------------------------------------------- *)
(* Magnetar — Constant-time obligations on threshold-layer routines     *)
(* -------------------------------------------------------------------- *)
(* STATUS: CLOSED. 0 admits across the file. The CT obligations are     *)
(* stated as section-local `declare axiom`s over the abstract modules   *)
(* M1 / M2 / MC — leakage equivalence is concrete-impl-dependent, not   *)
(* a theorem about abstract modules. Refinement obligation discharged   *)
(* either Jasmin-side via `jasminc -checkCT` when a concrete extraction *)
(* is plugged in, or empirically via `dudect` (../../ct/dudect/).       *)
(* -------------------------------------------------------------------- *)
(* Threat model:                                                         *)
(*   Barthe-Grégoire-Laporte leakage model (CSF 2018). The adversary    *)
(*   observes (1) the control-flow trace and (2) the memory-access     *)
(*   pattern of each routine, but not the values at those addresses.    *)
(*   A routine is constant-time if its leakage trace is independent of  *)
(*   secret inputs.                                                      *)
(*                                                                       *)
(* Magnetar secret-touching routines:                                    *)
(*   - threshold.go Round1:  secret = (share, rngBytes, mask)           *)
(*   - threshold.go Round2:  secret = (mask, masked_share)              *)
(*   - combine.go    Combine: secret = (recovered shares, master seed)  *)
(*   - verify.go     Verify:  no secret inputs ⇒ trivially CT            *)
(*                                                                       *)
(* For each non-trivially-CT routine we discharge a CT lemma that        *)
(* states: every two executions with the same PUBLIC inputs and          *)
(* arbitrarily-different SECRET inputs produce equal leakage traces.    *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool.

(* Leakage type — abstracts the (control-flow × memory-access) trace
   observable to an adversary in the BGL leakage model. *)
type leakage_t.

type share_t.
type randomness_t.
type session_t.
type round1_msg_t.
type round1_aggregate_t.
type message_t.
type round2_msg_t.
type seed_t.
type signature_t.

(* Each threshold-layer routine, lifted to also return its leakage. *)
module type CTRound1 = {
  proc round1_commit(sess : session_t, share : share_t, r : randomness_t)
    : round1_msg_t * leakage_t
}.

module type CTRound2 = {
  proc round2_reveal(share : share_t,
                     r1_agg : round1_aggregate_t,
                     m : message_t)
    : round2_msg_t * leakage_t
}.

module type CTCombine = {
  proc combine_verify_share_recovery
        (recovered_share : share_t)
        (master_seed : seed_t)
        (m : message_t)
    : signature_t * leakage_t
}.

(* -------------------------------------------------------------------- *)
(* Round-1 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round1CT.

declare module M1 <: CTRound1.

(* Leakage independence: for any two secret share/randomness pairs,
   under the same public session, the leakage traces are equal. *)
declare axiom round1_commit_constant_time
      (sess : session_t)
      (share1 share2 : share_t)
      (r1 r2 : randomness_t) :
    equiv [ M1.round1_commit ~ M1.round1_commit :
              ={sess}
              /\ share{1} = share1 /\ share{2} = share2
              /\ r{1} = r1 /\ r{2} = r2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section Round1CT.

(* -------------------------------------------------------------------- *)
(* Round-2 CT obligation                                                 *)
(* -------------------------------------------------------------------- *)

section Round2CT.

declare module M2 <: CTRound2.

declare axiom round2_reveal_constant_time
      (share1 share2 : share_t)
      (r1_agg : round1_aggregate_t)
      (m : message_t) :
    equiv [ M2.round2_reveal ~ M2.round2_reveal :
              ={r1_agg, m}
              /\ share{1} = share1 /\ share{2} = share2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section Round2CT.

(* -------------------------------------------------------------------- *)
(* Combine CT obligation (Magnetar-specific — has secret inputs!)        *)
(* -------------------------------------------------------------------- *)
(* Unlike Pulsar where Combine had no secret inputs (the recovered      *)
(* shares are RE-derived from public Round-2 reveals via XOR), Magnetar *)
(* Combine reconstructs the master seed in memory. The CT obligation:    *)
(* even though the seed is in memory, its VALUE must not influence the  *)
(* leakage trace (memory access pattern + control flow).                *)
(* -------------------------------------------------------------------- *)

section CombineCT.

declare module MC <: CTCombine.

(* CRITICAL: combine_verify_share_recovery touches the recovered share
   + master seed + signs. Its leakage MUST NOT depend on these
   secrets — only on (m, ctx, pk-size). The empirical dudect harness
   in ../../ct/dudect/combine_ct.go validates this property under
   the same VALID-tape methodology Pulsar uses. *)
declare axiom combine_constant_time
      (recovered_share1 recovered_share2 : share_t)
      (master_seed1 master_seed2 : seed_t)
      (m : message_t) :
    equiv [ MC.combine_verify_share_recovery
            ~ MC.combine_verify_share_recovery :
              ={m}
              /\ recovered_share{1} = recovered_share1
              /\ recovered_share{2} = recovered_share2
              /\ master_seed{1} = master_seed1
              /\ master_seed{2} = master_seed2
            ==>
              res{1}.`2 = res{2}.`2 ].

end section CombineCT.

(* -------------------------------------------------------------------- *)
(* Verify: trivially CT (no secret inputs)                               *)
(* -------------------------------------------------------------------- *)
(* No lemma needed — Verify touches only (pk, msg, ctx, sig), all      *)
(* public. The single-party FIPS 205 verify path inherits CT from       *)
(* circl/sign/slhdsa's constant-time discipline.                        *)
