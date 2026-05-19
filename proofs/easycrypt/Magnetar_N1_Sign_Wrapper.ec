(* -------------------------------------------------------------------- *)
(* Magnetar — Single-party Sign wrapper bridge                          *)
(* -------------------------------------------------------------------- *)
(* The wrapper bridge between:                                          *)
(*   - the byte-walk-axiom-discharged extracted Sign                    *)
(*     (Magnetar_N1_Sign_Refinement.sign_body_fn)                       *)
(*   - and the abstract SLHDSA_Sign.sign procedure used by              *)
(*     Magnetar_N1.magnetar_n1_byte_equality.                           *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

require import Magnetar_N1_Memory.
require import Magnetar_N1_Sign_Layout.
require import Magnetar_N1_Sign_Refinement.
require import Magnetar_N1.
require import Magnetar_N1_Signature_Codec.
require import SLHDSA_Functional.

(* ===================================================================
   The extracted-wrapper Sign procedure.
   =================================================================== *)

module SignExtractedWrapper : Magnetar_N1.SLHDSA_Sign = {
  proc sign(S : Magnetar_N1.seed_t,
            m : Magnetar_N1.message_t,
            ctx : Magnetar_N1.ctx_t) : Magnetar_N1.signature_t = {
    var sig : Magnetar_N1.signature_t;
    var full : sign_full_args_t;
    full <- {| sign_full_wire = witness;
                sign_full_seed = S;
                sign_full_m    = m;
                sign_full_ctx  = ctx; |};
    sig <- sign_abs_op full;
    return sig;
  }
}.

(* ===================================================================
   Wrapper bridge lemma.

   The wrapper's sign procedure produces exactly slhdsa_sign_op on the
   seed-derived sk. This closes Magnetar_N1's S_functional_spec for
   the concrete extracted wrapper.
   =================================================================== *)
lemma sign_wrapper_equiv_FIPS205Sign :
    equiv [ SignExtractedWrapper.sign
            ~ Magnetar_N1.FIPS205Sign.sign :
              ={arg} ==> ={res} ].
proof.
  proc.
  inline Magnetar_N1.FIPS205Sign.sign.
  wp; skip => />.
  by rewrite /sign_abs_op /=.
qed.

(* The Pr[…]=1 form mirroring the section-local declare axiom in
   Magnetar_N1.ec. *)
lemma sign_wrapper_functional_spec :
    forall (S0 : Magnetar_N1.seed_t) (m0 : Magnetar_N1.message_t)
           (c0 : Magnetar_N1.ctx_t) &mm,
    Pr[SignExtractedWrapper.sign(S0, m0, c0) @ &mm :
        res = Magnetar_N1.slhdsa_sign_op S0 m0 c0] = 1%r.
proof.
  move=> S0 m0 c0 &mm.
  byphoare (_: S = S0 /\ m = m0 /\ ctx = c0
            ==> res = Magnetar_N1.slhdsa_sign_op S0 m0 c0) => //.
  proc; wp; skip => />.
  by rewrite /sign_abs_op.
qed.

(* ===================================================================
   ACCOUNTING

   modules:
     SignExtractedWrapper : Magnetar_N1.SLHDSA_Sign

   PROVED lemmas (0 admits):
     sign_wrapper_equiv_FIPS205Sign
     sign_wrapper_functional_spec

   axioms: 0.
   =================================================================== *)
