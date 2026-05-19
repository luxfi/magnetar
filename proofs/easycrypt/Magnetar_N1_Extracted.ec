(* -------------------------------------------------------------------- *)
(* Magnetar — Class N1-analog extracted byte-equality corollary         *)
(* -------------------------------------------------------------------- *)
(* The concrete extracted Class N1-analog byte-equality theorem.       *)
(* Composes the combine-side and sign-side wrapper modules and         *)
(* instantiates the generic `Magnetar_N1.magnetar_n1_byte_equality`    *)
(* theorem with the equivalence hypotheses from each side's            *)
(* wrapper-bridge lemma.                                                *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

require import Magnetar_N1_Combine_Wrapper.
require import Magnetar_N1_Sign_Wrapper.
require import Magnetar_N1.

(* ===================================================================
   The concrete extracted Class N1-analog byte-equality corollary.

   Trust boundary of this corollary (v0.4.0):
     - 1 atomic byte-walk axiom in the combine-refinement file:
         combine_body_compute_sig_spec
       (closing this is the byte-walk through combine.go lines 47-206)
     - 1 atomic byte-walk axiom in the sign-refinement file:
         sign_body_compute_sig_spec
       (closing this is "trust circl/sign/slhdsa.SignDeterministic"
        = "trust the FIPS 205 NIST analysis as inherited by Cloudflare
        CIRCL")
     - 1 codec roundtrip axiom in the signature codec:
         encode_signature_wf
       (slots into the FIPS 205 §10.2 sig-length-invariant category)
     - 3 protocol-level axioms in Magnetar_N1:
         lagrange_inverse_eval         (Lean-bridged, shared with Pulsar)
         mix_to_seed_injective_byteSum (cSHAKE256 first-arg injectivity)
         derive_pk_is_slhdsa_pk_from_seed (definition pin)
     - 1 NIST-anchored axiom in SLHDSA_Functional:
         slhdsa_correctness            (FIPS 205 §10 single-party correctness)
     - 0 module-contract axioms in scope here
       (combine_body_axiom + S_functional_spec are
        section-local inside Magnetar_N1; this corollary
        does NOT depend on them, using the wrapper-bridge equivs which
        are real lemmas).
     - 5 Lean-bridged algebraic axioms (Lagrange/Shamir; CROSS-CITED
       from Pulsar's `proofs/lean-easycrypt-bridge.md` since
       Magnetar's byte-wise Shamir over GF(257) is algebraically
       identical to Pulsar's).

   Headline trust footprint (v0.4.0):
     2 byte-walks (combine + sign — both monolithic, no kappa loop)
     + 4 algebra/codec axioms (Shamir + mix + derive_pk + sig length)
     + 1 NIST-anchored FIPS 205 axiom (correctness)
     + Lean-bridged Shamir/Lagrange (cross-cited)

   Compare to Pulsar v8 cascade: 3 stage-level + 2 narrow z-stage + 2
   c_tilde-w sub + 2 mu codec + 5 Lean = 14 residual axioms.

   Magnetar's smaller axiom budget is the structural simplification
   SLH-DSA SignDeterministic (straight-line) buys over ML-DSA Sign
   (rejection-sampling kappa loop).
   =================================================================== *)

lemma magnetar_n1_byte_equality_extracted :
  equiv [
    Magnetar_N1.ThresholdRun(CombineExtractedWrapper).run
    ~ Magnetar_N1.SinglePartyRun(SignExtractedWrapper).run :
        ={group_pk, shares, quorum, committee_root, m, ctx}
      /\ uniq quorum{1}
      /\ size shares{1} = size quorum{1}
      /\ group_pk{1} = Magnetar_N1.derive_pk
                        (Magnetar_N1.recover_seed
                           quorum{1} shares{1} committee_root{1})
      /\ Magnetar_N1.poly_degree
           (Magnetar_N1.reconstruct quorum{1} shares{1}) < size quorum{1}
      /\ shares{1} = List.map
           (Magnetar_N1.poly_eval
              (Magnetar_N1.reconstruct quorum{1} shares{1}))
           quorum{1}
    ==> ={res}
  ].
proof.
  (* Instantiate the generic byte-equality theorem with the two
     wrapper modules and their bridge lemmas. The wrapper bridges
     provide the combine_body_axiom + S_functional_spec instances at
     the wrapper level. *)
  proc.
  inline Magnetar_N1.ThresholdRun(CombineExtractedWrapper).run
         Magnetar_N1.SinglePartyRun(SignExtractedWrapper).run.
  (* Transitivity through CombineAbs: T.combine ~ CombineAbs.combine
     (the wrapper bridge) and CombineAbs.combine dispatches to
     FIPS205Sign.sign on recover_seed. *)
  transitivity{1}
    { sig <@ Magnetar_N1.CombineAbs.combine
              (group_pk, m, ctx, quorum, shares,
                committee_root, witness, witness); }
    ( ={group_pk, shares, quorum, committee_root, m, ctx}
      /\ uniq quorum{1}
      /\ size shares{1} = size quorum{1}
      /\ group_pk{1} = Magnetar_N1.derive_pk
                        (Magnetar_N1.recover_seed
                           quorum{1} shares{1} committee_root{1})
      /\ Magnetar_N1.poly_degree
           (Magnetar_N1.reconstruct quorum{1} shares{1}) < size quorum{1}
      /\ shares{1} = List.map
           (Magnetar_N1.poly_eval
              (Magnetar_N1.reconstruct quorum{1} shares{1}))
           quorum{1}
      ==> ={sig} )
    ( ={group_pk, shares, quorum, committee_root, m, ctx}
      ==> ={sig} ).
  - move=> &m1 &m2 [#] *.
    by exists (group_pk{m1}, shares{m1}, quorum{m1},
                committee_root{m1}, m{m1}, ctx{m1}) => /#.
  - by trivial.
  - call combine_wrapper_equiv_CombineAbs; skip; smt().
  (* CombineAbs ~ SinglePartyRun(SignExtractedWrapper).run on the
     RHS. Both reduce to slhdsa_sign_op on recover_seed. *)
  inline Magnetar_N1.CombineAbs.combine
         Magnetar_N1.FIPS205Sign.sign
         SignExtractedWrapper.sign.
  wp; skip => />.
  by rewrite /sign_abs_op /=.
qed.

(* ===================================================================
   ACCOUNTING

   axioms (0):
     (none — this file is pure composition of wrapper-bridge lemmas)

   PROVED lemmas (0 admits):
     magnetar_n1_byte_equality_extracted (headline)

   The 2 byte-walk obligations are owned by the refinement files.
   The protocol/algebra axioms are owned by Magnetar_N1.ec; the FIPS
   205 correctness axiom is owned by SLHDSA_Functional.ec.

   See proofs/lean-easycrypt-bridge.md for the algebraic-bridge
   correspondence and the cross-citation of Pulsar's Shamir bridges.
   =================================================================== *)
