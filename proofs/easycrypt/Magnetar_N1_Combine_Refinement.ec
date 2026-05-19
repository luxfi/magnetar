(* -------------------------------------------------------------------- *)
(* Magnetar — Class N1-analog Combine refinement (extracted ↔ abstract) *)
(* -------------------------------------------------------------------- *)
(* This file is the discharge path for Magnetar_N1.ec's section-local   *)
(* refinement axiom                                                     *)
(*                                                                      *)
(*    declare axiom combine_body_axiom :                                *)
(*      equiv [ T.combine ~ CombineAbs.combine :                        *)
(*                ={arg} ==> ={res} ].                                  *)
(*                                                                      *)
(* Structural simplification vs Pulsar Combine_Refinement.ec            *)
(* -------------------------------------------------------                *)
(* Pulsar's Combine_Refinement decomposes the byte-walk along the       *)
(* FIPS 204 §3.5.5 packing boundary into c_tilde / z / h stages, each   *)
(* further decomposed into sub-axioms (mu input, w polynomial, etc.).   *)
(* Pulsar v8 has roughly:                                               *)
(*                                                                      *)
(*   - 3 stage-level byte-walks (combine_body_{h,z,c_tilde}_spec        *)
(*     after derivation cascade)                                        *)
(*   - 2 narrow combine z-stage axioms (aggregation shape + per-party PR)
       - 2 c_tilde dependency sub-axioms (w)
       - 2 codec layout axioms (mu_input prefix + ctx + m sub-axioms)   *)
(*                                                                      *)
(* Magnetar's Combine is structurally simpler: there is no FIPS-204     *)
(* §3.5.5 decomposition because SLH-DSA SignDeterministic emits a      *)
(* monolithic signature blob (not a (c_tilde, z, h) triple). The       *)
(* signature is the verbatim output of                                  *)
(*    slhdsa.SignDeterministic(slhdsa.KeyFromSeed(S), msg, ctx)         *)
(* on the reconstructed seed S. So the byte-walk has exactly ONE       *)
(* atomic axiom:                                                        *)
(*                                                                      *)
(*    combine_body_compute_sig_spec :                                   *)
(*       layout-conforming inputs map under the extracted body to       *)
(*       bytes that decode to slhdsa_sign_op (recover_seed Q shares cr) *)
(*                                  m ctx                              *)
(*                                                                      *)
(* Closing this axiom is a byte-walk through                            *)
(*   ref/go/pkg/magnetar/combine.go lines 47-206                        *)
(* which is dominated by:                                               *)
(*                                                                      *)
(*   - The Lagrange reconstruct (`shamirReconstructGF`) — algebraic,    *)
(*     reduces to `lagrange_inverse_eval` (Lean-bridged Shamir).        *)
(*   - The cSHAKE256 mix (`cshake256(mixInput, …, tagSeedShare)`) —    *)
(*     STRUCTURAL definition of `mix_to_seed` matches.                  *)
(*   - The `KeyFromSeed` dispatch — the FIPS 205 §10.1 §10.2 Algorithm  *)
(*     21/22 entry point.                                               *)
(*   - The `slhdsa.SignDeterministic` dispatch — FIPS 205 §10.2         *)
(*     Algorithm 22.                                                    *)
(*                                                                      *)
(* The byte-walk is structurally a one-step composition of these four,  *)
(* in contrast to Pulsar's k-stage decomposition through the ML-DSA     *)
(* rejection-sampling loop.                                             *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv Distr DBool DInterval SmtMap.

(* Concrete byte-level layout. *)
require import Magnetar_N1_Combine_Layout.

(* Magnetar_N1 provides the protocol-level abstract types share_t,
   message_t, ctx_t, randomness_t, group_pk_t, round1_t, round2_t,
   signature_t, plus slhdsa_sign_op, reconstruct, recover_seed, etc. *)
require import Magnetar_N1.

(* ===================================================================
   L2 — Protocol-extended args.

   `combine_full_args_t` carries THREE distinct categories of field:

     [WIRE]    full_wire     : laid out in memory by encode_combine_args
                                (group_pk, quorum, shares, committee_root,
                                 msg, ctx). Concrete bytes read by the
                                byte-walk axiom through layout_combine_args.

     [DERIVED] full_gpk,     : protocol-level fields with a CHECKED
                                BINDING. The group pubkey must equal
                                derive_pk(recover_seed quorum shares cr)
                                — enforced by protocol_consistency
                                below; threaded into the byte-walk
                                axiom precondition.
               full_quorum,
               full_shares,
               full_committee_root,

     [GHOST]   full_m,       : protocol-level fields with no direct
               full_ctx       wire counterpart at this layer; the
                              Wrapper's derive_* ops fold them into
                              the wire fields.
   =================================================================== *)

type combine_full_args_t = {
  (* [WIRE] *)
  full_wire    : Magnetar_N1_Combine_Layout.combine_abs_args_t;
  (* [DERIVED] *)
  full_gpk             : Magnetar_N1.group_pk_t;
  full_quorum          : int list;
  full_shares          : Magnetar_N1.share_t list;
  full_committee_root  : Magnetar_N1.committee_root_t;
  (* [GHOST] *)
  full_m    : Magnetar_N1.message_t;
  full_ctx  : Magnetar_N1.ctx_t;
}.

op wire_args_of_full (full : combine_full_args_t)
   : Magnetar_N1_Combine_Layout.combine_abs_args_t =
  full.`full_wire.

(* Protocol consistency predicate.

   `combine_full_args_t` carries `full_gpk` as a DERIVED field that
   `combine_abs_op` doesn't consume — combine_abs_op uses
   `recover_seed quorum shares committee_root` and discards full_gpk
   entirely. An adversarial caller could therefore construct a
   `combine_full_args_t` with a `full_gpk` UNRELATED to recover_seed,
   and the byte-walk axiom would still claim the extracted output
   equals slhdsa_sign_op on the wrong key — yielding a "valid
   threshold signature" under any chosen group public key.

   `protocol_consistency` rules out the inconsistent constructions by
   requiring the ghost group pubkey to be the actual derived pubkey of
   the reconstructed seed. *)
op protocol_consistency (full : combine_full_args_t) : bool =
  full.`full_gpk =
  Magnetar_N1.derive_pk
    (Magnetar_N1.recover_seed full.`full_quorum
                                full.`full_shares
                                full.`full_committee_root).

(* Threshold protocol invariants — preconditions of the Lean Lagrange
   theorem applied to combine_full_args_t. Bundles four conjuncts:

     - uniq full_quorum             — distinct party indices
     - size full_shares
         = size full_quorum         — shape match
     - poly_degree (reconstruct ...) < size full_quorum
                                    — sharing polynomial degree bound
     - full_shares = map (poly_eval (reconstruct ...)) full_quorum
                                    — honest sharing (each share is the
                                      polynomial evaluation at the
                                      party's index)

   Mirrors Magnetar_N1's `magnetar_n1_byte_equality` preconditions. *)
op threshold_protocol_invariants (full : combine_full_args_t) : bool =
  let s_recon =
    Magnetar_N1.reconstruct full.`full_quorum full.`full_shares in
  uniq full.`full_quorum
  /\ size full.`full_shares = size full.`full_quorum
  /\ Magnetar_N1.poly_degree s_recon < size full.`full_quorum
  /\ full.`full_shares
     = List.map (Magnetar_N1.poly_eval s_recon) full.`full_quorum.

(* ===================================================================
   L2 — Functional spec operator (DEFINITION, not axiom).

   `combine_abs_op` is the abstract-side spec of the combine entry
   point: it returns the centralised FIPS 205 SLH-DSA signature on the
   reconstructed master seed. Since `slhdsa_sign_op` is the FIPS 205
   functional operator, this DEFINITION captures the Magnetar
   Class-N1-analog correctness identity at the operator level. The
   byte-walk axiom below (`combine_body_compute_sig_spec`) discharges
   this identity at the byte level for the extracted combine.
   =================================================================== *)

op combine_abs_op (full : combine_full_args_t) : Magnetar_N1.signature_t =
  Magnetar_N1.slhdsa_sign_op
    (Magnetar_N1.recover_seed full.`full_quorum
                                full.`full_shares
                                full.`full_committee_root)
    full.`full_m full.`full_ctx.

(* ===================================================================
   L3 — Status word from the extracted body.

   Magnetar's Combine returns (signature, error). On error,
   sig_out_ptr is left undefined. The byte-walk axiom is conditioned
   on `status = 0` so the rejection branch makes no claim about the
   signature buffer content.
   =================================================================== *)

op combine_body_compute_status :
  Magnetar_N1_Memory.mem_t ->
  Magnetar_N1_Combine_Layout.combine_ptrs_t ->
  int.

(* ===================================================================
   L3 — Refinement-fn projecting the extracted body's output signature.

   Mirrors Pulsar's `combine_body_compute_sig` but defined directly as
   an abstract op (no per-stage decomposition because SLH-DSA is
   straight-line). The byte-walk axiom below claims it equals
   combine_abs_op on layout-consistent + threshold-consistent inputs.
   =================================================================== *)

op combine_body_compute_sig :
  Magnetar_N1_Memory.mem_t ->
  Magnetar_N1_Combine_Layout.combine_ptrs_t ->
  Magnetar_N1_Signature_Codec.signature_t.

(* combine_body_fn writes the computed signature at sig_out_ptr and
   leaves all other memory untouched. *)
op combine_body_fn
   (mem_pre : Magnetar_N1_Memory.mem_t)
   (ptrs : Magnetar_N1_Combine_Layout.combine_ptrs_t)
   : Magnetar_N1_Memory.mem_t =
  Magnetar_N1_Combine_Layout.write_signature_at
    mem_pre
    ptrs.`Magnetar_N1_Combine_Layout.sig_out_ptr
    (combine_body_compute_sig mem_pre ptrs).

(* ===================================================================
   L3 — THE atomic byte-walk axiom.

   `combine_body_compute_sig_spec` says: given inputs whose wire-level
   layout matches the abstract args, and given the threshold protocol
   invariants + protocol consistency hold, and given the extracted
   body returns status = 0 (no error), the extracted
   `combine_body_compute_sig` returns a `signature_t` equal to
   `combine_abs_op full` — i.e., the centralised FIPS 205 SLH-DSA
   signature on the reconstructed master seed.

   This is the ONLY byte-walk axiom in this file. Closing it is the
   byte-walk through `ref/go/pkg/magnetar/combine.go` lines 47-206:

     - Round-2 commit-bind loop (lines 82-117): mask + masked share
       parsing + cSHAKE256 re-derive + constant-time digest equality.
       Algebraic content: the recovered share equals the original
       (committed) share by XOR linearity.

     - Lagrange reconstruct + mix (lines 130-158): per-byte Lagrange
       over GF(257) recovers master_byteSum, mixed with committee_root
       via cSHAKE256 to produce master_seed. Algebraic content:
       `recover_seed quorum shares committee_root` by definition.

     - KeyFromSeed + SignDeterministic (lines 163, 187):
       `slhdsa.Scheme(...).DeriveKey(masterSeed)` then
       `slhdsa.SignDeterministic(sk, msg, ctx)`. Algebraic content:
       `slhdsa_sign_op masterSeed msg ctx` by definition.

     - sk.Pub.Equal(groupPubkey) check (line 174): captured by
       protocol_consistency + derive_pk_is_slhdsa_pk_from_seed
       precondition.

   The byte-walk shows that the loop invariants plus the final
   slhdsa.SignDeterministic call produce exactly `combine_abs_op full`.
   =================================================================== *)
axiom combine_body_compute_sig_spec :
  forall (mem_pre : Magnetar_N1_Memory.mem_t)
         (ptrs : Magnetar_N1_Combine_Layout.combine_ptrs_t)
         (full : combine_full_args_t),
    Magnetar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    Magnetar_N1_Combine_Layout.combine_ptrs_disjoint
      ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    threshold_protocol_invariants full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    refine_sig_to_n1
      (combine_body_compute_sig mem_pre ptrs)
    = combine_abs_op full.

(* The signature-type coercion is IDENTITY (Pulsar pattern v11+):
   Magnetar_N1.signature_t IS Magnetar_N1_Signature_Codec.signature_t,
   aliased at the type level. Every downstream proof that uses
   refine_sig_to_n1 as a coercion now witnesses an honest identity. *)
op refine_sig_to_n1
   (s : Magnetar_N1_Signature_Codec.signature_t)
   : Magnetar_N1.signature_t = s.

(* ===================================================================
   Derived lemmas — wire layout + signature read identities.
   =================================================================== *)

(* Reading the signature at sig_out_ptr in the post-combine memory
   returns the computed signature. *)
lemma read_signature_at_post_combine
        (mem_pre : Magnetar_N1_Memory.mem_t)
        (ptrs : Magnetar_N1_Combine_Layout.combine_ptrs_t) :
    Magnetar_N1_Combine_Layout.read_signature_at
      (combine_body_fn mem_pre ptrs)
      ptrs.`Magnetar_N1_Combine_Layout.sig_out_ptr
    = combine_body_compute_sig mem_pre ptrs.
proof.
  rewrite /combine_body_fn.
  by rewrite Magnetar_N1_Combine_Layout.read_signature_at_after_write.
qed.

(* Composed: the extracted body's output, read back, equals
   combine_abs_op. *)
lemma combine_body_output_eq_abs_op
        (mem_pre : Magnetar_N1_Memory.mem_t)
        (ptrs : Magnetar_N1_Combine_Layout.combine_ptrs_t)
        (full : combine_full_args_t) :
    Magnetar_N1_Combine_Layout.layout_combine_args
      mem_pre ptrs (wire_args_of_full full) =>
    Magnetar_N1_Combine_Layout.combine_ptrs_disjoint
      ptrs (wire_args_of_full full) =>
    protocol_consistency full =>
    threshold_protocol_invariants full =>
    combine_body_compute_status mem_pre ptrs = 0 =>
    refine_sig_to_n1
      (Magnetar_N1_Combine_Layout.read_signature_at
         (combine_body_fn mem_pre ptrs)
         ptrs.`Magnetar_N1_Combine_Layout.sig_out_ptr)
    = combine_abs_op full.
proof.
  move=> Hlay Hdisj Hcons Hthresh Hstatus.
  rewrite read_signature_at_post_combine.
  by apply combine_body_compute_sig_spec.
qed.

(* The byte-level write at sig_out_ptr does not affect bytes outside
   the signature range. *)
lemma combine_body_separation
        (mem_pre : Magnetar_N1_Memory.mem_t)
        (ptrs : Magnetar_N1_Combine_Layout.combine_ptrs_t)
        (q : int) :
    q < ptrs.`Magnetar_N1_Combine_Layout.sig_out_ptr
    \/ ptrs.`Magnetar_N1_Combine_Layout.sig_out_ptr
       + Magnetar_N1_Signature_Codec.sig_len <= q =>
    Magnetar_N1_Memory.load_byte (combine_body_fn mem_pre ptrs) q
    = Magnetar_N1_Memory.load_byte mem_pre q.
proof.
  move=> Hdisj.
  rewrite /combine_body_fn /Magnetar_N1_Combine_Layout.write_signature_at.
  by apply Magnetar_N1_Signature_Codec.write_sig_separation.
qed.

(* ===================================================================
   ACCOUNTING

   ops (definitions; no proof obligation):
     combine_full_args_t, wire_args_of_full,
     protocol_consistency, threshold_protocol_invariants,
     combine_abs_op,
     combine_body_compute_status, combine_body_compute_sig,
     combine_body_fn,
     refine_sig_to_n1.

   axioms (1 — the atomic byte-walk; Jasmin / Go extraction trust
   boundary):
     combine_body_compute_sig_spec

   PROVED lemmas (0 admits):
     read_signature_at_post_combine
     combine_body_output_eq_abs_op
     combine_body_separation

   Closure plan for combine_body_compute_sig_spec:
     - reduce to the 4 sub-claims listed in the axiom's documentation
       comment;
     - sub-claim 1 (Round-2 commit-bind) reduces to the Lagrange
       layer's algebraic content (the recovered share is the original
       share — by XOR linearity);
     - sub-claim 2 (Lagrange + cSHAKE256 mix) reduces to
       `lagrange_inverse_eval` (Lean-bridged) +
       `mix_to_seed_injective_byteSum` (cSHAKE256 first-arg
       injectivity);
     - sub-claim 3 (KeyFromSeed) is a pure dispatch identity on
       slhdsa_pk_from_seed / slhdsa_sk_from_seed;
     - sub-claim 4 (SignDeterministic) reduces to slhdsa_sign_axiom
       (the FIPS 205 functional spec).
   =================================================================== *)
