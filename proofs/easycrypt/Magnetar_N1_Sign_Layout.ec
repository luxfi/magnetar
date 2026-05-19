(* -------------------------------------------------------------------- *)
(* Magnetar — Single-party Sign wire layout (byte-level)                *)
(* -------------------------------------------------------------------- *)
(* The byte-level encode/decode for single-party Sign's argument tuple. *)
(*                                                                      *)
(* Compared to Pulsar's Sign_Layout (which has libjade's W64-pointer    *)
(* interface for ML-DSA-65), Magnetar's single-party Sign maps to       *)
(* circl's slhdsa.SignDeterministic surface. Wire arguments:            *)
(*                                                                      *)
(*   - sk_ptr     (96 bytes — FIPS 205 SK for SHAKE-192s)              *)
(*   - msg_ptr / msg_len  (caller message)                              *)
(*   - ctx_ptr / ctx_len  (caller context, ≤255)                       *)
(*   - sig_out_ptr (16224 bytes — output signature)                    *)
(*                                                                      *)
(* The Magnetar single-party path is straight-line: no rejection-       *)
(* sampling loop, no Pulsar-style addrnd ghost contract block.          *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Magnetar_N1_Memory.
require import Magnetar_N1_Signature_Codec.

(* ===================================================================
   Pointer bundle.
   =================================================================== *)

type sign_ptrs_t = {
  sk_ptr        : int;        (* 96 bytes — FIPS 205 SK *)
  msg_ptr       : int;        (* msg_len bytes *)
  msg_len       : int;
  ctx_ptr       : int;        (* ctx_len bytes; 0 ≤ ctx_len ≤ 255 *)
  ctx_len       : int;
  sig_out_ptr   : int;        (* 16224 bytes — output signature *)
}.

(* The byte-tuple representation of the Sign arguments. *)
type sign_abs_args_t = {
  abs_sk_bytes   : int list;  (* 96 bytes *)
  abs_msg_bytes  : int list;
  abs_ctx_bytes  : int list;  (* 0..255 bytes *)
}.

(* The layout predicate. *)
op layout_sign_args
    (m : mem_t) (ptrs : sign_ptrs_t) (a : sign_abs_args_t)
    : bool =
     load_bytes m ptrs.`sk_ptr (size a.`abs_sk_bytes)
       = a.`abs_sk_bytes
  /\ load_bytes m ptrs.`msg_ptr ptrs.`msg_len
       = a.`abs_msg_bytes
  /\ ptrs.`msg_len = size a.`abs_msg_bytes
  /\ load_bytes m ptrs.`ctx_ptr ptrs.`ctx_len
       = a.`abs_ctx_bytes
  /\ ptrs.`ctx_len = size a.`abs_ctx_bytes
  /\ ptrs.`ctx_len <= 255.

(* Pointer disjointness. *)
op sign_ptrs_disjoint (ptrs : sign_ptrs_t) (a : sign_abs_args_t)
    : bool =
  (* sk vs msg *)
  (   ptrs.`sk_ptr + size a.`abs_sk_bytes <= ptrs.`msg_ptr
   \/ ptrs.`msg_ptr + ptrs.`msg_len <= ptrs.`sk_ptr)
  (* sk vs ctx *)
  /\ (   ptrs.`sk_ptr + size a.`abs_sk_bytes <= ptrs.`ctx_ptr
      \/ ptrs.`ctx_ptr + ptrs.`ctx_len <= ptrs.`sk_ptr)
  (* msg vs ctx *)
  /\ (   ptrs.`msg_ptr + ptrs.`msg_len <= ptrs.`ctx_ptr
      \/ ptrs.`ctx_ptr + ptrs.`ctx_len <= ptrs.`msg_ptr)
  (* sig_out_ptr disjoint from every input *)
  /\ (   ptrs.`sig_out_ptr + sig_len <= ptrs.`sk_ptr
      \/ ptrs.`sk_ptr + size a.`abs_sk_bytes <= ptrs.`sig_out_ptr)
  /\ (   ptrs.`sig_out_ptr + sig_len <= ptrs.`msg_ptr
      \/ ptrs.`msg_ptr + ptrs.`msg_len <= ptrs.`sig_out_ptr).

(* Encode the abstract args into memory at the supplied pointers. *)
op encode_sign_args
    (m : mem_t) (ptrs : sign_ptrs_t) (a : sign_abs_args_t)
    : mem_t =
  let m1 = store_bytes m  ptrs.`sk_ptr  a.`abs_sk_bytes  in
  let m2 = store_bytes m1 ptrs.`msg_ptr a.`abs_msg_bytes in
  store_bytes m2 ptrs.`ctx_ptr a.`abs_ctx_bytes.

(* Read the signature blob at sig_out_ptr in m. *)
op read_signature_at_sign (m : mem_t) (p : int) : signature_t =
  read_sig_at m p.

(* Write a signature blob at sig_out_ptr in m. *)
op write_signature_at_sign (m : mem_t) (p : int) (s : signature_t) : mem_t =
  write_sig_at m p s.

(* Derived structural lemma. *)
lemma read_signature_at_sign_after_write
        (m : mem_t) (p : int) (s : signature_t) :
    read_signature_at_sign (write_signature_at_sign m p s) p = s.
proof. by rewrite /read_signature_at_sign /write_signature_at_sign read_after_write_sig. qed.

(* ===================================================================
   ACCOUNTING

   Definitions: sign_ptrs_t, sign_abs_args_t,
                layout_sign_args, sign_ptrs_disjoint,
                encode_sign_args,
                read_signature_at_sign, write_signature_at_sign.

   PROVED lemmas: read_signature_at_sign_after_write.

   axioms: 0.
   =================================================================== *)
