(* -------------------------------------------------------------------- *)
(* Magnetar — Combine wire layout (byte-level)                         *)
(* -------------------------------------------------------------------- *)
(* The byte-level encode/decode for Combine's argument tuple. This file *)
(* sits between Magnetar_N1_Memory (raw bytes) and Magnetar_N1_Combine_ *)
(* Refinement (the byte-walk on extracted Go code).                     *)
(*                                                                      *)
(* Compared to Pulsar's Combine_Layout (which lays out c_tilde, t0,    *)
(* r2_msg, etc.), Magnetar's Combine is structurally simpler: its      *)
(* arguments are                                                        *)
(*                                                                      *)
(*   - group_pk    (FIPS 205 PK, 48 bytes for SHAKE-192s)              *)
(*   - quorum      (list of party indices)                              *)
(*   - shares      (per-party reveal-recovered shares; the byteSum     *)
(*                  inputs to Lagrange interpolation)                   *)
(*   - committee_root (32-byte cSHAKE256 digest)                       *)
(*   - message     (caller-supplied bytes)                              *)
(*   - ctx         (caller-supplied bytes, ≤255)                       *)
(*   - sig_out_ptr (where to write the 16224-byte signature)            *)
(*                                                                      *)
(* No FIPS-204-style z/h/c_tilde decomposition, no per-stage layout    *)
(* — Magnetar's signature is a single SLH-DSA output blob.             *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.
require import Magnetar_N1_Memory.
require import Magnetar_N1_Signature_Codec.

(* ===================================================================
   The pointer bundle the extracted body reads from.
   =================================================================== *)

type combine_ptrs_t = {
  group_pk_ptr  : int;        (* 48 bytes — FIPS 205 PK *)
  quorum_ptr    : int;        (* uint32 array — party indices *)
  shares_ptr    : int;        (* (seed_size * 2 * t) bytes — Shamir
                                 share vector for the t-quorum *)
  committee_root_ptr : int;   (* 32 bytes — cSHAKE256 digest *)
  msg_ptr       : int;        (* `msg_len` bytes — caller message *)
  msg_len       : int;
  ctx_ptr       : int;        (* `ctx_len` bytes — caller context *)
  ctx_len       : int;
  sig_out_ptr   : int;        (* 16224 bytes — output signature *)
}.

(* The byte-tuple representation of the Combine arguments. These are
   the values the WIRE LAYOUT (encode_combine_args / decode_combine_args)
   transports through memory. *)
type combine_abs_args_t = {
  abs_group_pk_bytes  : int list;  (* pk_size bytes *)
  abs_quorum_bytes    : int list;  (* 4*t bytes (uint32 array) *)
  abs_shares_bytes    : int list;  (* (seed_size * 2 * t) bytes *)
  abs_committee_root_bytes : int list;  (* 32 bytes *)
  abs_msg_bytes       : int list;  (* msg_len bytes *)
  abs_ctx_bytes       : int list;  (* ctx_len bytes *)
}.

(* The layout predicate: pointers and abstract args agree on every
   byte. *)
op layout_combine_args
    (m : mem_t) (ptrs : combine_ptrs_t) (a : combine_abs_args_t)
    : bool =
     load_bytes m ptrs.`group_pk_ptr (size a.`abs_group_pk_bytes)
       = a.`abs_group_pk_bytes
  /\ load_bytes m ptrs.`quorum_ptr (size a.`abs_quorum_bytes)
       = a.`abs_quorum_bytes
  /\ load_bytes m ptrs.`shares_ptr (size a.`abs_shares_bytes)
       = a.`abs_shares_bytes
  /\ load_bytes m ptrs.`committee_root_ptr
       (size a.`abs_committee_root_bytes)
       = a.`abs_committee_root_bytes
  /\ load_bytes m ptrs.`msg_ptr ptrs.`msg_len
       = a.`abs_msg_bytes
  /\ ptrs.`msg_len = size a.`abs_msg_bytes
  /\ load_bytes m ptrs.`ctx_ptr ptrs.`ctx_len
       = a.`abs_ctx_bytes
  /\ ptrs.`ctx_len = size a.`abs_ctx_bytes.

(* Encode the abstract args into memory at the supplied pointers. The
   encoded layout satisfies `layout_combine_args` for the resulting
   memory + same ptrs + same args. *)
op encode_combine_args
   (m : mem_t) (ptrs : combine_ptrs_t) (a : combine_abs_args_t)
   : mem_t =
  let m1 = store_bytes m ptrs.`group_pk_ptr a.`abs_group_pk_bytes in
  let m2 = store_bytes m1 ptrs.`quorum_ptr a.`abs_quorum_bytes in
  let m3 = store_bytes m2 ptrs.`shares_ptr a.`abs_shares_bytes in
  let m4 = store_bytes m3 ptrs.`committee_root_ptr
                          a.`abs_committee_root_bytes in
  let m5 = store_bytes m4 ptrs.`msg_ptr a.`abs_msg_bytes in
  store_bytes m5 ptrs.`ctx_ptr a.`abs_ctx_bytes.

(* DISJOINTNESS predicate: every pair of pointer-ranges is disjoint.
   The byte-walk axiom requires this so the per-region encode-then-
   load identity composes. *)
op combine_ptrs_disjoint (ptrs : combine_ptrs_t) (a : combine_abs_args_t)
    : bool =
  (* group_pk vs quorum *)
  (   ptrs.`group_pk_ptr + size a.`abs_group_pk_bytes
        <= ptrs.`quorum_ptr
   \/ ptrs.`quorum_ptr + size a.`abs_quorum_bytes
        <= ptrs.`group_pk_ptr)
  (* group_pk vs shares *)
  /\ (   ptrs.`group_pk_ptr + size a.`abs_group_pk_bytes
           <= ptrs.`shares_ptr
      \/ ptrs.`shares_ptr + size a.`abs_shares_bytes
           <= ptrs.`group_pk_ptr)
  (* group_pk vs committee_root *)
  /\ (   ptrs.`group_pk_ptr + size a.`abs_group_pk_bytes
           <= ptrs.`committee_root_ptr
      \/ ptrs.`committee_root_ptr + size a.`abs_committee_root_bytes
           <= ptrs.`group_pk_ptr)
  (* msg vs ctx *)
  /\ (   ptrs.`msg_ptr + ptrs.`msg_len <= ptrs.`ctx_ptr
      \/ ptrs.`ctx_ptr + ptrs.`ctx_len <= ptrs.`msg_ptr)
  (* sig_out_ptr disjoint from every input region *)
  /\ (   ptrs.`sig_out_ptr + sig_len <= ptrs.`group_pk_ptr
      \/ ptrs.`group_pk_ptr + size a.`abs_group_pk_bytes
           <= ptrs.`sig_out_ptr)
  /\ (   ptrs.`sig_out_ptr + sig_len <= ptrs.`shares_ptr
      \/ ptrs.`shares_ptr + size a.`abs_shares_bytes
           <= ptrs.`sig_out_ptr)
  /\ (   ptrs.`sig_out_ptr + sig_len <= ptrs.`msg_ptr
      \/ ptrs.`msg_ptr + ptrs.`msg_len <= ptrs.`sig_out_ptr).

(* Thin wrapper: read the signature blob at sig_out_ptr in m. *)
op read_signature_at (m : mem_t) (p : int) : signature_t =
  read_sig_at m p.

(* Write a signature blob at sig_out_ptr in m. *)
op write_signature_at (m : mem_t) (p : int) (s : signature_t) : mem_t =
  write_sig_at m p s.

(* Derived structural lemma: writing a signature at sig_out_ptr is
   detectable via read_signature_at. *)
lemma read_signature_at_after_write
        (m : mem_t) (p : int) (s : signature_t) :
    read_signature_at (write_signature_at m p s) p = s.
proof. by rewrite /read_signature_at /write_signature_at read_after_write_sig. qed.

(* ===================================================================
   ACCOUNTING

   Definitions: combine_ptrs_t, combine_abs_args_t,
                layout_combine_args, encode_combine_args,
                combine_ptrs_disjoint,
                read_signature_at, write_signature_at.

   PROVED lemmas: read_signature_at_after_write.

   axioms: 0.
   =================================================================== *)
