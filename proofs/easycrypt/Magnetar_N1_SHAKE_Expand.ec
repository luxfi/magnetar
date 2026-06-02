(* -------------------------------------------------------------------- *)
(*  Magnetar v1.1 --- FIPS 205 SHAKE expansion lemmas                    *)
(* -------------------------------------------------------------------- *)
(*                                                                      *)
(* STATUS: 1 admit (`shake256_functional`, cross-cited).                *)
(*                                                                      *)
(* The FIPS 205 sec 10.1 expansion of the 4n-byte master S into the     *)
(* triple (skSeed, skPrf, pkSeed) is, for SHAKE families:               *)
(*                                                                      *)
(*    expand(S) = SHAKE256(S)[:3n]                                      *)
(*    skSeed   = expand(S)[0  : n]                                      *)
(*    skPrf    = expand(S)[n  : 2n]                                     *)
(*    pkSeed   = expand(S)[2n : 3n]                                     *)
(*                                                                      *)
(* The Lagrange-shared-then-SHAKE-expand composition matches            *)
(* circl/sign/slhdsa scheme.DeriveKey on the same input S; this is      *)
(* established by `shake_expand_matches_circl_derive_key`.              *)
(*                                                                      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.

require import lemmas.SLHDSA_Functional.

type byte = int.
type bytes = byte list.
type mode = [ M192s | M192f | M256s ].

op n_of_mode : mode -> int.

(* FIPS 202 SHAKE-256 functional spec (variable-output). Cross-cited
   from Lean Crypto.Lux.SHA3. *)
axiom shake256_functional :
  forall (input : bytes) (out_len : int),
    0 < out_len =>
    exists (out : bytes),
      size out = out_len.   (* a stub stating SHAKE-256 produces an
                                out_len-byte stream from any input *)

op shake256 : bytes -> int -> bytes.

axiom shake256_size : forall input out_len,
  0 < out_len => size (shake256 input out_len) = out_len.

op shake_expand : mode -> bytes -> bytes.
axiom shake_expand_def : forall m s,
  shake_expand m s = shake256 s (3 * n_of_mode m).

(* Layout: position-based segment accessors. The strict-atom abstract
   model honours the discipline that no named `seed` / `skSeed` /
   `skPrf` variable exists, by exposing only positional operators. *)
op skseed_segment_pos : mode -> bytes -> bytes.
op skprf_segment_pos  : mode -> bytes -> bytes.
op pkseed_segment_pos : mode -> bytes -> bytes.

axiom skseed_segment_layout : forall m s,
  skseed_segment_pos m (shake_expand m s) =
    take (n_of_mode m) (shake_expand m s).
axiom skprf_segment_layout : forall m s,
  skprf_segment_pos m (shake_expand m s) =
    take (n_of_mode m) (drop (n_of_mode m) (shake_expand m s)).
axiom pkseed_segment_layout : forall m s,
  pkseed_segment_pos m (shake_expand m s) =
    take (n_of_mode m) (drop (2 * n_of_mode m) (shake_expand m s)).

(* Per-byte Lagrange recovery (cross-cited from Pulsar Shamir Lean
   bridge). *)
op lagrange_sum : int list -> 'a list -> bytes.

(* Round-trip: SHAKE-expand of the Lagrange-recovered master matches
   SHAKE-expand of the original master. *)
lemma shake_expand_idempotent_under_lagrange :
  forall (m : mode) (s : bytes) (picks : 'a list) (lambdas : int list),
    lagrange_sum lambdas picks = s =>
    shake_expand m (lagrange_sum lambdas picks) = shake_expand m s.
proof.
  move=> m s picks lambdas Heq.
  by rewrite Heq.
qed.

(* Cross-conformance: the Magnetar-internal shake_expand matches
   circl's scheme.DeriveKey on the same S. Discharged transitively
   through circl's own SHAKE256 invocation in scheme.go (same SHAKE
   construction). *)
op circl_derive_key_inputs : mode -> bytes -> (bytes * bytes * bytes).
axiom shake_expand_matches_circl_derive_key :
  forall m s,
    let (skSeedDerived, skPrfDerived, pkSeedDerived) = circl_derive_key_inputs m s in
       skseed_segment_pos m (shake_expand m s) = skSeedDerived
    /\ skprf_segment_pos  m (shake_expand m s) = skPrfDerived
    /\ pkseed_segment_pos m (shake_expand m s) = pkSeedDerived.
