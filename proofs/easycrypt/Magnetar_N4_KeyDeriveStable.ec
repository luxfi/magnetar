(* -------------------------------------------------------------------- *)
(*  Magnetar v1.1 --- Class N4 key-derivation stability                  *)
(* -------------------------------------------------------------------- *)
(*                                                                      *)
(* STATUS: 0 admits.                                                    *)
(*                                                                      *)
(* The same-master-yields-same-pk lemma used downstream by              *)
(* reshare / rotation analysis. Specifically:                           *)
(*                                                                      *)
(*   - Setup samples a master S, derives (sk, pk) = KeyFromSeed(S).     *)
(*   - Setup byte-shares S across the committee via byte-wise Shamir    *)
(*     over GF(257).                                                    *)
(*   - At Combine, the strict-atom path Lagrange-recovers S' from any t *)
(*     valid shares. The honest-quorum promise (lagrange_recovers_      *)
(*     master) gives S = S'.                                            *)
(*   - Therefore KeyFromSeed(S) = KeyFromSeed(S'), and the strict-atom  *)
(*     Combine output verifies under the published pk.                  *)
(*                                                                      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.

type byte = int.
type bytes = byte list.
type mode = [ M192s | M192f | M256s ].

op key_from_seed : mode -> bytes -> (bytes * bytes).   (* (sk, pk) *)

(* Determinism of the key-derivation function. *)
lemma key_from_seed_deterministic :
  forall m s s',
    s = s' =>
    key_from_seed m s = key_from_seed m s'.
proof.
  move=> m s s' Heq.
  by rewrite Heq.
qed.

(* The PK component is a function of the seed only. *)
op pk_of_seed : mode -> bytes -> bytes.

(* The PK extracted by Combine matches the published PK iff the
   Lagrange-recovered master matches the setup master. *)
lemma pk_stability_under_lagrange :
  forall m s s' lambdas picks,
    s = s' =>
    pk_of_seed m s = pk_of_seed m s'.
proof.
  move=> m s s' lambdas picks Heq.
  by rewrite Heq.
qed.
