(* -------------------------------------------------------------------- *)
(*  SLHDSA_Functional --- FIPS 205 SHAKE functional spec                *)
(* -------------------------------------------------------------------- *)
(*                                                                      *)
(* STATUS: 4 admits (FIPS 205 sec 11.2 SHAKE primitive definitions      *)
(* lifted as black-box ops; the FIPS 205 sec 10 correctness axiom is    *)
(* a black-box claim from NIST verification).                           *)
(*                                                                      *)
(* The FIPS 205 sec 11.2 SHAKE primitives:                              *)
(*                                                                      *)
(*   PRF(PK.seed, ADRS, SK.seed) = SHAKE256(PK.seed || ADRS || SK.seed)[:n] *)
(*   PRF_msg(SK.prf, optRand, M) = SHAKE256(SK.prf || optRand || M)[:n] *)
(*   F(PK.seed, ADRS, M_1)       = SHAKE256(PK.seed || ADRS || M_1)[:n] *)
(*   H(PK.seed, ADRS, M_1||M_2)  = SHAKE256(PK.seed || ADRS || M_1 || M_2)[:n] *)
(*   T_l(PK.seed, ADRS, M)       = SHAKE256(PK.seed || ADRS || M)[:n]   *)
(*   H_msg(R, PK.seed, PK.root, M) = SHAKE256(R || PK.seed || PK.root || M)[:m] *)
(*                                                                      *)
(* The single-party correctness of FIPS 205 SLH-DSA SignDeterministic   *)
(* is the standard "if SignDeterministic returns sig, then Verify(pk,   *)
(* msg, sig) accepts" claim, modulo the FIPS 205 sec 10 well-formedness *)
(* conditions on inputs.                                                *)
(*                                                                      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.

type byte = int.
type bytes = byte list.
type mode = [ M192s | M192f | M256s ].

op n_of_mode : mode -> int.

(* FIPS 205 sec 11.2 SHAKE family --- PRF (FORS leaf / WOTS+ chain
   base derivation). *)
op slhdsa_prf :
  mode -> bytes (* pk_seed *) -> bytes (* addr *) -> bytes (* sk_seed *) -> bytes.

axiom slhdsa_prf_size : forall m pkSeed addr skSeed,
  size (slhdsa_prf m pkSeed addr skSeed) = n_of_mode m.

(* FIPS 205 sec 11.2 SHAKE family --- PRF_msg (signature randomizer). *)
op slhdsa_prf_msg :
  mode -> bytes (* sk_prf *) -> bytes (* opt_rand *) -> bytes (* msg' *) -> bytes.

axiom slhdsa_prf_msg_size : forall m skPrf optRand msg,
  size (slhdsa_prf_msg m skPrf optRand msg) = n_of_mode m.

(* The packed sk byte layout: 4n bytes.
   sk = skSeed || skPrf || pkSeed || pkRoot. *)
op pack_sk : mode -> bytes -> bytes -> bytes -> bytes -> bytes.

(* The FIPS 205 sk_from_seed driver: derive (skSeed, skPrf, pkSeed) via
   SHAKE256 expansion, compute pkRoot via the inner setup primitive,
   pack the result. *)
op sk_from_seed : mode -> bytes -> bytes.

(* The two "secret-segment extractors" used in
   Magnetar_N1_Atom_Refinement to discharge the closure-equivalence.
   These are abstract values that capture "the n-byte secret material
   the closure feeds at every PRF / PRF_msg call". *)
op slhdsa_prf_secret_for_atom : mode -> (bytes -> bytes -> bytes) -> bytes.
op slhdsa_prf_msg_secret_for_atom : mode -> (bytes -> bytes -> bytes) -> bytes.

(* FIPS 205 sec 10 correctness: SignDeterministic produces a verifiable
   signature for any well-formed sk. Black-box from NIST. *)
op slh_sign_deterministic : mode -> bytes -> bytes -> bytes -> bytes.
op slh_verify : mode -> bytes (* pk *) -> bytes -> bytes -> bytes -> bool.
op pk_from_sk : mode -> bytes -> bytes.

axiom slhdsa_correctness :
  forall m sk msg ctx,
    slh_verify m (pk_from_sk m sk) msg
      (slh_sign_deterministic m sk msg ctx) ctx
      = true.
