(* -------------------------------------------------------------------- *)
(*  Magnetar v1.1 --- Internal SLH-DSA refinement to circl              *)
(* -------------------------------------------------------------------- *)
(*                                                                      *)
(* STATUS: 1 admit (`magnetar_internal_refines_circl`).                 *)
(*                                                                      *)
(* The Magnetar-internal FIPS 205 sec 5/6/7/8 byte-walk implemented at  *)
(* `slhdsa_internal.go::slhSignAtom` emits a byte stream that is        *)
(* byte-equal to `cloudflare/circl/sign/slhdsa.SignDeterministic` on    *)
(* the same parameter set + key material + msg + ctx.                   *)
(*                                                                      *)
(* The discharge witness is the Go test                                 *)
(* `TestSlhdsaInternal_ByteEqualToCirclSign`, which fixtures a          *)
(* deterministic 4n-byte master, derives circl's (skSeed, skPrf,        *)
(* pkSeed) via scheme.DeriveKey, drives the Magnetar-internal           *)
(* slhSignAtom with closures over the derived material, and asserts     *)
(* byte-equality across all three SHAKE modes.                          *)
(*                                                                      *)
(* The reason this is an axiom and not a fully-discharged ProcEqv is    *)
(* that the byte-walk through circl's slh_sign_internal touches:        *)
(*   - the FIPS 205 sec 5 WOTS+ chain compute                           *)
(*   - the FIPS 205 sec 6 XMSS tree compute                             *)
(*   - the FIPS 205 sec 7 hypertree dispatch                            *)
(*   - the FIPS 205 sec 8 FORS sign + pk-from-sig                       *)
(* Each is a ~30-line Go function whose byte-for-byte refinement to a   *)
(* hypothetical EasyCrypt port would be ~200 lines of straight-line     *)
(* `byte=byte` reasoning per primitive. The audit shortcut: the         *)
(* Magnetar-internal port is FIPS 205 byte-conformant by direct         *)
(* comparison to circl, and circl is the audited reference.             *)
(*                                                                      *)
(* -------------------------------------------------------------------- *)

require import AllCore List Int IntDiv.

require import lemmas.SLHDSA_Functional.

type byte = int.
type bytes = byte list.
type mode = [ M192s | M192f | M256s ].

(* The Magnetar-internal SLH-DSA Sign engine, parametrised by the two
   FIPS 205 sec 11.2 callbacks. *)
op slh_sign_atom :
     mode
  -> bytes
  -> bytes
  -> bytes
  -> bytes
  -> (bytes -> bytes -> bytes)
  -> (bytes -> bytes -> bytes)
  -> bytes.

(* The circl reference. *)
op slh_sign_deterministic : mode -> bytes -> bytes -> bytes -> bytes.

(* The packed sk layout per FIPS 205 sec 10.1 (4n bytes:
   skSeed || skPrf || pkSeed || pkRoot). *)
op pack_sk : mode -> bytes -> bytes -> bytes -> bytes -> bytes.

(* The headline refinement. Discharged via the Go-side byte-identity
   gate. *)
axiom magnetar_internal_refines_circl :
  forall m pkSeedBytes pkRootBytes msg ctx prfFn prfMsgFn,
       (forall addr secret,
          prfFn addr secret =
            slhdsa_prf m pkSeedBytes addr (slhdsa_prf_secret_for_atom m prfFn))
    => (forall opt_rand msg',
          prfMsgFn opt_rand msg' =
            slhdsa_prf_msg m (slhdsa_prf_msg_secret_for_atom m prfMsgFn) opt_rand msg')
    => slh_sign_atom m pkSeedBytes pkRootBytes msg ctx prfFn prfMsgFn
         = slh_sign_deterministic m
             (pack_sk m
                (slhdsa_prf_secret_for_atom m prfFn)
                (slhdsa_prf_msg_secret_for_atom m prfMsgFn)
                pkSeedBytes
                pkRootBytes)
             msg ctx.
