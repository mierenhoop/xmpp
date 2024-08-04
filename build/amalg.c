#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ed25519/fe_0.c"
#include "ed25519/fe_1.c"
#include "ed25519/fe_add.c"
#include "ed25519/fe_cmov.c"
#include "ed25519/fe_copy.c"
#include "ed25519/fe_frombytes.c"
#include "ed25519/fe_invert.c"
#include "ed25519/fe_isnegative.c"
#include "ed25519/fe_isnonzero.c"
#include "ed25519/fe_mul.c"
#include "ed25519/fe_neg.c"
#include "ed25519/fe_pow22523.c"
#include "ed25519/fe_sq2.c"
#include "ed25519/fe_sq.c"
#include "ed25519/fe_sub.c"
#include "ed25519/fe_tobytes.c"
#include "ed25519/ge_add.c"
#include "ed25519/ge_double_scalarmult.c"
#include "ed25519/ge_frombytes.c"
#include "ed25519/ge_madd.c"
#include "ed25519/ge_msub.c"
#include "ed25519/ge_p1p1_to_p2.c"
#include "ed25519/ge_p1p1_to_p3.c"
#include "ed25519/ge_p2_0.c"
#include "ed25519/ge_p2_dbl.c"
#include "ed25519/ge_p3_0.c"
#include "ed25519/ge_p3_dbl.c"
#include "ed25519/ge_p3_tobytes.c"
#include "ed25519/ge_p3_to_cached.c"
#include "ed25519/ge_p3_to_p2.c"
#include "ed25519/ge_precomp_0.c"
#include "ed25519/ge_scalarmult_base.c"
#include "ed25519/ge_sub.c"
#include "ed25519/ge_tobytes.c"
#include "ed25519/open.c"
#include "ed25519/sc_muladd.c"
#include "ed25519/sc_reduce.c"
#include "ed25519/sign.c"

#include "ed25519/additions/compare.c"
#include "ed25519/additions/curve_sigs.c"
#include "ed25519/additions/ed_sigs.c"
#include "ed25519/additions/elligator.c"
#include "ed25519/additions/fe_edy_to_montx.c"
#include "ed25519/additions/fe_isequal.c"
#include "ed25519/additions/fe_isreduced.c"
#include "ed25519/additions/fe_mont_rhs.c"
#include "ed25519/additions/fe_montx_to_edy.c"
#include "ed25519/additions/fe_sqrt.c"
#include "ed25519/additions/ge_isneutral.c"
#include "ed25519/additions/ge_montx_to_p3.c"
#include "ed25519/additions/ge_neg.c"
#include "ed25519/additions/ge_p3_to_montx.c"
#include "ed25519/additions/ge_scalarmult.c"
#include "ed25519/additions/ge_scalarmult_cofactor.c"
#include "ed25519/additions/keygen.c"
#include "ed25519/additions/open_modified.c"
#include "ed25519/additions/sc_clamp.c"
#include "ed25519/additions/sc_cmov.c"
#include "ed25519/additions/sc_neg.c"
#include "ed25519/additions/sign_modified.c"
#include "ed25519/additions/xeddsa.c"
#include "ed25519/additions/zeroize.c"

#include "ed25519/additions/generalized/gen_veddsa.c"
#include "ed25519/additions/generalized/gen_labelset.c"
#include "ed25519/additions/generalized/gen_x.c"
#include "ed25519/additions/generalized/ge_p3_add.c"
#include "ed25519/additions/generalized/point_isreduced.c"
#include "ed25519/additions/generalized/sc_isreduced.c"
#include "ed25519/additions/generalized/gen_eddsa.c"

#include "ed25519/nacl_sha512/blocks.c"
#include "ed25519/nacl_sha512/hash.c"

// TODO: we might use mbedtls' curve
#include "curve25519-donna.c"