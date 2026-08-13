#ifndef SECP256K1_FROST_H
#define SECP256K1_FROST_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/** This code is currently a work in progress. It's not secure nor stable.
 * IT IS EXTREMELY DANGEROUS AND RECKLESS TO USE THIS MODULE IN PRODUCTION!
 *
 * This module implements a variant of Flexible Round-Optimized Schnorr
 * Threshold Signatures (FROST) by Chelsea Komlo and Ian Goldberg
 * (https://crysp.uwaterloo.ca/software/frost/).
 */

/** Opaque data structures
 *
 *  The exact representation of data inside the opaque data structures is
 *  implementation defined and not guaranteed to be portable between different
 *  platforms or versions. With the exception of `secp256k1_frost_secnonce`, the
 *  data structures can be safely copied/moved. If you need to convert to a
 *  format suitable for storage, transmission, or comparison, use the
 *  corresponding serialization and parsing functions.
 */

 /** Opaque data structure that holds a FROST threshold public key and
 * accumulated tweak information.
 *
 * The object is initialized from a user-provided threshold public key.
 * It is updated by the FROST tweak functions and is required when signing for
 * a tweaked threshold key.
 *
 * Guaranteed to be 101 bytes in size.
 */
typedef struct secp256k1_frost_tweak_ctx {
    unsigned char data[101];
} secp256k1_frost_tweak_ctx;

/** Initializes a FROST tweak context from a threshold public key.
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object 
 *  Out:       tweak_ctx: if non-NULL, pointer to a FROST tweak context
 *  In: threshold_pubkey: pointer to a threshold public key
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_tweak_ctx_init(
    const secp256k1_context *ctx,
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const secp256k1_pubkey *threshold_pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3);

/** Obtain the threshold public key from a tweak_ctx.
 *
 *  This is only useful if you need the non-xonly public key, in particular for
 *  plain (non-xonly) tweaking
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:             ctx: pointer to a context object
 *  Out: threshold_pubkey: the frost-threshold public key.
 *  In:      tweak_ctx: pointer to a `frost_tweak_ctx` struct initialized by
 *                    `frost_tweak_ctx_init`
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_frost_tweak_pubkey_get(
    const secp256k1_context *ctx,
    secp256k1_pubkey *threshold_pubkey,
    const secp256k1_frost_tweak_ctx *tweak_ctx
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Apply plain "EC" tweaking to a public key in a given tweak_ctx by adding
 *  the generator multiplied with `tweak32` to it. This is useful for deriving
 *  child keys from a threshold public key via BIP 32 where `tweak32` is set to
 *  a hash as defined in BIP 32.
 *
 *  Callers are responsible for deriving `tweak32` in a way that does not reduce
 *  the security of FROST (for example, by following BIP 32).
 *
 *  The tweaking method is the same as `secp256k1_ec_pubkey_tweak_add`. So after
 *  the following pseudocode buf and buf2 have identical contents (absent
 *  earlier failures).
 *
 *  secp256k1_frost_tweak_ctx_init(..., tweak_ctx, pubkeys, ...)
 *  secp256k1_frost_pubkey_get(..., threshold_pk, tweak_ctx)
 *  secp256k1_frost_pubkey_ec_tweak_add(..., output_pk, tweak32, tweak_ctx)
 *  secp256k1_ec_pubkey_serialize(..., buf, ..., output_pk, ...)
 *  secp256k1_ec_pubkey_tweak_add(..., threshold_pk, tweak32)
 *  secp256k1_ec_pubkey_serialize(..., buf2, ..., threshold_pk, ...)
 *
 *  This function is required if you want to _sign_ for a tweaked threshold key.
 *  If you are only computing a public key but not intending to create a
 *  signature for it, use `secp256k1_ec_pubkey_tweak_add` instead.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object
 *  Out:   output_pubkey: pointer to a public key to store the result. Will be set
 *                        to an invalid value if this function returns 0. If you
 *                        do not need it, this arg can be NULL.
 *  In/Out: tweak_ctx: pointer to a `frost_tweak_ctx` struct initialized by
 *                       `frost_tweak_ctx_init`
 *  In:          tweak32: pointer to a 32-byte tweak. The tweak is valid if it passes
 *                        `secp256k1_ec_seckey_verify` and is not equal to the
 *                        secret key corresponding to the public key represented
 *                        by tweak_ctx or its negation. For uniformly random
 *                        32-byte arrays the chance of being invalid is
 *                        negligible (around 1 in 2^128).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_frost_pubkey_ec_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Apply x-only tweaking to a public key in a given tweak_ctx by adding the
 *  generator multiplied with `tweak32` to it. This is useful for creating
 *  Taproot outputs where `tweak32` is set to a TapTweak hash as defined in BIP
 *  341.
 *
 *  Callers are responsible for deriving `tweak32` in a way that does not reduce
 *  the security of frost (for example, by following Taproot BIP 341).
 *
 *  The tweaking method is the same as `secp256k1_xonly_pubkey_tweak_add`. So in
 *  the following pseudocode xonly_pubkey_tweak_add_check (absent earlier
 *  failures) returns 1.
 *
 *  secp256k1_frost_tweak_ctx_init(..., threshold_pk, tweak_ctx, pubkeys, ...)
 *  secp256k1_frost_pubkey_xonly_tweak_add(..., output_pk, tweak_ctx, tweak32)
 *  secp256k1_xonly_pubkey_serialize(..., buf, output_pk)
 *  secp256k1_xonly_pubkey_tweak_add_check(..., buf, ..., threshold_pk, tweak32)
 *
 *  This function is required if you want to _sign_ for a tweaked threshold key.
 *  If you are only computing a public key but not intending to create a
 *  signature for it, use `secp256k1_xonly_pubkey_tweak_add` instead.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:            ctx: pointer to a context object
 *  Out:   output_pubkey: pointer to a public key to store the result. Will be set
 *                        to an invalid value if this function returns 0. If you
 *                        do not need it, this arg can be NULL.
 *  In/Out: tweak_ctx: pointer to a `frost_tweak_ctx` struct initialized by
 *                       `frost_tweak_ctx_init`
 *  In:          tweak32: pointer to a 32-byte tweak. The tweak is valid if it passes
 *                        `secp256k1_ec_seckey_verify` and is not equal to the
 *                        secret key corresponding to the public key represented
 *                        by tweak_ctx or its negation. For uniformly random
 *                        32-byte arrays the chance of being invalid is
 *                        negligible (around 1 in 2^128).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int
secp256k1_frost_pubkey_xonly_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const unsigned char *tweak32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif
