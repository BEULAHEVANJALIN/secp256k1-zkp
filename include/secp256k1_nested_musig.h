#ifndef SECP256K1_NESTED_MUSIG_H
#define SECP256K1_NESTED_MUSIG_H

#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/** Opaque data structures
 *
 *  The exact representation of data inside the opaque data structures is
 *  implementation defined and not guaranteed to be portable between different
 *  platforms or versions.
 */

/** Opaque data structure that caches information about public key aggregation.
 *
 *  Guaranteed to be 197 bytes in size. No serialization and parsing functions
 *  (yet).
 */
typedef struct secp256k1_nested_musig_keyagg_cache {
    unsigned char data[197];
} secp256k1_nested_musig_keyagg_cache;

/** Computes an aggregate public key and uses it to initialize a keyagg_cache
 *
 *  Different orders of `pubkeys` result in different `agg_pk`s.
 *
 *  Before aggregating, the pubkeys can be sorted with `secp256k1_ec_pubkey_sort`
 *  which ensures the same `agg_pk` result for the same multiset of pubkeys.
 *  For Nested MuSig sessions, this sorting is required independently at each
 *  aggregation node.
 *
 *  To obtain a child node's full public key for aggregation at its parent,
 *  use `secp256k1_nested_musig_pubkey_get` with the resulting keyagg_cache.
 *
 *  Returns: 0 if the arguments are invalid or aggregation fails, 1 otherwise
 *  Args:        ctx: pointer to a context object
 *  Out:      agg_pk: the Nested MuSig-aggregated x-only public key. If you do
 *                    not need it, this arg can be NULL.
 *      keyagg_cache: if non-NULL, pointer to a nested_musig_keyagg_cache struct
 *                    to initialize with the key aggregation information.
 *  In:      pubkeys: input array of pointers to public keys to aggregate. The order
 *                    is important; a different order will result in a different
 *                    aggregate public key.
 *         n_pubkeys: length of pubkeys array. Must be greater than 0 and
 *                    less than 2^32.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_nested_musig_pubkey_agg(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *agg_pk,
    secp256k1_nested_musig_keyagg_cache *keyagg_cache,
    const secp256k1_pubkey * const *pubkeys,
    size_t n_pubkeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(4);

/** Obtain the aggregate public key from a keyagg_cache.
 *
 *  Returns: 0 if the arguments are invalid, 1 otherwise
 *  Args:        ctx: pointer to a context object
 *  Out:      agg_pk: the Nested MuSig-aggregated public key.
 *  In: keyagg_cache: pointer to a `nested_musig_keyagg_cache` struct initialized
 *                    by `nested_musig_pubkey_agg`.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_nested_musig_pubkey_get(
    const secp256k1_context *ctx,
    secp256k1_pubkey *agg_pk,
    const secp256k1_nested_musig_keyagg_cache *keyagg_cache
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

#ifdef __cplusplus
}
#endif

#endif
