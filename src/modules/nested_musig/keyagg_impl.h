/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_NESTED_MUSIG_KEYAGG_IMPL_H
#define SECP256K1_MODULE_NESTED_MUSIG_KEYAGG_IMPL_H

#include <stdint.h>
#include <string.h>

#include "keyagg.h"
#include "../../ecmult.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"

static const unsigned char secp256k1_nested_musig_keyagg_cache_magic[4] = { 0x18, 0x43, 0xd0, 0x29 };

/* A keyagg cache consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized
 *   object.
 * - 64 byte aggregate public key
 * - 64 byte "second" public key (set to the point at infinity if not present)
 * - 32 byte hash of all public keys
 * - 1 byte parity
 * - 32 byte tweak
 */
/* Requires that cache_i->pk is not infinity. */
static void secp256k1_nested_musig_keyagg_cache_save(secp256k1_nested_musig_keyagg_cache *cache, const secp256k1_nested_musig_keyagg_cache_internal *cache_i) {
    unsigned char *ptr = cache->data;
    memcpy(ptr, secp256k1_nested_musig_keyagg_cache_magic, 4);
    ptr += 4;
    secp256k1_ge_to_bytes(ptr, &cache_i->pk);
    ptr += 64;
    secp256k1_ge_to_bytes_ext(ptr, &cache_i->second_pk);
    ptr += 64;
    memcpy(ptr, cache_i->pks_hash, 32);
    ptr += 32;
    *ptr = cache_i->parity_acc;
    ptr += 1;
    secp256k1_scalar_get_b32(ptr, &cache_i->tweak);
}

static int secp256k1_nested_musig_keyagg_cache_load(const secp256k1_context *ctx, secp256k1_nested_musig_keyagg_cache_internal *cache_i, const secp256k1_nested_musig_keyagg_cache *cache) {
    const unsigned char *ptr = cache->data;
    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_nested_musig_keyagg_cache_magic, 4) == 0);
    ptr += 4;
    secp256k1_ge_from_bytes(&cache_i->pk, ptr);
    ptr += 64;
    secp256k1_ge_from_bytes_ext(&cache_i->second_pk, ptr);
    ptr += 64;
    memcpy(cache_i->pks_hash, ptr, 32);
    ptr += 32;
    cache_i->parity_acc = *ptr & 1;
    ptr += 1;
    secp256k1_scalar_set_b32(&cache_i->tweak, ptr, NULL);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg list")||SHA256("KeyAgg list"). */
static void secp256k1_nested_musig_keyagglist_sha256(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0xb399d5e0ul, 0xc8fff302ul, 0x6badac71ul, 0x07c5b7f1ul,
        0x9701e2eful, 0x2a72ecf8ul, 0x201a4c7bul, 0xab148a38ul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* Computes pks_hash = tagged_hash(pk[0], ..., pk[np-1]) */
static int secp256k1_nested_musig_compute_pks_hash(const secp256k1_context *ctx, unsigned char *pks_hash, const secp256k1_pubkey * const *pks, size_t np) {
    secp256k1_sha256 sha;
    size_t i;

    secp256k1_nested_musig_keyagglist_sha256(&sha);
    for (i = 0; i < np; i++) {
        unsigned char ser[33];
        size_t ser_len = sizeof(ser);
        if (!secp256k1_ec_pubkey_serialize(ctx, ser, &ser_len, pks[i], SECP256K1_EC_COMPRESSED)) {
            return 0;
        }
        VERIFY_CHECK(ser_len == sizeof(ser));
        secp256k1_sha256_write(&ctx->hash_ctx, &sha, ser, sizeof(ser));
    }
    secp256k1_sha256_finalize(&ctx->hash_ctx, &sha, pks_hash);
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("KeyAgg coefficient")||SHA256("KeyAgg coefficient"). */
static void secp256k1_nested_musig_keyaggcoef_sha256(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x6ef02c5aul, 0x06a480deul, 0x1f298665ul, 0x1d1134f2ul,
        0x56a0b063ul, 0x52da4147ul, 0xf280d9d4ul, 0x4484be15ul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* Compute KeyAgg coefficient which is constant 1 for the second distinct public key and
 * otherwise tagged_hash(pks_hash, pk) where pks_hash is the hash of public keys.
 * second_pk is the point at infinity in case there is no second_pk. Assumes
 * that pk is not the point at infinity and that the Y-coordinates of pk and
 * second_pk are normalized. */
static void secp256k1_nested_musig_keyaggcoef_internal(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *r, const unsigned char *pks_hash, secp256k1_ge *pk, const secp256k1_ge *second_pk) {
    VERIFY_CHECK(!secp256k1_ge_is_infinity(pk));

    if (!secp256k1_ge_is_infinity(second_pk)
          && secp256k1_ge_eq_var(pk, second_pk)) {
        secp256k1_scalar_set_int(r, 1);
    } else {
        secp256k1_sha256 sha;
        unsigned char buf[33];
        secp256k1_nested_musig_keyaggcoef_sha256(&sha);
        secp256k1_sha256_write(hash_ctx, &sha, pks_hash, 32);
        /* Serialization does not fail since the pk is not the point at infinity
         * (according to this function's precondition). */
        secp256k1_ge_serialize33(pk, buf);
        secp256k1_sha256_write(hash_ctx, &sha, buf, sizeof(buf));
        secp256k1_sha256_finalize(hash_ctx, &sha, buf);
        secp256k1_scalar_set_b32(r, buf, NULL);
    }
}

/* Assumes that pk is not the point at infinity and that the Y-coordinates of pk
 * and cache_i->second_pk are normalized. */
static void secp256k1_nested_musig_keyaggcoef(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *r, const secp256k1_nested_musig_keyagg_cache_internal *cache_i, secp256k1_ge *pk) {
    secp256k1_nested_musig_keyaggcoef_internal(hash_ctx, r, cache_i->pks_hash, pk, &cache_i->second_pk);
}

typedef struct {
    const secp256k1_context *ctx;
    /* pks_hash is the hash of the public keys */
    unsigned char pks_hash[32];
    const secp256k1_pubkey * const *pks;
    secp256k1_ge second_pk;
} secp256k1_nested_musig_pubkey_agg_ecmult_data;

/* Callback for batch EC multiplication to compute keyaggcoef_0*P0 + keyaggcoef_1*P1 + ...  */
static int secp256k1_nested_musig_pubkey_agg_callback(secp256k1_scalar *sc, secp256k1_ge *pt, size_t idx, void *data) {
    secp256k1_nested_musig_pubkey_agg_ecmult_data *ctx = (secp256k1_nested_musig_pubkey_agg_ecmult_data *) data;
    int ret;
    ret = secp256k1_pubkey_load(ctx->ctx, pt, ctx->pks[idx]);
#ifdef VERIFY
    VERIFY_CHECK(ret);
#else
    (void) ret;
#endif
    secp256k1_nested_musig_keyaggcoef_internal(&ctx->ctx->hash_ctx, sc, ctx->pks_hash, pt, &ctx->second_pk);
    return 1;
}

int secp256k1_nested_musig_pubkey_agg(const secp256k1_context *ctx, secp256k1_xonly_pubkey *agg_pk, secp256k1_nested_musig_keyagg_cache *keyagg_cache, const secp256k1_pubkey * const *pubkeys, size_t n_pubkeys) {
    secp256k1_nested_musig_pubkey_agg_ecmult_data ecmult_data;
    secp256k1_gej pkj;
    secp256k1_ge pkp;
    size_t i;

    VERIFY_CHECK(ctx != NULL);
    if (agg_pk != NULL) {
        memset(agg_pk, 0, sizeof(*agg_pk));
    }
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(n_pubkeys > 0);
    ARG_CHECK(n_pubkeys <= UINT32_MAX);
    for (i = 0; i < n_pubkeys; i++) {
        ARG_CHECK(pubkeys[i] != NULL);
    }

    ecmult_data.ctx = ctx;
    ecmult_data.pks = pubkeys;

    secp256k1_ge_set_infinity(&ecmult_data.second_pk);
    for (i = 1; i < n_pubkeys; i++) {
        if (secp256k1_memcmp_var(pubkeys[0], pubkeys[i], sizeof(*pubkeys[0])) != 0) {
            secp256k1_ge pk;
            if (!secp256k1_pubkey_load(ctx, &pk, pubkeys[i])) {
                return 0;
            }
            ecmult_data.second_pk = pk;
            break;
        }
    }
    if (!secp256k1_nested_musig_compute_pks_hash(ctx, ecmult_data.pks_hash, pubkeys, n_pubkeys)) {
        return 0;
    }
    if (!secp256k1_ecmult_multi_var(&ctx->error_callback, NULL, &pkj, NULL, secp256k1_nested_musig_pubkey_agg_callback, (void *) &ecmult_data, n_pubkeys)) {
        return 0;
    }
    if (secp256k1_gej_is_infinity(&pkj)) {
        return 0;
    }
    secp256k1_ge_set_gej(&pkp, &pkj);
    secp256k1_fe_normalize_var(&pkp.y);
    /* Infinity was rejected before converting to affine coordinates. */
    VERIFY_CHECK(!secp256k1_ge_is_infinity(&pkp));
    if (keyagg_cache != NULL) {
        secp256k1_nested_musig_keyagg_cache_internal cache_i = { 0 };
        cache_i.pk = pkp;
        cache_i.second_pk = ecmult_data.second_pk;
        memcpy(cache_i.pks_hash, ecmult_data.pks_hash, sizeof(cache_i.pks_hash));
        secp256k1_nested_musig_keyagg_cache_save(keyagg_cache, &cache_i);
    }

    if (agg_pk != NULL) {
        secp256k1_extrakeys_ge_even_y(&pkp);
        secp256k1_xonly_pubkey_save(agg_pk, &pkp);
    }
    return 1;
}

int secp256k1_nested_musig_pubkey_get(const secp256k1_context *ctx, secp256k1_pubkey *agg_pk, const secp256k1_nested_musig_keyagg_cache *keyagg_cache) {
    secp256k1_nested_musig_keyagg_cache_internal cache_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(agg_pk != NULL);
    memset(agg_pk, 0, sizeof(*agg_pk));
    ARG_CHECK(keyagg_cache != NULL);

    if (!secp256k1_nested_musig_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    secp256k1_pubkey_save(agg_pk, &cache_i.pk);
    return 1;
}

#endif
