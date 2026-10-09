/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_NESTED_MUSIG_TESTS_IMPL_H
#define SECP256K1_MODULE_NESTED_MUSIG_TESTS_IMPL_H

#include <stdint.h>
#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_nested_musig.h"

#include "keyagg.h"
#include "../../scalar.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"
#include "../../unit_test.h"

#include "vectors.h"

static int nested_musig_create_keypair_and_pk(secp256k1_keypair *keypair, secp256k1_pubkey *pk, const unsigned char *sk) {
    int ret;
    secp256k1_keypair keypair_tmp;

    ret = secp256k1_keypair_create(CTX, &keypair_tmp, sk);
    ret &= secp256k1_keypair_pub(CTX, pk, &keypair_tmp);
    if (keypair != NULL) {
        *keypair = keypair_tmp;
    }
    return ret;
}

static int nested_musig_memcmp_and_randomize(unsigned char *value, const unsigned char *expected, size_t len) {
    int ret;
    size_t i;

    ret = secp256k1_memcmp_var(value, expected, len);
    for (i = 0; i < len; i++) {
        value[i] = testrand_bits(8);
    }
    return ret;
}

static void nested_musig_api_tests(void) {
    unsigned char sk[2][32];
    unsigned char zeros64[64] = { 0 };
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_pubkey full_agg_pk;
    secp256k1_nested_musig_keyagg_cache keyagg_cache;
    secp256k1_nested_musig_keyagg_cache invalid_keyagg_cache;
    secp256k1_pubkey pk[2];
    const secp256k1_pubkey *pk_ptr[2];
    secp256k1_pubkey invalid_pk;
    const secp256k1_pubkey *invalid_pk_ptr2[2];
    const secp256k1_pubkey *invalid_pk_ptr3[3];
    int i;

    /** setup **/

    /* Simulate uninitialized objects with zeroed structs, avoiding undefined
     * behavior from reading actually uninitialized memory. */
    memset(&invalid_keyagg_cache, 0, sizeof(invalid_keyagg_cache));
    memset(&invalid_pk, 0, sizeof(invalid_pk));

    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];
        invalid_pk_ptr2[i] = &invalid_pk;
        invalid_pk_ptr3[i] = &pk[i];
        testrand256(sk[i]);
        CHECK(nested_musig_create_keypair_and_pk(NULL, &pk[i], sk[i]));
    }
    /* Two valid keys followed by an invalid key exercise validation of
     * later participants, after the second distinct key has been found. */
    invalid_pk_ptr3[2] = &invalid_pk;

    /** Key aggregation **/

    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, NULL, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, NULL, pk_ptr, 2) == 1);
    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, NULL, NULL, pk_ptr, 2) == 1);
    CHECK(secp256k1_nested_musig_pubkey_agg(STATIC_CTX, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);

    /* Check that NULL entries in the public-key pointer array are rejected. */
    for (i = 0; i < 2; i++) {
        const secp256k1_pubkey *original_ptr = pk_ptr[i];
        pk_ptr[i] = NULL;
        CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, NULL, pk_ptr, 2));
        CHECK(nested_musig_memcmp_and_randomize(agg_pk.data, zeros64, sizeof(agg_pk.data)) == 0);
        pk_ptr[i] = original_ptr;
    }

    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, NULL, 2));
    CHECK(nested_musig_memcmp_and_randomize(agg_pk.data, zeros64, sizeof(agg_pk.data)) == 0);

    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, invalid_pk_ptr2, 2));
    CHECK(nested_musig_memcmp_and_randomize(agg_pk.data, zeros64, sizeof(agg_pk.data)) == 0);

    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, invalid_pk_ptr3, 3));
    CHECK(nested_musig_memcmp_and_randomize(agg_pk.data, zeros64, sizeof(agg_pk.data)) == 0);

    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, pk_ptr, 0));
    CHECK(nested_musig_memcmp_and_randomize(agg_pk.data, zeros64, sizeof(agg_pk.data)) == 0);

    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, NULL, 0));
    CHECK(nested_musig_memcmp_and_randomize(agg_pk.data, zeros64, sizeof(agg_pk.data)) == 0);

#if SIZE_MAX > UINT32_MAX
    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, pk_ptr, (size_t)UINT32_MAX + 1));
    CHECK(nested_musig_memcmp_and_randomize(agg_pk.data, zeros64, sizeof(agg_pk.data)) == 0);
#endif

    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);

    /** pubkey_get **/

    CHECK(secp256k1_nested_musig_pubkey_get(CTX, &full_agg_pk, &keyagg_cache) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_get(CTX, NULL, &keyagg_cache));

    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_get(CTX, &full_agg_pk, NULL));
    CHECK(nested_musig_memcmp_and_randomize(full_agg_pk.data, zeros64, sizeof(full_agg_pk.data)) == 0);

    CHECK_ILLEGAL(CTX, secp256k1_nested_musig_pubkey_get(CTX, &full_agg_pk, &invalid_keyagg_cache));
    CHECK(nested_musig_memcmp_and_randomize(full_agg_pk.data, zeros64, sizeof(full_agg_pk.data)) == 0);
}

/* Checks that the initialized tagged hashes have the expected state. */
static void nested_musig_sha256_tag_test(void) {
    secp256k1_sha256 sha;
    const secp256k1_hash_ctx *hash_ctx = &CTX->hash_ctx;

    {
        /* "KeyAgg list" */
        static const unsigned char tag[] = {'K', 'e', 'y', 'A', 'g', 'g', ' ', 'l', 'i', 's', 't'};
        secp256k1_nested_musig_keyagglist_sha256(&sha);
        test_sha256_tag_midstate(hash_ctx, &sha, tag, sizeof(tag));
    }
    {
        /* "KeyAgg coefficient" */
        static const unsigned char tag[] = {'K', 'e', 'y', 'A', 'g', 'g', ' ', 'c', 'o', 'e', 'f', 'f', 'i', 'c', 'i', 'e', 'n', 't'};
        secp256k1_nested_musig_keyaggcoef_sha256(&sha);
        test_sha256_tag_midstate(hash_ctx, &sha, tag, sizeof(tag));
    }
}

/* Key aggregation portion of MuSig's vector helper. */
static int nested_musig_vectors_keyagg(
    enum NESTED_MUSIG_ERROR *error,
    secp256k1_nested_musig_keyagg_cache *keyagg_cache,
    unsigned char *agg_pk_ser,
    const unsigned char pubkeys33[][33],
    size_t key_indices_len,
    const size_t *key_indices
) {
    secp256k1_pubkey pubkeys[ARRAY_SIZE(nested_musig_key_agg_vector.pubkeys)];
    const secp256k1_pubkey *pk_ptr[ARRAY_SIZE(nested_musig_key_agg_vector.pubkeys)];
    secp256k1_pubkey agg_pk;
    secp256k1_xonly_pubkey agg_pk_xonly;
    size_t i;

    CHECK(key_indices_len <= ARRAY_SIZE(pubkeys));
    for (i = 0; i < key_indices_len; i++) {
        if (!secp256k1_ec_pubkey_parse(CTX, &pubkeys[i], pubkeys33[key_indices[i]], 33)) {
            *error = NESTED_MUSIG_PUBKEY;
            return 0;
        }
        pk_ptr[i] = &pubkeys[i];
    }

    if (!secp256k1_nested_musig_pubkey_agg(CTX, NULL, keyagg_cache, pk_ptr, key_indices_len)) {
        *error = NESTED_MUSIG_OTHER;
        return 0;
    }
    if (!secp256k1_nested_musig_pubkey_get(CTX, &agg_pk, keyagg_cache)) {
        *error = NESTED_MUSIG_OTHER;
        return 0;
    }
    if (!secp256k1_xonly_pubkey_from_pubkey(CTX, &agg_pk_xonly, NULL, &agg_pk)) {
        *error = NESTED_MUSIG_OTHER;
        return 0;
    }
    if (agg_pk_ser != NULL) {
        if (!secp256k1_xonly_pubkey_serialize(CTX, agg_pk_ser, &agg_pk_xonly)) {
            *error = NESTED_MUSIG_OTHER;
            return 0;
        }
    }
    return 1;
}

static void nested_musig_test_vectors_keyagg(void) {
    size_t i;
    const struct nested_musig_key_agg_vector *vector = &nested_musig_key_agg_vector;

    for (i = 0; i < ARRAY_SIZE(vector->valid_case); i++) {
        const struct nested_musig_key_agg_valid_test_case *c = &vector->valid_case[i];
        enum NESTED_MUSIG_ERROR error;
        secp256k1_nested_musig_keyagg_cache keyagg_cache;
        unsigned char agg_pk[32];

        CHECK(nested_musig_vectors_keyagg(&error, &keyagg_cache, agg_pk, vector->pubkeys, c->key_indices_len, c->key_indices));
        CHECK(secp256k1_memcmp_var(agg_pk, c->expected, sizeof(agg_pk)) == 0);
    }

    for (i = 0; i < ARRAY_SIZE(vector->error_case); i++) {
        const struct nested_musig_key_agg_error_test_case *c = &vector->error_case[i];
        enum NESTED_MUSIG_ERROR error;
        secp256k1_nested_musig_keyagg_cache keyagg_cache;

        /* These cases require tweak functions, which are not implemented yet. */
        if (c->tweak_indices_len != 0) {
            CHECK(c->error == NESTED_MUSIG_TWEAK);
            continue;
        }

        CHECK(!nested_musig_vectors_keyagg(&error, &keyagg_cache, NULL, vector->pubkeys, c->key_indices_len, c->key_indices));
        CHECK(c->error == error);
    }
}

static void nested_musig_keyagg_nested_test(void) {
    static const unsigned char expected_singleton[33] = {
        0x02, 0x74, 0x10, 0x8c, 0xa6, 0xd5, 0xed, 0x40,
        0xb3, 0x7c, 0x4a, 0x44, 0x1e, 0x96, 0x43, 0x8d,
        0x14, 0x4b, 0xd7, 0xe9, 0x5c, 0xd5, 0x15, 0xb9,
        0x96, 0xca, 0x4f, 0x70, 0xf7, 0x83, 0x42, 0xf0,
        0xad
    };
    static const unsigned char expected_parent[33] = {
        0x03, 0x76, 0xa1, 0xda, 0x52, 0x8d, 0x90, 0x1b,
        0xae, 0x2d, 0xd0, 0xb1, 0xb0, 0x00, 0xda, 0xc2,
        0x1e, 0xb0, 0x89, 0xc1, 0xff, 0x3f, 0xe2, 0x88,
        0xc8, 0x78, 0x31, 0x76, 0x33, 0x51, 0xd9, 0x0b,
        0x12
    };
    secp256k1_pubkey pk[3], child, parent, singleton;
    secp256k1_xonly_pubkey child_xonly;
    const secp256k1_pubkey *child_ptr[4];
    const secp256k1_pubkey *parent_ptr[2];
    secp256k1_nested_musig_keyagg_cache keyagg_cache;
    secp256k1_nested_musig_keyagg_cache cache_copy;
    secp256k1_nested_musig_keyagg_cache_internal cache_i;
    unsigned char buf[33];
    size_t buflen;
    size_t i;

    for (i = 0; i < ARRAY_SIZE(pk); i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &pk[i], nested_musig_key_agg_vector.pubkeys[i], 33));
    }

    child_ptr[0] = &pk[0];
    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, NULL, &keyagg_cache, child_ptr, 1) == 1);
    CHECK(secp256k1_nested_musig_pubkey_get(CTX, &singleton, &keyagg_cache) == 1);
    buflen = sizeof(buf);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, buf, &buflen, &singleton, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(buflen == sizeof(buf));
    CHECK(secp256k1_memcmp_var(buf, expected_singleton, sizeof(buf)) == 0);
    CHECK(secp256k1_nested_musig_keyagg_cache_load(CTX, &cache_i, &keyagg_cache));
    CHECK(secp256k1_ge_is_infinity(&cache_i.second_pk));

    child_ptr[0] = &pk[0];
    child_ptr[1] = &pk[0];
    child_ptr[2] = &pk[1];
    child_ptr[3] = &pk[1];
    CHECK(secp256k1_ec_pubkey_sort(CTX, child_ptr, 4));
    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, &child_xonly, &keyagg_cache, child_ptr, 4) == 1);

    cache_copy = keyagg_cache;
    CHECK(secp256k1_nested_musig_pubkey_get(CTX, &child, &cache_copy) == 1);
    buflen = sizeof(buf);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, buf, &buflen, &child, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(buflen == sizeof(buf));
    CHECK(buf[0] == 0x03);
    CHECK(secp256k1_memcmp_var(buf + 1, nested_musig_key_agg_vector.valid_case[3].expected, 32) == 0);
    CHECK(secp256k1_xonly_pubkey_serialize(CTX, buf, &child_xonly) == 1);
    CHECK(secp256k1_memcmp_var(buf, nested_musig_key_agg_vector.valid_case[3].expected, 32) == 0);

    CHECK(secp256k1_nested_musig_keyagg_cache_load(CTX, &cache_i, &cache_copy));
    CHECK(cache_i.parity_acc == 0);
    CHECK(secp256k1_scalar_is_zero(&cache_i.tweak));

    parent_ptr[0] = &child;
    parent_ptr[1] = &pk[2];
    CHECK(secp256k1_ec_pubkey_sort(CTX, parent_ptr, 2));
    CHECK(secp256k1_nested_musig_pubkey_agg(CTX, NULL, &keyagg_cache, parent_ptr, 2) == 1);
    CHECK(secp256k1_nested_musig_pubkey_get(CTX, &parent, &keyagg_cache) == 1);

    buflen = sizeof(buf);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, buf, &buflen, &parent, SECP256K1_EC_COMPRESSED) == 1);
    CHECK(buflen == sizeof(buf));
    CHECK(secp256k1_memcmp_var(buf, expected_parent, sizeof(buf)) == 0);
}

/* --- Test registry --- */
static const struct tf_test_entry tests_nested_musig[] = {
    CASE1(nested_musig_api_tests),
    CASE1(nested_musig_sha256_tag_test),
    CASE1(nested_musig_test_vectors_keyagg),
    CASE1(nested_musig_keyagg_nested_test),
};

#endif
