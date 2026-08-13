/**********************************************************************
 * Copyright (c) 2021-2024 Jesse Posner                               *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_FROST_TWEAK_IMPL_H
#define SECP256K1_MODULE_FROST_TWEAK_IMPL_H

#include <string.h>

#include "tweak.h"

#include "../../eckey.h"
#include "../../field.h"
#include "../../group.h"
#include "../../scalar.h"
#include "../../util.h"

static const unsigned char secp256k1_frost_tweak_ctx_magic[4] = { 0xdb, 0xaf, 0xcc, 0xb7 };

int secp256k1_frost_tweak_ctx_init(
    const secp256k1_context *ctx,
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const secp256k1_pubkey *threshold_pubkey
) {
    secp256k1_ge pkp;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(threshold_pubkey != NULL);

    if (!secp256k1_pubkey_load(ctx, &pkp, threshold_pubkey)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&pkp.y);
    /* The resulting public key is infinity with negligible probability */
    VERIFY_CHECK(!secp256k1_ge_is_infinity(&pkp));
    if (tweak_ctx != NULL) {
        secp256k1_frost_tweak_ctx_internal ctx_i = { 0 }; 
        ctx_i.pk = pkp;
        secp256k1_frost_tweak_ctx_save(tweak_ctx, &ctx_i);
    }

    return 1;
}

/* A tweak context consists of
 * - 4 byte magic set during initialization to allow detecting an uninitialized object.
 * - 64 byte threshold (and potentially tweaked) public key
 * - 1 byte the parity of the internal key (if tweaked, otherwise 0)
 * - 32 byte tweak
*/
/* Requires that ctx_i->pk is not infinity. */
static void secp256k1_frost_tweak_ctx_save(
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const secp256k1_frost_tweak_ctx_internal *ctx_i
) {
    unsigned char *ptr = tweak_ctx->data;
    VERIFY_CHECK(!secp256k1_ge_is_infinity(&ctx_i->pk));
    memcpy(ptr, secp256k1_frost_tweak_ctx_magic, 4);
    ptr += 4;
    secp256k1_ge_to_bytes(ptr, &ctx_i->pk);
    ptr += 64;
    *ptr = (unsigned char)ctx_i->parity_acc;
    ptr += 1;
    secp256k1_scalar_get_b32(ptr, &ctx_i->tweak);
}

static int secp256k1_frost_tweak_ctx_load(
    const secp256k1_context *ctx,
    secp256k1_frost_tweak_ctx_internal *ctx_i,
    const secp256k1_frost_tweak_ctx *tweak_ctx
) {
    const unsigned char *ptr = tweak_ctx->data;
    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_frost_tweak_ctx_magic, 4) == 0);
    ptr += 4;
    secp256k1_ge_from_bytes(&ctx_i->pk, ptr);
    ptr += 64;
    ctx_i->parity_acc = *ptr & 1;
    ptr += 1;
    secp256k1_scalar_set_b32(&ctx_i->tweak, ptr, NULL);
    return 1;
}

int secp256k1_frost_tweak_pubkey_get(
    const secp256k1_context *ctx,
    secp256k1_pubkey *threshold_pubkey,
    const secp256k1_frost_tweak_ctx *tweak_ctx
) {
    secp256k1_frost_tweak_ctx_internal ctx_i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(threshold_pubkey != NULL);
    memset(threshold_pubkey, 0, sizeof(*threshold_pubkey));
    ARG_CHECK(tweak_ctx != NULL);

    if (!secp256k1_frost_tweak_ctx_load(ctx, &ctx_i, tweak_ctx)) {
        return 0;
    }
    secp256k1_pubkey_save(threshold_pubkey, &ctx_i.pk);
    return 1;
}

static int secp256k1_frost_pubkey_tweak_add_internal(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const unsigned char *tweak32,
    int xonly
) {
    secp256k1_frost_tweak_ctx_internal ctx_i;
    secp256k1_scalar tweak;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    if (output_pubkey != NULL) {
        memset(output_pubkey, 0, sizeof(*output_pubkey));
    }
    ARG_CHECK(tweak_ctx != NULL);
    ARG_CHECK(tweak32 != NULL);

    if (!secp256k1_frost_tweak_ctx_load(ctx, &ctx_i, tweak_ctx)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&tweak, tweak32, &overflow);
    if (overflow) {
        return 0;
    }
    if (xonly && secp256k1_extrakeys_ge_even_y(&ctx_i.pk)) {
        ctx_i.parity_acc ^= 1;
        secp256k1_scalar_negate(&ctx_i.tweak, &ctx_i.tweak);
    }
    secp256k1_scalar_add(&ctx_i.tweak, &ctx_i.tweak, &tweak);
    if (!secp256k1_eckey_pubkey_tweak_add(&ctx_i.pk,&tweak)) {
        return 0;
    }
    /* eckey_pubkey_tweak_add fails if ctx_i.pk is infinity */
    VERIFY_CHECK(!secp256k1_ge_is_infinity(&ctx_i.pk));
    secp256k1_frost_tweak_ctx_save(tweak_ctx, &ctx_i);
    if (output_pubkey != NULL) {
        secp256k1_pubkey_save(output_pubkey, &ctx_i.pk);
    }
    return 1;
}

int secp256k1_frost_pubkey_ec_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const unsigned char *tweak32
) {
    return secp256k1_frost_pubkey_tweak_add_internal(ctx, output_pubkey, tweak_ctx, tweak32, 0);
}

int secp256k1_frost_pubkey_xonly_tweak_add(
    const secp256k1_context *ctx,
    secp256k1_pubkey *output_pubkey,
    secp256k1_frost_tweak_ctx *tweak_ctx,
    const unsigned char *tweak32
) {
    return secp256k1_frost_pubkey_tweak_add_internal(ctx, output_pubkey, tweak_ctx, tweak32, 1);
}

#endif