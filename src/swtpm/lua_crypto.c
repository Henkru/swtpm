/* SPDX-License-Identifier: BSD-3-Clause */
#include <config.h>

#include <stdint.h>

#include <lauxlib.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "lua_crypto.h"

#define DATA_LIMIT (1024U * 1024)
#define HMAC_KEY_LIMIT 1024U
#define DER_LIMIT 4096U
#define LABEL_LIMIT 64U
#define RSA_SIZE 256U
#define SALT_SIZE 32U
#define AES_SIZE 16U
#define ECC_COORD_SIZE 32U
#define ECC_POINT_SIZE (2U + ECC_COORD_SIZE + 2U + ECC_COORD_SIZE)

static int crypto_error(lua_State *L, const char *message)
{
    ERR_clear_error();
    return luaL_error(L, "%s", message);
}

static const unsigned char *check_bytes(lua_State *L, int arg, size_t min,
                                        size_t max, size_t *length)
{
    const char *data;

    /* luaL_checklstring would also accept and convert numbers. */
    luaL_checktype(L, arg, LUA_TSTRING);
    data = lua_tolstring(L, arg, length);
    if (*length < min || *length > max)
        luaL_argerror(L, arg, "invalid byte string length");
    return (const unsigned char *)data;
}

struct result {
    unsigned char *data;
    size_t length;
};

struct result_pair {
    struct result first;
    struct result second;
};

static int copy_result(lua_State *L)
{
    const struct result *result = lua_touserdata(L, 1);

    lua_pushlstring(L, (const char *)result->data, result->length);
    return 1;
}

static int copy_result_pair(lua_State *L)
{
    const struct result_pair *results = lua_touserdata(L, 1);

    lua_pushlstring(L, (const char *)results->first.data,
                    results->first.length);
    lua_pushlstring(L, (const char *)results->second.data,
                    results->second.length);
    return 2;
}

/* The copy can fail at the Lua memory limit. Protect it so temporary secrets
 * are cleansed even then. No OpenSSL objects may remain at this point. */
static int push_result(lua_State *L, unsigned char *data, size_t length,
                       size_t capacity)
{
    struct result result = { data, length };
    int rc;

    lua_pushcfunction(L, copy_result);
    lua_pushlightuserdata(L, &result);
    rc = lua_pcall(L, 1, 1, 0);
    OPENSSL_cleanse(data, capacity);
    if (rc != LUA_OK)
        return lua_error(L);
    return 1;
}

/* Copy two results in one protected call. If either allocation fails, both C
 * staging buffers are still cleansed before propagating the Lua error. */
static int push_result_pair(lua_State *L,
                            unsigned char *first, size_t first_length,
                            unsigned char *second, size_t second_length)
{
    struct result_pair results = {
        { first, first_length },
        { second, second_length },
    };
    int rc;

    lua_pushcfunction(L, copy_result_pair);
    lua_pushlightuserdata(L, &results);
    rc = lua_pcall(L, 1, 2, 0);
    OPENSSL_cleanse(first, first_length);
    OPENSSL_cleanse(second, second_length);
    if (rc != LUA_OK)
        return lua_error(L);
    return 2;
}

static int sha256(lua_State *L)
{
    size_t length;
    const unsigned char *data = check_bytes(L, 1, 0, DATA_LIMIT, &length);
    unsigned char digest[SALT_SIZE];
    unsigned int written = 0;

    if (EVP_Digest(data, length, digest, &written, EVP_sha256(), NULL) != 1 ||
        written != sizeof(digest)) {
        OPENSSL_cleanse(digest, sizeof(digest));
        return crypto_error(L, "SHA-256 failed");
    }
    return push_result(L, digest, sizeof(digest), sizeof(digest));
}

static int hmac_sha256(lua_State *L)
{
    size_t key_length, data_length, written = 0;
    const unsigned char *key = check_bytes(L, 1, 0, HMAC_KEY_LIMIT, &key_length);
    const unsigned char *data = check_bytes(L, 2, 0, DATA_LIMIT, &data_length);
    unsigned char digest[SALT_SIZE];
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0),
        OSSL_PARAM_END
    };
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *ctx = mac ? EVP_MAC_CTX_new(mac) : NULL;
    int ok = ctx && EVP_MAC_init(ctx, key, key_length, params) == 1 &&
             EVP_MAC_update(ctx, data, data_length) == 1 &&
             EVP_MAC_final(ctx, digest, &written, sizeof(digest)) == 1 &&
             written == sizeof(digest);

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    if (!ok) {
        OPENSSL_cleanse(digest, sizeof(digest));
        return crypto_error(L, "HMAC-SHA-256 failed");
    }
    return push_result(L, digest, sizeof(digest), sizeof(digest));
}

static EVP_PKEY *rsa_private_key(const unsigned char *der, size_t length)
{
    const unsigned char *cursor = der;
    PKCS8_PRIV_KEY_INFO *info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &cursor, length);
    EVP_PKEY *key = NULL;
    BIGNUM *n = NULL;

    if (info && cursor == der + length)
        key = EVP_PKCS82PKEY(info);
    PKCS8_PRIV_KEY_INFO_free(info);
    if (!key || !EVP_PKEY_is_a(key, "RSA") ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        BN_is_negative(n) || !BN_is_odd(n) || BN_num_bits(n) != 2048) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    BN_free(n);
    return key;
}

static int p256_group(EVP_PKEY *key)
{
    char name[80];
    size_t length = 0;

    return EVP_PKEY_get_group_name(key, name, sizeof(name), &length) == 1 &&
           length < sizeof(name) &&
           OBJ_txt2nid(name) == NID_X9_62_prime256v1;
}

/* Encode the provider public-key representation as a canonical
 * TPMS_ECC_POINT and optionally return its X coordinate. */
static int p256_encode_public(EVP_PKEY *key,
                              unsigned char point[ECC_POINT_SIZE],
                              unsigned char x[ECC_COORD_SIZE])
{
    unsigned char encoded[1 + 2 * ECC_COORD_SIZE];
    size_t length = 0;
    int ok;

    ok = p256_group(key) &&
         EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                         encoded, sizeof(encoded),
                                         &length) == 1 &&
         length == sizeof(encoded) && encoded[0] == POINT_CONVERSION_UNCOMPRESSED;
    if (ok) {
        point[0] = 0;
        point[1] = ECC_COORD_SIZE;
        memcpy(point + 2, encoded + 1, ECC_COORD_SIZE);
        point[2 + ECC_COORD_SIZE] = 0;
        point[3 + ECC_COORD_SIZE] = ECC_COORD_SIZE;
        memcpy(point + 4 + ECC_COORD_SIZE,
               encoded + 1 + ECC_COORD_SIZE, ECC_COORD_SIZE);
        if (x)
            memcpy(x, encoded + 1, ECC_COORD_SIZE);
    }
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return ok;
}

static int der_value(const unsigned char **cursor, const unsigned char *end,
                     unsigned char tag, const unsigned char **value,
                     size_t *length)
{
    size_t bytes, result = 0;
    unsigned char first;

    if (*cursor >= end || *(*cursor)++ != tag || *cursor >= end)
        return 0;
    first = *(*cursor)++;
    if (!(first & 0x80)) {
        result = first;
    } else {
        bytes = first & 0x7f;
        if (!bytes || bytes > sizeof(result) ||
            (size_t)(end - *cursor) < bytes || **cursor == 0)
            return 0;
        while (bytes--) {
            if (result > (SIZE_MAX >> 8))
                return 0;
            result = (result << 8) | *(*cursor)++;
        }
        /* DER requires the shortest possible length encoding. */
        if (result < 128)
            return 0;
    }
    if ((size_t)(end - *cursor) < result)
        return 0;
    *value = *cursor;
    *length = result;
    *cursor += result;
    return 1;
}

/* EVP may reconstruct a public key from an EC private scalar. Require the
 * original RFC 5915 value inside PKCS#8 to carry the publicKey field too, and
 * require it to agree with the provider's validated public component. */
static int p256_has_public_component(const PKCS8_PRIV_KEY_INFO *info,
                                     const unsigned char point[ECC_POINT_SIZE])
{
    const unsigned char *inner = NULL, *cursor, *end, *sequence, *value;
    int inner_length = 0;
    size_t sequence_length, length;

    if (PKCS8_pkey_get0(NULL, &inner, &inner_length, NULL, info) != 1 ||
        !inner || inner_length <= 0)
        return 0;
    cursor = inner;
    end = inner + inner_length;
    if (!der_value(&cursor, end, 0x30, &sequence, &sequence_length) ||
        cursor != end)
        return 0;
    cursor = sequence;
    end = sequence + sequence_length;
    if (!der_value(&cursor, end, 0x02, &value, &length) ||
        length != 1 || value[0] != 1 ||
        !der_value(&cursor, end, 0x04, &value, &length) || !length)
        return 0;
    if (cursor < end && *cursor == 0xa0 &&
        !der_value(&cursor, end, 0xa0, &value, &length))
        return 0;
    if (!der_value(&cursor, end, 0xa1, &sequence, &sequence_length) ||
        cursor != end)
        return 0;
    cursor = sequence;
    end = sequence + sequence_length;
    if (!der_value(&cursor, end, 0x03, &value, &length) || cursor != end ||
        length != 2 + 2 * ECC_COORD_SIZE || value[0] != 0 ||
        value[1] != POINT_CONVERSION_UNCOMPRESSED)
        return 0;
    return CRYPTO_memcmp(value + 2, point + 2, ECC_COORD_SIZE) == 0 &&
           CRYPTO_memcmp(value + 2 + ECC_COORD_SIZE,
                         point + 4 + ECC_COORD_SIZE, ECC_COORD_SIZE) == 0;
}

/* Decode the one supported TPM point form. EVP_PKEY_fromdata and
 * EVP_PKEY_public_check provide the on-curve and non-infinity checks without
 * relying on deprecated mutable EC_KEY internals. */
static EVP_PKEY *p256_public_key(const unsigned char *point,
                                 unsigned char x_bytes[ECC_COORD_SIZE])
{
    static const unsigned char field_prime[ECC_COORD_SIZE] = {
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    unsigned char encoded[1 + 2 * ECC_COORD_SIZE];
    BIGNUM *x = NULL, *y = NULL, *prime = NULL;
    OSSL_PARAM_BLD *builder = NULL;
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *fromdata = NULL, *check = NULL;
    EVP_PKEY *key = NULL;
    int valid_sizes, ok = 0;

    valid_sizes = point[0] == 0 && point[1] == ECC_COORD_SIZE &&
                  point[2 + ECC_COORD_SIZE] == 0 &&
                  point[3 + ECC_COORD_SIZE] == ECC_COORD_SIZE;
    if (!valid_sizes)
        goto cleanup;
    x = BN_bin2bn(point + 2, ECC_COORD_SIZE, NULL);
    y = BN_bin2bn(point + 4 + ECC_COORD_SIZE, ECC_COORD_SIZE, NULL);
    prime = BN_bin2bn(field_prime, sizeof(field_prime), NULL);
    if (!x || !y || !prime || BN_is_zero(x) || BN_is_zero(y) ||
        BN_cmp(x, prime) >= 0 || BN_cmp(y, prime) >= 0)
        goto cleanup;

    encoded[0] = POINT_CONVERSION_UNCOMPRESSED;
    memcpy(encoded + 1, point + 2, ECC_COORD_SIZE);
    memcpy(encoded + 1 + ECC_COORD_SIZE,
           point + 4 + ECC_COORD_SIZE, ECC_COORD_SIZE);
    builder = OSSL_PARAM_BLD_new();
    if (!builder ||
        OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME,
                                        SN_X9_62_prime256v1, 0) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY,
                                         encoded, sizeof(encoded)) != 1 ||
        !(params = OSSL_PARAM_BLD_to_param(builder)) ||
        !(fromdata = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) ||
        EVP_PKEY_fromdata_init(fromdata) <= 0 ||
        EVP_PKEY_fromdata(fromdata, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0 ||
        !(check = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) ||
        EVP_PKEY_public_check(check) <= 0 || !p256_group(key))
        goto cleanup;
    memcpy(x_bytes, point + 2, ECC_COORD_SIZE);
    ok = 1;

cleanup:
    if (!ok) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(check);
    EVP_PKEY_CTX_free(fromdata);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    BN_free(prime);
    BN_free(y);
    BN_free(x);
    OPENSSL_cleanse(encoded, sizeof(encoded));
    return key;
}

static EVP_PKEY *p256_private_key(const unsigned char *der, size_t length,
                                  unsigned char public_x[ECC_COORD_SIZE])
{
    const unsigned char *cursor = der;
    PKCS8_PRIV_KEY_INFO *info = NULL;
    EVP_PKEY_CTX *check = NULL;
    EVP_PKEY *key = NULL;
    BIGNUM *private = NULL;
    unsigned char point[ECC_POINT_SIZE];
    int ok = 0;

    info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &cursor, length);
    if (!info || cursor != der + length || !(key = EVP_PKCS82PKEY(info)) ||
        !EVP_PKEY_is_a(key, "EC") || !p256_group(key) ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &private) != 1 ||
        !private || BN_is_zero(private) || BN_is_negative(private) ||
        !p256_encode_public(key, point, public_x) ||
        !p256_has_public_component(info, point) ||
        !(check = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) ||
        EVP_PKEY_private_check(check) <= 0 ||
        EVP_PKEY_public_check(check) <= 0 ||
        EVP_PKEY_pairwise_check(check) <= 0)
        goto cleanup;
    ok = 1;

cleanup:
    if (!ok) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(check);
    BN_clear_free(private);
    PKCS8_PRIV_KEY_INFO_free(info);
    OPENSSL_cleanse(point, sizeof(point));
    return key;
}

static EVP_PKEY *p256_generate_key(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *key = NULL;

    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_group_name(ctx, SN_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_generate(ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int p256_ecdh(EVP_PKEY *private, EVP_PKEY *peer,
                      unsigned char secret[ECC_COORD_SIZE])
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private, NULL);
    size_t length = 0;
    int ok = ctx && EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, peer) > 0 &&
             EVP_PKEY_derive(ctx, NULL, &length) > 0 &&
             length == ECC_COORD_SIZE &&
             EVP_PKEY_derive(ctx, secret, &length) > 0 &&
             length == ECC_COORD_SIZE;

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int p256_kdfe(const unsigned char secret[ECC_COORD_SIZE],
                     const unsigned char ephemeral_x[ECC_COORD_SIZE],
                     const unsigned char static_x[ECC_COORD_SIZE],
                     unsigned char salt[SALT_SIZE])
{
    static const unsigned char counter[] = { 0, 0, 0, 1 };
    static const unsigned char label[] = { 'S', 'E', 'C', 'R', 'E', 'T', 0 };
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned int written = 0;
    int ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
             EVP_DigestUpdate(ctx, counter, sizeof(counter)) == 1 &&
             EVP_DigestUpdate(ctx, secret, ECC_COORD_SIZE) == 1 &&
             EVP_DigestUpdate(ctx, label, sizeof(label)) == 1 &&
             EVP_DigestUpdate(ctx, ephemeral_x, ECC_COORD_SIZE) == 1 &&
             EVP_DigestUpdate(ctx, static_x, ECC_COORD_SIZE) == 1 &&
             EVP_DigestFinal_ex(ctx, salt, &written) == 1 &&
             written == SALT_SIZE;

    EVP_MD_CTX_free(ctx);
    return ok;
}

static int ecc_p256_salt_from_private(lua_State *L)
{
    size_t der_length, point_length;
    const unsigned char *der = check_bytes(L, 1, 1, DER_LIMIT, &der_length);
    const unsigned char *point = check_bytes(L, 2, ECC_POINT_SIZE,
                                             ECC_POINT_SIZE, &point_length);
    unsigned char static_x[ECC_COORD_SIZE], ephemeral_x[ECC_COORD_SIZE];
    unsigned char secret[ECC_COORD_SIZE], salt[SALT_SIZE];
    EVP_PKEY *private = NULL, *peer = NULL;
    const char *error = "invalid P-256 private key";
    int ok = 0;

    private = p256_private_key(der, der_length, static_x);
    if (!private)
        goto cleanup;
    error = "invalid P-256 point";
    peer = p256_public_key(point, ephemeral_x);
    if (!peer)
        goto cleanup;
    error = "P-256 salt derivation failed";
    if (!p256_ecdh(private, peer, secret) ||
        !p256_kdfe(secret, ephemeral_x, static_x, salt))
        goto cleanup;
    ok = 1;

cleanup:
    EVP_PKEY_free(peer);
    EVP_PKEY_free(private);
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(ephemeral_x, sizeof(ephemeral_x));
    OPENSSL_cleanse(static_x, sizeof(static_x));
    if (!ok) {
        OPENSSL_cleanse(salt, sizeof(salt));
        return crypto_error(L, error);
    }
    return push_result(L, salt, sizeof(salt), sizeof(salt));
}

static int ecc_p256_salt_to_public(lua_State *L)
{
    size_t point_length;
    const unsigned char *static_point = check_bytes(L, 1, ECC_POINT_SIZE,
                                                    ECC_POINT_SIZE,
                                                    &point_length);
    unsigned char point[ECC_POINT_SIZE];
    unsigned char static_x[ECC_COORD_SIZE], ephemeral_x[ECC_COORD_SIZE];
    unsigned char secret[ECC_COORD_SIZE], salt[SALT_SIZE];
    EVP_PKEY *peer = NULL, *ephemeral = NULL;
    const char *error = "invalid P-256 point";
    int ok = 0;

    peer = p256_public_key(static_point, static_x);
    if (!peer)
        goto cleanup;
    error = "P-256 key generation failed";
    ephemeral = p256_generate_key();
    if (!ephemeral ||
        !p256_encode_public(ephemeral, point, ephemeral_x))
        goto cleanup;
    error = "P-256 salt derivation failed";
    if (!p256_ecdh(ephemeral, peer, secret) ||
        !p256_kdfe(secret, ephemeral_x, static_x, salt))
        goto cleanup;
    ok = 1;

cleanup:
    EVP_PKEY_free(ephemeral);
    EVP_PKEY_free(peer);
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(ephemeral_x, sizeof(ephemeral_x));
    OPENSSL_cleanse(static_x, sizeof(static_x));
    if (!ok) {
        OPENSSL_cleanse(point, sizeof(point));
        OPENSSL_cleanse(salt, sizeof(salt));
        return crypto_error(L, error);
    }
    return push_result_pair(L, point, sizeof(point), salt, sizeof(salt));
}

static EVP_PKEY *public_key(const unsigned char *modulus, uint32_t exponent)
{
    BIGNUM *n = BN_bin2bn(modulus, RSA_SIZE, NULL);
    OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    if (!n || !builder ||
        OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_RSA_N, n) != 1 ||
        OSSL_PARAM_BLD_push_uint32(builder, OSSL_PKEY_PARAM_RSA_E, exponent) != 1 ||
        !(params = OSSL_PARAM_BLD_to_param(builder)) ||
        !(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) ||
        EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    BN_free(n);
    return key;
}

static int set_oaep(EVP_PKEY_CTX *ctx, const unsigned char *label, size_t length)
{
    unsigned char *copy;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
        return 0;
    if (!length)
        return 1;
    copy = OPENSSL_memdup(label, length);
    if (!copy)
        return 0;
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, copy, length) <= 0) {
        OPENSSL_free(copy);
        return 0;
    }
    return 1; /* ctx owns the copy. */
}

static int rsa_oaep_sha256_decrypt(lua_State *L)
{
    size_t der_length, ciphertext_length, label_length;
    const unsigned char *der = check_bytes(L, 1, 1, DER_LIMIT, &der_length);
    const unsigned char *ciphertext = check_bytes(L, 2, RSA_SIZE, RSA_SIZE,
                                                  &ciphertext_length);
    const unsigned char *label = check_bytes(L, 3, 0, LABEL_LIMIT, &label_length);
    unsigned char plaintext[RSA_SIZE];
    size_t written = sizeof(plaintext);
    EVP_PKEY *key = rsa_private_key(der, der_length);
    EVP_PKEY_CTX *ctx = key ? EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL) : NULL;
    const char *error = key ? "RSA OAEP decryption failed" : "invalid RSA key";
    int ok = ctx && EVP_PKEY_decrypt_init(ctx) > 0 &&
             set_oaep(ctx, label, label_length) &&
             EVP_PKEY_decrypt(ctx, plaintext, &written, ciphertext,
                              ciphertext_length) > 0 && written == SALT_SIZE;

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) {
        OPENSSL_cleanse(plaintext, sizeof(plaintext));
        return crypto_error(L, error);
    }
    return push_result(L, plaintext, written, sizeof(plaintext));
}

static int rsa_oaep_sha256_encrypt(lua_State *L)
{
    size_t modulus_length, plaintext_length, label_length;
    const unsigned char *modulus = check_bytes(L, 1, RSA_SIZE, RSA_SIZE,
                                               &modulus_length);
    lua_Integer exponent;
    const unsigned char *plaintext, *label;
    unsigned char ciphertext[RSA_SIZE];
    size_t written = sizeof(ciphertext);
    EVP_PKEY *key;
    EVP_PKEY_CTX *ctx;
    int ok;

    if (!lua_isinteger(L, 2))
        return crypto_error(L, "invalid RSA exponent");
    exponent = lua_tointeger(L, 2);
    if (exponent < 3 || (uint64_t)exponent > UINT32_MAX || !(exponent & 1))
        return crypto_error(L, "invalid RSA exponent");
    plaintext = check_bytes(L, 3, SALT_SIZE, SALT_SIZE, &plaintext_length);
    label = check_bytes(L, 4, 0, LABEL_LIMIT, &label_length);
    /* The raw modulus is an unsigned, big-endian integer. */
    if (!(modulus[0] & 0x80) || !(modulus[RSA_SIZE - 1] & 1))
        return crypto_error(L, "invalid RSA modulus");
    key = public_key(modulus, (uint32_t)exponent);
    ctx = key ? EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL) : NULL;
    ok = ctx && EVP_PKEY_encrypt_init(ctx) > 0 &&
         set_oaep(ctx, label, label_length) &&
         EVP_PKEY_encrypt(ctx, ciphertext, &written, plaintext,
                          plaintext_length) > 0 && written == RSA_SIZE;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    if (!ok) {
        OPENSSL_cleanse(ciphertext, sizeof(ciphertext));
        return crypto_error(L, "RSA OAEP encryption failed");
    }
    return push_result(L, ciphertext, written, sizeof(ciphertext));
}

static int aes_128_cfb_transform(lua_State *L, int encrypt)
{
    size_t key_length, iv_length, length;
    const unsigned char *key = check_bytes(L, 1, AES_SIZE, AES_SIZE, &key_length);
    const unsigned char *iv = check_bytes(L, 2, AES_SIZE, AES_SIZE, &iv_length);
    const unsigned char *input = check_bytes(L, 3, 0, DATA_LIMIT, &length);
    luaL_Buffer buffer;
    /* Allocate through Lua before creating any OpenSSL objects. */
    unsigned char *output = (unsigned char *)luaL_buffinitsize(
                                L, &buffer, length + EVP_MAX_BLOCK_LENGTH);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int written = 0, final = 0;
    int ok = ctx &&
             EVP_CipherInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv,
                               encrypt) == 1 &&
             EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
             EVP_CipherUpdate(ctx, output, &written, input, length) == 1 &&
             EVP_CipherFinal_ex(ctx, output + written, &final) == 1 &&
             (size_t)(written + final) == length;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        OPENSSL_cleanse(output, length + EVP_MAX_BLOCK_LENGTH);
        return crypto_error(L, encrypt ? "AES-CFB encryption failed" :
                                      "AES-CFB decryption failed");
    }
    push_result(L, output, length, length + EVP_MAX_BLOCK_LENGTH);
    /* Keep the result in an argument slot while closing the now-cleansed
     * buffer. Its Lua 5.4 to-be-closed stack slot must stay in place. */
    lua_replace(L, 1);
    luaL_pushresultsize(&buffer, 0);
    lua_pushvalue(L, 1);
    return 1;
}

static int aes_128_cfb_encrypt(lua_State *L)
{
    return aes_128_cfb_transform(L, 1);
}

static int aes_128_cfb_decrypt(lua_State *L)
{
    return aes_128_cfb_transform(L, 0);
}

void lua_crypto_register(lua_State *L)
{
    static const luaL_Reg functions[] = {
        { "sha256", sha256 },
        { "hmac_sha256", hmac_sha256 },
        { "rsa_oaep_sha256_decrypt", rsa_oaep_sha256_decrypt },
        { "rsa_oaep_sha256_encrypt", rsa_oaep_sha256_encrypt },
        { "ecc_p256_salt_from_private", ecc_p256_salt_from_private },
        { "ecc_p256_salt_to_public", ecc_p256_salt_to_public },
        { "aes_128_cfb_encrypt", aes_128_cfb_encrypt },
        { "aes_128_cfb_decrypt", aes_128_cfb_decrypt },
        { NULL, NULL }
    };

    luaL_setfuncs(L, functions, 0);
}
