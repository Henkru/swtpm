/* SPDX-License-Identifier: BSD-3-Clause */
#include <config.h>

#include <stdint.h>

#include <lauxlib.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
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

static int copy_result(lua_State *L)
{
    const struct result *result = lua_touserdata(L, 1);

    lua_pushlstring(L, (const char *)result->data, result->length);
    return 1;
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

static EVP_PKEY *private_key(const unsigned char *der, size_t length)
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
    EVP_PKEY *key = private_key(der, der_length);
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

static int aes_128_cfb_decrypt(lua_State *L)
{
    size_t key_length, iv_length, length;
    const unsigned char *key = check_bytes(L, 1, AES_SIZE, AES_SIZE, &key_length);
    const unsigned char *iv = check_bytes(L, 2, AES_SIZE, AES_SIZE, &iv_length);
    const unsigned char *ciphertext = check_bytes(L, 3, 0, DATA_LIMIT, &length);
    luaL_Buffer buffer;
    /* Allocate through Lua before creating any OpenSSL objects. */
    unsigned char *plaintext = (unsigned char *)luaL_buffinitsize(L, &buffer,
                                                   length + EVP_MAX_BLOCK_LENGTH);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int written = 0, final = 0;
    int ok = ctx && EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb128(), NULL, key, iv) == 1 &&
             EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
             EVP_DecryptUpdate(ctx, plaintext, &written, ciphertext, length) == 1 &&
             EVP_DecryptFinal_ex(ctx, plaintext + written, &final) == 1 &&
             (size_t)(written + final) == length;

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        OPENSSL_cleanse(plaintext, length + EVP_MAX_BLOCK_LENGTH);
        return crypto_error(L, "AES-CFB decryption failed");
    }
    push_result(L, plaintext, length, length + EVP_MAX_BLOCK_LENGTH);
    /* Keep the result in an argument slot while closing the now-cleansed
     * buffer. Its Lua 5.4 to-be-closed stack slot must stay in place. */
    lua_replace(L, 1);
    luaL_pushresultsize(&buffer, 0);
    lua_pushvalue(L, 1);
    return 1;
}

void lua_crypto_register(lua_State *L)
{
    static const luaL_Reg functions[] = {
        { "sha256", sha256 },
        { "hmac_sha256", hmac_sha256 },
        { "rsa_oaep_sha256_decrypt", rsa_oaep_sha256_decrypt },
        { "rsa_oaep_sha256_encrypt", rsa_oaep_sha256_encrypt },
        { "aes_128_cfb_decrypt", aes_128_cfb_decrypt },
        { NULL, NULL }
    };

    luaL_setfuncs(L, functions, 0);
}
