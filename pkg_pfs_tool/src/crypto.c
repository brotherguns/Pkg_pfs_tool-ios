/*
 * crypto.c — pkg_pfs_tool
 *
 * Optimization 1 (Apple AES-XTS acceleration):
 *   On __APPLE__ targets the encdec_device uses CommonCrypto's kCCModeXTS,
 *   which routes every sector through the A-series dedicated AES hardware
 *   accelerator instead of the mbedTLS software path.
 *   CCCryptorReset() is called once per sector to load the tweak/sector-IV
 *   so the accelerator sees the correct XTS sequence number.
 *
 * All other code (RSA, SHA-256, HMAC, CBC-CTS, OEX, CMAC) is unchanged and
 * continues to use mbedTLS on every platform.
 *
 * Portability: every Apple-specific symbol is inside #if defined(__APPLE__).
 */

#include "crypto.h"
#include "util.h"

/* ── mbedTLS (all platforms) ─────────────────────────────────────────────── */
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/rsa.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/md.h>

/* ── Apple hardware crypto (iOS / macOS) ─────────────────────────────────── */
#if defined(__APPLE__)
#  include <CommonCrypto/CommonCryptor.h>
/*
 * kCCModeXTS is in the public CommonCrypto API since iOS 5 / macOS 10.7.
 * Key layout for XTS: first half = AES data key, second half = AES tweak key.
 * This matches the mbedTLS convention (combined = data_key || tweak_key).
 */
#endif /* __APPLE__ */

/* ─────────────────────────────────────────────────────────────────────────── */

struct encdec_device {
#if defined(__APPLE__)
    /*
     * One CCCryptorRef per direction.  We call CCCryptorReset() with the
     * 16-byte little-endian sector number before every CCCryptorUpdate() so
     * the hardware sees the correct XTS tweak.
     */
    CCCryptorRef enc_ctx;
    CCCryptorRef dec_ctx;
#else
    mbedtls_aes_xts_context enc_ctx;
    mbedtls_aes_xts_context dec_ctx;
#endif
    size_t   sector_size;
    uint8_t* sector_buf;
    int      sector_size_shift;
    int      initialized;
};

/* ── Module-level mbedTLS state (unchanged) ──────────────────────────────── */

static mbedtls_entropy_context    s_entropy;
static mbedtls_ctr_drbg_context   s_ctr_drbg;
static const mbedtls_cipher_info_t* s_aes128_cipher_info = NULL;
static const mbedtls_md_info_t*   s_sha256_md_info = NULL;
static int s_initialized = 0;

static int setup_rsa_keyset(mbedtls_rsa_context* ctx,
                             const struct rsa_keyset* keyset,
                             int is_private);

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

int crypto_initialize(void) {
    int ret;

    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctr_drbg);

    s_initialized = 1;

    s_aes128_cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (!s_aes128_cipher_info) {
        warning("No AES-128-ECB support.");
        return 0;
    }

    s_sha256_md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!s_sha256_md_info) {
        warning("No SHA-256 support.");
        return 0;
    }

    ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg, &mbedtls_entropy_func,
                                  &s_entropy, NULL, 0);
    if (ret != 0) {
        warning("Unable to seed CTR DRBG (error: 0x%08" PRIX32 ").", ret);
        return 0;
    }

    return 1;
}

void crypto_finalize(void) {
    if (s_initialized) {
        s_sha256_md_info = NULL;
        mbedtls_ctr_drbg_free(&s_ctr_drbg);
        mbedtls_entropy_free(&s_entropy);
    }
}

/* ── RSA (mbedTLS on all platforms, unchanged) ───────────────────────────── */

int rsa_public(const struct rsa_keyset* keyset, const void* in, void* out) {
    mbedtls_rsa_context ctx;
    int status = 0;
    int ret;

    assert(keyset != NULL);
    assert(in != NULL);
    assert(out != NULL);

    memset(&ctx, 0, sizeof(ctx));

    mbedtls_rsa_init(&ctx, 0, 0);
    if (!setup_rsa_keyset(&ctx, keyset, 0)) {
        warning("Invalid RSA keyset.");
        goto error;
    }

    ret = mbedtls_rsa_public(&ctx, (const uint8_t*)in, (uint8_t*)out);
    if (ret != 0) {
        if (ret < 0)
            warning("Unable to perform public RSA operation on data (error: -0x%X).", -ret);
        else
            warning("Unable to perform public RSA operation on data (error: 0x%X).", ret);
        goto error;
    }

    status = 1;

error:
    mbedtls_rsa_free(&ctx);
    return status;
}

int rsa_private(const struct rsa_keyset* keyset, const void* in, void* out) {
    mbedtls_rsa_context ctx;
    int status = 0;
    int ret;

    assert(keyset != NULL);
    assert(in != NULL);
    assert(out != NULL);

    memset(&ctx, 0, sizeof(ctx));

    mbedtls_rsa_init(&ctx, 0, 0);
    if (!setup_rsa_keyset(&ctx, keyset, 0)) {
        warning("Invalid RSA keyset.");
        goto error;
    }

    ret = mbedtls_rsa_private(&ctx, &mbedtls_ctr_drbg_random, &s_ctr_drbg,
                               (const uint8_t*)in, (uint8_t*)out);
    if (ret != 0) {
        if (ret < 0)
            warning("Unable to perform private RSA operation on data (error: -0x%X).", -ret);
        else
            warning("Unable to perform private RSA operation on data (error: 0x%X).", ret);
        goto error;
    }

    status = 1;

error:
    mbedtls_rsa_free(&ctx);
    return status;
}

static int mbedtls_rsa_rsaes_pkcs1_v15_decrypt_ex(
    mbedtls_rsa_context* ctx,
    int (*f_rng)(void*, unsigned char*, size_t), void* p_rng,
    int mode, int mode2,
    size_t* olen, const unsigned char* input,
    unsigned char* output, size_t output_max_len)
{
    uint8_t buf[MBEDTLS_MPI_MAX_SIZE];
    uint8_t bad, pad_done = 0;
    size_t ilen, pad_count = 0;
    uint8_t* p;
    size_t i;
    int ret;

    if (mode == MBEDTLS_RSA_PRIVATE && ctx->padding != MBEDTLS_RSA_PKCS_V15)
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    ilen = ctx->len;
    if (ilen < 16 || ilen > sizeof(buf))
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;

    ret = (mode == MBEDTLS_RSA_PUBLIC)
        ? mbedtls_rsa_public(ctx, input, buf)
        : mbedtls_rsa_private(ctx, f_rng, p_rng, input, buf);
    if (ret != 0)
        goto cleanup;

    p = buf;
    bad = 0;
    bad |= *p++;

    if (mode2 == MBEDTLS_RSA_PRIVATE) {
        bad |= *p++ ^ MBEDTLS_RSA_CRYPT;
        for (i = 0; i < ilen - 3; ++i) {
            pad_done  |= ((p[i] | (uint8_t)-p[i]) >> 7) ^ 1;
            pad_count += ((pad_done | (uint8_t)-pad_done) >> 7) ^ 1;
        }
    } else {
        bad |= *p++ ^ MBEDTLS_RSA_SIGN;
        for (i = 0; i < ilen - 3; ++i) {
            pad_done |= (p[i] != 0xFF);
            pad_count += (pad_done == 0);
        }
    }

    p += pad_count;
    bad |= *p++;
    bad |= (pad_count < 8);

    if (bad) {
        ret = MBEDTLS_ERR_RSA_INVALID_PADDING;
        goto cleanup;
    }

    if (ilen - (p - buf) > output_max_len) {
        ret = MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
        goto cleanup;
    }

    *olen = ilen - (p - buf);
    memcpy(output, p, *olen);
    ret = 0;

cleanup:
    return ret;
}

int rsa_pkcsv15_decrypt(const struct rsa_keyset* keyset,
                         const void* in, size_t in_size,
                         void* out, size_t* out_size,
                         int is_private, int is_private_2)
{
    mbedtls_rsa_context ctx;
    size_t size;
    int status = 0;
    int ret;

    assert(keyset != NULL);
    assert(in != NULL);
    assert(out != NULL);
    assert(out_size != NULL);

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);

    if (!setup_rsa_keyset(&ctx, keyset, is_private)) {
        warning("Invalid RSA keyset.");
        goto error;
    }

    if (in_size < ctx.len) {
        warning("Invalid input data size (expected: %" PRIuMAX ", got: %" PRIuMAX ").",
                (uintmax_t)ctx.len, (uintmax_t)in_size);
        goto error;
    }

    size = *out_size;
    ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt_ex(
        &ctx, &mbedtls_ctr_drbg_random, &s_ctr_drbg,
        is_private   ? MBEDTLS_RSA_PRIVATE : MBEDTLS_RSA_PUBLIC,
        is_private_2 ? MBEDTLS_RSA_PRIVATE : MBEDTLS_RSA_PUBLIC,
        &size, (const uint8_t*)in, (uint8_t*)out, size);
    if (ret != 0) {
        if (ret < 0)
            warning("Unable to decrypt RSA data (error: -0x%X).", -ret);
        else
            warning("Unable to decrypt RSA data (error: 0x%X).", ret);
        goto error;
    }

    *out_size = size;
    status = 1;

error:
    mbedtls_rsa_free(&ctx);
    return status;
}

int rsa_pkcsv15_verify_by_hash(const struct rsa_keyset* keyset,
                                uint8_t* hash, size_t hash_size,
                                const void* signature, size_t signature_size)
{
    mbedtls_rsa_context ctx;
    int status = 0;
    int ret;

    assert(keyset != NULL);
    assert(hash != NULL);
    assert(signature != NULL);

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_rsa_init(&ctx, MBEDTLS_RSA_PKCS_V15, 0);

    if (!setup_rsa_keyset(&ctx, keyset, 0)) {
        warning("Invalid RSA keyset.");
        goto error;
    }

    if (signature_size < ctx.len) {
        warning("Invalid data size (expected: %" PRIuMAX ", got: %" PRIuMAX ").",
                (uintmax_t)ctx.len, (uintmax_t)signature_size);
        goto error;
    }

    ret = mbedtls_rsa_pkcs1_verify(&ctx, &mbedtls_ctr_drbg_random, &s_ctr_drbg,
                                    MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
                                    (unsigned int)hash_size, hash,
                                    (const uint8_t*)signature);
    if (ret != 0) {
        warning("Unable to verify RSA data (error: 0x%08" PRIX32 ").", ret);
        goto error;
    }

    status = 1;

error:
    mbedtls_rsa_free(&ctx);
    return status;
}

int rsa_pkcsv15_verify(const struct rsa_keyset* keyset,
                        const void* data, size_t data_size,
                        const void* signature, size_t signature_size)
{
    uint8_t hash[32];

    assert(keyset != NULL);
    assert(data != NULL);
    assert(signature != NULL);

    sha256_buffer(data, data_size, hash);
    return rsa_pkcsv15_verify_by_hash(keyset, hash, sizeof(hash),
                                       signature, signature_size);
}

static int setup_rsa_keyset(mbedtls_rsa_context* ctx,
                              const struct rsa_keyset* keyset,
                              int is_private)
{
    int ret = 0;
    const int radix = 16;
    int have_d_or_primes = 0;
    int tmp;

    assert(ctx != NULL);
    assert(keyset != NULL);

    if (!ctx->N.p) {
        if (keyset->n)
            ret |= mbedtls_mpi_read_string(&ctx->N, radix, keyset->n);
        else {
            if (keyset->name)
                warning("No public modulus provided for keyset '%s'.", keyset->name);
            else
                warning("No public modulus provided for keyset.");
        }
    }
    if (!ctx->E.p) {
        if (keyset->e)
            ret |= mbedtls_mpi_read_string(&ctx->E, radix, keyset->e);
        else if (!is_private) {
            if (keyset->name)
                warning("No public exponent provided for keyset '%s'.", keyset->name);
            else
                warning("No public exponent provided for keyset.");
        }
    }
    if (!ctx->P.p) {
        if (keyset->p) {
            tmp = mbedtls_mpi_read_string(&ctx->P, radix, keyset->p);
            if (tmp == 0) have_d_or_primes |= 1;
            ret |= tmp;
        }
    }
    if (!ctx->Q.p) {
        if (keyset->q) {
            tmp = mbedtls_mpi_read_string(&ctx->Q, radix, keyset->q);
            if (tmp == 0) have_d_or_primes |= 1;
            ret |= tmp;
        }
    }
    if (!ctx->DP.p) {
        if (keyset->dp)
            ret |= mbedtls_mpi_read_string(&ctx->DP, radix, keyset->dp);
    }
    if (!ctx->DQ.p) {
        if (keyset->dq)
            ret |= mbedtls_mpi_read_string(&ctx->DQ, radix, keyset->dq);
    }
    if (!ctx->QP.p) {
        if (keyset->qp)
            ret |= mbedtls_mpi_read_string(&ctx->QP, radix, keyset->qp);
    }
    if (!ctx->D.p) {
        if (keyset->d) {
            tmp = mbedtls_mpi_read_string(&ctx->D, radix, keyset->d);
            if (tmp == 0) have_d_or_primes |= 1;
            ret |= tmp;
        }
    }

    if (is_private && !have_d_or_primes) {
        if (keyset->name)
            warning("No private exponent provided for keyset '%s'.", keyset->name);
        else
            warning("No private exponent provided for keyset.");
    }

    if (ret != 0) {
        if (keyset->name)
            warning("Unable to load keyset '%s'.", keyset->name);
        else
            warning("Unable to load keyset.");
        return 0;
    }

    ctx->len = mbedtls_mpi_size(&ctx->N);

#if defined(DEBUG)
    if (is_private) {
        ret = mbedtls_rsa_check_privkey(ctx);
        if (ret != 0) {
            if (keyset->name)
                warning("Invalid private key provided for keyset '%s'.", keyset->name);
            else
                warning("Invalid private key provided for keyset.");
        }
    } else {
        ret = mbedtls_rsa_check_pubkey(ctx);
        if (ret != 0) {
            if (keyset->name)
                warning("Invalid public key provided for keyset '%s'.", keyset->name);
            else
                warning("Invalid public key provided for keyset.");
        }
    }
#endif

    return 1;
}

/* ── SHA-256 / HMAC-SHA-256 (mbedTLS, unchanged) ────────────────────────── */

void sha256_buffer(const void* data, size_t data_size, uint8_t hash[32]) {
    mbedtls_md_context_t ctx;

    assert(data != NULL);
    assert(hash != NULL);

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, s_sha256_md_info, 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const uint8_t*)data, data_size);
    mbedtls_md_finish(&ctx, hash);
    mbedtls_md_free(&ctx);
}

int sha256_buffer_chunked(read_chunk_cb read_cb, void* read_cb_arg,
                           uint8_t* chunk, size_t chunk_size,
                           uint8_t hash[32])
{
    mbedtls_md_context_t ctx;
    size_t n;
    int status = 0;

    assert(read_cb != NULL);
    assert(chunk != NULL);
    assert(hash != NULL);

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, s_sha256_md_info, 0);
    mbedtls_md_starts(&ctx);

    do {
        status = (*read_cb)(read_cb_arg, chunk, chunk_size, &n);
        if (!status)
            goto error;
        if (n > 0)
            mbedtls_md_update(&ctx, (const uint8_t*)chunk, n);
    } while (n > 0);

    mbedtls_md_finish(&ctx, hash);
    status = 1;

error:
    mbedtls_md_free(&ctx);
    return status;
}

void hmac_sha256_buffer(const void* key, size_t key_size,
                         const void* data, size_t data_size,
                         uint8_t hash[32])
{
    mbedtls_md_context_t ctx;

    assert(key != NULL);
    assert(data != NULL);
    assert(hash != NULL);

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, s_sha256_md_info, 1);
    mbedtls_md_hmac_starts(&ctx, (const uint8_t*)key, key_size);
    mbedtls_md_hmac_update(&ctx, (const uint8_t*)data, data_size);
    mbedtls_md_hmac_finish(&ctx, hash);
    mbedtls_md_free(&ctx);
}

int hmac_sha256_buffer_chunked(const void* key, size_t key_size,
                                read_chunk_cb read_cb, void* read_cb_arg,
                                uint8_t* chunk, size_t chunk_size,
                                uint8_t hash[32])
{
    mbedtls_md_context_t ctx;
    size_t n;
    int status = 0;

    assert(key != NULL);
    assert(read_cb != NULL);
    assert(chunk != NULL);
    assert(hash != NULL);

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, s_sha256_md_info, 1);
    mbedtls_md_hmac_starts(&ctx, (const uint8_t*)key, key_size);

    do {
        status = (*read_cb)(read_cb_arg, chunk, chunk_size, &n);
        if (!status)
            goto error;
        if (n > 0)
            mbedtls_md_hmac_update(&ctx, (const uint8_t*)chunk, n);
    } while (n > 0);

    mbedtls_md_hmac_finish(&ctx, hash);

error:
    mbedtls_md_free(&ctx);
    return status;
}

/* ── AES-CBC-CTS / OEX / CMAC (mbedTLS, unchanged) ─────────────────────── */

int aes_encrypt_cbc_cts(const void* key, size_t key_size, void* iv,
                          const void* in_data, void* out_data, size_t data_size)
{
    mbedtls_aes_context ctx;
    const uint8_t* src;
    const uint8_t* src_left;
    uint8_t* dst;
    uint8_t* dst_left;
    const size_t block_size = 16;
    uint8_t tmp[16];
    size_t data_size_trunc, data_size_left;
    size_t i;

    assert(key != NULL);
    assert(in_data != NULL);
    assert(out_data != NULL);

    if (data_size == 0)
        goto error;

    src = (const uint8_t*)in_data;
    dst = (uint8_t*)out_data;

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_aes_init(&ctx);

    if (mbedtls_aes_setkey_enc(&ctx, (const uint8_t*)key,
                                (unsigned int)(key_size * 8)))
        goto error_free_ctx;

    if (iv)
        memcpy(tmp, iv, block_size);
    else
        memset(tmp, 0, block_size);

    if (data_size >= block_size) {
        data_size_left  = data_size - block_size;
        data_size_trunc = data_size_left / block_size * block_size + block_size;

        src_left = src + data_size_trunc;
        dst_left = dst + data_size_trunc;

        if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT,
                                   data_size_trunc, tmp, src, dst))
            goto error_free_ctx;

        data_size_left &= block_size - 1;
    } else {
        data_size_left = data_size;
        src_left = src;
        dst_left = dst;
    }

    if (data_size_left == 0)
        goto done;

    if (mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, tmp, tmp))
        goto error_free_ctx;

    for (i = 0; i < data_size_left; ++i)
        dst_left[i] = src_left[i] ^ tmp[i];

done:
    if (iv)
        memcpy(iv, tmp, block_size);
    mbedtls_aes_free(&ctx);
    return 1;

error_free_ctx:
    mbedtls_aes_free(&ctx);
error:
    return 0;
}

int aes_decrypt_cbc_cts(const void* key, size_t key_size, void* iv,
                          const void* in_data, void* out_data, size_t data_size)
{
    mbedtls_aes_context ctx;
    const uint8_t* src;
    const uint8_t* src_left;
    uint8_t* dst;
    uint8_t* dst_left;
    const size_t block_size = 16;
    uint8_t tmp[16];
    size_t data_size_trunc, data_size_left;
    size_t i;

    assert(key != NULL);
    assert(in_data != NULL);
    assert(out_data != NULL);

    if (data_size == 0)
        goto error;

    src = (const uint8_t*)in_data;
    dst = (uint8_t*)out_data;

    if (iv)
        memcpy(tmp, iv, block_size);
    else
        memset(tmp, 0, block_size);

    if (data_size >= block_size) {
        data_size_left  = data_size - block_size;
        data_size_trunc = data_size_left / block_size * block_size + block_size;

        src_left = src + data_size_trunc;
        dst_left = dst + data_size_trunc;

        memset(&ctx, 0, sizeof(ctx));
        mbedtls_aes_init(&ctx);

        if (mbedtls_aes_setkey_dec(&ctx, (const uint8_t*)key,
                                    (unsigned int)(key_size * 8)))
            goto error_free_ctx;

        if (mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT,
                                   data_size_trunc, tmp, src, dst))
            goto error_free_ctx;

        mbedtls_aes_free(&ctx);
        data_size_left &= block_size - 1;
    } else {
        data_size_left = data_size;
        src_left = src;
        dst_left = dst;
    }

    if (data_size_left == 0)
        goto done;

    memset(&ctx, 0, sizeof(ctx));
    mbedtls_aes_init(&ctx);

    if (mbedtls_aes_setkey_enc(&ctx, (const uint8_t*)key,
                                (unsigned int)(key_size * 8)))
        goto error_free_ctx;

    if (mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, tmp, tmp))
        goto error_free_ctx;

    mbedtls_aes_free(&ctx);

    for (i = 0; i < data_size_left; ++i)
        dst_left[i] = src_left[i] ^ tmp[i];

done:
    if (iv)
        memcpy(iv, tmp, block_size);
    return 1;

error_free_ctx:
    mbedtls_aes_free(&ctx);
error:
    return 0;
}

int aes_decrypt_oex(const void* key, size_t key_size,
                     uint64_t offset,
                     const void* in_data, void* out_data, size_t data_size)
{
    mbedtls_aes_context ctx;
    const uint8_t* src;
    uint8_t* dst;
    const size_t block_size = 16;
    union {
        uint8_t  raw[16];
        uint64_t offset;
    } tmp;
    size_t data_size_left;
    size_t cur_size;
    size_t i;

    assert(key != NULL);
    assert(in_data != NULL);
    assert(out_data != NULL);

    if (data_size == 0)
        goto error;

    src = (const uint8_t*)in_data;
    dst = (uint8_t*)out_data;

    if (mbedtls_aes_setkey_enc(&ctx, (const uint8_t*)key,
                                (unsigned int)(key_size * 8)))
        goto error_free_ctx;

    data_size_left = data_size;
    while (data_size_left != 0) {
        memset(&tmp, 0, sizeof(tmp));
        tmp.offset = LE64(offset);

        if (mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT,
                                   tmp.raw, tmp.raw))
            goto error_free_ctx;

        cur_size = (data_size_left > block_size) ? block_size : data_size_left;

        for (i = 0; i < cur_size; ++i)
            dst[i] = src[i] ^ tmp.raw[i];

        src            += cur_size;
        dst            += cur_size;
        offset         += cur_size;
        data_size_left -= cur_size;
    }

    mbedtls_aes_free(&ctx);
    return 1;

error_free_ctx:
    mbedtls_aes_free(&ctx);
error:
    return 0;
}

int aes_cmac(const void* key, size_t key_size,
              const void* data, size_t data_size,
              uint8_t digest[16])
{
    int status = 0;

    assert(data != NULL);
    assert(digest != NULL);

    if (mbedtls_cipher_cmac(s_aes128_cipher_info,
                             (const uint8_t*)key, (unsigned int)key_size * 8,
                             (const uint8_t*)data, data_size, digest))
        goto error;

    status = 1;

error:
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * AES-XTS encdec_device
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * On Apple targets we use CommonCrypto (kCCModeXTS) so that every sector
 * decryption is dispatched to the A19 Pro hardware AES accelerator instead
 * of the mbedTLS software implementation.
 *
 * Key layout (identical to mbedTLS convention):
 *   combined_key = data_key || tweak_key   (IEEE 1619 K1 || K2)
 *
 * Per-sector tweak update:
 *   CCCryptorReset(ctx, &sector_iv_buf)  — sets the 16-byte XTS tweak
 *   CCCryptorUpdate(ctx, …)              — hardware-accelerated AES-XTS
 * ═══════════════════════════════════════════════════════════════════════════ */

struct encdec_device* encdec_device_alloc(
    const void* tweak_key, size_t tweak_key_size,
    const void* data_key,  size_t data_key_size,
    size_t sector_size)
{
    struct encdec_device* dev = NULL;
    uint8_t combined_key[32 * 2];   /* max 256-bit XTS: 64 bytes */

    assert(tweak_key != NULL);
    assert(data_key  != NULL);

    if (tweak_key_size != 16 && tweak_key_size != 24 && tweak_key_size != 32)
        goto error;
    if (data_key_size  != 16 && data_key_size  != 24 && data_key_size  != 32)
        goto error;
    if (tweak_key_size != data_key_size)
        goto error;

    dev = (struct encdec_device*)malloc(sizeof(*dev));
    if (!dev)
        goto error;
    memset(dev, 0, sizeof(*dev));

    dev->sector_size       = sector_size;
    dev->sector_size_shift = ilog2_64(sector_size);

    dev->sector_buf = (uint8_t*)malloc(sector_size);
    if (!dev->sector_buf)
        goto error;
    memset(dev->sector_buf, 0, sector_size);

    /* Build combined key:
     *   mbedTLS convention  : data_key  || tweak_key  (K1 || K2)
     *   CommonCrypto kCCModeXTS: tweak_key || data_key (K2 || K1)
     * We build the mbedTLS layout first (used on non-Apple), then a separate
     * cc_combined_key in the reversed order for CommonCrypto on Apple.
     */
    memcpy(combined_key,                data_key,  data_key_size);
    memcpy(combined_key + data_key_size, tweak_key, tweak_key_size);

#if defined(__APPLE__)
    /* ── Apple: create CCCryptorRef pair for hardware AES-XTS ────────────── */
    {
        /*
         * CommonCrypto kCCModeXTS key layout is K2 || K1
         * (tweak key first, then data key) — the reverse of the mbedTLS
         * combined_key we built above.  Build a separate buffer here so
         * the mbedTLS path below remains correct.
         */
        uint8_t cc_combined_key[32 * 2];
        const size_t combined_len = data_key_size + tweak_key_size;
        uint8_t zero_iv[16];
        CCCryptorStatus cc_status;

        memcpy(cc_combined_key,                 tweak_key, tweak_key_size);
        memcpy(cc_combined_key + tweak_key_size, data_key,  data_key_size);
        memset(zero_iv, 0, sizeof(zero_iv));

        /*
         * CCCryptorCreateWithMode signature (12 args):
         *   op, mode, alg, padding, iv,
         *   key, keyLength, tweak, tweakLength,
         *   numRounds, options, &cryptorRef
         *
         * For XTS the "tweak" arg here is unused (we update it per-sector
         * via CCCryptorReset); pass NULL/0.  iv is the initial sector tweak
         * and is also overwritten by Reset before first use.
         */
        cc_status = CCCryptorCreateWithMode(
            kCCEncrypt, kCCModeXTS, kCCAlgorithmAES,
            ccNoPadding,
            zero_iv,
            cc_combined_key, combined_len,
            /* tweak= */ NULL, /* tweakLength= */ 0,
            /* numRounds= */ 0, /* options= */ 0,
            &dev->enc_ctx);
        if (cc_status != kCCSuccess) {
            warning("CCCryptorCreateWithMode(encrypt/XTS) failed: %d", (int)cc_status);
            goto error;
        }

        cc_status = CCCryptorCreateWithMode(
            kCCDecrypt, kCCModeXTS, kCCAlgorithmAES,
            ccNoPadding,
            zero_iv,
            cc_combined_key, combined_len,
            /* tweak= */ NULL, /* tweakLength= */ 0,
            /* numRounds= */ 0, /* options= */ 0,
            &dev->dec_ctx);
        if (cc_status != kCCSuccess) {
            warning("CCCryptorCreateWithMode(decrypt/XTS) failed: %d", (int)cc_status);
            goto error;
        }
    }
#else
    /* ── Non-Apple: mbedTLS software AES-XTS ────────────────────────────── */
    {
        const unsigned int key_bits = (unsigned int)(tweak_key_size + data_key_size) * 8;

        memset(&dev->enc_ctx, 0, sizeof(dev->enc_ctx));
        mbedtls_aes_xts_init(&dev->enc_ctx);
        if (mbedtls_aes_xts_setkey_enc(&dev->enc_ctx, combined_key, key_bits))
            goto error;

        memset(&dev->dec_ctx, 0, sizeof(dev->dec_ctx));
        mbedtls_aes_xts_init(&dev->dec_ctx);
        if (mbedtls_aes_xts_setkey_dec(&dev->dec_ctx, combined_key, key_bits))
            goto error;
    }
#endif /* __APPLE__ */

    return dev;

error:
    if (dev) {
#if defined(__APPLE__)
        if (dev->enc_ctx) CCCryptorRelease(dev->enc_ctx);
        if (dev->dec_ctx) CCCryptorRelease(dev->dec_ctx);
#else
        /* mbedTLS contexts were either never initialised or already freed */
#endif
        if (dev->sector_buf)
            free(dev->sector_buf);
        free(dev);
    }
    return NULL;
}

void encdec_device_free(struct encdec_device* dev) {
    if (!dev)
        return;

#if defined(__APPLE__)
    if (dev->enc_ctx) { CCCryptorRelease(dev->enc_ctx); dev->enc_ctx = NULL; }
    if (dev->dec_ctx) { CCCryptorRelease(dev->dec_ctx); dev->dec_ctx = NULL; }
#else
    mbedtls_aes_xts_free(&dev->enc_ctx);
    mbedtls_aes_xts_free(&dev->dec_ctx);
#endif

    free(dev->sector_buf);
    free(dev);
}

encdec_sector_no encdec_device_process(
    struct encdec_device* dev,
    const void* in, void* out,
    encdec_sector_no start_sector,
    uint64_t data_size,
    int encrypt)
{
    size_t            sector_size   = dev->sector_size;
    uint8_t*          sector_buf    = dev->sector_buf;
    const uint8_t*    in_cur        = (const uint8_t*)in;
    uint8_t*          out_cur       = (uint8_t*)out;
    encdec_sector_no  num_sectors   = data_size >> dev->sector_size_shift;
    encdec_sector_no  end_sector    = start_sector + num_sectors;
    uint64_t          data_size_left =
        data_size - (size_t)(num_sectors << dev->sector_size_shift);
    encdec_sector_no  i;
    union {
        uint64_t iv_index;
        uint8_t  iv_buf[16];
    } u;

    assert(dev != NULL);
    assert(in  != NULL);
    assert(out != NULL);

    memset(u.iv_buf, 0, sizeof(u.iv_buf));

#if defined(__APPLE__)
    /* ── Apple: hardware AES-XTS via CommonCrypto ────────────────────────── */
    {
        CCCryptorRef   cc_ctx = encrypt ? dev->enc_ctx : dev->dec_ctx;
        CCCryptorStatus cc_st;
        size_t         moved;

        for (i = start_sector; i < end_sector; ++i) {
            u.iv_index = LE64((uint64_t)i);

            /* Load the sector tweak into the hardware context */
            cc_st = CCCryptorReset(cc_ctx, u.iv_buf);
            if (cc_st != kCCSuccess)
                return start_sector; /* signal error */

            moved = 0;
            cc_st = CCCryptorUpdate(cc_ctx,
                                     in_cur,  sector_size,
                                     out_cur, sector_size,
                                     &moved);
            if (cc_st != kCCSuccess)
                return start_sector;

            in_cur  += sector_size;
            out_cur += sector_size;
        }

        /* Handle any trailing partial sector (pad to full sector, en/decrypt,
         * then copy only the valid prefix back) */
        if (data_size_left != 0) {
            memset(sector_buf, 0, sector_size);
            memcpy(sector_buf, in_cur, data_size_left);

            u.iv_index = LE64((uint64_t)i);
            cc_st = CCCryptorReset(cc_ctx, u.iv_buf);
            if (cc_st != kCCSuccess)
                return start_sector;

            moved = 0;
            cc_st = CCCryptorUpdate(cc_ctx,
                                     sector_buf, sector_size,
                                     sector_buf, sector_size,
                                     &moved);
            if (cc_st != kCCSuccess)
                return start_sector;

            memcpy(out_cur, sector_buf, data_size_left);
        }
    }
#else
    /* ── Non-Apple: mbedTLS software AES-XTS ────────────────────────────── */
    {
        mbedtls_aes_xts_context* ctx  =
            encrypt ? &dev->enc_ctx : &dev->dec_ctx;
        int mode = encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;

        for (i = start_sector; i < end_sector; ++i) {
            u.iv_index = LE64((uint64_t)i);
            mbedtls_aes_crypt_xts(ctx, mode, sector_size, u.iv_buf,
                                   in_cur, out_cur);
            in_cur  += sector_size;
            out_cur += sector_size;
        }

        if (data_size_left != 0) {
            memset(sector_buf, 0, sector_size);
            memcpy(sector_buf, in_cur, data_size_left);

            u.iv_index = LE64((uint64_t)i);
            mbedtls_aes_crypt_xts(ctx, mode, sector_size, u.iv_buf,
                                   sector_buf, sector_buf);

            memcpy(out_cur, sector_buf, data_size_left);
        }
    }
#endif /* __APPLE__ */

    return end_sector;
}
