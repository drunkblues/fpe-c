/**
 * @file fpe.c
 * @brief Main FPE API implementation
 */

#include "fpe_internal.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

/* Forward declarations for algorithm-specific functions */
extern int ff1_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                       unsigned int len, const unsigned char *tweak, unsigned int tweak_len);
extern int ff1_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                       unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

extern int ff3_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                       unsigned int len, const unsigned char *tweak, unsigned int tweak_len);
extern int ff3_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                       unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

extern int ff3_1_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                         unsigned int len, const unsigned char *tweak, unsigned int tweak_len);
extern int ff3_1_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                         unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

/* ========================================================================= */
/*                          Context Management                               */
/* ========================================================================= */

FPE_CTX *FPE_CTX_new(void) {
    FPE_CTX *ctx = (FPE_CTX *)calloc(1, sizeof(FPE_CTX));
    if (!ctx) return NULL;
    
    ctx->cipher_ctx = NULL;
    
    return ctx;
}

void FPE_CTX_free(FPE_CTX *ctx) {
    if (!ctx) return;
    
    /* Clean up OpenSSL contexts */
    if (ctx->cipher_ctx) {
        EVP_CIPHER_CTX_free(ctx->cipher_ctx);
    }
    /* Note: CMAC context removed - FF1 now uses ECB like FF3/FF3-1 */
    
    /* Securely zero sensitive data */
    fpe_secure_zero(ctx->key, sizeof(ctx->key));
    fpe_secure_zero(&ctx->params, sizeof(ctx->params));
    
    free(ctx);
}

int FPE_CTX_init(FPE_CTX *ctx,
                 FPE_MODE mode,
                 FPE_ALGO algo,
                 const unsigned char *key,
                 unsigned int bits,
                 unsigned int radix) {
    if (!ctx || !key) return -1;
    
    /* Validate parameters */
    if (fpe_validate_radix(radix) != 0) return -1;
    
    /* Validate key length */
    if (algo == FPE_ALGO_AES) {
        if (bits != 128 && bits != 192 && bits != 256) return -1;
    } else if (algo == FPE_ALGO_SM4) {
        if (bits != 128) return -1;
    } else {
        return -1;
    }
    
    /* Store configuration */
    ctx->mode = mode;
    ctx->algo = algo;
    ctx->radix = radix;
    ctx->key_bits = bits;
    ctx->key_len = bits / 8;
    
    /* Copy key */
    memcpy(ctx->key, key, ctx->key_len);
    
    /* Initialize OpenSSL contexts based on mode and algorithm */
    if (mode == FPE_MODE_FF1) {
        /* FF1 uses AES-ECB (not CMAC!) */
        ctx->cipher_ctx = EVP_CIPHER_CTX_new();
        if (!ctx->cipher_ctx) return -1;
        
        /* Initialize ECB cipher */
        const EVP_CIPHER *cipher = NULL;
        if (algo == FPE_ALGO_AES) {
            if (bits == 128) cipher = EVP_aes_128_ecb();
            else if (bits == 192) cipher = EVP_aes_192_ecb();
            else if (bits == 256) cipher = EVP_aes_256_ecb();
        }
#ifdef HAVE_OPENSSL_SM4
        else if (algo == FPE_ALGO_SM4) {
            cipher = EVP_sm4_ecb();
        }
#endif
        
        if (!cipher) return -1;
        
        if (!EVP_EncryptInit_ex(ctx->cipher_ctx, cipher, NULL, key, NULL)) {
            return -1;
        }
        
        /* Disable padding for ECB */
        EVP_CIPHER_CTX_set_padding(ctx->cipher_ctx, 0);
        
        /* Set FF1-specific parameters */
        ctx->params.ff1.minlen = 2;  /* FF1 minimum length */
        ctx->params.ff1.maxlen = 0;  /* No maximum */
        
    } else if (mode == FPE_MODE_FF3 || mode == FPE_MODE_FF3_1) {
        /* FF3/FF3-1 use ECB */
        ctx->cipher_ctx = EVP_CIPHER_CTX_new();
        if (!ctx->cipher_ctx) return -1;
        
        const EVP_CIPHER *cipher = NULL;
        if (algo == FPE_ALGO_AES) {
            if (bits == 128) cipher = EVP_aes_128_ecb();
            else if (bits == 192) cipher = EVP_aes_192_ecb();
            else if (bits == 256) cipher = EVP_aes_256_ecb();
        }
#ifdef HAVE_OPENSSL_SM4
        else if (algo == FPE_ALGO_SM4) {
            cipher = EVP_sm4_ecb();
        }
#endif
        
        if (!cipher) return -1;
        
        /* FF3/FF3-1 require reversed key */
        unsigned char reversed_key[32];
        fpe_reverse_key(key, reversed_key, ctx->key_len);
        
        if (!EVP_EncryptInit_ex(ctx->cipher_ctx, cipher, NULL, reversed_key, NULL)) {
            fpe_secure_zero(reversed_key, sizeof(reversed_key));
            return -1;
        }
        
        /* Store reversed key in params */
        if (mode == FPE_MODE_FF3) {
            memcpy(ctx->params.ff3.reversed_key, reversed_key, ctx->key_len);
            ctx->params.ff3.minlen = 2;  /* FF3 minimum length */
        } else {
            memcpy(ctx->params.ff3_1.reversed_key, reversed_key, ctx->key_len);
            ctx->params.ff3_1.minlen = 2;  /* FF3-1 minimum length */
        }
        
        fpe_secure_zero(reversed_key, sizeof(reversed_key));
    }
    
    return 0;
}

/* ========================================================================= */
/*                         Unified Generic Interface                         */
/* ========================================================================= */

int FPE_encrypt(FPE_CTX *ctx,
                const unsigned int *in, unsigned int *out, unsigned int len,
                const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !in || !out) return -1;
    
    /* Validate tweak */
    if (fpe_validate_tweak(ctx->mode, tweak_len) != 0) return -1;
    
    /* Dispatch to algorithm-specific function */
    switch (ctx->mode) {
        case FPE_MODE_FF1:
            return ff1_encrypt(ctx, in, out, len, tweak, tweak_len);
        case FPE_MODE_FF3:
            return ff3_encrypt(ctx, in, out, len, tweak, tweak_len);
        case FPE_MODE_FF3_1:
            return ff3_1_encrypt(ctx, in, out, len, tweak, tweak_len);
        default:
            return -1;
    }
}

int FPE_decrypt(FPE_CTX *ctx,
                const unsigned int *in, unsigned int *out, unsigned int len,
                const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !in || !out) return -1;
    
    /* Validate tweak */
    if (fpe_validate_tweak(ctx->mode, tweak_len) != 0) return -1;
    
    /* Dispatch to algorithm-specific function */
    switch (ctx->mode) {
        case FPE_MODE_FF1:
            return ff1_decrypt(ctx, in, out, len, tweak, tweak_len);
        case FPE_MODE_FF3:
            return ff3_decrypt(ctx, in, out, len, tweak, tweak_len);
        case FPE_MODE_FF3_1:
            return ff3_1_decrypt(ctx, in, out, len, tweak, tweak_len);
        default:
            return -1;
    }
}

/* ========================================================================= */
/*                         String / Helper Interface                         */
/* ========================================================================= */

int FPE_encrypt_str(FPE_CTX *ctx, const char *alphabet,
                    const char *in, char *out,
                    const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !alphabet || !in || !out) return -1;
    
    /* Validate alphabet and check radix matches */
    unsigned int radix = fpe_validate_alphabet(alphabet);
    if (radix == 0 || radix != ctx->radix) return -1;
    
    unsigned int len = (unsigned int)strlen(in);
    if (len == 0) return -1;
    
    /* Allocate temporary arrays */
    unsigned int *in_arr = (unsigned int *)malloc(len * sizeof(unsigned int));
    unsigned int *out_arr = (unsigned int *)malloc(len * sizeof(unsigned int));
    if (!in_arr || !out_arr) {
        free(in_arr);
        free(out_arr);
        return -1;
    }
    
    /* Convert string to array */
    if (fpe_str_to_array(alphabet, in, in_arr, len) != 0) {
        free(in_arr);
        free(out_arr);
        return -1;
    }
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, in_arr, out_arr, len, tweak, tweak_len);
    
    if (ret == 0) {
        /* Convert array back to string */
        ret = fpe_array_to_str(alphabet, out_arr, out, len);
    }
    
    free(in_arr);
    free(out_arr);
    return ret;
}

int FPE_decrypt_str(FPE_CTX *ctx, const char *alphabet,
                    const char *in, char *out,
                    const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !alphabet || !in || !out) return -1;
    
    /* Validate alphabet and check radix matches */
    unsigned int radix = fpe_validate_alphabet(alphabet);
    if (radix == 0 || radix != ctx->radix) return -1;
    
    unsigned int len = (unsigned int)strlen(in);
    if (len == 0) return -1;
    
    /* Allocate temporary arrays */
    unsigned int *in_arr = (unsigned int *)malloc(len * sizeof(unsigned int));
    unsigned int *out_arr = (unsigned int *)malloc(len * sizeof(unsigned int));
    if (!in_arr || !out_arr) {
        free(in_arr);
        free(out_arr);
        return -1;
    }
    
    /* Convert string to array */
    if (fpe_str_to_array(alphabet, in, in_arr, len) != 0) {
        free(in_arr);
        free(out_arr);
        return -1;
    }
    
    /* Decrypt */
    int ret = FPE_decrypt(ctx, in_arr, out_arr, len, tweak, tweak_len);
    
    if (ret == 0) {
        /* Convert array back to string */
        ret = fpe_array_to_str(alphabet, out_arr, out, len);
    }
    
    free(in_arr);
    free(out_arr);
    return ret;
}

/* ========================================================================= */
/*                       Convenience / Stateless Interface                   */
/* ========================================================================= */

int FPE_encrypt_oneshot(FPE_MODE mode, FPE_ALGO algo,
                        const unsigned char *key, unsigned int key_bits,
                        unsigned int radix,
                        const unsigned int *in, unsigned int *out, unsigned int len,
                        const unsigned char *tweak, unsigned int tweak_len) {
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    int ret = FPE_CTX_init(ctx, mode, algo, key, key_bits, radix);
    if (ret == 0) {
        ret = FPE_encrypt(ctx, in, out, len, tweak, tweak_len);
    }
    
    FPE_CTX_free(ctx);
    return ret;
}

int FPE_decrypt_oneshot(FPE_MODE mode, FPE_ALGO algo,
                        const unsigned char *key, unsigned int key_bits,
                        unsigned int radix,
                        const unsigned int *in, unsigned int *out, unsigned int len,
                        const unsigned char *tweak, unsigned int tweak_len) {
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    int ret = FPE_CTX_init(ctx, mode, algo, key, key_bits, radix);
    if (ret == 0) {
        ret = FPE_decrypt(ctx, in, out, len, tweak, tweak_len);
    }
    
    FPE_CTX_free(ctx);
    return ret;
}

int FPE_encrypt_str_oneshot(FPE_MODE mode, FPE_ALGO algo,
                            const unsigned char *key, unsigned int key_bits,
                            const char *alphabet,
                            const char *in, char *out,
                            const unsigned char *tweak, unsigned int tweak_len) {
    if (!alphabet) return -1;
    
    unsigned int radix = fpe_validate_alphabet(alphabet);
    if (radix == 0) return -1;
    
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    int ret = FPE_CTX_init(ctx, mode, algo, key, key_bits, radix);
    if (ret == 0) {
        ret = FPE_encrypt_str(ctx, alphabet, in, out, tweak, tweak_len);
    }
    
    FPE_CTX_free(ctx);
    return ret;
}

int FPE_decrypt_str_oneshot(FPE_MODE mode, FPE_ALGO algo,
                            const unsigned char *key, unsigned int key_bits,
                            const char *alphabet,
                            const char *in, char *out,
                            const unsigned char *tweak, unsigned int tweak_len) {
    if (!alphabet) return -1;
    
    unsigned int radix = fpe_validate_alphabet(alphabet);
    if (radix == 0) return -1;
    
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    int ret = FPE_CTX_init(ctx, mode, algo, key, key_bits, radix);
    if (ret == 0) {
        ret = FPE_decrypt_str(ctx, alphabet, in, out, tweak, tweak_len);
    }
    
    FPE_CTX_free(ctx);
    return ret;
}

/* ========================================================================= */
/*                          Internal Helper Functions                        */
/* ========================================================================= */

void fpe_reverse_key(const unsigned char *key, unsigned char *reversed, unsigned int len) {
    for (unsigned int i = 0; i < len; i++) {
        reversed[i] = key[len - 1 - i];
    }
}
