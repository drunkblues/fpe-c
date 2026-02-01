/**
 * @file fpe_internal.h
 * @brief Internal data structures and definitions for FPE implementation
 * 
 * This header is NOT exposed to library users - it contains internal
 * implementation details including the opaque FPE_CTX structure.
 */

#ifndef FPE_INTERNAL_H
#define FPE_INTERNAL_H

#include "../include/fpe.h"
#include <openssl/evp.h>
/* Note: FF1 uses AES-ECB with CBC-MAC construction, not CMAC */

/**
 * @brief Internal FPE Context Structure (Opaque to users)
 * 
 * This structure encapsulates all state needed for FPE operations,
 * including algorithm parameters, OpenSSL contexts, and precomputed values.
 */
struct fpe_ctx_st {
    /* Configuration */
    FPE_MODE mode;          /**< FPE algorithm mode (FF1/FF3/FF3-1) */
    FPE_ALGO algo;          /**< Underlying cipher (AES/SM4) */
    unsigned int radix;     /**< Radix (base) for numeral strings */
    unsigned int key_bits;  /**< Key length in bits (128/192/256) */
    
    /* Key material */
    unsigned char key[32];  /**< Raw key bytes (max 256 bits) */
    unsigned int key_len;   /**< Actual key length in bytes */
    
    /* OpenSSL cipher context - all modes use ECB */
    EVP_CIPHER_CTX *cipher_ctx;  /**< For ECB operations (FF1/FF3/FF3-1) */
    
    /* Algorithm-specific data */
    union {
        struct {
            /* FF1-specific precomputed values */
            unsigned int minlen;
            unsigned int maxlen;
        } ff1;
        
        struct {
            /* FF3-specific precomputed values */
            unsigned int minlen;
            unsigned char reversed_key[32];  /**< FF3 uses reversed key */
        } ff3;
        
        struct {
            /* FF3-1-specific precomputed values */
            unsigned int minlen;
            unsigned char reversed_key[32];  /**< FF3-1 also uses reversed key */
        } ff3_1;
    } params;
};

/* Internal utility functions */

/**
 * @brief Initialize OpenSSL cipher context for AES
 */
int fpe_init_aes_context(FPE_CTX *ctx);

/**
 * @brief Initialize OpenSSL cipher context for SM4
 */
int fpe_init_sm4_context(FPE_CTX *ctx);

/**
 * @brief Reverse key bytes (required for FF3/FF3-1)
 */
void fpe_reverse_key(const unsigned char *key, unsigned char *reversed, unsigned int len);

/**
 * @brief Securely zero memory
 */
void fpe_secure_zero(void *ptr, size_t len);

#endif /* FPE_INTERNAL_H */
