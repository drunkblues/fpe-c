/**
 * @file fpe.h
 * @brief Format Preserving Encryption (FPE) API
 *
 * This header defines the interface for FPE FF1, FF3, and FF3-1 algorithms.
 * Conforms to NIST SP 800-38G.
 */

#ifndef HSM_FPE_H
#define HSM_FPE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/**
 * @brief Supported Underlying Encryption Algorithms
 */
typedef enum {
    FPE_ALGO_AES = 0, /**< AES Algorithm */
    FPE_ALGO_SM4 = 1  /**< SM4 Algorithm */
} FPE_ALGO;

/**
 * @brief Supported FPE Modes
 */
typedef enum {
    FPE_MODE_FF1 = 0,
    FPE_MODE_FF3 = 1, /* Deprecated by NIST, retained for legacy */
    FPE_MODE_FF3_1 = 2
} FPE_MODE;

/**
 * @struct fpe_ctx_st
 * @brief Opaque FPE Context Structure
 */
typedef struct fpe_ctx_st FPE_CTX;

/**
 * @brief Create a new FPE Context
 */
FPE_CTX *FPE_CTX_new(void);

/**
 * @brief Free FPE Context
 */
void FPE_CTX_free(FPE_CTX *ctx);

/**
 * @brief Initialize FPE Context
 *
 * @param ctx The context object.
 * @param mode FPE mode (FF1, FF3, FF3_1).
 * @param algo Underlying cipher (AES, SM4).
 * @param key The secret key bytes.
 * @param bits Key length in bits (128, 192, 256 for AES; 128 for SM4).
 * @param radix The radix (base) of the data.
 * @return 0 on success, non-zero on failure.
 */
int FPE_CTX_init(FPE_CTX *ctx,
                 FPE_MODE mode,
                 FPE_ALGO algo,
                 const unsigned char *key,
                 unsigned int bits,
                 unsigned int radix);

/* ========================================================================= */
/*                           Unified Generic Interface                       */
/* ========================================================================= */

/**
 * @brief Generic Encrypt Function
 *
 * Automatically dispatches to FF1/FF3/FF3-1 based on context mode.
 *
 * @param ctx Initialized FPE context.
 * @param in Input numeral string (array of integers).
 * @param out Output buffer.
 * @param len Length of numeral string.
 * @param tweak Tweak bytes.
 * @param tweak_len Length of tweak (Must match requirement for FF3/FF3-1).
 * @return 0 on success, -1 on failure (e.g. invalid tweak len for mode).
 */
int FPE_encrypt(FPE_CTX *ctx,
                const unsigned int *in, unsigned int *out, unsigned int len,
                const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief Generic Decrypt Function
 */
int FPE_decrypt(FPE_CTX *ctx,
                const unsigned int *in, unsigned int *out, unsigned int len,
                const unsigned char *tweak, unsigned int tweak_len);

/* ========================================================================= */
/*                           String / Helper Interface                       */
/* ========================================================================= */

/**
 * @brief Encrypt a string using a custom alphabet
 *
 * Maps characters from the input string to integers based on the 'alphabet',
 * encrypts them, and maps back to characters.
 *
 * @param ctx Initialized FPE context. (Radix must match strlen(alphabet))
 * @param alphabet The set of allowed characters (e.g., "0123456789").
 * @param in Input string (must only contain chars from alphabet).
 * @param out Output string buffer (must be at least strlen(in) + 1).
 * @param tweak Tweak bytes.
 * @param tweak_len Length of tweak.
 * @return 0 on success, -1 on failure (invalid char or encryption error).
 */
int FPE_encrypt_str(FPE_CTX *ctx, const char *alphabet,
                    const char *in, char *out,
                    const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief Decrypt a string using a custom alphabet
 */
int FPE_decrypt_str(FPE_CTX *ctx, const char *alphabet,
                    const char *in, char *out,
                    const unsigned char *tweak, unsigned int tweak_len);

/* ========================================================================= */
/*                           Convenience / Stateless Interface               */
/* ========================================================================= */

/**
 * @brief One-shot raw encryption function (Stateless)
 *
 * Creates a context, encrypts the raw integer array, and frees the context.
 *
 * @param mode FPE mode
 * @param algo Underlying algo
 * @param key Key bytes
 * @param key_bits Key bits
 * @param radix Radix
 * @param in Input integer array
 * @param out Output buffer
 * @param len Length of integer array
 * @param tweak Tweak bytes
 * @param tweak_len Tweak length
 * @return 0 on success, -1 on failure.
 */
int FPE_encrypt_oneshot(FPE_MODE mode, FPE_ALGO algo,
                        const unsigned char *key, unsigned int key_bits,
                        unsigned int radix,
                        const unsigned int *in, unsigned int *out, unsigned int len,
                        const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief One-shot raw decryption function (Stateless)
 */
int FPE_decrypt_oneshot(FPE_MODE mode, FPE_ALGO algo,
                        const unsigned char *key, unsigned int key_bits,
                        unsigned int radix,
                        const unsigned int *in, unsigned int *out, unsigned int len,
                        const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief One-shot string encryption function (Stateless)
 *
 * Creates a context, encrypts the string data, and frees the context.
 * Useful for simple or one-off operations on strings.
 *
 * @param mode FPE mode (FF1, FF3_1, etc.)
 * @param algo Underlying algo (AES, SM4)
 * @param key Key bytes
 * @param key_bits Key bits
 * @param alphabet Alphabet string (determines radix)
 * @param in Input string
 * @param out Output buffer
 * @param tweak Tweak bytes
 * @param tweak_len Tweak length
 * @return 0 on success, -1 on failure.
 */
int FPE_encrypt_str_oneshot(FPE_MODE mode, FPE_ALGO algo,
                            const unsigned char *key, unsigned int key_bits,
                            const char *alphabet,
                            const char *in, char *out,
                            const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief One-shot string decryption function (Stateless)
 */
int FPE_decrypt_str_oneshot(FPE_MODE mode, FPE_ALGO algo,
                            const unsigned char *key, unsigned int key_bits,
                            const char *alphabet,
                            const char *in, char *out,
                            const unsigned char *tweak, unsigned int tweak_len);

#ifdef __cplusplus
}
#endif

#endif
