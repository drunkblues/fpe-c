/**
 * @file ff3.h
 * @brief FF3 Algorithm Internal Header (DEPRECATED)
 */

#ifndef FF3_H
#define FF3_H

#include "fpe_internal.h"

/**
 * @brief FF3 encryption function
 */
int ff3_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief FF3 decryption function
 */
int ff3_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

#endif /* FF3_H */
