/**
 * @file ff1.h
 * @brief FF1 Algorithm Internal Header
 */

#ifndef FF1_H
#define FF1_H

#include "fpe_internal.h"

/**
 * @brief FF1 encryption function
 */
int ff1_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief FF1 decryption function
 */
int ff1_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

#endif /* FF1_H */
