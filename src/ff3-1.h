/**
 * @file ff3-1.h
 * @brief FF3-1 Algorithm Internal Header
 */

#ifndef FF3_1_H
#define FF3_1_H

#include "fpe_internal.h"

/**
 * @brief FF3-1 encryption function
 */
int ff3_1_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                  unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

/**
 * @brief FF3-1 decryption function
 */
int ff3_1_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                  unsigned int len, const unsigned char *tweak, unsigned int tweak_len);

#endif /* FF3_1_H */
