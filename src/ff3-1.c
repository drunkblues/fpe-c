/**
 * @file ff3-1.c
 * @brief FF3-1 Algorithm Implementation (NIST SP 800-38G Rev 1)
 * 
 * FF3-1 is the secure revision of FF3, fixing security vulnerabilities.
 * Main differences from FF3:
 * - Tweak is exactly 56 bits (7 bytes)
 * - Different tweak processing to address security issues
 */

#include "ff3-1.h"
#include "utils.h"
#include <string.h>
#include <math.h>
#include <openssl/evp.h>

/* FF3-1 constants */
#define FF3_1_ROUNDS 8
#define FF3_1_BLOCK_SIZE 16

/**
 * @brief Calculate ceiling(a/b) for integers
 */
static inline unsigned int ceildiv(unsigned int a, unsigned int b) {
    return (a + b - 1) / b;
}

/**
 * @brief Convert numeral string to big integer (reversed order for FF3-1)
 */
static void num_to_bytes_rev(const unsigned int *x, unsigned int len, unsigned int radix,
                              unsigned char *out, unsigned int out_len) {
    memset(out, 0, out_len);
    
    /* Process digits from last to first (reversed) */
    for (int i = (int)len - 1; i >= 0; i--) {
        unsigned int carry = x[i];
        for (int j = (int)out_len - 1; j >= 0; j--) {
            unsigned long long tmp = (unsigned long long)out[j] * radix + carry;
            out[j] = (unsigned char)(tmp & 0xFF);
            carry = (unsigned int)(tmp >> 8);
        }
    }
}

/**
 * @brief Convert big integer to numeral string (reversed order for FF3-1)
 * 
 * Processes from i=0 to i=len-1: x[i] = (bytes % radix), then bytes /= radix
 */
static void bytes_to_num_rev(const unsigned char *bytes, unsigned int byte_len,
                              unsigned int *x, unsigned int len, unsigned int radix) {
    memset(x, 0, len * sizeof(unsigned int));
    
    unsigned char temp[256];
    memcpy(temp, bytes, byte_len);
    
    /* Generate digits from i=0 to i=len-1 (reversed output) */
    for (unsigned int i = 0; i < len; i++) {
        unsigned int remainder = 0;
        for (unsigned int j = 0; j < byte_len; j++) {
            unsigned long long tmp = ((unsigned long long)remainder << 8) | temp[j];
            temp[j] = (unsigned char)(tmp / radix);
            remainder = (unsigned int)(tmp % radix);
        }
        x[i] = remainder;
    }
}

/**
 * @brief Convert numeral string to big integer (big-endian byte array)
 */
static void num_to_bytes(const unsigned int *x, unsigned int len, unsigned int radix,
                         unsigned char *out, unsigned int out_len) {
    memset(out, 0, out_len);
    
    for (unsigned int i = 0; i < len; i++) {
        unsigned int carry = x[i];
        for (int j = (int)out_len - 1; j >= 0; j--) {
            unsigned long long tmp = (unsigned long long)out[j] * radix + carry;
            out[j] = (unsigned char)(tmp & 0xFF);
            carry = (unsigned int)(tmp >> 8);
        }
    }
}

/**
 * @brief Convert big integer to numeral string
 */
static void bytes_to_num(const unsigned char *bytes, unsigned int byte_len,
                         unsigned int *x, unsigned int len, unsigned int radix) {
    memset(x, 0, len * sizeof(unsigned int));
    
    unsigned char temp[256];
    memcpy(temp, bytes, byte_len);
    
    for (int i = (int)len - 1; i >= 0; i--) {
        unsigned int remainder = 0;
        for (unsigned int j = 0; j < byte_len; j++) {
            unsigned long long tmp = ((unsigned long long)remainder << 8) | temp[j];
            temp[j] = (unsigned char)(tmp / radix);
            remainder = (unsigned int)(tmp % radix);
        }
        x[i] = remainder;
    }
}

/**
 * @brief FF3-1 Round Function using AES-ECB
 * 
 * Similar to FF3 but with modified tweak handling for security
 */
static int ff3_1_round_encrypt(FPE_CTX *ctx, const unsigned char *T, unsigned int round,
                               const unsigned int *B, unsigned int B_len,
                               unsigned int radix, unsigned char *W, unsigned int W_len) {
    if (!ctx->cipher_ctx) return -1;
    
    /* Build plaintext for ECB encryption */
    unsigned char plaintext[FF3_1_BLOCK_SIZE];
    memset(plaintext, 0, FF3_1_BLOCK_SIZE);
    
    /* FF3-1 tweak processing:
     * For even rounds: use Tl (first 28 bits) || 0^4 || round || NUM(B)
     * For odd rounds:  use Tr (last 28 bits) || 0^4 || round || NUM(B)
     */
    
    /* Copy tweak portion (4 bytes) */
    memcpy(plaintext, T, 4);
    
    /* XOR round number into last byte of tweak section */
    plaintext[3] ^= (unsigned char)round;
    
    /* Add NUM(B) to the right side - use REVERSED order for FF3-1 */
    unsigned int b = ceildiv((unsigned int)ceil(B_len * log2((double)radix)), 8);
    if (b > 12) b = 12;
    
    num_to_bytes_rev(B, B_len, radix, plaintext + (FF3_1_BLOCK_SIZE - b), b);
    
    /* Reverse bytes before encryption (FF3-1 spec requirement) */
    fpe_reverse_bytes(plaintext, FF3_1_BLOCK_SIZE);
    
    /* Encrypt with ECB */
    unsigned char ciphertext[FF3_1_BLOCK_SIZE];
    int outlen = 0;
    
    if (!EVP_EncryptUpdate(ctx->cipher_ctx, ciphertext, &outlen, plaintext, FF3_1_BLOCK_SIZE)) {
        return -1;
    }
    
    /* Reverse bytes after encryption (FF3-1 spec requirement) */
    fpe_reverse_bytes(ciphertext, FF3_1_BLOCK_SIZE);
    
    /* Copy to output */
    memcpy(W, ciphertext, (W_len < FF3_1_BLOCK_SIZE) ? W_len : FF3_1_BLOCK_SIZE);
    
    return 0;
}

/**
 * @brief FF3-1 Encryption
 */
int ff3_1_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                  unsigned int len, const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !in || !out) return -1;
    if (len < 2 || len > 256) return -1;
    
    /* FF3-1 requires exactly 56 bits (7 bytes) tweak, or 64 bits with 8 bits ignored */
    if (tweak_len != 7 && tweak_len != 8 && tweak_len != 0) return -1;
    
    unsigned int radix = ctx->radix;
    
    /* Compute split point - u should be the larger half for odd lengths */
    unsigned int u = (len + 1) / 2;  /* Ceiling division */
    unsigned int v = len - u;
    
    /* Working buffers */
    unsigned int A[256], B[256];
    memcpy(A, in, u * sizeof(unsigned int));
    memcpy(B, in + u, v * sizeof(unsigned int));
    
    /* Use pointers for swapping */
    unsigned int *pA = A;
    unsigned int *pB = B;
    
    /* Process tweak: split into Tl (28 bits = 3.5 bytes) and Tr (28 bits) 
     * For simplicity, use 4 bytes for each half */
    unsigned char Tl[4] = {0};
    unsigned char Tr[4] = {0};
    
    if (tweak_len >= 7) {
        /* Tl = bits 0-27 (bytes 0-2 + high 4 bits of byte 3) */
        Tl[0] = tweak[0];
        Tl[1] = tweak[1];
        Tl[2] = tweak[2];
        Tl[3] = tweak[3] & 0xF0;  /* Only high 4 bits of byte 3 */
        
        /* Tr = bits 28-55 (low 4 bits of byte 3 + bytes 4-6) */
        Tr[0] = tweak[3] & 0x0F;  /* Only low 4 bits of byte 3 */
        Tr[1] = tweak[4];
        Tr[2] = tweak[5];
        Tr[3] = tweak[6];
    }
    
    /* 8 rounds */
    for (unsigned int i = 0; i < FF3_1_ROUNDS; i++) {
        /* Select tweak half based on round 
         * Odd rounds (i=1,3,5,7): use Tl (first 28 bits)
         * Even rounds (i=0,2,4,6): use Tr (last 28 bits)
         */
        unsigned char *T = (i & 1) ? Tl : Tr;
        
        /* Compute m based on round number */
        unsigned int m = (i & 1) ? v : u;
        unsigned int other_len = len - m;
        
        /* Compute W = Round_Encrypt(T, i, B) */
        unsigned int b = ceildiv((unsigned int)ceil(other_len * log2((double)radix)), 8);
        if (b > 16) b = 16;
        
        unsigned char W[16];
        if (ff3_1_round_encrypt(ctx, T, i, pB, other_len, radix, W, 16) != 0) {
            return -1;
        }
        
        /* Convert W to numeral - use full 16 bytes with REVERSED order */
        unsigned int y[256];
        bytes_to_num_rev(W, 16, y, m, radix);
        
        /* Compute c = (NUM(A) + y) mod radix^m
         * In reversed order, position 0 is least significant digit
         * So add from position 0 (low) to position m-1 (high)
         */
        unsigned int carry = 0;
        for (unsigned int j = 0; j < m; j++) {
            unsigned long long sum = (unsigned long long)pA[j] + y[j] + carry;
            pA[j] = (unsigned int)(sum % radix);
            carry = (unsigned int)(sum / radix);
        }
        
        /* Swap A and B after every round */
        unsigned int *swap = pA;
        pA = pB;
        pB = swap;
    }
    
    /* Concatenate A || B */
    memcpy(out, pA, u * sizeof(unsigned int));
    memcpy(out + u, pB, v * sizeof(unsigned int));
    
    return 0;
}

/**
 * @brief FF3-1 Decryption
 */
int ff3_1_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                  unsigned int len, const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !in || !out) return -1;
    if (len < 2 || len > 256) return -1;
    
    if (tweak_len != 7 && tweak_len != 8 && tweak_len != 0) return -1;
    
    unsigned int radix = ctx->radix;
    
    /* Compute split point - u should be the larger half for odd lengths */
    unsigned int u = (len + 1) / 2;  /* Ceiling division */
    unsigned int v = len - u;
    
    /* Working buffers */
    unsigned int A[256], B[256];
    memcpy(A, in, u * sizeof(unsigned int));
    memcpy(B, in + u, v * sizeof(unsigned int));
    
    /* Use pointers for swapping */
    unsigned int *pA = A;
    unsigned int *pB = B;
    
    /* Process tweak */
    unsigned char Tl[4] = {0};
    unsigned char Tr[4] = {0};
    
    if (tweak_len >= 7) {
        /* Tl = bits 0-27 (bytes 0-2 + high 4 bits of byte 3) */
        Tl[0] = tweak[0];
        Tl[1] = tweak[1];
        Tl[2] = tweak[2];
        Tl[3] = tweak[3] & 0xF0;  /* Only high 4 bits of byte 3 */
        
        /* Tr = bits 28-55 (low 4 bits of byte 3 + bytes 4-6) */
        Tr[0] = tweak[3] & 0x0F;  /* Only low 4 bits of byte 3 */
        Tr[1] = tweak[4];
        Tr[2] = tweak[5];
        Tr[3] = tweak[6];
    }
    
    /* 8 rounds in reverse */
    for (int i = FF3_1_ROUNDS - 1; i >= 0; i--) {
        /* Swap first (opposite of encryption) */
        unsigned int *swap = pA;
        pA = pB;
        pB = swap;
        
        /* Select tweak half 
         * Odd rounds (i=1,3,5,7): use Tl (first 28 bits)
         * Even rounds (i=0,2,4,6): use Tr (last 28 bits)
         */
        unsigned char *T = (i & 1) ? Tl : Tr;
        
        /* Compute m based on round number */
        unsigned int m = (i & 1) ? v : u;
        unsigned int other_len = len - m;
        
        /* Compute W */
        unsigned int b = ceildiv((unsigned int)ceil(other_len * log2((double)radix)), 8);
        if (b > 16) b = 16;
        
        unsigned char W[16];
        if (ff3_1_round_encrypt(ctx, T, (unsigned int)i, pB, other_len, radix, W, 16) != 0) {
            return -1;
        }
        
        /* Convert W to numeral - use full 16 bytes with REVERSED order */
        unsigned int y[256];
        bytes_to_num_rev(W, 16, y, m, radix);
        
        /* Compute c = (NUM(A) - y) mod radix^m
         * In reversed order, position 0 is least significant digit
         * So subtract from position 0 (low) to position m-1 (high)
         */
        int borrow = 0;
        for (unsigned int j = 0; j < m; j++) {
            long long diff = (long long)pA[j] - y[j] - borrow;
            if (diff < 0) {
                diff += radix;
                borrow = 1;
            } else {
                borrow = 0;
            }
            pA[j] = (unsigned int)diff;
        }
    }
    
    /* Concatenate A || B */
    memcpy(out, pA, u * sizeof(unsigned int));
    memcpy(out + u, pB, v * sizeof(unsigned int));
    
    return 0;
}
