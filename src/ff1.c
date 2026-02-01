/**
 * @file ff1.c
 * @brief FF1 Algorithm Implementation (NIST SP 800-38G)
 * 
 * FF1 uses a 10-round Feistel network with AES-CMAC or SM4-CMAC
 * for the round function.
 */

#include "ff1.h"
#include "utils.h"
#include <string.h>
#include <math.h>

/* FF1 constants */
#define FF1_ROUNDS 10
#define FF1_BLOCK_SIZE 16

/**
 * @brief Calculate ceiling(a/b) for integers
 */
static inline unsigned int ceildiv(unsigned int a, unsigned int b) {
    return (a + b - 1) / b;
}

/**
 * @brief Convert numeral string to big integer (big-endian byte array)
 * 
 * Converts X[0..n-1] in radix to a big-endian byte representation
 */
static void num_to_bytes(const unsigned int *x, unsigned int len, unsigned int radix,
                         unsigned char *out, unsigned int out_len) {
    /* Start with zero */
    memset(out, 0, out_len);
    
    /* Convert numeral string to big integer using Horner's method */
    for (unsigned int i = 0; i < len; i++) {
        /* Multiply current result by radix and add next digit */
        unsigned int carry = x[i];
        for (int j = (int)out_len - 1; j >= 0; j--) {
            unsigned long long tmp = (unsigned long long)out[j] * radix + carry;
            out[j] = (unsigned char)(tmp & 0xFF);
            carry = (unsigned int)(tmp >> 8);
        }
    }
}

/**
 * @brief Convert big integer (big-endian byte array) to numeral string
 */
static void bytes_to_num(const unsigned char *bytes, unsigned int byte_len,
                         unsigned int *x, unsigned int len, unsigned int radix) {
    /* Start with zero */
    memset(x, 0, len * sizeof(unsigned int));
    
    /* Convert big integer to numeral string */
    unsigned char temp[256];
    memcpy(temp, bytes, byte_len);
    
    for (int i = (int)len - 1; i >= 0; i--) {
        /* Divide temp by radix, remainder goes to x[i] */
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
 * @brief FF1 Round Function using AES-ECB + CBC-MAC (not CMAC!)
 * 
 * Computes PRF(P || Q) using CBC-MAC construction:
 * 1. R = AES-ECB(P)
 * 2. For each block of Q: R = AES-ECB(Q_i XOR R)
 * 3. Extend R if needed using counter mode
 */
static int ff1_prf(FPE_CTX *ctx, const unsigned char *P, unsigned int P_len,
                   const unsigned char *Q, unsigned int Q_len,
                   unsigned char *S, unsigned int S_len) {
    if (!ctx->cipher_ctx) return -1;
    if (P_len != 16) return -1;  /* P must be exactly 16 bytes */
    
    unsigned char R[16];
    int outlen = 0;
    
    /* Step 1: R = AES-ECB(P) */
    if (!EVP_EncryptUpdate(ctx->cipher_ctx, R, &outlen, P, 16)) {
        return -1;
    }
    
    /* Step 2: CBC-MAC over Q */
    unsigned int num_q_blocks = Q_len / 16;
    for (unsigned int i = 0; i < num_q_blocks; i++) {
        unsigned char Ri[16];
        /* XOR current Q block with R */
        for (int j = 0; j < 16; j++) {
            Ri[j] = Q[i * 16 + j] ^ R[j];
        }
        /* R = AES-ECB(Ri) */
        if (!EVP_EncryptUpdate(ctx->cipher_ctx, R, &outlen, Ri, 16)) {
            return -1;
        }
    }
    
    /* Step 3: Now R contains the CBC-MAC result */
    if (S_len <= 16) {
        memcpy(S, R, S_len);
    } else {
        /* For S_len > 16, use counter mode to extend */
        memcpy(S, R, 16);
        
        unsigned int num_extra_blocks = ceildiv(S_len, 16) - 1;
        for (unsigned int j = 1; j <= num_extra_blocks; j++) {
            unsigned char tmp[16];
            memset(tmp, 0, 16);
            
            /* Big-endian counter at the end */
            tmp[15] = j & 0xff;
            tmp[14] = (j >> 8) & 0xff;
            tmp[13] = (j >> 16) & 0xff;
            tmp[12] = (j >> 24) & 0xff;
            
            /* XOR with R */
            for (int k = 0; k < 16; k++) {
                tmp[k] ^= R[k];
            }
            
            /* Encrypt */
            unsigned char SS[16];
            if (!EVP_EncryptUpdate(ctx->cipher_ctx, SS, &outlen, tmp, 16)) {
                return -1;
            }
            
            /* Copy to output */
            unsigned int copy_len = (j == num_extra_blocks) ? (S_len - j * 16) : 16;
            memcpy(S + j * 16, SS, copy_len);
        }
    }
    
    return 0;
}

/**
 * @brief FF1 Encryption
 */
int ff1_encrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !in || !out) return -1;
    if (len < 2 || len > 0xFFFFFFFF) return -1;  /* Minimum length requirement */
    
    unsigned int radix = ctx->radix;
    
    /* Compute split point */
    unsigned int u = len / 2;
    unsigned int v = len - u;
    
    /* Allocate working buffers for A and B */
    unsigned int A[256], B[256];
    if (len > 256) return -1;  /* Practical limit */
    
    memcpy(A, in, u * sizeof(unsigned int));
    memcpy(B, in + u, v * sizeof(unsigned int));
    
    /* Use pointers to track current A and B for swapping */
    unsigned int *pA = A;
    unsigned int *pB = B;
    
    /* Compute b = ceiling(ceiling(v * log2(radix)) / 8) */
    double log2_radix = log2((double)radix);
    unsigned int b = ceildiv((unsigned int)ceil(v * log2_radix), 8);
    
    /* Compute d = 4 * ceiling(b / 4) + 4 */
    unsigned int d = 4 * ceildiv(b, 4) + 4;
    
    /* Build P: [1][2][1][radix][10][u%256][len][tweak_len] */
    unsigned char P[16];
    P[0] = 1;  /* version */
    P[1] = 2;  /* method (CMAC) */
    P[2] = 1;  /* addition */
    P[3] = (unsigned char)((radix >> 16) & 0xFF);
    P[4] = (unsigned char)((radix >> 8) & 0xFF);
    P[5] = (unsigned char)(radix & 0xFF);
    P[6] = 10;  /* reserved */
    P[7] = (unsigned char)(u & 0xFF);
    P[8] = (unsigned char)((len >> 24) & 0xFF);
    P[9] = (unsigned char)((len >> 16) & 0xFF);
    P[10] = (unsigned char)((len >> 8) & 0xFF);
    P[11] = (unsigned char)(len & 0xFF);
    P[12] = (unsigned char)((tweak_len >> 24) & 0xFF);
    P[13] = (unsigned char)((tweak_len >> 16) & 0xFF);
    P[14] = (unsigned char)((tweak_len >> 8) & 0xFF);
    P[15] = (unsigned char)(tweak_len & 0xFF);
    
    #ifdef FF1_DEBUG
    printf("P vector: ");
    for (int i = 0; i < 16; i++) printf("%02x ", P[i]);
    printf("\n");
    printf("u=%u, v=%u, b=%u, d=%u\n", u, v, b, d);
    #endif
    
    /* 10 rounds */
    for (unsigned int i = 0; i < FF1_ROUNDS; i++) {
        /* m alternates between u and v based on round number */
        unsigned int m = (i & 1) ? v : u;
        unsigned int other_len = len - m;  /* Length of the B part */
        
        #ifdef FF1_DEBUG
        printf("Round %u: m=%u, other_len=%u\n", i, m, other_len);
        printf("  pA points to %s (size %u), first %u elements: ", 
               (pA == A) ? "A" : "B", (pA == A) ? u : v, m);
        for (unsigned int j = 0; j < m; j++) printf("%u", pA[j]);
        printf("\n  pB points to %s (size %u), first %u elements: ", 
               (pB == A) ? "A" : "B", (pB == A) ? u : v, other_len);
        for (unsigned int j = 0; j < other_len; j++) printf("%u", pB[j]);
        printf("\n");
        #endif
        
        /* Compute Q = T || [0]^(-t-b-1) || [i] || NUMradix(B) */
        unsigned char Q[256];
        unsigned int Q_len = 0;
        
        /* Add tweak */
        if (tweak_len > 0) {
            memcpy(Q + Q_len, tweak, tweak_len);
            Q_len += tweak_len;
        }
        
        /* Add padding: Q must be multiple of 16 bytes total */
        /* Padding formula: (-t - b - 1) mod 16 */
        int pad_amount = -(int)tweak_len - (int)b - 1;
        unsigned int padding_len = ((pad_amount % 16) + 16) % 16;
        memset(Q + Q_len, 0, padding_len);
        Q_len += padding_len;
        
        /* Add round number */
        Q[Q_len++] = (unsigned char)i;
        
        /* Add NUMradix(B) - B is the OTHER part (len - m characters) */
        unsigned char B_bytes[256];
        memset(Q + Q_len, 0, b);  // Clear the b bytes first
        num_to_bytes(pB, other_len, radix, B_bytes, b);
        memcpy(Q + Q_len, B_bytes, b);  // Copy b bytes
        Q_len += b;
        
        #ifdef FF1_DEBUG
        if (i == 0) {
            printf("  NUM(B) bytes: ");
            for (unsigned int j = 0; j < b; j++) printf("%02x ", B_bytes[j]);
            printf(" (from pB=");
            for (unsigned int j = 0; j < other_len; j++) printf("%u", pB[j]);
            printf(")\n");
        }
        #endif
        
        /* Compute S = PRF(P || Q) */
        unsigned char S[256];
        if (ff1_prf(ctx, P, 16, Q, Q_len, S, d) != 0) {
            return -1;
        }
        
        #ifdef FF1_DEBUG
        if (i == 0) {  // Only print for first round
            printf("  Q (len=%u): ", Q_len);
            for (unsigned int j = 0; j < Q_len; j++) printf("%02x ", Q[j]);
            printf("\n");
            printf("  S (first %u bytes): ", d);
            for (unsigned int j = 0; j < d; j++) printf("%02x ", S[j]);
            printf("\n");
        }
        #endif
        
        /* Convert S to integer y */
        unsigned char y_bytes[256];
        memcpy(y_bytes, S, d);  // Use d bytes, not b bytes!
        
        /* Convert y_bytes to numeral */
        unsigned int y_num[256];
        bytes_to_num(y_bytes, d, y_num, m, radix);  // Use d bytes!
        
        #ifdef FF1_DEBUG
        if (i == 0) {
            printf("  y_num: ");
            for (unsigned int j = 0; j < m; j++) printf("%u", y_num[j]);
            printf("\n");
        }
        #endif
        
        /* Compute c = (NUM(A) + y) mod radix^m */
        /* Add A + y mod radix for each digit */
        unsigned int carry = 0;
        for (int j = (int)m - 1; j >= 0; j--) {
            unsigned long long sum = (unsigned long long)pA[j] + y_num[j] + carry;
            pA[j] = (unsigned int)(sum % radix);
            carry = (unsigned int)(sum / radix);
        }
        
        #ifdef FF1_DEBUG
        printf("  After addition: pA=");
        for (unsigned int j = 0; j < m; j++) printf("%u", pA[j]);
        printf("\n");
        #endif
        
        /* Swap pointers A and B after each round (including the last one) */
        unsigned int *swap_ptr = pA;
        pA = pB;
        pB = swap_ptr;
        
        #ifdef FF1_DEBUG
        printf("  After swap: pA=");
        unsigned int check_len_a = (i & 1) ? u : v;  // After swap, what length?
        // Actually after swap, pA points to what was pB
        // In round 0: before swap pA had u elements, pB had v elements
        // After swap: pA points to B (v elements), pB points to A (u elements)
        // But wait, A and B arrays have fixed sizes!
        // Let me just print 5 elements for now
        for (unsigned int j = 0; j < 5; j++) printf("%u", pA[j]);
        printf(", pB=");
        for (unsigned int j = 0; j < 5; j++) printf("%u", pB[j]);
        printf("\n");
        #endif
    }
    
    /* After 10 swaps (even number), pointers are back to original positions.
     * pA points to A buffer, pB points to B buffer.
     * Final output is A || B which is u characters followed by v characters.
     */
    #ifdef FF1_DEBUG
    printf("Final: pA=");
    for (unsigned int j = 0; j < u; j++) printf("%u", pA[j]);
    printf(", pB=");
    for (unsigned int j = 0; j < v; j++) printf("%u", pB[j]);
    printf("\n");
    printf("Output will be: pA || pB\n");
    #endif
    
    /* Concatenate A || B */
    memcpy(out, pA, u * sizeof(unsigned int));
    memcpy(out + u, pB, v * sizeof(unsigned int));
    
    return 0;
}

/**
 * @brief FF1 Decryption (reverse of encryption)
 */
int ff1_decrypt(FPE_CTX *ctx, const unsigned int *in, unsigned int *out,
                unsigned int len, const unsigned char *tweak, unsigned int tweak_len) {
    if (!ctx || !in || !out) return -1;
    if (len < 2) return -1;
    
    unsigned int radix = ctx->radix;
    
    /* Compute split point */
    unsigned int u = len / 2;
    unsigned int v = len - u;
    
    /* Allocate working buffers for A and B */
    unsigned int A[256], B[256];
    if (len > 256) return -1;
    
    memcpy(A, in, u * sizeof(unsigned int));
    memcpy(B, in + u, v * sizeof(unsigned int));
    
    /* Use pointers to track current A and B for swapping */
    unsigned int *pA = A;
    unsigned int *pB = B;
    
    /* Compute parameters (same as encryption) */
    double log2_radix = log2((double)radix);
    unsigned int b = ceildiv((unsigned int)ceil(v * log2_radix), 8);
    unsigned int d = 4 * ceildiv(b, 4) + 4;
    
    /* Build P (same as encryption) */
    unsigned char P[16];
    P[0] = 1;
    P[1] = 2;
    P[2] = 1;
    P[3] = (unsigned char)((radix >> 16) & 0xFF);
    P[4] = (unsigned char)((radix >> 8) & 0xFF);
    P[5] = (unsigned char)(radix & 0xFF);
    P[6] = 10;
    P[7] = (unsigned char)(u & 0xFF);
    P[8] = (unsigned char)((len >> 24) & 0xFF);
    P[9] = (unsigned char)((len >> 16) & 0xFF);
    P[10] = (unsigned char)((len >> 8) & 0xFF);
    P[11] = (unsigned char)(len & 0xFF);
    P[12] = (unsigned char)((tweak_len >> 24) & 0xFF);
    P[13] = (unsigned char)((tweak_len >> 16) & 0xFF);
    P[14] = (unsigned char)((tweak_len >> 8) & 0xFF);
    P[15] = (unsigned char)(tweak_len & 0xFF);
    
    /* 10 rounds in reverse */
    for (int i = FF1_ROUNDS - 1; i >= 0; i--) {
        /* Swap pointers A and B first (opposite of encryption where we swap after) */
        unsigned int *swap_ptr = pA;
        pA = pB;
        pB = swap_ptr;
        
        /* m alternates between u and v based on round number */
        unsigned int m = (i & 1) ? v : u;
        unsigned int other_len = len - m;  /* Length of the B part */
        
        /* Compute Q (same as encryption) */
        unsigned char Q[256];
        unsigned int Q_len = 0;
        
        if (tweak_len > 0) {
            memcpy(Q + Q_len, tweak, tweak_len);
            Q_len += tweak_len;
        }
        
        /* Add padding: (-t - b - 1) mod 16 */
        int pad_amount = -(int)tweak_len - (int)b - 1;
        unsigned int padding_len = ((pad_amount % 16) + 16) % 16;
        memset(Q + Q_len, 0, padding_len);
        Q_len += padding_len;
        
        Q[Q_len++] = (unsigned char)i;
        
        /* Add NUMradix(B) - B is the OTHER part (len - m characters) */
        unsigned char B_bytes[256];
        memset(Q + Q_len, 0, b);
        num_to_bytes(pB, other_len, radix, B_bytes, b);
        memcpy(Q + Q_len, B_bytes, b);
        Q_len += b;
        
        /* Compute S */
        unsigned char S[256];
        if (ff1_prf(ctx, P, 16, Q, Q_len, S, d) != 0) {
            return -1;
        }
        
        /* Convert S to integer y - USE D BYTES, NOT B! */
        unsigned char y_bytes[256];
        memcpy(y_bytes, S, d);
        
        unsigned int y_num[256];
        bytes_to_num(y_bytes, d, y_num, m, radix);
        
        /* Compute c = (NUM(A) - y) mod radix^m */
        /* Subtract A - y mod radix for each digit */
        int borrow = 0;
        for (int j = (int)m - 1; j >= 0; j--) {
            long long diff = (long long)pA[j] - y_num[j] - borrow;
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
