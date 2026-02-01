/**
 * @file test_vectors.c
 * @brief NIST SP 800-38G and SM4 Test Vector Validation
 * 
 * Tests all 50 test vectors (39 AES + 11 SM4):
 * - FF1: 9 AES vectors + 4 SM4 vectors
 * - FF3: 15 AES vectors + 3 SM4 vectors (deprecated)
 * - FF3-1: 15 AES vectors + 4 SM4 vectors
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "fpe.h"
#include "vectors.h"

/* Helper: Parse algorithm name to determine algo and key bits */
static int parse_algo_name(const char *alg_name, FPE_ALGO *algo, unsigned int *key_bits) {
    if (strncmp(alg_name, "AES-", 4) == 0) {
        *algo = FPE_ALGO_AES;
        *key_bits = atoi(alg_name + 4);
        return 0;
    } else if (strncmp(alg_name, "SM4-", 4) == 0) {
        *algo = FPE_ALGO_SM4;
        *key_bits = 128;  /* SM4 only supports 128-bit keys */
        return 0;
    }
    return -1;
}

/* Helper: Convert hex string to bytes */
static int hex_to_bytes(const char *hex, unsigned char *bytes, size_t *out_len) {
    if (!hex || !bytes || !out_len) return -1;
    
    size_t hex_len = strlen(hex);
    if (hex_len == 0) {
        *out_len = 0;
        return 0;
    }
    
    if (hex_len % 2 != 0) return -1;  /* Must be even length */
    
    size_t byte_len = hex_len / 2;
    for (size_t i = 0; i < byte_len; i++) {
        unsigned int byte_val;
        if (sscanf(hex + 2*i, "%2x", &byte_val) != 1) {
            return -1;
        }
        bytes[i] = (unsigned char)byte_val;
    }
    
    *out_len = byte_len;
    return 0;
}

/* Helper: Generate alphabet for given radix */
static void generate_alphabet(unsigned int radix, char *alphabet) {
    if (radix <= 10) {
        /* Digits only: "0123456789" */
        for (unsigned int i = 0; i < radix; i++) {
            alphabet[i] = '0' + i;
        }
        alphabet[radix] = '\0';
    } else if (radix <= 36) {
        /* Digits + lowercase letters: "0123456789abcdefghijklmnopqrstuvwxyz" */
        for (unsigned int i = 0; i < 10; i++) {
            alphabet[i] = '0' + i;
        }
        for (unsigned int i = 10; i < radix; i++) {
            alphabet[i] = 'a' + (i - 10);
        }
        alphabet[radix] = '\0';
    } else {
        /* Extended ASCII for higher radixes */
        for (unsigned int i = 0; i < radix && i < 256; i++) {
            alphabet[i] = (char)(33 + i);  /* Start from '!' */
        }
        alphabet[radix] = '\0';
    }
}

/* Helper: Test a single vector */
static int test_single_vector(const fpe_test_vector_t *vec, int vector_num) {
    FPE_ALGO algo;
    unsigned int key_bits;
    
    /* Parse algorithm */
    if (parse_algo_name(vec->alg_name, &algo, &key_bits) != 0) {
        printf("  [%d] SKIP: Unknown algorithm '%s'\n", vector_num, vec->alg_name);
        return -1;
    }
    
#ifndef HAVE_OPENSSL_SM4
    /* Skip SM4 tests if not compiled with SM4 support */
    if (algo == FPE_ALGO_SM4) {
        printf("  [%d] SKIP: SM4 not supported (compiled without HAVE_OPENSSL_SM4)\n", vector_num);
        return 0;
    }
#endif
    
    /* Parse key */
    unsigned char key[64];
    size_t key_len;
    if (hex_to_bytes(vec->key_hex, key, &key_len) != 0) {
        printf("  [%d] FAIL: Invalid key hex\n", vector_num);
        return -1;
    }
    
    /* Parse tweak */
    unsigned char tweak[256];
    size_t tweak_len;
    if (hex_to_bytes(vec->tweak_hex, tweak, &tweak_len) != 0) {
        printf("  [%d] FAIL: Invalid tweak hex\n", vector_num);
        return -1;
    }
    
    /* Create context */
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        printf("  [%d] FAIL: FPE_CTX_new failed\n", vector_num);
        return -1;
    }
    
    /* Initialize context */
    if (FPE_CTX_init(ctx, vec->mode, algo, key, key_bits, vec->radix) != 0) {
        printf("  [%d] FAIL: FPE_CTX_init failed\n", vector_num);
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Generate alphabet */
    char alphabet[257];
    generate_alphabet(vec->radix, alphabet);
    
    /* Test encryption */
    char ciphertext[512];
    if (FPE_encrypt_str(ctx, alphabet, vec->plaintext, ciphertext,
                        tweak, (unsigned int)tweak_len) != 0) {
        printf("  [%d] FAIL: FPE_encrypt_str failed\n", vector_num);
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Verify ciphertext */
    if (strcmp(ciphertext, vec->ciphertext) != 0) {
        printf("  [%d] FAIL: Ciphertext mismatch\n", vector_num);
        printf("      Mode: %s-%s\n", vec->alg_name, 
               (vec->mode == FPE_MODE_FF1) ? "FF1" :
               (vec->mode == FPE_MODE_FF3) ? "FF3" : "FF3-1");
        printf("      Radix: %u\n", vec->radix);
        printf("      Plaintext:  %s\n", vec->plaintext);
        printf("      Expected:   %s\n", vec->ciphertext);
        printf("      Got:        %s\n", ciphertext);
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Test decryption (reversibility) */
    char decrypted[512];
    if (FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted,
                        tweak, (unsigned int)tweak_len) != 0) {
        printf("  [%d] FAIL: FPE_decrypt_str failed\n", vector_num);
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Verify decryption matches original plaintext */
    if (strcmp(decrypted, vec->plaintext) != 0) {
        printf("  [%d] FAIL: Decryption mismatch\n", vector_num);
        printf("      Mode: %s-%s\n", vec->alg_name,
               (vec->mode == FPE_MODE_FF1) ? "FF1" :
               (vec->mode == FPE_MODE_FF3) ? "FF3" : "FF3-1");
        printf("      Original:   %s\n", vec->plaintext);
        printf("      Decrypted:  %s\n", decrypted);
        FPE_CTX_free(ctx);
        return -1;
    }
    
    printf("  [%d] PASS: %s-%s (radix=%u, plen=%lu, tlen=%lu)\n",
           vector_num, vec->alg_name,
           (vec->mode == FPE_MODE_FF1) ? "FF1" :
           (vec->mode == FPE_MODE_FF3) ? "FF3" : "FF3-1",
           vec->radix, strlen(vec->plaintext), tweak_len);
    
    FPE_CTX_free(ctx);
    return 0;
}

int main(void) {
    printf("=================================================\n");
    printf(" FPE Test Vector Validation (NIST SP 800-38G)\n");
    printf("=================================================\n\n");
    
    int total = 0;
    int passed = 0;
    int failed = 0;
    int skipped = 0;
    
    /* Count and categorize vectors */
    int ff1_count = 0, ff3_count = 0, ff3_1_count = 0;
    int aes_count = 0, sm4_count = 0;
    
    for (int i = 0; test_vectors[i].alg_name != NULL; i++) {
        total++;
        
        /* Categorize by mode */
        if (test_vectors[i].mode == FPE_MODE_FF1) ff1_count++;
        else if (test_vectors[i].mode == FPE_MODE_FF3) ff3_count++;
        else if (test_vectors[i].mode == FPE_MODE_FF3_1) ff3_1_count++;
        
        /* Categorize by algorithm */
        if (strncmp(test_vectors[i].alg_name, "AES-", 4) == 0) aes_count++;
        else if (strncmp(test_vectors[i].alg_name, "SM4-", 4) == 0) sm4_count++;
    }
    
    printf("Total test vectors: %d\n", total);
    printf("  FF1:   %d vectors\n", ff1_count);
    printf("  FF3:   %d vectors (deprecated)\n", ff3_count);
    printf("  FF3-1: %d vectors\n", ff3_1_count);
    printf("  AES:   %d vectors\n", aes_count);
    printf("  SM4:   %d vectors\n\n", sm4_count);
    
    /* Run all tests */
    printf("Running tests...\n");
    for (int i = 0; test_vectors[i].alg_name != NULL; i++) {
        int result = test_single_vector(&test_vectors[i], i + 1);
        if (result == 0) {
            passed++;
        } else if (result == -1) {
            /* Check if it was skipped */
            FPE_ALGO algo;
            unsigned int key_bits;
            if (parse_algo_name(test_vectors[i].alg_name, &algo, &key_bits) == 0) {
#ifndef HAVE_OPENSSL_SM4
                if (algo == FPE_ALGO_SM4) {
                    skipped++;
                    continue;
                }
#endif
            }
            failed++;
        }
    }
    
    /* Print summary */
    printf("\n=================================================\n");
    printf(" Test Summary\n");
    printf("=================================================\n");
    printf("Total:   %d\n", total);
    printf("Passed:  %d\n", passed);
    printf("Failed:  %d\n", failed);
    printf("Skipped: %d\n", skipped);
    
    if (failed == 0) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ %d test(s) failed\n", failed);
        return 1;
    }
}
