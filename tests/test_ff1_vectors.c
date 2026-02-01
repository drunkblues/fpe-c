/**
 * @file test_ff1_vectors.c
 * @brief Comprehensive NIST FF1 test vectors validation
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include "vectors.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Helper function to run a single test vector */
static int run_ff1_vector(const fpe_test_vector_t *vec) {
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    /* Parse key */
    unsigned char key[32];
    int key_len = fpe_hex_to_bytes(vec->key_hex, key, 32);
    if (key_len < 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Determine algorithm */
    FPE_ALGO algo;
    if (strncmp(vec->alg_name, "SM4", 3) == 0) {
#ifdef HAVE_OPENSSL_SM4
        algo = FPE_ALGO_SM4;
#else
        FPE_CTX_free(ctx);
        return -2;  /* Skip SM4 tests if not supported */
#endif
    } else {
        algo = FPE_ALGO_AES;
    }
    
    /* Initialize context */
    if (FPE_CTX_init(ctx, vec->mode, algo, key, key_len * 8, vec->radix) != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Parse tweak */
    unsigned char tweak[256];
    int tweak_len = 0;
    if (vec->tweak_hex && strlen(vec->tweak_hex) > 0) {
        tweak_len = fpe_hex_to_bytes(vec->tweak_hex, tweak, 256);
        if (tweak_len < 0) {
            FPE_CTX_free(ctx);
            return -1;
        }
    }
    
    /* Convert plaintext and expected ciphertext */
    const char *alphabet = (vec->radix == 10) ? "0123456789" : "0123456789abcdefghijklmnopqrstuvwxyz";
    unsigned int len = strlen(vec->plaintext);
    
    unsigned int plaintext[256];
    unsigned int expected[256];
    unsigned int ciphertext[256];
    
    if (fpe_str_to_array(alphabet, vec->plaintext, plaintext, len) != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    if (fpe_str_to_array(alphabet, vec->ciphertext, expected, len) != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Encrypt */
    int enc_ret = FPE_encrypt(ctx, plaintext, ciphertext, len, 
                    (tweak_len > 0) ? tweak : NULL, tweak_len);
    if (enc_ret != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Compare */
    int match = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (ciphertext[i] != expected[i]) {
            match = 0;
            break;
        }
    }
    
    /* Test reversibility */
    unsigned int decrypted[256];
    if (FPE_decrypt(ctx, ciphertext, decrypted, len, 
                    (tweak_len > 0) ? tweak : NULL, tweak_len) != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    int reversible = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (decrypted[i] != plaintext[i]) {
            reversible = 0;
            break;
        }
    }
    
    FPE_CTX_free(ctx);
    
    if (!match) return -1;
    if (!reversible) return -1;
    
    return 0;
}

/* Test all FF1 AES-128 vectors */
void test_ff1_aes128_all_vectors(void) {
    int count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int tested = 0;
    int passed = 0;
    
    for (int i = 0; i < count && test_vectors[i].alg_name != NULL; i++) {
        if (test_vectors[i].mode == FPE_MODE_FF1 && 
            strncmp(test_vectors[i].alg_name, "AES-128", 7) == 0) {
            tested++;
            if (run_ff1_vector(&test_vectors[i]) == 0) {
                passed++;
            }
        }
    }
    
    TEST_ASSERT_EQUAL_INT(tested, passed);
    TEST_ASSERT_TRUE(tested >= 3);  /* At least 3 AES-128 vectors */
}

/* Test all FF1 AES-192 vectors */
void test_ff1_aes192_all_vectors(void) {
    int count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int tested = 0;
    int passed = 0;
    
    for (int i = 0; i < count && test_vectors[i].alg_name != NULL; i++) {
        if (test_vectors[i].mode == FPE_MODE_FF1 && 
            strncmp(test_vectors[i].alg_name, "AES-192", 7) == 0) {
            tested++;
            if (run_ff1_vector(&test_vectors[i]) == 0) {
                passed++;
            }
        }
    }
    
    TEST_ASSERT_EQUAL_INT(tested, passed);
    TEST_ASSERT_TRUE(tested >= 3);  /* At least 3 AES-192 vectors */
}

/* Test all FF1 AES-256 vectors */
void test_ff1_aes256_all_vectors(void) {
    int count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int tested = 0;
    int passed = 0;
    
    for (int i = 0; i < count && test_vectors[i].alg_name != NULL; i++) {
        if (test_vectors[i].mode == FPE_MODE_FF1 && 
            strncmp(test_vectors[i].alg_name, "AES-256", 7) == 0) {
            tested++;
            if (run_ff1_vector(&test_vectors[i]) == 0) {
                passed++;
            }
        }
    }
    
    TEST_ASSERT_EQUAL_INT(tested, passed);
    TEST_ASSERT_TRUE(tested >= 3);  /* At least 3 AES-256 vectors */
}

/* Test all FF1 SM4 vectors */
void test_ff1_sm4_all_vectors(void) {
#ifdef HAVE_OPENSSL_SM4
    int count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int tested = 0;
    int passed = 0;
    
    for (int i = 0; i < count && test_vectors[i].alg_name != NULL; i++) {
        if (test_vectors[i].mode == FPE_MODE_FF1 && 
            strncmp(test_vectors[i].alg_name, "SM4", 3) == 0) {
            tested++;
            if (run_ff1_vector(&test_vectors[i]) == 0) {
                passed++;
            }
        }
    }
    
    TEST_ASSERT_EQUAL_INT(tested, passed);
    TEST_ASSERT_TRUE(tested >= 3);  /* At least 3 SM4 vectors */
#else
    TEST_IGNORE_MESSAGE("SM4 not supported");
#endif
}

/* Test FF1 reversibility for all vectors */
void test_ff1_reversibility(void) {
    int count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int tested = 0;
    int reversible = 0;
    
    for (int i = 0; i < count && test_vectors[i].alg_name != NULL; i++) {
        if (test_vectors[i].mode != FPE_MODE_FF1) continue;
        
        int result = run_ff1_vector(&test_vectors[i]);
        if (result == -2) continue;  /* Skip SM4 if not supported */
        
        tested++;
        if (result == 0) {
            reversible++;
        }
    }
    
    TEST_ASSERT_EQUAL_INT(tested, reversible);
    TEST_ASSERT_TRUE(tested >= 12);  /* At least 12 FF1 vectors total */
}

/* Test FF1 with empty tweaks */
void test_ff1_empty_tweak_vectors(void) {
    int count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int tested = 0;
    int passed = 0;
    
    for (int i = 0; i < count && test_vectors[i].alg_name != NULL; i++) {
        if (test_vectors[i].mode == FPE_MODE_FF1 && 
            strlen(test_vectors[i].tweak_hex) == 0) {
            int result = run_ff1_vector(&test_vectors[i]);
            if (result == -2) continue;  /* Skip SM4 if not supported */
            
            tested++;
            if (result == 0) {
                passed++;
            }
        }
    }
    
    TEST_ASSERT_EQUAL_INT(tested, passed);
    TEST_ASSERT_TRUE(tested >= 3);  /* At least 3 empty tweak vectors */
}

/* Test FF1 with non-empty tweaks */
void test_ff1_nonempty_tweak_vectors(void) {
    int count = sizeof(test_vectors) / sizeof(test_vectors[0]);
    int tested = 0;
    int passed = 0;
    
    for (int i = 0; i < count && test_vectors[i].alg_name != NULL; i++) {
        if (test_vectors[i].mode == FPE_MODE_FF1 && 
            strlen(test_vectors[i].tweak_hex) > 0) {
            int result = run_ff1_vector(&test_vectors[i]);
            if (result == -2) continue;  /* Skip SM4 if not supported */
            
            tested++;
            if (result == 0) {
                passed++;
            }
        }
    }
    
    TEST_ASSERT_EQUAL_INT(tested, passed);
    TEST_ASSERT_TRUE(tested >= 8);  /* At least 8 non-empty tweak vectors */
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_ff1_aes128_all_vectors);
    RUN_TEST(test_ff1_aes192_all_vectors);
    RUN_TEST(test_ff1_aes256_all_vectors);
    RUN_TEST(test_ff1_sm4_all_vectors);
    RUN_TEST(test_ff1_reversibility);
    RUN_TEST(test_ff1_empty_tweak_vectors);
    RUN_TEST(test_ff1_nonempty_tweak_vectors);
    
    return UNITY_END();
}
