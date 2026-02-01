/**
 * @file test_ff3.c
 * @brief Unit tests for FF3 algorithm
 * 
 * Tests for FF3 key derivation, round function, and encryption/decryption
 * with various radices.
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include "vectors.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================= */
/*                     FF3 Key Derivation Tests (AES)                        */
/* ========================================================================= */

void test_ff3_key_derivation_aes128(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_ff3_key_derivation_aes192(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[24] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 192, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_ff3_key_derivation_aes256(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[32] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 256, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                     FF3 Key Derivation Tests (SM4)                        */
/* ========================================================================= */

#ifdef HAVE_OPENSSL_SM4
void test_ff3_key_derivation_sm4(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16];
    fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}
#endif

/* ========================================================================= */
/*                     FF3 Round Function Tests                              */
/* ========================================================================= */

void test_ff3_round_function_basic(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Test that encryption produces different output than input */
    unsigned int plaintext[] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0};
    unsigned int ciphertext[18];
    unsigned char tweak[8] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x73};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 18, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify ciphertext is different from plaintext */
    int different = 0;
    for (int i = 0; i < 18; i++) {
        if (ciphertext[i] != plaintext[i]) {
            different = 1;
            break;
        }
    }
    TEST_ASSERT_TRUE(different);
    
    FPE_CTX_free(ctx);
}

void test_ff3_round_function_deterministic(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    unsigned char tweak[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    /* Encrypt twice with same inputs */
    ret = FPE_encrypt(ctx, plaintext, ciphertext1, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext2, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Results should be identical */
    TEST_ASSERT_EQUAL_UINT_ARRAY(ciphertext1, ciphertext2, 10);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                FF3 Encryption/Decryption Tests (Various Radices)          */
/* ========================================================================= */

void test_ff3_encrypt_decrypt_radix10(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10));
    
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    unsigned char tweak[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Decrypt */
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify reversibility */
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

void test_ff3_encrypt_decrypt_radix16(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 16));
    
    unsigned int plaintext[] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 
                                 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF};
    unsigned int ciphertext[16];
    unsigned int decrypted[16];
    unsigned char tweak[8] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0};
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Decrypt */
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 16, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify reversibility */
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 16);
    
    FPE_CTX_free(ctx);
}

void test_ff3_encrypt_decrypt_radix26(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 26));
    
    /* String "abcdefghijklmnop" as indices 0-15 */
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    unsigned int ciphertext[16];
    unsigned int decrypted[16];
    unsigned char tweak[8] = {0x9A, 0x76, 0x8A, 0x92, 0xF6, 0x0E, 0x12, 0xD8};
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 16, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Decrypt */
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 16, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify reversibility */
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 16);
    
    FPE_CTX_free(ctx);
}

void test_ff3_encrypt_decrypt_radix36(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 36));
    
    /* Alphanumeric string "0123456789abc" */
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    unsigned int ciphertext[13];
    unsigned int decrypted[13];
    unsigned char tweak[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 13, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Decrypt */
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 13, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify reversibility */
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 13);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                        Main Test Runner                                   */
/* ========================================================================= */

int main(void) {
    UNITY_BEGIN();
    
    /* FF3 Key Derivation Tests (AES) - Task 5.11 */
    RUN_TEST(test_ff3_key_derivation_aes128);
    RUN_TEST(test_ff3_key_derivation_aes192);
    RUN_TEST(test_ff3_key_derivation_aes256);
    
    /* FF3 Key Derivation Tests (SM4) - Task 5.12 */
#ifdef HAVE_OPENSSL_SM4
    RUN_TEST(test_ff3_key_derivation_sm4);
#endif
    
    /* FF3 Round Function Tests - Task 5.13 */
    RUN_TEST(test_ff3_round_function_basic);
    RUN_TEST(test_ff3_round_function_deterministic);
    
    /* FF3 Encryption/Decryption Tests (Various Radices) - Task 5.14 */
    RUN_TEST(test_ff3_encrypt_decrypt_radix10);
    RUN_TEST(test_ff3_encrypt_decrypt_radix16);
    RUN_TEST(test_ff3_encrypt_decrypt_radix26);
    RUN_TEST(test_ff3_encrypt_decrypt_radix36);
    
    return UNITY_END();
}
