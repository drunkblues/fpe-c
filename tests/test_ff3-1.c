/**
 * @file test_ff3-1.c
 * @brief Unit tests for FF3-1 algorithm
 * 
 * Tests for FF3-1 key derivation, round function, and encryption/decryption
 * with various radices. FF3-1 is the secure version of FF3 with security fixes.
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include "vectors.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================= */
/*                    FF3-1 Key Derivation Tests (AES)                       */
/* ========================================================================= */

void test_ff3_1_key_derivation_aes128(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_ff3_1_key_derivation_aes192(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[24] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 192, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_ff3_1_key_derivation_aes256(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[32] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94,
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 256, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                    FF3-1 Key Derivation Tests (SM4)                       */
/* ========================================================================= */

#ifdef HAVE_OPENSSL_SM4
void test_ff3_1_key_derivation_sm4(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16];
    fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}
#endif

/* ========================================================================= */
/*                    FF3-1 Round Function Tests                             */
/* ========================================================================= */

void test_ff3_1_round_function_basic(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // Test that we can encrypt and decrypt (which exercises the round function)
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

void test_ff3_1_round_function_deterministic(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    
    unsigned char tweak[7] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    // Encrypt twice with same inputs - should produce identical outputs
    ret = FPE_encrypt(ctx, plaintext, ciphertext1, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext2, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(ciphertext1, ciphertext2, 10);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*              FF3-1 Encryption/Decryption Tests (Various Radices)          */
/* ========================================================================= */

void test_ff3_1_encrypt_decrypt_radix10(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

void test_ff3_1_encrypt_decrypt_radix16(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 16);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    unsigned int plaintext[8] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1};
    unsigned int ciphertext[8];
    unsigned int decrypted[8];
    
    unsigned char tweak[7] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 8, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 8, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 8);
    
    FPE_CTX_free(ctx);
}

void test_ff3_1_encrypt_decrypt_radix26(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 26);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // "hello" = {7, 4, 11, 11, 14}
    unsigned int plaintext[5] = {7, 4, 11, 11, 14};
    unsigned int ciphertext[5];
    unsigned int decrypted[5];
    
    unsigned char tweak[7] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 5, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 5, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 5);
    
    FPE_CTX_free(ctx);
}

void test_ff3_1_encrypt_decrypt_radix36(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 36);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // "test123" = {29, 4, 28, 29, 1, 2, 3} (alphanumeric)
    unsigned int plaintext[7] = {29, 4, 28, 29, 1, 2, 3};
    unsigned int ciphertext[7];
    unsigned int decrypted[7];
    
    unsigned char tweak[7] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99};
    
    ret = FPE_encrypt(ctx, plaintext, ciphertext, 7, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 7, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 7);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                            Main Test Runner                               */
/* ========================================================================= */

int main(void) {
    UNITY_BEGIN();
    
    // FF3-1 Key Derivation Tests (AES)
    RUN_TEST(test_ff3_1_key_derivation_aes128);
    RUN_TEST(test_ff3_1_key_derivation_aes192);
    RUN_TEST(test_ff3_1_key_derivation_aes256);
    
    // FF3-1 Key Derivation Tests (SM4)
#ifdef HAVE_OPENSSL_SM4
    RUN_TEST(test_ff3_1_key_derivation_sm4);
#endif
    
    // FF3-1 Round Function Tests
    RUN_TEST(test_ff3_1_round_function_basic);
    RUN_TEST(test_ff3_1_round_function_deterministic);
    
    // FF3-1 Encryption/Decryption Tests (Various Radices)
    RUN_TEST(test_ff3_1_encrypt_decrypt_radix10);
    RUN_TEST(test_ff3_1_encrypt_decrypt_radix16);
    RUN_TEST(test_ff3_1_encrypt_decrypt_radix26);
    RUN_TEST(test_ff3_1_encrypt_decrypt_radix36);
    
    return UNITY_END();
}
