/**
 * @file test_ff1.c
 * @brief Unit tests for FF1 algorithm
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include "vectors.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================= */
/*                     FF1 Key Derivation Tests                              */
/* ========================================================================= */

void test_ff1_key_derivation_aes128(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_ff1_key_derivation_aes192(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[24] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 192, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

void test_ff1_key_derivation_aes256(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[32] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}

#ifdef HAVE_OPENSSL_SM4
void test_ff1_key_derivation_sm4(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16];
    fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    FPE_CTX_free(ctx);
}
#endif

/* ========================================================================= */
/*                     FF1 Encryption/Decryption Tests                       */
/* ========================================================================= */

void test_ff1_encrypt_decrypt_radix10(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10));
    
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    /* Encrypt */
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, NULL, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Decrypt */
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, NULL, 0);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

void test_ff1_encrypt_decrypt_radix36(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 36));
    
    /* "0123456789abcdefghi" in radix 36 */
    const char *alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
    const char *plaintext_str = "0123456789abcdefghi";
    
    unsigned int plaintext[19];
    unsigned int ciphertext[19];
    unsigned int decrypted[19];
    
    TEST_ASSERT_EQUAL_INT(0, fpe_str_to_array(alphabet, plaintext_str, plaintext, 19));
    
    /* Encrypt */
    unsigned char tweak[] = {0x37, 0x37, 0x37, 0x37, 0x70, 0x71, 0x72, 0x73, 0x37, 0x37, 0x37};
    int ret = FPE_encrypt(ctx, plaintext, ciphertext, 19, tweak, 11);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Decrypt */
    ret = FPE_decrypt(ctx, ciphertext, decrypted, 19, tweak, 11);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    /* Verify */
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 19);
    
    FPE_CTX_free(ctx);
}

void test_ff1_with_tweak(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10));
    
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    
    unsigned char tweak1[] = {0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30};
    unsigned char tweak2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    /* Encrypt with tweak1 */
    TEST_ASSERT_EQUAL_INT(0, FPE_encrypt(ctx, plaintext, ciphertext1, 10, tweak1, 10));
    
    /* Encrypt with tweak2 */
    TEST_ASSERT_EQUAL_INT(0, FPE_encrypt(ctx, plaintext, ciphertext2, 10, tweak2, 10));
    
    /* Different tweaks should produce different ciphertexts */
    int different = 0;
    for (int i = 0; i < 10; i++) {
        if (ciphertext1[i] != ciphertext2[i]) {
            different = 1;
            break;
        }
    }
    TEST_ASSERT_TRUE(different);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                     FF1 Edge Cases Tests                                  */
/* ========================================================================= */

void test_ff1_minimum_length(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10));
    
    /* Minimum length is 2 */
    unsigned int plaintext[] = {5, 7};
    unsigned int ciphertext[2];
    unsigned int decrypted[2];
    
    TEST_ASSERT_EQUAL_INT(0, FPE_encrypt(ctx, plaintext, ciphertext, 2, NULL, 0));
    TEST_ASSERT_EQUAL_INT(0, FPE_decrypt(ctx, ciphertext, decrypted, 2, NULL, 0));
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 2);
    
    FPE_CTX_free(ctx);
}

void test_ff1_empty_tweak(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10));
    
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    /* Empty tweak (NULL with length 0) */
    TEST_ASSERT_EQUAL_INT(0, FPE_encrypt(ctx, plaintext, ciphertext, 10, NULL, 0));
    TEST_ASSERT_EQUAL_INT(0, FPE_decrypt(ctx, ciphertext, decrypted, 10, NULL, 0));
    TEST_ASSERT_EQUAL_UINT_ARRAY(plaintext, decrypted, 10);
    
    FPE_CTX_free(ctx);
}

/* ========================================================================= */
/*                     FF1 NIST Test Vectors                                 */
/* ========================================================================= */

void test_ff1_nist_aes128_empty_tweak(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    /* NIST test vector: AES-128, empty tweak */
    unsigned char key[16];
    fpe_hex_to_bytes("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10));
    
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int expected[] = {2, 4, 3, 3, 4, 7, 7, 4, 8, 4};
    unsigned int ciphertext[10];
    
    TEST_ASSERT_EQUAL_INT(0, FPE_encrypt(ctx, plaintext, ciphertext, 10, NULL, 0));
    TEST_ASSERT_EQUAL_UINT_ARRAY(expected, ciphertext, 10);
    
    FPE_CTX_free(ctx);
}

void test_ff1_nist_aes128_with_tweak(void) {
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    
    unsigned char key[16];
    fpe_hex_to_bytes("2B7E151628AED2A6ABF7158809CF4F3C", key, 16);
    
    TEST_ASSERT_EQUAL_INT(0, FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10));
    
    unsigned int plaintext[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    unsigned int expected[] = {6, 1, 2, 4, 2, 0, 0, 7, 7, 3};
    unsigned int ciphertext[10];
    
    unsigned char tweak[10];
    fpe_hex_to_bytes("39383736353433323130", tweak, 10);
    
    TEST_ASSERT_EQUAL_INT(0, FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 10));
    TEST_ASSERT_EQUAL_UINT_ARRAY(expected, ciphertext, 10);
    
    FPE_CTX_free(ctx);
}

int main(void) {
    UNITY_BEGIN();
    
    /* Key derivation tests */
    RUN_TEST(test_ff1_key_derivation_aes128);
    RUN_TEST(test_ff1_key_derivation_aes192);
    RUN_TEST(test_ff1_key_derivation_aes256);
#ifdef HAVE_OPENSSL_SM4
    RUN_TEST(test_ff1_key_derivation_sm4);
#endif
    
    /* Encryption/decryption tests */
    RUN_TEST(test_ff1_encrypt_decrypt_radix10);
    RUN_TEST(test_ff1_encrypt_decrypt_radix36);
    RUN_TEST(test_ff1_with_tweak);
    
    /* Edge cases */
    RUN_TEST(test_ff1_minimum_length);
    RUN_TEST(test_ff1_empty_tweak);
    
    /* NIST test vectors */
    RUN_TEST(test_ff1_nist_aes128_empty_tweak);
    RUN_TEST(test_ff1_nist_aes128_with_tweak);
    
    return UNITY_END();
}
