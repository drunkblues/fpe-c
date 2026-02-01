/**
 * @file test_oneshot.c
 * @brief Unit tests for one-shot API functions
 * 
 * Tests for one-shot encryption/decryption and string operations.
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* ========================================================================= */
/*              One-Shot Encryption/Decryption Tests (9.5)                   */
/* ========================================================================= */

void test_oneshot_ff1_encrypt_decrypt(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                                   plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                               ciphertext, decrypted, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
}

void test_oneshot_ff1_aes256(void) {
    unsigned char key[32] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C,
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 10,
                                   plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 256, 10,
                               ciphertext, decrypted, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
}

void test_oneshot_ff3_encrypt_decrypt(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[8] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x00};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10,
                                   plaintext, ciphertext, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_oneshot(FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10,
                               ciphertext, decrypted, 10, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
}

void test_oneshot_ff3_1_encrypt_decrypt(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10,
                                   plaintext, ciphertext, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_oneshot(FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10,
                               ciphertext, decrypted, 10, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
}

#ifdef HAVE_OPENSSL_SM4
void test_oneshot_ff1_sm4(void) {
    unsigned char key[16];
    fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned int decrypted[10];
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10,
                                   plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_SM4, key, 128, 10,
                               ciphertext, decrypted, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 10);
}
#endif

void test_oneshot_radix_16(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    unsigned int plaintext[8] = {0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x0, 0x1};
    unsigned int ciphertext[8];
    unsigned int decrypted[8];
    
    unsigned char tweak[4] = {0x12, 0x34, 0x56, 0x78};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 16,
                                   plaintext, ciphertext, 8, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 16,
                               ciphertext, decrypted, 8, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 8);
}

void test_oneshot_radix_26(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    // "hello" = {7, 4, 11, 11, 14}
    unsigned int plaintext[5] = {7, 4, 11, 11, 14};
    unsigned int ciphertext[5];
    unsigned int decrypted[5];
    
    unsigned char tweak[4] = {0x00, 0x00, 0x00, 0x00};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 26,
                                   plaintext, ciphertext, 5, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 26,
                               ciphertext, decrypted, 5, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(plaintext, decrypted, 5);
}

void test_oneshot_inplace_encryption(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    unsigned int data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int original[10];
    memcpy(original, data, sizeof(data));
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    // In-place encryption
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                                   data, data, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // In-place decryption
    ret = FPE_decrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                               data, data, 10, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_UINT32_ARRAY(original, data, 10);
}

void test_oneshot_null_input(void) {
    unsigned char key[16] = {0};
    unsigned int ciphertext[10];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                                   NULL, ciphertext, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_oneshot_null_output(void) {
    unsigned char key[16] = {0};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                                   plaintext, NULL, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_oneshot_invalid_key_length(void) {
    unsigned char key[16] = {0};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    // Invalid key length (should be 128, 192, or 256)
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 512, 10,
                                   plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_oneshot_invalid_radix(void) {
    unsigned char key[16] = {0};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    // Invalid radix (too small)
    int ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 1,
                                   plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
    
    // Invalid radix (too large)
    ret = FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 65537,
                               plaintext, ciphertext, 10, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

/* ========================================================================= */
/*                 One-Shot String Operations Tests (9.6)                    */
/* ========================================================================= */

void test_oneshot_str_numeric_alphabet(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    const char *plaintext = "1234567890";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                   alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
}

void test_oneshot_str_lowercase_alphabet(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    const char *plaintext = "hello";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "abcdefghijklmnopqrstuvwxyz";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                   alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
}

void test_oneshot_str_alphanumeric(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    const char *plaintext = "test123";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                   alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
}

void test_oneshot_str_custom_alphabet(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    const char *plaintext = "ACGT";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "ACGT";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                   alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
}

void test_oneshot_str_ff3(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    const char *plaintext = "8901212345";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[8] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x00};
    const char *alphabet = "0123456789";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF3, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF3, FPE_ALGO_AES, key, 128,
                                   alphabet, ciphertext, decrypted, tweak, 8);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
}

void test_oneshot_str_ff3_1(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    const char *plaintext = "8901212345";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    const char *alphabet = "0123456789";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128,
                                   alphabet, ciphertext, decrypted, tweak, 7);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
}

void test_oneshot_str_inplace(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    char data[32] = "1234567890";
    char original[32];
    strcpy(original, data);
    
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    // In-place encryption
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                       alphabet, data, data, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    // In-place decryption
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                   alphabet, data, data, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(original, data);
}

void test_oneshot_str_null_output(void) {
    unsigned char key[16] = {0};
    const char *plaintext = "1234567890";
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, NULL, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

void test_oneshot_str_invalid_character(void) {
    unsigned char key[16] = {0};
    const char *plaintext = "123abc"; // 'abc' not in numeric alphabet
    char ciphertext[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_NOT_EQUAL(0, ret);
}

#ifdef HAVE_OPENSSL_SM4
void test_oneshot_str_sm4(void) {
    unsigned char key[16];
    fpe_hex_to_bytes("0123456789ABCDEFFEDCBA9876543210", key, 16);
    
    const char *plaintext = "1234567890";
    char ciphertext[32];
    char decrypted[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    int ret = FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_SM4, key, 128,
                                       alphabet, plaintext, ciphertext, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    ret = FPE_decrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_SM4, key, 128,
                                   alphabet, ciphertext, decrypted, tweak, 4);
    TEST_ASSERT_EQUAL_INT(0, ret);
    
    TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
}
#endif

/* ========================================================================= */
/*                            Main Test Runner                               */
/* ========================================================================= */

int main(void) {
    UNITY_BEGIN();
    
    // One-Shot Encryption/Decryption Tests (9.5)
    RUN_TEST(test_oneshot_ff1_encrypt_decrypt);
    RUN_TEST(test_oneshot_ff1_aes256);
    RUN_TEST(test_oneshot_ff3_encrypt_decrypt);
    RUN_TEST(test_oneshot_ff3_1_encrypt_decrypt);
#ifdef HAVE_OPENSSL_SM4
    RUN_TEST(test_oneshot_ff1_sm4);
#endif
    RUN_TEST(test_oneshot_radix_16);
    RUN_TEST(test_oneshot_radix_26);
    RUN_TEST(test_oneshot_inplace_encryption);
    RUN_TEST(test_oneshot_null_input);
    RUN_TEST(test_oneshot_null_output);
    RUN_TEST(test_oneshot_invalid_key_length);
    RUN_TEST(test_oneshot_invalid_radix);
    
    // One-Shot String Operations Tests (9.6)
    RUN_TEST(test_oneshot_str_numeric_alphabet);
    RUN_TEST(test_oneshot_str_lowercase_alphabet);
    RUN_TEST(test_oneshot_str_alphanumeric);
    RUN_TEST(test_oneshot_str_custom_alphabet);
    RUN_TEST(test_oneshot_str_ff3);
    RUN_TEST(test_oneshot_str_ff3_1);
    RUN_TEST(test_oneshot_str_inplace);
    RUN_TEST(test_oneshot_str_null_output);
    RUN_TEST(test_oneshot_str_invalid_character);
#ifdef HAVE_OPENSSL_SM4
    RUN_TEST(test_oneshot_str_sm4);
#endif
    
    return UNITY_END();
}
