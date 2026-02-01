/**
 * @file test_memory.c
 * @brief Memory leak detection tests
 *
 * This file contains tests to verify that the library properly
 * frees all allocated memory and has no leaks.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unity/src/unity.h"

#include "../include/fpe.h"

/* Unity setup/teardown */
void setUp(void) {
    /* Called before each test */
}

void tearDown(void) {
    /* Called after each test */
}

void test_context_creation_and_destruction(void) {
    printf("\n=== Testing context lifecycle ===\n");

    for (int i = 0; i < 1000; i++) {
        FPE_CTX *ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);
        FPE_CTX_free(ctx);
    }
    printf("✓ Created and destroyed 1000 contexts\n");
}

void test_context_initialization_and_cleanup(void) {
    printf("\n=== Testing context initialization cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    for (int i = 0; i < 1000; i++) {
        FPE_CTX *ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);

        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
        FPE_CTX_free(ctx);
    }
    printf("✓ Initialized and destroyed 1000 contexts\n");
}

void test_encryption_and_cleanup(void) {
    printf("\n=== Testing encryption operation cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    for (int i = 0; i < 10000; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
    }
    printf("✓ Performed 10000 encryption operations\n");

    FPE_CTX_free(ctx);
}

void test_decryption_and_cleanup(void) {
    printf("\n=== Testing decryption operation cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);

    for (int i = 0; i < 10000; i++) {
        FPE_decrypt(ctx, ciphertext, plaintext, 10, tweak, 8);
    }
    printf("✓ Performed 10000 decryption operations\n");

    FPE_CTX_free(ctx);
}

void test_string_operations_cleanup(void) {
    printf("\n=== Testing string operation cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    const char *alphabet = "0123456789";
    char plaintext[20] = "1234567890123456789";
    char ciphertext[20];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    for (int i = 0; i < 10000; i++) {
        FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 8);
        FPE_decrypt_str(ctx, alphabet, ciphertext, plaintext, tweak, 8);
    }
    printf("✓ Performed 10000 string encrypt/decrypt operations\n");

    FPE_CTX_free(ctx);
}

void test_oneshot_operations_cleanup(void) {
    printf("\n=== Testing one-shot operation cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    for (int i = 0; i < 1000; i++) {
        FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                          plaintext, ciphertext, 10, tweak, 8);
        FPE_decrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                          ciphertext, plaintext, 10, tweak, 8);
    }
    printf("✓ Performed 1000 one-shot encrypt/decrypt operations\n");
}

void test_multiple_contexts_cleanup(void) {
    printf("\n=== Testing multiple contexts cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *contexts[10];

    for (int i = 0; i < 10; i++) {
        contexts[i] = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(contexts[i]);
        FPE_CTX_init(contexts[i], FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    }

    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < 10; j++) {
            FPE_encrypt(contexts[j], plaintext, ciphertext, 10, tweak, 8);
        }
    }
    printf("✓ Performed 10000 operations with 10 contexts\n");

    for (int i = 0; i < 10; i++) {
        FPE_CTX_free(contexts[i]);
    }
}

void test_error_path_cleanup(void) {
    printf("\n=== Testing error path cleanup ===\n");

    unsigned char key[16] = {0};

    for (int i = 0; i < 1000; i++) {
        FPE_CTX *ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);

        /* Initialize with invalid parameters */
        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 64, 10);

        /* Initialize with valid parameters */
        FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

        FPE_CTX_free(ctx);
    }
    printf("✓ Tested 1000 error path operations\n");
}

void test_all_algorithms_cleanup(void) {
    printf("\n=== Testing all algorithms cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0};

    FPE_MODE modes[] = {FPE_MODE_FF1, FPE_MODE_FF3, FPE_MODE_FF3_1};
    const char *mode_names[] = {"FF1", "FF3", "FF3-1"};

    for (int i = 0; i < 3; i++) {
        FPE_CTX *ctx = FPE_CTX_new();
        TEST_ASSERT_NOT_NULL(ctx);

        FPE_CTX_init(ctx, modes[i], FPE_ALGO_AES, key, 128, 10);

        for (int j = 0; j < 1000; j++) {
            FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
            FPE_decrypt(ctx, ciphertext, plaintext, 10, tweak, 8);
        }

        printf("✓ Performed 2000 operations with %s\n", mode_names[i]);

        FPE_CTX_free(ctx);
    }
}

void test_null_context_handling(void) {
    printf("\n=== Testing NULL context handling ===\n");

    unsigned int arr[10] = {0};
    unsigned char tweak[8] = {0};

    /* These should not crash or leak memory */
    FPE_CTX_free(NULL);

    for (int i = 0; i < 10; i++) {
        FPE_encrypt(NULL, arr, arr, 10, tweak, 8);
        FPE_decrypt(NULL, arr, arr, 10, tweak, 8);
    }

    printf("✓ Handled NULL context operations without leaks\n");
}

void test_in_place_operations_cleanup(void) {
    printf("\n=== Testing in-place operation cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int arr[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    for (int i = 0; i < 10000; i++) {
        FPE_encrypt(ctx, arr, arr, 10, tweak, 8);
        FPE_decrypt(ctx, arr, arr, 10, tweak, 8);
    }
    printf("✓ Performed 10000 in-place encrypt/decrypt operations\n");

    FPE_CTX_free(ctx);
}

void test_large_input_cleanup(void) {
    printf("\n=== Testing large input cleanup ===\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int *plaintext = malloc(256 * sizeof(unsigned int));
    unsigned int *ciphertext = malloc(256 * sizeof(unsigned int));
    unsigned char tweak[8] = {0};

    TEST_ASSERT_NOT_NULL(plaintext);
    TEST_ASSERT_NOT_NULL(ciphertext);

    for (unsigned int i = 0; i < 256; i++) {
        plaintext[i] = i % 10;
    }

    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    for (int i = 0; i < 1000; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, 256, tweak, 8);
        FPE_decrypt(ctx, ciphertext, plaintext, 256, tweak, 8);
    }
    printf("✓ Performed 2000 operations with 256-digit inputs\n");

    FPE_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_context_creation_and_destruction);
    RUN_TEST(test_context_initialization_and_cleanup);
    RUN_TEST(test_encryption_and_cleanup);
    RUN_TEST(test_decryption_and_cleanup);
    RUN_TEST(test_string_operations_cleanup);
    RUN_TEST(test_oneshot_operations_cleanup);
    RUN_TEST(test_multiple_contexts_cleanup);
    RUN_TEST(test_error_path_cleanup);
    RUN_TEST(test_all_algorithms_cleanup);
    RUN_TEST(test_null_context_handling);
    RUN_TEST(test_in_place_operations_cleanup);
    RUN_TEST(test_large_input_cleanup);

    printf("\n=== Memory leak tests complete ===\n");
    printf("To check for leaks, run with:\n");
    printf("  - AddressSanitizer: cmake -DSANITIZE_ADDRESS=ON .. && make test_memory && ./tests/test_memory\n");
    printf("  - Valgrind: valgrind --leak-check=full --show-leak-kinds=all ./tests/test_memory\n");

    return UNITY_END();
}
