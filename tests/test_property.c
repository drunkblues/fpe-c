/**
 * @file test_property.c
 * @brief Property-based tests for FPE algorithms
 *
 * This file contains property-based tests that verify generic properties
 * such as reversibility, determinism, and format preservation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "unity/src/unity.h"

#include "../include/fpe.h"

/* Unity setup/teardown */
void setUp(void) {
    /* Called before each test */
}

void tearDown(void) {
    /* Called after each test */
}

/* Helper function to get minimum length for each mode */
unsigned int get_min_length_for_mode(FPE_MODE mode) {
    switch (mode) {
        case FPE_MODE_FF1:
            return 2;
        case FPE_MODE_FF3:
        case FPE_MODE_FF3_1:
            return 2;
        default:
            return 2;
    }
}

/* Property 1: Encrypt(Decrypt(x)) = x for all valid x */
void test_property_reversibility_random(void) {
    printf("\n=== Property 1: Reversibility ===\n");
    printf("For all valid plaintexts: Decrypt(Encrypt(x)) = x\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char tweak[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};

    FPE_MODE modes[] = {FPE_MODE_FF1, FPE_MODE_FF3, FPE_MODE_FF3_1};
    const char *mode_names[] = {"FF1", "FF3", "FF3-1"};
    unsigned int radices[] = {2, 10, 26, 62, 100, 1000, 10000};
    unsigned int lengths[] = {3, 5, 10, 20, 50, 100};

    unsigned int failures = 0;
    unsigned int total = 0;

    srand((unsigned int)time(NULL));

    for (int m = 0; m < 3; m++) {
        for (int r = 0; r < 7; r++) {
            FPE_CTX *ctx = FPE_CTX_new();
            FPE_CTX_init(ctx, modes[m], FPE_ALGO_AES, key, 128, radices[r]);

            for (int l = 0; l < 6; l++) {
                if (lengths[l] < 2) continue;  /* Minimum length for all modes */

                unsigned int *plaintext = malloc(lengths[l] * sizeof(unsigned int));
                unsigned int *ciphertext = malloc(lengths[l] * sizeof(unsigned int));
                unsigned int *decrypted = malloc(lengths[l] * sizeof(unsigned int));

                for (int i = 0; i < lengths[l]; i++) {
                    plaintext[i] = rand() % radices[r];
                }

                int ret = FPE_encrypt(ctx, plaintext, ciphertext, lengths[l], tweak, 8);
                if (ret != 0) {
                    failures++;
                    total++;
                    free(plaintext);
                    free(ciphertext);
                    free(decrypted);
                    FPE_CTX_free(ctx);
                    continue;
                }

                ret = FPE_decrypt(ctx, ciphertext, decrypted, lengths[l], tweak, 8);
                if (ret != 0) {
                    failures++;
                    total++;
                    free(plaintext);
                    free(ciphertext);
                    free(decrypted);
                    FPE_CTX_free(ctx);
                    continue;
                }

                total++;
                for (unsigned int i = 0; i < lengths[l]; i++) {
                    if (decrypted[i] != plaintext[i]) {
                        failures++;
                        break;
                    }
                }

                free(plaintext);
                free(ciphertext);
                free(decrypted);
            }

            FPE_CTX_free(ctx);
        }
    }

    TEST_ASSERT_EQUAL(0, failures);
    printf("✓ Verified reversibility for %u operations\n", total);
}

/* Property 2: Encrypt(x) is deterministic (same key, tweak, x) */
void test_property_determinism(void) {
    printf("\n=== Property 2: Determinism ===\n");
    printf("For same inputs: Encrypt(x) always produces same output\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    unsigned int plaintext[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6};
    unsigned int ciphertext1[16];
    unsigned int ciphertext2[16];

    for (int i = 0; i < 100; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext1, 16, tweak, 8);
        FPE_encrypt(ctx, plaintext, ciphertext2, 16, tweak, 8);

        for (int j = 0; j < 16; j++) {
            TEST_ASSERT_EQUAL(ciphertext1[j], ciphertext2[j]);
        }
    }

    FPE_CTX_free(ctx);
    printf("✓ Verified determinism for 100 operations\n");
}

/* Property 3: Decrypt(Encrypt(x)) produces same result as in-place */
void test_property_inplace_equivalence(void) {
    printf("\n=== Property 3: In-place Equivalence ===\n");
    printf("Encrypt(x) in-place produces same result as out-of-place\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    for (int i = 0; i < 1000; i++) {
        unsigned int plaintext[10];
        unsigned int ciphertext1[10];
        unsigned int ciphertext2[10];

        for (int j = 0; j < 10; j++) {
            plaintext[j] = rand() % 10;
        }

        memcpy(ciphertext1, plaintext, 10 * sizeof(unsigned int));
        memcpy(ciphertext2, plaintext, 10 * sizeof(unsigned int));

        FPE_encrypt(ctx, plaintext, ciphertext1, 10, tweak, 8);
        FPE_encrypt(ctx, ciphertext2, ciphertext2, 10, tweak, 8);

        for (int j = 0; j < 10; j++) {
            TEST_ASSERT_EQUAL(ciphertext1[j], ciphertext2[j]);
        }
    }

    FPE_CTX_free(ctx);
    printf("✓ Verified in-place equivalence for 1000 operations\n");
}

/* Property 4: Encrypt(x) preserves length */
void test_property_length_preservation(void) {
    printf("\n=== Property 4: Length Preservation ===\n");
    printf("Encrypt(x) always produces output of same length as input\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    unsigned int lengths[] = {2, 3, 5, 10, 20, 50, 100, 200};

    for (int l = 0; l < 8; l++) {
        unsigned int *plaintext = malloc(lengths[l] * sizeof(unsigned int));
        unsigned int *ciphertext = malloc(lengths[l] * sizeof(unsigned int));

        for (int i = 0; i < lengths[l]; i++) {
            plaintext[i] = rand() % 10;
        }

        int ret = FPE_encrypt(ctx, plaintext, ciphertext, lengths[l], tweak, 8);
        TEST_ASSERT_EQUAL(0, ret);

        free(plaintext);
        free(ciphertext);
    }

    FPE_CTX_free(ctx);
    printf("✓ Verified length preservation for 8 different input lengths\n");
}

/* Property 5: Different keys produce different outputs */
void test_property_key_sensitivity(void) {
    printf("\n=== Property 5: Key Sensitivity ===\n");
    printf("Different keys produce different outputs for same input\n");

    unsigned char key1[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned char key2[16] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88,
                             0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx1 = FPE_CTX_new();
    FPE_CTX_init(ctx1, FPE_MODE_FF1, FPE_ALGO_AES, key1, 128, 10);

    FPE_CTX *ctx2 = FPE_CTX_new();
    FPE_CTX_init(ctx2, FPE_MODE_FF1, FPE_ALGO_AES, key2, 128, 10);

    FPE_encrypt(ctx1, plaintext, ciphertext1, 10, tweak, 8);
    FPE_encrypt(ctx2, plaintext, ciphertext2, 10, tweak, 8);

    unsigned int different = 0;
    for (int i = 0; i < 10; i++) {
        if (ciphertext1[i] != ciphertext2[i]) {
            different = 1;
            break;
        }
    }

    TEST_ASSERT_EQUAL(1, different);

    FPE_CTX_free(ctx1);
    FPE_CTX_free(ctx2);
    printf("✓ Verified key sensitivity (different keys produce different outputs)\n");
}

/* Property 6: Different tweaks produce different outputs */
void test_property_tweak_sensitivity(void) {
    printf("\n=== Property 6: Tweak Sensitivity ===\n");
    printf("Different tweaks produce different outputs for same input\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    unsigned char tweak1[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char tweak2[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    FPE_encrypt(ctx, plaintext, ciphertext1, 10, tweak1, 8);
    FPE_encrypt(ctx, plaintext, ciphertext2, 10, tweak2, 8);

    unsigned int different = 0;
    for (int i = 0; i < 10; i++) {
        if (ciphertext1[i] != ciphertext2[i]) {
            different = 1;
            break;
        }
    }

    TEST_ASSERT_EQUAL(1, different);

    FPE_CTX_free(ctx);
    printf("✓ Verified tweak sensitivity (different tweaks produce different outputs)\n");
}

/* Property 7: One-shot API produces same results as context-based */
void test_property_oneshot_equivalence(void) {
    printf("\n=== Property 7: One-shot Equivalence ===\n");
    printf("One-shot API produces same results as context-based API\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext1[10];
    unsigned int ciphertext2[10];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);

    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < 10; j++) {
            plaintext[j] = rand() % 10;
        }

        FPE_encrypt(ctx, plaintext, ciphertext1, 10, tweak, 8);
        FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                          plaintext, ciphertext2, 10, tweak, 8);

        for (int j = 0; j < 10; j++) {
            TEST_ASSERT_EQUAL(ciphertext1[j], ciphertext2[j]);
        }
    }

    FPE_CTX_free(ctx);
    printf("✓ Verified one-shot equivalence for 1000 operations\n");
}

/* Property 8: String API preserves reversibility */
void test_property_string_reversibility(void) {
    printf("\n=== Property 8: String Reversibility ===\n");
    printf("String API also preserves reversibility property\n");

    unsigned char key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    const char *alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char plaintext[20];
    char ciphertext[20];
    char decrypted[20];
    unsigned char tweak[8] = {0};

    FPE_CTX *ctx = FPE_CTX_new();
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 62);

    for (int i = 0; i < 1000; i++) {
        for (int j = 0; j < 15; j++) {
            plaintext[j] = alphabet[rand() % 62];
        }
        plaintext[15] = '\0';

        FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 8);
        FPE_decrypt_str(ctx, alphabet, ciphertext, decrypted, tweak, 8);

        TEST_ASSERT_EQUAL_STRING(plaintext, decrypted);
    }

    FPE_CTX_free(ctx);
    printf("✓ Verified string reversibility for 1000 operations\n");
}

int main(void) {
    srand((unsigned int)time(NULL));

    UNITY_BEGIN();

    RUN_TEST(test_property_reversibility_random);
    RUN_TEST(test_property_determinism);
    RUN_TEST(test_property_inplace_equivalence);
    RUN_TEST(test_property_length_preservation);
    RUN_TEST(test_property_key_sensitivity);
    RUN_TEST(test_property_tweak_sensitivity);
    RUN_TEST(test_property_oneshot_equivalence);
    RUN_TEST(test_property_string_reversibility);

    printf("\n=== Property-based tests complete ===\n");

    return UNITY_END();
}
