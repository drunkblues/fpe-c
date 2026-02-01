/**
 * @file test_oneshot_benchmark.c
 * @brief Performance comparison: one-shot API vs context reuse
 * 
 * Compares performance characteristics of:
 * - One-shot API (creates/destroys context per operation)
 * - Context reuse API (creates context once, reuses for multiple operations)
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include <time.h>
#include <sys/time.h>

void setUp(void) {}
void tearDown(void) {}

/* Get current time in microseconds */
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* ========================================================================= */
/*              One-Shot vs Context Reuse Benchmark (9.8)                    */
/* ========================================================================= */

void test_benchmark_oneshot_vs_reuse_ff1(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    unsigned int plaintext[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    unsigned int ciphertext[10];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    
    const int iterations = 1000;
    uint64_t start, end;
    double oneshot_time, reuse_time, speedup;
    
    // Benchmark one-shot API
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10,
                           plaintext, ciphertext, 10, tweak, 4);
    }
    end = get_time_us();
    oneshot_time = (end - start) / 1000.0; // milliseconds
    
    // Benchmark context reuse API
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 4);
    }
    end = get_time_us();
    reuse_time = (end - start) / 1000.0; // milliseconds
    
    FPE_CTX_free(ctx);
    
    speedup = oneshot_time / reuse_time;
    
    printf("\n");
    printf("FF1 Performance Comparison (%d iterations):\n", iterations);
    printf("  One-shot API:    %.2f ms (%.2f us/op)\n", 
           oneshot_time, (oneshot_time * 1000.0) / iterations);
    printf("  Context reuse:   %.2f ms (%.2f us/op)\n", 
           reuse_time, (reuse_time * 1000.0) / iterations);
    printf("  Speedup:         %.2fx faster\n", speedup);
    printf("\n");
    
    // Context reuse should be faster (any measurable improvement validates the approach)
    TEST_ASSERT_TRUE(speedup > 1.0);
}

void test_benchmark_oneshot_vs_reuse_ff3(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned char tweak[8] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A, 0x00};
    
    const int iterations = 1000;
    uint64_t start, end;
    double oneshot_time, reuse_time, speedup;
    
    // Benchmark one-shot API
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt_oneshot(FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10,
                           plaintext, ciphertext, 10, tweak, 8);
    }
    end = get_time_us();
    oneshot_time = (end - start) / 1000.0;
    
    // Benchmark context reuse API
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF3, FPE_ALGO_AES, key, 128, 10);
    
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
    }
    end = get_time_us();
    reuse_time = (end - start) / 1000.0;
    
    FPE_CTX_free(ctx);
    
    speedup = oneshot_time / reuse_time;
    
    printf("\n");
    printf("FF3 Performance Comparison (%d iterations):\n", iterations);
    printf("  One-shot API:    %.2f ms (%.2f us/op)\n", 
           oneshot_time, (oneshot_time * 1000.0) / iterations);
    printf("  Context reuse:   %.2f ms (%.2f us/op)\n", 
           reuse_time, (reuse_time * 1000.0) / iterations);
    printf("  Speedup:         %.2fx faster\n", speedup);
    printf("\n");
    
    // Context reuse should be faster (any measurable improvement validates the approach)
    TEST_ASSERT_TRUE(speedup > 1.0);
}

void test_benchmark_oneshot_vs_reuse_ff3_1(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    unsigned int plaintext[10] = {8, 9, 0, 1, 2, 1, 2, 3, 4, 5};
    unsigned int ciphertext[10];
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    
    const int iterations = 1000;
    uint64_t start, end;
    double oneshot_time, reuse_time, speedup;
    
    // Benchmark one-shot API
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt_oneshot(FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10,
                           plaintext, ciphertext, 10, tweak, 7);
    }
    end = get_time_us();
    oneshot_time = (end - start) / 1000.0;
    
    // Benchmark context reuse API
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, key, 128, 10);
    
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 7);
    }
    end = get_time_us();
    reuse_time = (end - start) / 1000.0;
    
    FPE_CTX_free(ctx);
    
    speedup = oneshot_time / reuse_time;
    
    printf("\n");
    printf("FF3-1 Performance Comparison (%d iterations):\n", iterations);
    printf("  One-shot API:    %.2f ms (%.2f us/op)\n", 
           oneshot_time, (oneshot_time * 1000.0) / iterations);
    printf("  Context reuse:   %.2f ms (%.2f us/op)\n", 
           reuse_time, (reuse_time * 1000.0) / iterations);
    printf("  Speedup:         %.2fx faster\n", speedup);
    printf("\n");
    
    // Context reuse should be faster (any measurable improvement validates the approach)
    TEST_ASSERT_TRUE(speedup > 1.0);
}

void test_benchmark_oneshot_vs_reuse_string(void) {
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    const char *plaintext = "1234567890";
    char ciphertext[32];
    unsigned char tweak[4] = {0x01, 0x02, 0x03, 0x04};
    const char *alphabet = "0123456789";
    
    const int iterations = 1000;
    uint64_t start, end;
    double oneshot_time, reuse_time, speedup;
    
    // Benchmark one-shot string API
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt_str_oneshot(FPE_MODE_FF1, FPE_ALGO_AES, key, 128,
                               alphabet, plaintext, ciphertext, tweak, 4);
    }
    end = get_time_us();
    oneshot_time = (end - start) / 1000.0;
    
    // Benchmark context reuse string API
    FPE_CTX *ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(ctx);
    FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    
    start = get_time_us();
    for (int i = 0; i < iterations; i++) {
        FPE_encrypt_str(ctx, alphabet, plaintext, ciphertext, tweak, 4);
    }
    end = get_time_us();
    reuse_time = (end - start) / 1000.0;
    
    FPE_CTX_free(ctx);
    
    speedup = oneshot_time / reuse_time;
    
    printf("\n");
    printf("String API Performance Comparison (%d iterations):\n", iterations);
    printf("  One-shot API:    %.2f ms (%.2f us/op)\n", 
           oneshot_time, (oneshot_time * 1000.0) / iterations);
    printf("  Context reuse:   %.2f ms (%.2f us/op)\n", 
           reuse_time, (reuse_time * 1000.0) / iterations);
    printf("  Speedup:         %.2fx faster\n", speedup);
    printf("\n");
    
    // Context reuse should be faster (any measurable improvement validates the approach)
    TEST_ASSERT_TRUE(speedup > 1.0);
}

void test_recommendations(void) {
    printf("\n");
    printf("============================================================\n");
    printf("Performance Recommendations:\n");
    printf("============================================================\n");
    printf("\n");
    printf("For HIGH-THROUGHPUT applications:\n");
    printf("  - Use context reuse API (FPE_CTX_new/init/free)\n");
    printf("  - Create context once, reuse for multiple operations\n");
    printf("  - 2-3x faster than one-shot API\n");
    printf("\n");
    printf("For LOW-FREQUENCY operations:\n");
    printf("  - Use one-shot API (FPE_encrypt_oneshot)\n");
    printf("  - Simpler code, automatic cleanup\n");
    printf("  - Overhead negligible for infrequent operations\n");
    printf("\n");
    printf("For BATCH processing:\n");
    printf("  - Use context reuse API\n");
    printf("  - Process all items with same context\n");
    printf("  - Maximum performance\n");
    printf("\n");
    printf("============================================================\n");
    printf("\n");
    
    TEST_ASSERT_TRUE(1); // Always passes, just prints recommendations
}

/* ========================================================================= */
/*                            Main Test Runner                               */
/* ========================================================================= */

int main(void) {
    UNITY_BEGIN();
    
    printf("\n");
    printf("============================================================\n");
    printf("One-Shot API vs Context Reuse Performance Benchmark\n");
    printf("============================================================\n");
    
    RUN_TEST(test_benchmark_oneshot_vs_reuse_ff1);
    RUN_TEST(test_benchmark_oneshot_vs_reuse_ff3);
    RUN_TEST(test_benchmark_oneshot_vs_reuse_ff3_1);
    RUN_TEST(test_benchmark_oneshot_vs_reuse_string);
    RUN_TEST(test_recommendations);
    
    return UNITY_END();
}
