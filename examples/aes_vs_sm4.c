/**
 * @file aes_vs_sm4.c
 * @brief AES vs SM4 Performance Comparison Example
 * 
 * This example compares the performance of AES and SM4 ciphers across
 * all FPE algorithms (FF1, FF3, FF3-1).
 * 
 * Key Comparisons:
 * - AES-128 vs SM4-128 (same key length)
 * - Performance across FF1, FF3, FF3-1
 * - Throughput (TPS) comparison
 * - Latency comparison
 * 
 * Build:
 *   gcc -I../include aes_vs_sm4.c -L../build -lfpe -Wl,-rpath,../build -o aes_vs_sm4
 * 
 * Run:
 *   ./aes_vs_sm4
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "fpe.h"

/* Benchmark configuration */
#define BENCHMARK_ITERATIONS 1000
#define INPUT_LENGTH 16
#define RADIX 10

/* Result structure */
typedef struct {
    double elapsed_sec;
    int operations;
    double tps;
    double usec_per_op;
} benchmark_result_t;

/**
 * Run a benchmark for a specific configuration
 */
int run_benchmark(FPE_MODE mode, FPE_ALGO algo, int key_bits,
                  benchmark_result_t* result) {
    /* Setup context */
    FPE_CTX* ctx = FPE_CTX_new();
    if (!ctx) return -1;
    
    unsigned char key[32] = {0};
    for (int i = 0; i < 32; i++) key[i] = i;
    
    int ret = FPE_CTX_init(ctx, mode, algo, key, key_bits, RADIX);
    if (ret != 0) {
        FPE_CTX_free(ctx);
        return -1;
    }
    
    /* Prepare test data */
    unsigned int plaintext[INPUT_LENGTH];
    unsigned int ciphertext[INPUT_LENGTH];
    unsigned int decrypted[INPUT_LENGTH];
    
    for (int i = 0; i < INPUT_LENGTH; i++) {
        plaintext[i] = i % RADIX;
    }
    
    unsigned char tweak[8] = {1,2,3,4,5,6,7,8};
    int tweak_len = (mode == FPE_MODE_FF3_1) ? 7 : 8;
    
    /* Warm-up */
    FPE_encrypt(ctx, plaintext, ciphertext, INPUT_LENGTH, tweak, tweak_len);
    FPE_decrypt(ctx, ciphertext, decrypted, INPUT_LENGTH, tweak, tweak_len);
    
    /* Benchmark */
    clock_t start = clock();
    
    for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
        FPE_encrypt(ctx, plaintext, ciphertext, INPUT_LENGTH, tweak, tweak_len);
        FPE_decrypt(ctx, ciphertext, decrypted, INPUT_LENGTH, tweak, tweak_len);
    }
    
    clock_t end = clock();
    
    /* Calculate results */
    result->elapsed_sec = (double)(end - start) / CLOCKS_PER_SEC;
    result->operations = BENCHMARK_ITERATIONS * 2;  /* encrypt + decrypt */
    result->tps = result->operations / result->elapsed_sec;
    result->usec_per_op = (result->elapsed_sec * 1000000.0) / result->operations;
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    return 0;
}

/**
 * Print comparison header
 */
void print_header(const char* title) {
    printf("\n%s\n", title);
    for (size_t i = 0; i < strlen(title); i++) printf("=");
    printf("\n\n");
}

/**
 * Example 1: FF1 AES vs SM4 Comparison
 */
void example1_ff1_comparison(void) {
    print_header("Example 1: FF1 - AES-128 vs SM4-128");
    
    printf("Configuration:\n");
    printf("• Algorithm: FF1\n");
    printf("• Key length: 128 bits\n");
    printf("• Radix: %d\n", RADIX);
    printf("• Input length: %d digits\n", INPUT_LENGTH);
    printf("• Iterations: %d (encrypt + decrypt pairs)\n\n", BENCHMARK_ITERATIONS);
    
    /* Benchmark AES-128 */
    benchmark_result_t aes_result;
    int ret = run_benchmark(FPE_MODE_FF1, FPE_ALGO_AES, 128, &aes_result);
    
    if (ret != 0) {
        printf("❌ AES-128 benchmark failed\n");
        return;
    }
    
    /* Benchmark SM4-128 */
    benchmark_result_t sm4_result;
    ret = run_benchmark(FPE_MODE_FF1, FPE_ALGO_SM4, 128, &sm4_result);
    
    if (ret != 0) {
        printf("⚠️  SM4-128 not available (requires OpenSSL 3.0+)\n");
        printf("\nAES-128 Results:\n");
        printf("• TPS: %.0f operations/second\n", aes_result.tps);
        printf("• Latency: %.2f µs/operation\n", aes_result.usec_per_op);
        return;
    }
    
    /* Print comparison */
    printf("%-15s %15s %15s\n", "Cipher", "TPS", "Latency (µs)");
    printf("%-15s %15s %15s\n", "---------------", "---------------", "---------------");
    printf("%-15s %15.0f %15.2f\n", "AES-128", aes_result.tps, aes_result.usec_per_op);
    printf("%-15s %15.0f %15.2f\n", "SM4-128", sm4_result.tps, sm4_result.usec_per_op);
    
    /* Calculate difference */
    double tps_diff = ((aes_result.tps - sm4_result.tps) / sm4_result.tps) * 100.0;
    
    printf("\nPerformance Difference:\n");
    if (aes_result.tps > sm4_result.tps) {
        printf("• AES-128 is %.1f%% faster than SM4-128\n", tps_diff);
    } else {
        printf("• SM4-128 is %.1f%% faster than AES-128\n", -tps_diff);
    }
    
    printf("\n✓ FF1 comparison complete\n");
}

/**
 * Example 2: FF3 AES vs SM4 Comparison
 */
void example2_ff3_comparison(void) {
    print_header("Example 2: FF3 - AES-128 vs SM4-128");
    
    printf("Configuration:\n");
    printf("• Algorithm: FF3 (deprecated)\n");
    printf("• Key length: 128 bits\n");
    printf("• Radix: %d\n", RADIX);
    printf("• Input length: %d digits\n", INPUT_LENGTH);
    printf("• Iterations: %d (encrypt + decrypt pairs)\n\n", BENCHMARK_ITERATIONS);
    
    /* Benchmark AES-128 */
    benchmark_result_t aes_result;
    int ret = run_benchmark(FPE_MODE_FF3, FPE_ALGO_AES, 128, &aes_result);
    
    if (ret != 0) {
        printf("❌ AES-128 benchmark failed\n");
        return;
    }
    
    /* Benchmark SM4-128 */
    benchmark_result_t sm4_result;
    ret = run_benchmark(FPE_MODE_FF3, FPE_ALGO_SM4, 128, &sm4_result);
    
    if (ret != 0) {
        printf("⚠️  SM4-128 not available (requires OpenSSL 3.0+)\n");
        printf("\nAES-128 Results:\n");
        printf("• TPS: %.0f operations/second\n", aes_result.tps);
        printf("• Latency: %.2f µs/operation\n", aes_result.usec_per_op);
        return;
    }
    
    /* Print comparison */
    printf("%-15s %15s %15s\n", "Cipher", "TPS", "Latency (µs)");
    printf("%-15s %15s %15s\n", "---------------", "---------------", "---------------");
    printf("%-15s %15.0f %15.2f\n", "AES-128", aes_result.tps, aes_result.usec_per_op);
    printf("%-15s %15.0f %15.2f\n", "SM4-128", sm4_result.tps, sm4_result.usec_per_op);
    
    /* Calculate difference */
    double tps_diff = ((aes_result.tps - sm4_result.tps) / sm4_result.tps) * 100.0;
    
    printf("\nPerformance Difference:\n");
    if (aes_result.tps > sm4_result.tps) {
        printf("• AES-128 is %.1f%% faster than SM4-128\n", tps_diff);
    } else {
        printf("• SM4-128 is %.1f%% faster than AES-128\n", -tps_diff);
    }
    
    printf("\n✓ FF3 comparison complete\n");
}

/**
 * Example 3: FF3-1 AES vs SM4 Comparison
 */
void example3_ff3_1_comparison(void) {
    print_header("Example 3: FF3-1 - AES-128 vs SM4-128");
    
    printf("Configuration:\n");
    printf("• Algorithm: FF3-1\n");
    printf("• Key length: 128 bits\n");
    printf("• Radix: %d\n", RADIX);
    printf("• Input length: %d digits\n", INPUT_LENGTH);
    printf("• Iterations: %d (encrypt + decrypt pairs)\n\n", BENCHMARK_ITERATIONS);
    
    /* Benchmark AES-128 */
    benchmark_result_t aes_result;
    int ret = run_benchmark(FPE_MODE_FF3_1, FPE_ALGO_AES, 128, &aes_result);
    
    if (ret != 0) {
        printf("❌ AES-128 benchmark failed\n");
        return;
    }
    
    /* Benchmark SM4-128 */
    benchmark_result_t sm4_result;
    ret = run_benchmark(FPE_MODE_FF3_1, FPE_ALGO_SM4, 128, &sm4_result);
    
    if (ret != 0) {
        printf("⚠️  SM4-128 not available (requires OpenSSL 3.0+)\n");
        printf("\nAES-128 Results:\n");
        printf("• TPS: %.0f operations/second\n", aes_result.tps);
        printf("• Latency: %.2f µs/operation\n", aes_result.usec_per_op);
        return;
    }
    
    /* Print comparison */
    printf("%-15s %15s %15s\n", "Cipher", "TPS", "Latency (µs)");
    printf("%-15s %15s %15s\n", "---------------", "---------------", "---------------");
    printf("%-15s %15.0f %15.2f\n", "AES-128", aes_result.tps, aes_result.usec_per_op);
    printf("%-15s %15.0f %15.2f\n", "SM4-128", sm4_result.tps, sm4_result.usec_per_op);
    
    /* Calculate difference */
    double tps_diff = ((aes_result.tps - sm4_result.tps) / sm4_result.tps) * 100.0;
    
    printf("\nPerformance Difference:\n");
    if (aes_result.tps > sm4_result.tps) {
        printf("• AES-128 is %.1f%% faster than SM4-128\n", tps_diff);
    } else {
        printf("• SM4-128 is %.1f%% faster than AES-128\n", -tps_diff);
    }
    
    printf("\n✓ FF3-1 comparison complete\n");
}

/**
 * Example 4: Comprehensive AES vs SM4 Summary
 */
void example4_comprehensive_summary(void) {
    print_header("Example 4: Comprehensive AES vs SM4 Summary");
    
    printf("Benchmarking all algorithms with AES-128 and SM4-128...\n\n");
    
    printf("%-12s %-15s %15s %15s\n", 
           "Algorithm", "Cipher", "TPS", "Latency (µs)");
    printf("%-12s %-15s %15s %15s\n", 
           "------------", "---------------", "---------------", "---------------");
    
    /* Test configurations */
    struct {
        FPE_MODE mode;
        const char* name;
    } algorithms[] = {
        {FPE_MODE_FF1, "FF1"},
        {FPE_MODE_FF3, "FF3"},
        {FPE_MODE_FF3_1, "FF3-1"}
    };
    
    struct {
        FPE_ALGO algo;
        const char* name;
    } ciphers[] = {
        {FPE_ALGO_AES, "AES-128"},
        {FPE_ALGO_SM4, "SM4-128"}
    };
    
    for (int a = 0; a < 3; a++) {
        for (int c = 0; c < 2; c++) {
            benchmark_result_t result;
            int ret = run_benchmark(algorithms[a].mode, ciphers[c].algo, 
                                   128, &result);
            
            if (ret == 0) {
                printf("%-12s %-15s %15.0f %15.2f\n", 
                       algorithms[a].name,
                       ciphers[c].name,
                       result.tps,
                       result.usec_per_op);
            } else {
                printf("%-12s %-15s %15s %15s\n", 
                       algorithms[a].name,
                       ciphers[c].name,
                       "N/A", "N/A");
            }
        }
    }
    
    printf("\n✓ Comprehensive summary complete\n");
}

/**
 * Example 5: Key Insights and Recommendations
 */
void example5_insights(void) {
    print_header("Example 5: Key Insights and Recommendations");
    
    printf("When to Use AES:\n");
    printf("• Widely supported (all OpenSSL versions)\n");
    printf("• Hardware acceleration on modern CPUs (AES-NI)\n");
    printf("• Best performance on x86/x64 platforms\n");
    printf("• International standard (NIST, ISO)\n");
    printf("• Recommended for most applications\n");
    printf("\n");
    
    printf("When to Use SM4:\n");
    printf("• Required for Chinese compliance (GM/T standards)\n");
    printf("• Government/financial applications in China\n");
    printf("• Comparable performance to AES\n");
    printf("• Requires OpenSSL 3.0+ for full support\n");
    printf("• May have hardware acceleration on Chinese CPUs\n");
    printf("\n");
    
    printf("Performance Expectations:\n");
    printf("• Performance difference typically < 20%%\n");
    printf("• AES may be faster with AES-NI support\n");
    printf("• SM4 may be faster on Chinese hardware\n");
    printf("• Both scale well with multi-threading\n");
    printf("• Choice should prioritize compliance over performance\n");
    printf("\n");
    
    printf("Compatibility Notes:\n");
    printf("• AES: OpenSSL 1.0.1+ (all versions)\n");
    printf("• SM4: OpenSSL 3.0+ (stable support)\n");
    printf("• SM4: OpenSSL 1.1.1+ (experimental, may not work)\n");
    printf("• Check SM4 availability at runtime\n");
    printf("• Fall back to AES if SM4 unavailable\n");
    printf("\n");
}

/* Main */
int main(void) {
    printf("=== AES vs SM4 Performance Comparison ===\n");
    printf("\nThis example compares AES and SM4 cipher performance\n");
    printf("across all FPE algorithms (FF1, FF3, FF3-1).\n");
    
    /* Run examples */
    example1_ff1_comparison();
    example2_ff3_comparison();
    example3_ff3_1_comparison();
    example4_comprehensive_summary();
    example5_insights();
    
    printf("\n=== AES vs SM4 Comparison Complete ===\n");
    printf("\nKey Takeaways:\n");
    printf("• AES and SM4 have comparable performance\n");
    printf("• Choose based on compliance requirements\n");
    printf("• AES is more widely supported\n");
    printf("• SM4 requires OpenSSL 3.0+ for stability\n");
    printf("• Both scale well with multi-threading\n");
    
    return 0;
}
