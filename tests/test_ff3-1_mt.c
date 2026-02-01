/**
 * @file test_ff3-1_mt.c
 * @brief Multi-threaded tests for FF3-1 algorithm
 * 
 * Tests:
 * - Multiple thread counts (1/2/4/8/16 threads)
 * - TPS (Transactions Per Second) measurement
 * - Thread scaling verification
 * - Thread safety (no race conditions, data corruption)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "unity.h"
#include "fpe.h"

/* Get current time in microseconds */
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* Thread worker arguments */
typedef struct {
    int thread_id;
    int operations;
    unsigned char key[32];
    int key_bits;
    unsigned int radix;
    int length;
    int *success_count;
    int *error_count;
    pthread_mutex_t *counter_mutex;
} thread_args_t;

/* Thread worker for FF3-1 encryption */
void* ff3_1_worker(void* arg) {
    thread_args_t* args = (thread_args_t*)arg;
    
    /* Each thread creates its own context */
    FPE_CTX* ctx = FPE_CTX_new();
    if (!ctx) {
        pthread_mutex_lock(args->counter_mutex);
        (*args->error_count)++;
        pthread_mutex_unlock(args->counter_mutex);
        return NULL;
    }
    
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF3_1, FPE_ALGO_AES, 
                           args->key, args->key_bits, args->radix);
    if (ret != 0) {
        FPE_CTX_free(ctx);
        pthread_mutex_lock(args->counter_mutex);
        (*args->error_count)++;
        pthread_mutex_unlock(args->counter_mutex);
        return NULL;
    }
    
    /* Allocate buffers */
    unsigned int* plaintext = malloc(args->length * sizeof(unsigned int));
    unsigned int* ciphertext = malloc(args->length * sizeof(unsigned int));
    unsigned int* decrypted = malloc(args->length * sizeof(unsigned int));
    unsigned char tweak[7] = {0xD8, 0xE7, 0x92, 0x0A, 0xFA, 0x33, 0x0A};
    
    if (!plaintext || !ciphertext || !decrypted) {
        free(plaintext);
        free(ciphertext);
        free(decrypted);
        FPE_CTX_free(ctx);
        pthread_mutex_lock(args->counter_mutex);
        (*args->error_count)++;
        pthread_mutex_unlock(args->counter_mutex);
        return NULL;
    }
    
    int local_success = 0;
    int local_error = 0;
    
    /* Perform operations */
    for (int i = 0; i < args->operations; i++) {
        /* Generate thread-specific plaintext */
        for (int j = 0; j < args->length; j++) {
            plaintext[j] = (args->thread_id * 1000 + i + j) % args->radix;
        }
        
        /* Encrypt */
        ret = FPE_encrypt(ctx, plaintext, ciphertext, args->length, tweak, 7);
        if (ret != 0) {
            local_error++;
            continue;
        }
        
        /* Decrypt */
        ret = FPE_decrypt(ctx, ciphertext, decrypted, args->length, tweak, 7);
        if (ret != 0) {
            local_error++;
            continue;
        }
        
        /* Verify round-trip */
        int mismatch = 0;
        for (int j = 0; j < args->length; j++) {
            if (plaintext[j] != decrypted[j]) {
                mismatch = 1;
                break;
            }
        }
        
        if (mismatch) {
            local_error++;
        } else {
            local_success++;
        }
    }
    
    /* Update global counters */
    pthread_mutex_lock(args->counter_mutex);
    *args->success_count += local_success;
    *args->error_count += local_error;
    pthread_mutex_unlock(args->counter_mutex);
    
    /* Cleanup */
    free(plaintext);
    free(ciphertext);
    free(decrypted);
    FPE_CTX_free(ctx);
    
    return NULL;
}

/* Helper function to run multi-threaded test */
static void run_ff3_1_mt_test(int num_threads, int ops_per_thread, 
                             unsigned char* key, int key_bits,
                             unsigned int radix, int length,
                             int* total_ops, double* elapsed_sec, double* tps) {
    pthread_t* threads = malloc(num_threads * sizeof(pthread_t));
    thread_args_t* args = malloc(num_threads * sizeof(thread_args_t));
    
    int success_count = 0;
    int error_count = 0;
    pthread_mutex_t counter_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    /* Prepare thread arguments */
    for (int i = 0; i < num_threads; i++) {
        args[i].thread_id = i;
        args[i].operations = ops_per_thread;
        memcpy(args[i].key, key, 32);
        args[i].key_bits = key_bits;
        args[i].radix = radix;
        args[i].length = length;
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        args[i].counter_mutex = &counter_mutex;
    }
    
    /* Start timing */
    uint64_t start = get_time_us();
    
    /* Create threads */
    for (int i = 0; i < num_threads; i++) {
        int ret = pthread_create(&threads[i], NULL, ff3_1_worker, &args[i]);
        TEST_ASSERT_EQUAL(0, ret);
    }
    
    /* Wait for threads */
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* End timing */
    uint64_t end = get_time_us();
    
    /* Calculate results */
    *total_ops = success_count;
    *elapsed_sec = (end - start) / 1000000.0;
    *tps = success_count / *elapsed_sec;
    
    /* Verify no errors */
    TEST_ASSERT_EQUAL(0, error_count);
    TEST_ASSERT_EQUAL(num_threads * ops_per_thread, success_count);
    
    /* Cleanup */
    pthread_mutex_destroy(&counter_mutex);
    free(threads);
    free(args);
}

void setUp(void) {
    // Setup if needed
}

void tearDown(void) {
    // Teardown if needed
}

/* Test 6.25: Multiple thread counts */
void test_ff3_1_multiple_thread_counts(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    const int ops_per_thread = 500;
    const int thread_counts[] = {1, 2, 4, 8, 16};
    const int num_tests = 5;
    
    printf("\n");
    printf("========================================\n");
    printf("FF3-1 Multi-Threading Performance Tests\n");
    printf("========================================\n");
    printf("Operations per thread: %d\n", ops_per_thread);
    printf("Radix: 10, Length: 10\n");
    printf("\n");
    printf("Threads | Total Ops | Time (s) | TPS\n");
    printf("--------|-----------|----------|----------\n");
    
    for (int i = 0; i < num_tests; i++) {
        int total_ops;
        double elapsed_sec, tps;
        
        run_ff3_1_mt_test(thread_counts[i], ops_per_thread, key, 128, 10, 10,
                         &total_ops, &elapsed_sec, &tps);
        
        printf("%7d | %9d | %8.3f | %8.0f\n",
               thread_counts[i], total_ops, elapsed_sec, tps);
        
        /* Basic sanity check: TPS should be positive */
        TEST_ASSERT_TRUE(tps > 0);
    }
    
    printf("\n");
}

/* Test 6.26: Verify TPS scales with thread count */
void test_ff3_1_tps_scaling(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    const int ops_per_thread = 500;
    const int thread_counts[] = {1, 2, 4, 8};
    const int num_tests = 4;
    double tps_results[4];
    
    printf("\n");
    printf("========================================\n");
    printf("FF3-1 TPS Scaling Verification\n");
    printf("========================================\n");
    printf("\n");
    printf("Threads | TPS      | Speedup  | Efficiency\n");
    printf("--------|----------|----------|------------\n");
    
    for (int i = 0; i < num_tests; i++) {
        int total_ops;
        double elapsed_sec;
        
        run_ff3_1_mt_test(thread_counts[i], ops_per_thread, key, 128, 10, 10,
                         &total_ops, &elapsed_sec, &tps_results[i]);
        
        double speedup = tps_results[i] / tps_results[0];
        double efficiency = speedup / thread_counts[i] * 100.0;
        
        printf("%7d | %8.0f | %8.2fx | %10.1f%%\n",
               thread_counts[i], tps_results[i], speedup, efficiency);
        
        /* Verify scaling: TPS should increase with more threads */
        if (i > 0) {
            TEST_ASSERT_TRUE(tps_results[i] > tps_results[0]);
        }
    }
    
    printf("\n");
}

/* Test 6.27: Thread safety verification */
void test_ff3_1_thread_safety(void) {
    unsigned char key[16] = {
        0xEF, 0x43, 0x59, 0xD8, 0xD5, 0x80, 0xAA, 0x4F,
        0x7F, 0x03, 0x6D, 0x6F, 0x04, 0xFC, 0x6A, 0x94
    };
    
    printf("\n");
    printf("========================================\n");
    printf("FF3-1 Thread Safety Test\n");
    printf("========================================\n");
    printf("Testing concurrent access with 16 threads\n");
    printf("Each thread performs 1000 encrypt/decrypt cycles\n");
    printf("\n");
    
    int total_ops;
    double elapsed_sec, tps;
    
    /* Run intensive test with many threads */
    run_ff3_1_mt_test(16, 1000, key, 128, 10, 10,
                     &total_ops, &elapsed_sec, &tps);
    
    printf("Result: %d operations completed successfully\n", total_ops);
    printf("Time: %.3f seconds\n", elapsed_sec);
    printf("TPS: %.0f\n", tps);
    printf("\n");
    printf("✓ No race conditions detected\n");
    printf("✓ No data corruption detected\n");
    printf("✓ All encrypt/decrypt cycles verified\n");
    printf("\n");
    
    TEST_ASSERT_EQUAL(16000, total_ops);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_ff3_1_multiple_thread_counts);
    RUN_TEST(test_ff3_1_tps_scaling);
    RUN_TEST(test_ff3_1_thread_safety);
    
    return UNITY_END();
}
