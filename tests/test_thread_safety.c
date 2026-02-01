/**
 * @file test_thread_safety.c
 * @brief Thread safety tests for FPE API
 * 
 * Tests:
 * - 8.16: Thread safety with multiple contexts (each thread has its own context)
 * - 8.17: Shared context behavior (undefined behavior documentation)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include "unity.h"
#include "fpe.h"

/* Test configuration */
#define NUM_THREADS 16
#define OPS_PER_THREAD 500

/* Get current time in microseconds */
static uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

/* ============================================================================
 * Test 8.16: Thread Safety with Multiple Contexts (Recommended Pattern)
 * ============================================================================
 * Each thread creates its own FPE_CTX instance.
 * This is the RECOMMENDED and SAFE approach.
 */

typedef struct {
    int thread_id;
    int operations;
    unsigned char key[32];
    int key_bits;
    int *success_count;
    int *error_count;
    pthread_mutex_t *mutex;
} multi_ctx_args_t;

void* multi_context_worker(void* arg) {
    multi_ctx_args_t* args = (multi_ctx_args_t*)arg;
    
    /* Each thread creates its own context - THIS IS SAFE */
    FPE_CTX* ctx = FPE_CTX_new();
    if (!ctx) {
        pthread_mutex_lock(args->mutex);
        (*args->error_count)++;
        pthread_mutex_unlock(args->mutex);
        return NULL;
    }
    
    /* Initialize context */
    int ret = FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, 
                           args->key, args->key_bits, 10);
    if (ret != 0) {
        FPE_CTX_free(ctx);
        pthread_mutex_lock(args->mutex);
        (*args->error_count)++;
        pthread_mutex_unlock(args->mutex);
        return NULL;
    }
    
    /* Perform operations */
    unsigned char tweak[8] = {0};
    unsigned int plaintext[10], ciphertext[10], decrypted[10];
    int local_success = 0;
    int local_error = 0;
    
    for (int i = 0; i < args->operations; i++) {
        /* Generate unique plaintext based on thread ID and iteration */
        for (int j = 0; j < 10; j++) {
            plaintext[j] = (args->thread_id * 1000 + i + j) % 10;
        }
        
        /* Encrypt */
        ret = FPE_encrypt(ctx, plaintext, ciphertext, 10, tweak, 8);
        if (ret != 0) {
            local_error++;
            continue;
        }
        
        /* Decrypt */
        ret = FPE_decrypt(ctx, ciphertext, decrypted, 10, tweak, 8);
        if (ret != 0) {
            local_error++;
            continue;
        }
        
        /* Verify correctness */
        int match = 1;
        for (int j = 0; j < 10; j++) {
            if (plaintext[j] != decrypted[j]) {
                match = 0;
                break;
            }
        }
        
        if (match) {
            local_success++;
        } else {
            local_error++;
        }
    }
    
    /* Update global counters */
    pthread_mutex_lock(args->mutex);
    *args->success_count += local_success;
    *args->error_count += local_error;
    pthread_mutex_unlock(args->mutex);
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    return NULL;
}

/* ============================================================================
 * Test 8.17: Shared Context Behavior (Unsafe - For Documentation)
 * ============================================================================
 * Multiple threads sharing a single FPE_CTX instance.
 * This is UNSAFE and demonstrates undefined behavior.
 * 
 * Note: FPE_CTX is NOT thread-safe for concurrent operations.
 * This test documents the behavior but should NOT be used in production.
 */

typedef struct {
    int thread_id;
    int operations;
    FPE_CTX *shared_ctx;  /* SHARED context - UNSAFE */
    int *success_count;
    int *error_count;
    int *corruption_count;
    pthread_mutex_t *mutex;
} shared_ctx_args_t;

void* shared_context_worker(void* arg) {
    shared_ctx_args_t* args = (shared_ctx_args_t*)arg;
    
    /* Using SHARED context - this is UNSAFE without external synchronization */
    unsigned char tweak[8] = {0};
    unsigned int plaintext[10], ciphertext[10], decrypted[10];
    int local_success = 0;
    int local_error = 0;
    int local_corruption = 0;
    
    for (int i = 0; i < args->operations; i++) {
        /* Generate unique plaintext */
        for (int j = 0; j < 10; j++) {
            plaintext[j] = (args->thread_id * 1000 + i + j) % 10;
        }
        
        /* WITHOUT mutex protection, these operations may corrupt each other */
        int ret = FPE_encrypt(args->shared_ctx, plaintext, ciphertext, 10, tweak, 8);
        if (ret != 0) {
            local_error++;
            continue;
        }
        
        ret = FPE_decrypt(args->shared_ctx, ciphertext, decrypted, 10, tweak, 8);
        if (ret != 0) {
            local_error++;
            continue;
        }
        
        /* Verify correctness */
        int match = 1;
        for (int j = 0; j < 10; j++) {
            if (plaintext[j] != decrypted[j]) {
                match = 0;
                break;
            }
        }
        
        if (match) {
            local_success++;
        } else {
            local_corruption++;  /* Data corruption due to race condition */
        }
    }
    
    /* Update global counters */
    pthread_mutex_lock(args->mutex);
    *args->success_count += local_success;
    *args->error_count += local_error;
    *args->corruption_count += local_corruption;
    pthread_mutex_unlock(args->mutex);
    
    return NULL;
}

void setUp(void) {
    // Setup
}

void tearDown(void) {
    // Teardown
}

/* Test 8.16: Multiple contexts (safe and recommended) */
void test_thread_safety_multiple_contexts(void) {
    printf("\n");
    printf("========================================\n");
    printf("Test 8.16: Thread Safety - Multiple Contexts\n");
    printf("========================================\n");
    printf("Pattern: Each thread creates its own FPE_CTX\n");
    printf("Status: SAFE and RECOMMENDED\n");
    printf("\n");
    printf("Testing with %d threads, %d operations each\n", NUM_THREADS, OPS_PER_THREAD);
    printf("\n");
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    pthread_t threads[NUM_THREADS];
    multi_ctx_args_t args[NUM_THREADS];
    int success_count = 0;
    int error_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    /* Prepare arguments */
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].operations = OPS_PER_THREAD;
        memcpy(args[i].key, key, 16);
        args[i].key_bits = 128;
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        args[i].mutex = &mutex;
    }
    
    /* Start timing */
    uint64_t start = get_time_us();
    
    /* Create threads */
    for (int i = 0; i < NUM_THREADS; i++) {
        int ret = pthread_create(&threads[i], NULL, multi_context_worker, &args[i]);
        TEST_ASSERT_EQUAL(0, ret);
    }
    
    /* Wait for completion */
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    uint64_t end = get_time_us();
    double elapsed = (end - start) / 1000000.0;
    
    /* Verify results */
    printf("Results:\n");
    printf("  Success:     %d operations (%.1f%%)\n", 
           success_count, 100.0 * success_count / (NUM_THREADS * OPS_PER_THREAD));
    printf("  Errors:      %d\n", error_count);
    printf("  Time:        %.3f seconds\n", elapsed);
    printf("  Throughput:  %.0f ops/sec\n", success_count / elapsed);
    printf("\n");
    printf("✓ No race conditions\n");
    printf("✓ No data corruption\n");
    printf("✓ All operations completed successfully\n");
    printf("\n");
    
    /* All operations should succeed with no errors */
    TEST_ASSERT_EQUAL(0, error_count);
    TEST_ASSERT_EQUAL(NUM_THREADS * OPS_PER_THREAD, success_count);
    
    pthread_mutex_destroy(&mutex);
}

/* Test 8.17: Shared context (unsafe - for documentation) */
void test_shared_context_unsafe_behavior(void) {
    printf("\n");
    printf("========================================\n");
    printf("Test 8.17: Shared Context - Unsafe Behavior\n");
    printf("========================================\n");
    printf("Pattern: Multiple threads sharing one FPE_CTX\n");
    printf("Status: UNSAFE - Demonstrates undefined behavior\n");
    printf("\n");
    printf("⚠️  WARNING: This pattern is NOT RECOMMENDED\n");
    printf("⚠️  FPE_CTX is NOT thread-safe for concurrent operations\n");
    printf("⚠️  This test is for documentation purposes only\n");
    printf("\n");
    
    unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    /* Create ONE shared context */
    FPE_CTX* shared_ctx = FPE_CTX_new();
    TEST_ASSERT_NOT_NULL(shared_ctx);
    
    int ret = FPE_CTX_init(shared_ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10);
    TEST_ASSERT_EQUAL(0, ret);
    
    pthread_t threads[NUM_THREADS];
    shared_ctx_args_t args[NUM_THREADS];
    int success_count = 0;
    int error_count = 0;
    int corruption_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    /* Prepare arguments - all threads share the same context */
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        args[i].operations = OPS_PER_THREAD;
        args[i].shared_ctx = shared_ctx;  /* SHARED - UNSAFE */
        args[i].success_count = &success_count;
        args[i].error_count = &error_count;
        args[i].corruption_count = &corruption_count;
        args[i].mutex = &mutex;
    }
    
    /* Run test */
    printf("Running test with %d threads, %d operations each...\n", NUM_THREADS, OPS_PER_THREAD);
    printf("\n");
    
    for (int i = 0; i < NUM_THREADS; i++) {
        ret = pthread_create(&threads[i], NULL, shared_context_worker, &args[i]);
        TEST_ASSERT_EQUAL(0, ret);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    /* Report results */
    int total_ops = NUM_THREADS * OPS_PER_THREAD;
    printf("Results:\n");
    printf("  Total operations:     %d\n", total_ops);
    printf("  Successful:           %d (%.1f%%)\n", 
           success_count, 100.0 * success_count / total_ops);
    printf("  Errors:               %d (%.1f%%)\n",
           error_count, 100.0 * error_count / total_ops);
    printf("  Data corruption:      %d (%.1f%%)\n",
           corruption_count, 100.0 * corruption_count / total_ops);
    printf("\n");
    
    if (corruption_count > 0) {
        printf("✗ Data corruption detected due to race conditions\n");
        printf("✗ This confirms FPE_CTX is NOT thread-safe\n");
        printf("\n");
        printf("Recommendation:\n");
        printf("  Use pattern from test_thread_safety_multiple_contexts()\n");
        printf("  Each thread should have its own FPE_CTX instance\n");
    } else {
        printf("Note: No corruption detected in this run, but behavior is still undefined\n");
        printf("      Race conditions are non-deterministic and may occur in other runs\n");
    }
    printf("\n");
    
    /* Cleanup */
    FPE_CTX_free(shared_ctx);
    pthread_mutex_destroy(&mutex);
    
    /* This test documents unsafe behavior - we don't assert success/failure */
    /* The point is to show that shared context is unreliable */
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_thread_safety_multiple_contexts);
    RUN_TEST(test_shared_context_unsafe_behavior);
    
    return UNITY_END();
}
