/**
 * @file test_basic.c
 * @brief Basic test to verify library compiles and links
 */

#include "../include/fpe.h"
#include <stdio.h>

int main(void) {
    printf("FPE Library Basic Test\n");
    
    /* Create context */
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        printf("Failed to create context\n");
        return 1;
    }
    
    printf("Context created successfully\n");
    
    /* Free context */
    FPE_CTX_free(ctx);
    printf("Context freed successfully\n");
    
    printf("Basic test PASSED\n");
    return 0;
}
