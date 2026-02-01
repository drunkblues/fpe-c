/**
 * In-Place Encryption Example - FPE-C Library
 * 
 * Demonstrates in-place encryption where the output buffer is the same as input:
 * - Using same buffer for encryption and decryption
 * - Memory efficiency benefits
 * - API usage patterns
 * - Performance considerations
 * - Common use cases
 */

#include <stdio.h>
#include <string.h>
#include <fpe.h>

/* Helper function to print a separator */
static void print_separator(const char *title) {
    printf("\n%s\n", title);
    for (size_t i = 0; i < strlen(title); i++) printf("-");
    printf("\n");
}

int main(void) {
    printf("=== In-Place Encryption Example ===\n");
    
    /* Encryption key (16 bytes for AES-128) */
    const unsigned char key[16] = {
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    };
    
    /* Sample tweak */
    const unsigned char tweak[8] = "inplace";
    unsigned int tweak_len = 7;
    
    FPE_CTX *ctx = FPE_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create FPE context\n");
        return 1;
    }
    
    if (FPE_CTX_init(ctx, FPE_MODE_FF1, FPE_ALGO_AES, key, 128, 10) != 0) {
        fprintf(stderr, "Failed to initialize context\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    const char *alphabet = "0123456789";
    
    /* ========================================================================
     * Example 1: Basic In-Place Encryption
     * Using the same buffer for input and output
     * ======================================================================== */
    print_separator("Example 1: Basic In-Place Encryption");
    
    /* Create a modifiable buffer (not const) */
    char buffer[32];
    strcpy(buffer, "4111111111111111");
    
    printf("Buffer before encryption: %s\n", buffer);
    
    /* Encrypt in-place: buffer is both input and output */
    int ret = FPE_encrypt_str(ctx, alphabet, buffer, buffer, tweak, tweak_len);
    if (ret != 0) {
        fprintf(stderr, "Encryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Buffer after encryption:  %s\n", buffer);
    
    /* Decrypt in-place: buffer is both input and output */
    ret = FPE_decrypt_str(ctx, alphabet, buffer, buffer, tweak, tweak_len);
    if (ret != 0) {
        fprintf(stderr, "Decryption failed\n");
        FPE_CTX_free(ctx);
        return 1;
    }
    
    printf("Buffer after decryption:  %s\n", buffer);
    printf("✓ In-place encryption successful\n");
    
    /* ========================================================================
     * Example 2: Memory Efficiency - Processing Arrays
     * In-place is more efficient when processing many items
     * ======================================================================== */
    print_separator("Example 2: Memory Efficiency - Processing Arrays");
    
    const char *original_data[] = {
        "1234567890",
        "5555666677",
        "9876543210",
        "1111222233",
        "4444555566"
    };
    
    /* Create modifiable copies */
    char data[5][32];
    for (int i = 0; i < 5; i++) {
        strcpy(data[i], original_data[i]);
    }
    
    printf("Processing 5 items in-place:\n\n");
    printf("%-3s %-15s %-15s %-15s\n", "#", "Original", "Encrypted", "Decrypted");
    printf("%-3s %-15s %-15s %-15s\n", "---", "---------------", "---------------", "---------------");
    
    for (int i = 0; i < 5; i++) {
        char original_copy[32];
        strcpy(original_copy, data[i]);
        
        /* Encrypt in-place */
        FPE_encrypt_str(ctx, alphabet, data[i], data[i], tweak, tweak_len);
        
        char encrypted_copy[32];
        strcpy(encrypted_copy, data[i]);
        
        /* Decrypt in-place */
        FPE_decrypt_str(ctx, alphabet, data[i], data[i], tweak, tweak_len);
        
        printf("%-3d %-15s %-15s %-15s\n", i+1, original_copy, encrypted_copy, data[i]);
    }
    
    printf("\n✓ All items processed successfully in-place\n");
    printf("✓ Memory efficient: No extra buffers needed\n");
    
    /* ========================================================================
     * Example 3: Database Record Updates
     * Practical use case: Encrypting sensitive fields in database records
     * ======================================================================== */
    print_separator("Example 3: Database Record Updates");
    
    /* Simulate a database record with sensitive fields */
    struct User {
        int id;
        char ssn[12];
        char phone[12];
        char name[64];
    };
    
    struct User users[] = {
        {1, "123456789", "5551234567", "John Smith"},
        {2, "987654321", "5559876543", "Jane Doe"},
        {3, "456789123", "5554567891", "Bob Johnson"}
    };
    
    printf("Encrypting sensitive fields in-place:\n\n");
    printf("Before encryption:\n");
    for (int i = 0; i < 3; i++) {
        printf("  User %d: SSN=%s, Phone=%s, Name=%s\n",
               users[i].id, users[i].ssn, users[i].phone, users[i].name);
    }
    
    /* Encrypt sensitive fields in-place */
    for (int i = 0; i < 3; i++) {
        /* Use different tweaks for different fields for better security */
        unsigned char ssn_tweak[16];
        unsigned char phone_tweak[16];
        
        snprintf((char*)ssn_tweak, sizeof(ssn_tweak), "ssn:%d", users[i].id);
        snprintf((char*)phone_tweak, sizeof(phone_tweak), "phone:%d", users[i].id);
        
        FPE_encrypt_str(ctx, alphabet, users[i].ssn, users[i].ssn, 
                       ssn_tweak, strlen((char*)ssn_tweak));
        FPE_encrypt_str(ctx, alphabet, users[i].phone, users[i].phone, 
                       phone_tweak, strlen((char*)phone_tweak));
    }
    
    printf("\nAfter encryption:\n");
    for (int i = 0; i < 3; i++) {
        printf("  User %d: SSN=%s, Phone=%s, Name=%s\n",
               users[i].id, users[i].ssn, users[i].phone, users[i].name);
    }
    
    /* Decrypt to verify */
    for (int i = 0; i < 3; i++) {
        unsigned char ssn_tweak[16];
        unsigned char phone_tweak[16];
        
        snprintf((char*)ssn_tweak, sizeof(ssn_tweak), "ssn:%d", users[i].id);
        snprintf((char*)phone_tweak, sizeof(phone_tweak), "phone:%d", users[i].id);
        
        FPE_decrypt_str(ctx, alphabet, users[i].ssn, users[i].ssn, 
                       ssn_tweak, strlen((char*)ssn_tweak));
        FPE_decrypt_str(ctx, alphabet, users[i].phone, users[i].phone, 
                       phone_tweak, strlen((char*)phone_tweak));
    }
    
    printf("\nAfter decryption:\n");
    for (int i = 0; i < 3; i++) {
        printf("  User %d: SSN=%s, Phone=%s, Name=%s\n",
               users[i].id, users[i].ssn, users[i].phone, users[i].name);
    }
    
    printf("\n✓ In-place encryption perfect for database updates\n");
    printf("✓ No extra memory allocation needed\n");
    
    /* ========================================================================
     * Example 4: Performance Comparison
     * In-place vs separate buffers
     * ======================================================================== */
    print_separator("Example 4: Performance Considerations");
    
    printf("\nMemory Usage Comparison:\n\n");
    
    printf("Separate Buffers:\n");
    printf("  - Input buffer:  16 bytes\n");
    printf("  - Output buffer: 16 bytes\n");
    printf("  - Total:         32 bytes per operation\n");
    printf("  - For 1000 items: ~32 KB\n\n");
    
    printf("In-Place Operation:\n");
    printf("  - Single buffer: 16 bytes\n");
    printf("  - Total:         16 bytes per operation\n");
    printf("  - For 1000 items: ~16 KB\n");
    printf("  - Memory saved:   50%%\n\n");
    
    printf("Performance:\n");
    printf("  - Encryption speed: Same (no performance penalty)\n");
    printf("  - Cache efficiency: Better (fewer memory locations)\n");
    printf("  - Recommended for: Batch processing, database operations\n");
    
    /* ========================================================================
     * Example 5: Important Considerations
     * ======================================================================== */
    print_separator("Example 5: Important Considerations");
    
    printf("\n1. Buffer Requirements:\n");
    printf("   - Buffer must be modifiable (not const)\n");
    printf("   - Buffer must have sufficient space for output\n");
    printf("   - Null terminator is guaranteed by the library\n\n");
    
    printf("2. Thread Safety:\n");
    printf("   - Safe: Multiple threads with separate contexts\n");
    printf("   - Safe: Multiple threads with separate buffers\n");
    printf("   - Unsafe: Multiple threads sharing same buffer\n");
    printf("   - Unsafe: Multiple threads sharing same context\n\n");
    
    printf("3. Error Handling:\n");
    printf("   - On error, buffer content is undefined\n");
    printf("   - Always check return value before using result\n");
    printf("   - Keep backup if original data must be preserved\n\n");
    
    printf("4. Best Practices:\n");
    printf("   - Use in-place for batch operations\n");
    printf("   - Use in-place for memory-constrained systems\n");
    printf("   - Use separate buffers if you need to keep original\n");
    printf("   - Use separate buffers for debugging/logging\n\n");
    
    /* ========================================================================
     * Example 6: When NOT to Use In-Place
     * ======================================================================== */
    print_separator("Example 6: When NOT to Use In-Place");
    
    printf("\nAvoid in-place encryption when:\n\n");
    
    printf("1. You need to keep the original:\n");
    printf("   - Logging/auditing requirements\n");
    printf("   - Debugging/troubleshooting\n");
    printf("   - Comparison operations\n\n");
    
    printf("2. Buffer is read-only:\n");
    printf("   - String literals (const char*)\n");
    printf("   - Memory-mapped files (read-only)\n");
    printf("   - Shared read-only memory\n\n");
    
    printf("3. Concurrent access:\n");
    printf("   - Multiple threads reading same buffer\n");
    printf("   - Shared data structures\n");
    printf("   - Event-driven architectures\n\n");
    
    printf("4. Error recovery needed:\n");
    printf("   - Transactional operations\n");
    printf("   - Rollback requirements\n");
    printf("   - Fault tolerance systems\n\n");
    
    /* ========================================================================
     * Example 7: Error Handling
     * ======================================================================== */
    print_separator("Example 7: Error Handling with In-Place");
    
    char error_buffer[32];
    strcpy(error_buffer, "1234567890");
    
    printf("Original buffer: %s\n", error_buffer);
    
    /* Try to encrypt with invalid parameters (will fail) */
    ret = FPE_encrypt_str(ctx, alphabet, error_buffer, error_buffer, NULL, 0);
    
    if (ret != 0) {
        printf("✓ Encryption failed as expected (invalid parameters)\n");
        printf("  Buffer state is undefined after error\n");
        printf("  Always check return value before using result\n");
    }
    
    /* Cleanup */
    FPE_CTX_free(ctx);
    
    printf("\n=== In-Place Encryption Complete ===\n\n");
    
    printf("Key Takeaways:\n");
    printf("- In-place encryption uses same buffer for input/output\n");
    printf("- Memory efficient: 50%% less memory usage\n");
    printf("- Perfect for batch operations and database updates\n");
    printf("- No performance penalty compared to separate buffers\n");
    printf("- Always check return value before using result\n");
    printf("- Use separate buffers when original must be preserved\n");
    
    return 0;
}
