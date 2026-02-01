/**
 * @file test_utils.c
 * @brief Unit tests for utility functions
 */

#include "../include/fpe.h"
#include "../src/utils.h"
#include "unity/src/unity.h"
#include <string.h>

/* Unity setup/teardown */
void setUp(void) {
    /* Called before each test */
}

void tearDown(void) {
    /* Called after each test */
}

/* ========================================================================= */
/*                     Character/Index Conversion Tests                      */
/* ========================================================================= */

void test_char_to_index_valid(void) {
    const char *alphabet = "0123456789";
    
    TEST_ASSERT_EQUAL_INT(0, fpe_char_to_index(alphabet, '0'));
    TEST_ASSERT_EQUAL_INT(5, fpe_char_to_index(alphabet, '5'));
    TEST_ASSERT_EQUAL_INT(9, fpe_char_to_index(alphabet, '9'));
}

void test_char_to_index_invalid_char(void) {
    const char *alphabet = "0123456789";
    
    TEST_ASSERT_EQUAL_INT(-1, fpe_char_to_index(alphabet, 'a'));
    TEST_ASSERT_EQUAL_INT(-1, fpe_char_to_index(alphabet, 'Z'));
}

void test_char_to_index_null_alphabet(void) {
    TEST_ASSERT_EQUAL_INT(-1, fpe_char_to_index(NULL, '0'));
}

void test_index_to_char_valid(void) {
    const char *alphabet = "0123456789";
    
    TEST_ASSERT_EQUAL_CHAR('0', fpe_index_to_char(alphabet, 0));
    TEST_ASSERT_EQUAL_CHAR('5', fpe_index_to_char(alphabet, 5));
    TEST_ASSERT_EQUAL_CHAR('9', fpe_index_to_char(alphabet, 9));
}

void test_index_to_char_out_of_bounds(void) {
    const char *alphabet = "0123456789";
    
    TEST_ASSERT_EQUAL_CHAR('\0', fpe_index_to_char(alphabet, 10));
    TEST_ASSERT_EQUAL_CHAR('\0', fpe_index_to_char(alphabet, 100));
}

void test_index_to_char_null_alphabet(void) {
    TEST_ASSERT_EQUAL_CHAR('\0', fpe_index_to_char(NULL, 0));
}

/* ========================================================================= */
/*                       String/Array Conversion Tests                       */
/* ========================================================================= */

void test_str_to_array_valid(void) {
    const char *alphabet = "0123456789";
    const char *str = "1234567890";
    unsigned int arr[10];
    unsigned int expected[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    
    TEST_ASSERT_EQUAL_INT(0, fpe_str_to_array(alphabet, str, arr, 10));
    TEST_ASSERT_EQUAL_UINT_ARRAY(expected, arr, 10);
}

void test_str_to_array_invalid_char(void) {
    const char *alphabet = "0123456789";
    const char *str = "123a567890";
    unsigned int arr[10];
    
    TEST_ASSERT_EQUAL_INT(-1, fpe_str_to_array(alphabet, str, arr, 10));
}

void test_str_to_array_null_params(void) {
    const char *alphabet = "0123456789";
    const char *str = "123";
    unsigned int arr[3];
    
    TEST_ASSERT_EQUAL_INT(-1, fpe_str_to_array(NULL, str, arr, 3));
    TEST_ASSERT_EQUAL_INT(-1, fpe_str_to_array(alphabet, NULL, arr, 3));
    TEST_ASSERT_EQUAL_INT(-1, fpe_str_to_array(alphabet, str, NULL, 3));
}

void test_array_to_str_valid(void) {
    const char *alphabet = "0123456789";
    unsigned int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    char str[11];
    
    TEST_ASSERT_EQUAL_INT(0, fpe_array_to_str(alphabet, arr, str, 10));
    TEST_ASSERT_EQUAL_STRING("1234567890", str);
}

void test_array_to_str_out_of_bounds(void) {
    const char *alphabet = "0123456789";
    unsigned int arr[] = {1, 2, 3, 10};  /* 10 is out of bounds */
    char str[5];
    
    TEST_ASSERT_EQUAL_INT(-1, fpe_array_to_str(alphabet, arr, str, 4));
}

void test_array_to_str_null_termination(void) {
    const char *alphabet = "0123456789";
    unsigned int arr[] = {1, 2, 3};
    char str[10];
    memset(str, 'X', sizeof(str));
    
    TEST_ASSERT_EQUAL_INT(0, fpe_array_to_str(alphabet, arr, str, 3));
    TEST_ASSERT_EQUAL_CHAR('\0', str[3]);
}

/* ========================================================================= */
/*                           Validation Tests                                */
/* ========================================================================= */

void test_validate_alphabet_valid(void) {
    TEST_ASSERT_EQUAL_UINT(10, fpe_validate_alphabet("0123456789"));
    TEST_ASSERT_EQUAL_UINT(26, fpe_validate_alphabet("abcdefghijklmnopqrstuvwxyz"));
    TEST_ASSERT_EQUAL_UINT(62, fpe_validate_alphabet("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"));
}

void test_validate_alphabet_with_duplicates(void) {
    TEST_ASSERT_EQUAL_UINT(0, fpe_validate_alphabet("0123456789012"));  /* Duplicate '0', '1', '2' */
    TEST_ASSERT_EQUAL_UINT(0, fpe_validate_alphabet("aabbcc"));
}

void test_validate_alphabet_too_short(void) {
    TEST_ASSERT_EQUAL_UINT(0, fpe_validate_alphabet("0"));  /* Radix must be >= 2 */
    TEST_ASSERT_EQUAL_UINT(0, fpe_validate_alphabet(""));
}

void test_validate_alphabet_null(void) {
    TEST_ASSERT_EQUAL_UINT(0, fpe_validate_alphabet(NULL));
}

void test_validate_radix_valid(void) {
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_radix(2));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_radix(10));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_radix(36));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_radix(65536));
}

void test_validate_radix_invalid(void) {
    TEST_ASSERT_EQUAL_INT(-1, fpe_validate_radix(0));
    TEST_ASSERT_EQUAL_INT(-1, fpe_validate_radix(1));
    TEST_ASSERT_EQUAL_INT(-1, fpe_validate_radix(65537));
}

void test_validate_tweak_ff1(void) {
    /* FF1 accepts any tweak length */
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF1, 0));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF1, 8));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF1, 100));
}

void test_validate_tweak_ff3(void) {
    /* FF3 requires 7 or 8 bytes (or empty) */
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF3, 0));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF3, 7));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF3, 8));
    TEST_ASSERT_EQUAL_INT(-1, fpe_validate_tweak(FPE_MODE_FF3, 5));
    TEST_ASSERT_EQUAL_INT(-1, fpe_validate_tweak(FPE_MODE_FF3, 10));
}

void test_validate_tweak_ff3_1(void) {
    /* FF3-1 requires 7 or 8 bytes (or empty) */
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF3_1, 0));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF3_1, 7));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_tweak(FPE_MODE_FF3_1, 8));
    TEST_ASSERT_EQUAL_INT(-1, fpe_validate_tweak(FPE_MODE_FF3_1, 5));
}

void test_validate_buffer_size(void) {
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_buffer_size(10, 10));
    TEST_ASSERT_EQUAL_INT(0, fpe_validate_buffer_size(20, 10));
    TEST_ASSERT_EQUAL_INT(-1, fpe_validate_buffer_size(5, 10));
}

/* ========================================================================= */
/*                          Hex Conversion Tests                             */
/* ========================================================================= */

void test_hex_to_bytes_valid(void) {
    unsigned char bytes[16];
    unsigned char expected[] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6};
    
    int len = fpe_hex_to_bytes("2b7e151628aed2a6", bytes, 16);
    TEST_ASSERT_EQUAL_INT(8, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bytes, 8);
}

void test_hex_to_bytes_uppercase(void) {
    unsigned char bytes[16];
    unsigned char expected[] = {0x2B, 0x7E, 0x15, 0x16};
    
    int len = fpe_hex_to_bytes("2B7E1516", bytes, 16);
    TEST_ASSERT_EQUAL_INT(4, len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bytes, 4);
}

void test_hex_to_bytes_odd_length(void) {
    unsigned char bytes[16];
    
    /* Odd-length hex strings should fail */
    TEST_ASSERT_EQUAL_INT(-1, fpe_hex_to_bytes("2b7e1", bytes, 16));
}

void test_hex_to_bytes_invalid_char(void) {
    unsigned char bytes[16];
    
    TEST_ASSERT_EQUAL_INT(-1, fpe_hex_to_bytes("2b7g1516", bytes, 16));
}

void test_hex_to_bytes_buffer_too_small(void) {
    unsigned char bytes[2];
    
    TEST_ASSERT_EQUAL_INT(-1, fpe_hex_to_bytes("2b7e1516", bytes, 2));
}

void test_bytes_to_hex_valid(void) {
    unsigned char bytes[] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6};
    char hex[17];
    
    TEST_ASSERT_EQUAL_INT(0, fpe_bytes_to_hex(bytes, 8, hex));
    TEST_ASSERT_EQUAL_STRING("2B7E151628AED2A6", hex);
}

/* ========================================================================= */
/*                           Security Tests                                  */
/* ========================================================================= */

void test_secure_zero(void) {
    unsigned char buffer[16];
    memset(buffer, 0xFF, sizeof(buffer));
    
    fpe_secure_zero(buffer, sizeof(buffer));
    
    for (size_t i = 0; i < sizeof(buffer); i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buffer[i]);
    }
}

void test_secure_zero_null_pointer(void) {
    /* Should not crash */
    fpe_secure_zero(NULL, 100);
    TEST_ASSERT(1);  /* If we get here, it didn't crash */
}

void test_reverse_bytes(void) {
    unsigned char bytes[] = {1, 2, 3, 4, 5, 6, 7, 8};
    unsigned char expected[] = {8, 7, 6, 5, 4, 3, 2, 1};
    
    fpe_reverse_bytes(bytes, 8);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bytes, 8);
}

void test_reverse_bytes_odd_length(void) {
    unsigned char bytes[] = {1, 2, 3, 4, 5};
    unsigned char expected[] = {5, 4, 3, 2, 1};
    
    fpe_reverse_bytes(bytes, 5);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bytes, 5);
}

void test_reverse_bytes_single(void) {
    unsigned char bytes[] = {42};
    unsigned char expected[] = {42};
    
    fpe_reverse_bytes(bytes, 1);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, bytes, 1);
}

/* ========================================================================= */
/*                         Performance Tests                                 */
/* ========================================================================= */

void test_get_time_usec(void) {
    uint64_t t1 = fpe_get_time_usec();
    uint64_t t2 = fpe_get_time_usec();
    
    /* Time should advance */
    TEST_ASSERT_GREATER_OR_EQUAL(t1, t2);
}

void test_calculate_tps(void) {
    /* 1,000 operations in 1 second (1,000,000 usec) = 1,000 TPS */
    double tps = fpe_calculate_tps(1000, 1000000);
    TEST_ASSERT_GREATER_THAN(999, (int)tps);
    TEST_ASSERT_LESS_THAN(1001, (int)tps);
    
    /* 10,000 operations in 0.5 seconds (500,000 usec) = 20,000 TPS */
    tps = fpe_calculate_tps(10000, 500000);
    TEST_ASSERT_GREATER_THAN(19999, (int)tps);
    TEST_ASSERT_LESS_THAN(20001, (int)tps);
}

void test_calculate_tps_zero_time(void) {
    /* Division by zero should return 0.0 */
    double tps = fpe_calculate_tps(1000, 0);
    TEST_ASSERT_EQUAL_INT(0, (int)tps);
}

/* ========================================================================= */
/*                              Main Test Runner                             */
/* ========================================================================= */

int main(void) {
    UNITY_BEGIN();
    
    /* Character/Index conversion */
    RUN_TEST(test_char_to_index_valid);
    RUN_TEST(test_char_to_index_invalid_char);
    RUN_TEST(test_char_to_index_null_alphabet);
    RUN_TEST(test_index_to_char_valid);
    RUN_TEST(test_index_to_char_out_of_bounds);
    RUN_TEST(test_index_to_char_null_alphabet);
    
    /* String/Array conversion */
    RUN_TEST(test_str_to_array_valid);
    RUN_TEST(test_str_to_array_invalid_char);
    RUN_TEST(test_str_to_array_null_params);
    RUN_TEST(test_array_to_str_valid);
    RUN_TEST(test_array_to_str_out_of_bounds);
    RUN_TEST(test_array_to_str_null_termination);
    
    /* Validation */
    RUN_TEST(test_validate_alphabet_valid);
    RUN_TEST(test_validate_alphabet_with_duplicates);
    RUN_TEST(test_validate_alphabet_too_short);
    RUN_TEST(test_validate_alphabet_null);
    RUN_TEST(test_validate_radix_valid);
    RUN_TEST(test_validate_radix_invalid);
    RUN_TEST(test_validate_tweak_ff1);
    RUN_TEST(test_validate_tweak_ff3);
    RUN_TEST(test_validate_tweak_ff3_1);
    RUN_TEST(test_validate_buffer_size);
    
    /* Hex conversion */
    RUN_TEST(test_hex_to_bytes_valid);
    RUN_TEST(test_hex_to_bytes_uppercase);
    RUN_TEST(test_hex_to_bytes_odd_length);
    RUN_TEST(test_hex_to_bytes_invalid_char);
    RUN_TEST(test_hex_to_bytes_buffer_too_small);
    RUN_TEST(test_bytes_to_hex_valid);
    
    /* Security */
    RUN_TEST(test_secure_zero);
    RUN_TEST(test_secure_zero_null_pointer);
    RUN_TEST(test_reverse_bytes);
    RUN_TEST(test_reverse_bytes_odd_length);
    RUN_TEST(test_reverse_bytes_single);
    
    /* Performance */
    RUN_TEST(test_get_time_usec);
    RUN_TEST(test_calculate_tps);
    RUN_TEST(test_calculate_tps_zero_time);
    
    return UNITY_END();
}
