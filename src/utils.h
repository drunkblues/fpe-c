/**
 * @file utils.h
 * @brief Internal utility functions for FPE implementation
 */

#ifndef FPE_UTILS_H
#define FPE_UTILS_H

#include <stddef.h>
#include <stdint.h>

/* ========================================================================= */
/*                         String/Alphabet Utilities                         */
/* ========================================================================= */

/**
 * @brief Convert a character to its index in the alphabet
 * 
 * @param alphabet The alphabet string
 * @param c The character to convert
 * @return Index (0 to radix-1), or -1 if not found
 */
int fpe_char_to_index(const char *alphabet, char c);

/**
 * @brief Convert an index to a character in the alphabet
 * 
 * @param alphabet The alphabet string
 * @param index The index (0 to radix-1)
 * @return The character, or '\0' if index out of bounds
 */
char fpe_index_to_char(const char *alphabet, unsigned int index);

/**
 * @brief Convert a string to an integer array using the alphabet
 * 
 * @param alphabet The alphabet string
 * @param str Input string
 * @param arr Output integer array (caller allocates)
 * @param len Length of string
 * @return 0 on success, -1 on error (invalid character)
 */
int fpe_str_to_array(const char *alphabet, const char *str, 
                     unsigned int *arr, unsigned int len);

/**
 * @brief Convert an integer array to a string using the alphabet
 * 
 * @param alphabet The alphabet string
 * @param arr Input integer array
 * @param str Output string (caller allocates, must have space for len+1)
 * @param len Length of array
 * @return 0 on success, -1 on error
 */
int fpe_array_to_str(const char *alphabet, const unsigned int *arr,
                     char *str, unsigned int len);

/* ========================================================================= */
/*                           Validation Functions                            */
/* ========================================================================= */

/**
 * @brief Validate alphabet (check for duplicates, minimum size)
 * 
 * @param alphabet The alphabet string
 * @return radix (alphabet length) on success, 0 on error
 */
unsigned int fpe_validate_alphabet(const char *alphabet);

/**
 * @brief Validate radix (must be in range 2-65536)
 * 
 * @param radix The radix value
 * @return 0 on success, -1 on error
 */
int fpe_validate_radix(unsigned int radix);

/**
 * @brief Validate tweak length for specific algorithm
 * 
 * @param mode FPE mode (FF1/FF3/FF3-1)
 * @param tweak_len Tweak length in bytes
 * @return 0 on success, -1 on error
 */
int fpe_validate_tweak(int mode, unsigned int tweak_len);

/**
 * @brief Validate buffer size
 * 
 * @param len Buffer length
 * @param required Minimum required length
 * @return 0 on success, -1 on error
 */
int fpe_validate_buffer_size(unsigned int len, unsigned int required);

/* ========================================================================= */
/*                          Hex Conversion Utilities                         */
/* ========================================================================= */

/**
 * @brief Convert hex string to byte array
 * 
 * @param hex Hex string (e.g., "AABBCCDD")
 * @param bytes Output byte array
 * @param max_bytes Maximum bytes to convert
 * @return Number of bytes converted, or -1 on error
 */
int fpe_hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_bytes);

/**
 * @brief Convert byte array to hex string
 * 
 * @param bytes Input byte array
 * @param len Length of byte array
 * @param hex Output hex string (must have space for 2*len+1)
 * @return 0 on success, -1 on error
 */
int fpe_bytes_to_hex(const unsigned char *bytes, size_t len, char *hex);

/* ========================================================================= */
/*                            Security Utilities                             */
/* ========================================================================= */

/**
 * @brief Securely zero memory (resistant to compiler optimization)
 * 
 * @param ptr Pointer to memory
 * @param len Length in bytes
 */
void fpe_secure_zero(void *ptr, size_t len);

/**
 * @brief Reverse bytes in place
 * 
 * @param bytes Byte array to reverse
 * @param len Length of byte array
 */
void fpe_reverse_bytes(unsigned char *bytes, unsigned int len);

/* ========================================================================= */
/*                          Performance Utilities                            */
/* ========================================================================= */

/**
 * @brief Get current time in microseconds
 * 
 * @return Time in microseconds
 */
uint64_t fpe_get_time_usec(void);

/**
 * @brief Calculate TPS (Transactions Per Second)
 * 
 * @param num_ops Number of operations
 * @param time_usec Time elapsed in microseconds
 * @return TPS value
 */
double fpe_calculate_tps(uint64_t num_ops, uint64_t time_usec);

#endif /* FPE_UTILS_H */
