/**
 * @file utils.c
 * @brief Utility functions implementation
 */

#include "utils.h"
#include "../include/fpe.h"
#include <string.h>
#include <ctype.h>
#include <sys/time.h>

/* ========================================================================= */
/*                         String/Alphabet Utilities                         */
/* ========================================================================= */

int fpe_char_to_index(const char *alphabet, char c) {
    if (!alphabet) return -1;
    
    const char *pos = strchr(alphabet, c);
    if (!pos) return -1;
    
    return (int)(pos - alphabet);
}

char fpe_index_to_char(const char *alphabet, unsigned int index) {
    if (!alphabet) return '\0';
    
    size_t len = strlen(alphabet);
    if (index >= len) return '\0';
    
    return alphabet[index];
}

int fpe_str_to_array(const char *alphabet, const char *str,
                     unsigned int *arr, unsigned int len) {
    if (!alphabet || !str || !arr) return -1;
    
    for (unsigned int i = 0; i < len; i++) {
        int idx = fpe_char_to_index(alphabet, str[i]);
        if (idx < 0) return -1;  /* Invalid character */
        arr[i] = (unsigned int)idx;
    }
    
    return 0;
}

int fpe_array_to_str(const char *alphabet, const unsigned int *arr,
                     char *str, unsigned int len) {
    if (!alphabet || !arr || !str) return -1;
    
    size_t radix = strlen(alphabet);
    
    for (unsigned int i = 0; i < len; i++) {
        if (arr[i] >= radix) return -1;  /* Out of bounds */
        str[i] = alphabet[arr[i]];
    }
    
    str[len] = '\0';  /* Null termination */
    return 0;
}

/* ========================================================================= */
/*                           Validation Functions                            */
/* ========================================================================= */

unsigned int fpe_validate_alphabet(const char *alphabet) {
    if (!alphabet) return 0;
    
    size_t len = strlen(alphabet);
    if (len < 2 || len > 65536) return 0;
    
    /* Check for duplicates using a simple O(n^2) approach */
    for (size_t i = 0; i < len; i++) {
        for (size_t j = i + 1; j < len; j++) {
            if (alphabet[i] == alphabet[j]) {
                return 0;  /* Duplicate found */
            }
        }
    }
    
    return (unsigned int)len;
}

int fpe_validate_radix(unsigned int radix) {
    if (radix < 2 || radix > 65536) return -1;
    return 0;
}

int fpe_validate_tweak(int mode, unsigned int tweak_len) {
    switch (mode) {
        case FPE_MODE_FF1:
            /* FF1: tweak can be 0 to 2^32 bytes (practically unlimited) */
            return 0;
            
        case FPE_MODE_FF3:
            /* FF3: tweak must be exactly 64 bits (8 bytes) or 56 bits (7 bytes) */
            if (tweak_len != 8 && tweak_len != 7 && tweak_len != 0) {
                return -1;
            }
            return 0;
            
        case FPE_MODE_FF3_1:
            /* FF3-1: tweak must be exactly 56 bits (7 bytes) or 64 bits with padding */
            if (tweak_len != 7 && tweak_len != 8 && tweak_len != 0) {
                return -1;
            }
            return 0;
            
        default:
            return -1;
    }
}

int fpe_validate_buffer_size(unsigned int len, unsigned int required) {
    return (len >= required) ? 0 : -1;
}

/* ========================================================================= */
/*                          Hex Conversion Utilities                         */
/* ========================================================================= */

static int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int fpe_hex_to_bytes(const char *hex, unsigned char *bytes, size_t max_bytes) {
    if (!hex || !bytes) return -1;
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;  /* Hex string must have even length */
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_bytes) return -1;
    
    for (size_t i = 0; i < byte_len; i++) {
        int high = hex_char_to_int(hex[2 * i]);
        int low = hex_char_to_int(hex[2 * i + 1]);
        
        if (high < 0 || low < 0) return -1;
        
        bytes[i] = (unsigned char)((high << 4) | low);
    }
    
    return (int)byte_len;
}

int fpe_bytes_to_hex(const unsigned char *bytes, size_t len, char *hex) {
    if (!bytes || !hex) return -1;
    
    const char hex_chars[] = "0123456789ABCDEF";
    
    for (size_t i = 0; i < len; i++) {
        hex[2 * i] = hex_chars[(bytes[i] >> 4) & 0xF];
        hex[2 * i + 1] = hex_chars[bytes[i] & 0xF];
    }
    
    hex[2 * len] = '\0';
    return 0;
}

/* ========================================================================= */
/*                            Security Utilities                             */
/* ========================================================================= */

void fpe_secure_zero(void *ptr, size_t len) {
    if (!ptr) return;
    
    /* Use volatile to prevent compiler optimization */
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void fpe_reverse_bytes(unsigned char *bytes, unsigned int len) {
    unsigned int half_len = len >> 1;
    for (unsigned int i = 0; i < half_len; i++) {
        unsigned char tmp = bytes[i];
        bytes[i] = bytes[len - i - 1];
        bytes[len - i - 1] = tmp;
    }
}

/* ========================================================================= */
/*                          Performance Utilities                            */
/* ========================================================================= */

uint64_t fpe_get_time_usec(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

double fpe_calculate_tps(uint64_t num_ops, uint64_t time_usec) {
    if (time_usec == 0) return 0.0;
    return (double)num_ops * 1000000.0 / (double)time_usec;
}
