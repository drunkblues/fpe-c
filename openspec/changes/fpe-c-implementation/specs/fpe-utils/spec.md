## ADDED Requirements

### Requirement: Test vector parsing utilities
The library SHALL provide utilities to parse and convert test vectors from tests/vectors.h format.

#### Scenario: Parse hex key string
- **WHEN** a hex key string like "2B7E151628AED2A6ABF7158809CF4F3C" is provided
- **THEN** library SHALL convert it to binary key bytes
- **AND** validate key length (16/24/32 bytes for AES, 16 bytes for SM4)

#### Scenario: Parse hex tweak string
- **WHEN** a hex tweak string like "D8E7920AFA330A73" is provided
- **THEN** library SHALL convert it to binary tweak bytes
- **AND** validate tweak length based on algorithm requirements

#### Scenario: Handle empty tweak
- **WHEN** an empty string "" is provided as tweak
- **THEN** library SHALL treat it as no tweak (all-zeroes internally)

#### Scenario: Convert plaintext to integer array
- **WHEN** a plaintext string like "0123456789" is provided with radix 10
- **THEN** library SHALL convert to integer array [0,1,2,3,4,5,6,7,8,9]
- **AND** validate each character is valid for radix

#### Scenario: Convert ciphertext for comparison
- **WHEN** a ciphertext string like "2433477484" is provided with radix 10
- **THEN** library SHALL convert to integer array for comparison
- **AND** validate each character is valid for radix

### Requirement: Performance timing utilities
The library SHALL provide utilities for measuring operation timing and throughput.

#### Scenario: Measure single operation time
- **WHEN** timing a single encryption or decryption operation
- **THEN** utility SHALL measure and report time in microseconds
- **AND** utility SHALL exclude initialization/setup time (only operation time)

#### Scenario: Measure throughput (operations per second)
- **WHEN** measuring throughput for N consecutive operations
- **THEN** utility SHALL calculate and report TPS (Transactions Per Second)
- **AND** formula SHALL be: TPS = N / (end_time - start_time)

#### Scenario: Benchmark with different input sizes
- **WHEN** benchmarking with input lengths 10, 16, 20, 100
- **THEN** utility SHALL report TPS for each input size
- **AND** allow comparison of performance vs input size

### Requirement: Alphabet-based character mapping
The library SHALL provide internal utilities to map between characters and integer indices based on a custom alphabet string.

#### Scenario: Map character to index (numeric alphabet)
- **WHEN** a character '5' is mapped using alphabet "0123456789"
- **THEN** the result SHALL be the integer 5

#### Scenario: Map character to index (alphanumeric alphabet)
- **WHEN** a character 'A' is mapped using alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
- **THEN** the result SHALL be the integer 10

#### Scenario: Map character to index (invalid character)
- **WHEN** a character 'X' is mapped using alphabet "0123456789"
- **THEN** the mapping SHALL fail
- **AND** FPE_encrypt_str SHALL return error -1

#### Scenario: Map index to character (numeric alphabet)
- **WHEN** an integer 5 is mapped to a character using alphabet "0123456789"
- **THEN** the result SHALL be the character '5'

#### Scenario: Map index to character (alphanumeric alphabet)
- **WHEN** an integer 10 is mapped to a character using alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
- **THEN** the result SHALL be the character 'A'

#### Scenario: Map index to character (out of bounds)
- **WHEN** an integer 62 is mapped to a character using alphabet of length 62
- **THEN** the mapping SHALL fail

### Requirement: String to integer array conversion
The library SHALL provide utilities to convert strings to integer arrays based on the alphabet.

#### Scenario: Convert valid string to integers
- **WHEN** a string "123" is converted using radix 10
- **THEN** the result SHALL be integer array [1, 2, 3]
- **AND** the length SHALL be 3

#### Scenario: Convert empty string to integers
- **WHEN** an empty string is converted
- **THEN** the result SHALL be an empty integer array
- **AND** the length SHALL be 0

#### Scenario: Convert string with invalid character
- **WHEN** a string "12A4" is converted using alphabet "0123456789"
- **THEN** the conversion SHALL fail
- **AND** FPE_encrypt_str SHALL return error -1

### Requirement: Integer array to string conversion
The library SHALL provide utilities to convert integer arrays to strings based on the alphabet.

#### Scenario: Convert integers to string
- **WHEN** integer array [1, 2, 3] is converted using alphabet "0123456789"
- **THEN** the result SHALL be string "123"
- **AND** the string SHALL be null-terminated

#### Scenario: Convert empty integer array to string
- **WHEN** an empty integer array is converted
- **THEN** the result SHALL be an empty string
- **AND** the string SHALL be null-terminated

#### Scenario: Convert integers with out-of-range values
- **WHEN** integer array [1, 2, 15] is converted using alphabet of length 10
- **THEN** the conversion SHALL fail
- **AND** FPE_decrypt_str SHALL return error -1

### Requirement: Custom alphabet validation
The library SHALL validate custom alphabets provided by the user.

#### Scenario: Valid alphabet (no duplicates)
- **WHEN** alphabet "0123456789" is validated
- **THEN** validation SHALL succeed
- **AND** all characters SHALL be unique
- **AND** length SHALL be 10

#### Scenario: Valid alphabet with lowercase
- **WHEN** alphabet "abcdefghijklmnopqrstuvwxyz" is validated
- **THEN** validation SHALL succeed
- **AND** all characters SHALL be unique
- **AND** length SHALL be 26

#### Scenario: Invalid alphabet with duplicate characters
- **WHEN** alphabet "01234567890" is validated (contains duplicate '0')
- **THEN** validation SHALL fail
- **AND** FPE_encrypt_str SHALL return error -1

#### Scenario: Invalid empty alphabet
- **WHEN** an empty string "" is provided as alphabet
- **THEN** validation SHALL fail
- **AND** FPE_encrypt_str SHALL return error -1

#### Scenario: Invalid NULL alphabet
- **WHEN** NULL is provided as alphabet pointer
- **THEN** validation SHALL fail
- **AND** FPE_encrypt_str SHALL return error -1

### Requirement: Radix validation
The library SHALL validate that the radix (alphabet length) is within the allowed range.

#### Scenario: Valid radix (minimum)
- **WHEN** radix 2 is used
- **THEN** validation SHALL succeed

#### Scenario: Valid radix (maximum)
- **WHEN** radix 65536 is used
- **THEN** validation SHALL succeed

#### Scenario: Valid radix (common values)
- **WHEN** radix 10 or 26 or 62 is used
- **THEN** validation SHALL succeed

#### Scenario: Invalid radix (below minimum)
- **WHEN** radix 1 is used
- **THEN** validation SHALL fail
- **AND** FPE_CTX_init SHALL return error -1

#### Scenario: Invalid radix (above maximum)
- **WHEN** radix 65537 is used
- **THEN** validation SHALL fail
- **AND** FPE_CTX_init SHALL return error -1

### Requirement: Radix and alphabet length consistency
The library SHALL ensure that the context radix matches the alphabet length used in string operations.

#### Scenario: Matching radix and alphabet length
- **WHEN** context is initialized with radix 10
- **AND** FPE_encrypt_str is called with alphabet of length 10
- **THEN** operation SHALL succeed

#### Scenario: Mismatched radix and alphabet length
- **WHEN** context is initialized with radix 10
- **AND** FPE_encrypt_str is called with alphabet of length 26
- **THEN** operation SHALL fail
- **AND** FPE_encrypt_str SHALL return error -1

### Requirement: Tweak validation by algorithm
The library SHALL validate tweak length according to the requirements of each FPE mode.

#### Scenario: FF1 with empty tweak
- **WHEN** FF1 is used with tweak_len=0
- **THEN** validation SHALL succeed
- **AND** a default all-zero tweak SHALL be used internally

#### Scenario: FF1 with arbitrary tweak length
- **WHEN** FF1 is used with any tweak_len between 0 and 2^32
- **THEN** validation SHALL succeed

#### Scenario: FF3 with valid 64-bit tweak
- **WHEN** FF3 is used with tweak_len=8 (64 bits)
- **THEN** validation SHALL succeed

#### Scenario: FF3 with valid 56-bit tweak
- **WHEN** FF3 is used with tweak_len=7 (56 bits)
- **THEN** validation SHALL succeed

#### Scenario: FF3 with invalid tweak length
- **WHEN** FF3 is used with tweak_len not equal to 7 or 8
- **THEN** validation SHALL fail
- **AND** FPE_encrypt SHALL return error -1

#### Scenario: FF3-1 with valid 64-bit tweak
- **WHEN** FF3-1 is used with tweak_len=8 (64 bits)
- **THEN** validation SHALL succeed

#### Scenario: FF3-1 with valid 56-bit tweak
- **WHEN** FF3-1 is used with tweak_len=7 (56 bits)
- **THEN** validation SHALL succeed

#### Scenario: FF3-1 with invalid tweak length
- **WHEN** FF3-1 is used with tweak_len not equal to 7 or 8
- **THEN** validation SHALL fail
- **AND** FPE_encrypt SHALL return error -1

### Requirement: Null tweak handling
The library SHALL handle NULL tweak pointers gracefully.

#### Scenario: FF1 with NULL tweak
- **WHEN** FF1 is used with tweak=NULL
- **THEN** the library SHALL treat it as an empty tweak
- **AND** operation SHALL succeed

#### Scenario: FF3 with NULL tweak
- **WHEN** FF3 is used with tweak=NULL
- **THEN** the library SHALL return error -1 (tweak is required for FF3)

### Requirement: Buffer size requirements
The library SHALL not require output buffers to be larger than input buffers for in-place operations.

#### Scenario: Integer array encryption buffer size
- **WHEN** encrypting an integer array of length N
- **THEN** the output buffer MUST be at least length N
- **AND** in-place encryption (same buffer) SHALL be supported

#### Scenario: String encryption buffer size
- **WHEN** encrypting a string of length L
- **THEN** the output buffer MUST be at least length L + 1 (for null terminator)
- **AND** in-place encryption (same buffer) SHALL be supported

### Requirement: Memory zeroing for sensitive data
The library SHALL provide utilities to securely zero memory containing sensitive data (keys, plaintext, ciphertext).

#### Scenario: Zero context key material
- **WHEN** FPE_CTX_free is called
- **THEN** all key material and derived keys in the context SHALL be zeroed
- **AND** OpenSSL internal key material SHALL be freed

#### Scenario: Zero temporary buffers
- **WHEN** temporary buffers containing sensitive data are no longer needed
- **THEN** the library SHALL zero these buffers before freeing or reusing

### Requirement: String null-termination guarantee
The library SHALL guarantee that output strings are properly null-terminated.

#### Scenario: String encryption output
- **WHEN** FPE_encrypt_str completes successfully
- **THEN** the output string SHALL be null-terminated
- **AND** the null terminator SHALL be at position output[len]

#### Scenario: String decryption output
- **WHEN** FPE_decrypt_str completes successfully
- **THEN** the output string SHALL be null-terminated
- **AND** the null terminator SHALL be at position output[len]

### Requirement: Input/output buffer validation
The library SHALL validate input and output buffer pointers.

#### Scenario: NULL input buffer validation
- **WHEN** any function receives a NULL input buffer
- **THEN** the function SHALL return error -1

#### Scenario: NULL output buffer validation
- **WHEN** any function receives a NULL output buffer
- **THEN** the function SHALL return error -1

#### Scenario: Zero-length input validation
- **WHEN** a function is called with len=0
- **THEN** the behavior SHALL depend on the specific algorithm's requirements
- **AND** algorithms that require minimum length SHALL return error -1

### Requirement: Case sensitivity in alphabets
The library SHALL respect case sensitivity in custom alphabets.

#### Scenario: Case-sensitive alphabet
- **WHEN** alphabet "ABCabc" is used
- **THEN** 'A' and 'a' SHALL map to different indices
- **AND** output SHALL preserve case

#### Scenario: Case-insensitive mapping (not supported by default)
- **WHEN** user wants case-insensitive mapping
- **THEN** they MUST use an alphabet with uppercase only or lowercase only
- **AND** the library SHALL NOT automatically fold case

### Requirement: Unicode/UTF-8 handling
The library SHALL operate on individual bytes, not multi-byte Unicode characters.

#### Scenario: ASCII characters only
- **WHEN** alphabet contains only ASCII characters (0-127)
- **THEN** operations SHALL work correctly
- **AND** each character SHALL map to one index

#### Scenario: UTF-8 characters
- **WHEN** alphabet contains UTF-8 multi-byte characters
- **THEN** the library SHALL treat each byte as a separate character
- **AND** this MAY NOT be the desired behavior for Unicode
- **AND** documentation SHOULD warn about UTF-8 limitations

### Requirement: Performance considerations for string utilities
The string-to-integer and integer-to-string conversions SHALL be efficient for common use cases.

#### Scenario: Fast conversion for numeric strings
- **WHEN** converting numeric strings (radix 10)
- **THEN** conversion SHALL use optimized arithmetic
- **AND** SHALL NOT use expensive operations (e.g., pow()) for each character

#### Scenario: Lookup table for character mappings
- **WHEN** mapping characters to/from indices
- **THEN** the library SHALL use a lookup table (256-byte array) for O(1) access
- **AND** SHALL NOT use linear search through alphabet string

### Requirement: Alphabet length limits
The library SHALL support the full range of alphabet lengths defined by the radix limits.

#### Scenario: Very small alphabet (radix 2)
- **WHEN** alphabet of length 2 is used (e.g., "01")
- **THEN** all string operations SHALL work correctly

#### Scenario: Very large alphabet (radix 65536)
- **WHEN** alphabet of length 65536 is used
- **THEN** all string operations SHALL work correctly
- **AND** memory usage SHALL be acceptable

#### Scenario: Alphabet length exceeds unsigned int range
- **WHEN** alphabet length exceeds 65535
- **THEN** validation SHALL fail
- **AND** FPE_CTX_init SHALL return error -1
