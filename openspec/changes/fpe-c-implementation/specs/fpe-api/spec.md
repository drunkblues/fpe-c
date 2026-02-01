## ADDED Requirements

### Requirement: Context creation and destruction
The library SHALL provide functions to create and destroy opaque FPE contexts using heap allocation.

#### Scenario: Create context successfully
- **WHEN** FPE_CTX_new is called
- **THEN** a new heap-allocated FPE_CTX pointer SHALL be returned
- **AND** the pointer SHALL not be NULL
- **AND** the context SHALL be in uninitialized state

#### Scenario: Create context with allocation failure
- **WHEN** FPE_CTX_new is called and heap allocation fails
- **THEN** the function SHALL return NULL

#### Scenario: Destroy valid context
- **WHEN** FPE_CTX_free is called with a valid context pointer
- **THEN** all allocated resources (OpenSSL contexts, derived keys) SHALL be freed
- **AND** the context SHALL no longer be usable

#### Scenario: Destroy NULL context
- **WHEN** FPE_CTX_free is called with NULL
- **THEN** the function SHALL not crash
- **AND** SHALL return without error

### Requirement: Context initialization
The library SHALL provide a function to initialize FPE contexts with algorithm mode, cipher algorithm, key, and radix.

#### Scenario: Initialize FF1 with AES-128
- **WHEN** FPE_CTX_init is called with FPE_MODE_FF1, FPE_ALGO_AES, valid AES-128 key, bits=128, and valid radix
- **THEN** the function SHALL return 0 (success)
- **AND** the context SHALL be initialized with FF1 algorithm
- **AND** the context SHALL use AES-128 for cryptographic operations
- **AND** derived keys SHALL be computed and cached

#### Scenario: Initialize FF1 with SM4-128
- **WHEN** FPE_CTX_init is called with FPE_MODE_FF1, FPE_ALGO_SM4, valid SM4-128 key, bits=128, and valid radix
- **THEN** the function SHALL return 0 (success)
- **AND** the context SHALL be initialized with FF1 algorithm
- **AND** the context SHALL use SM4-128 for cryptographic operations

#### Scenario: Initialize FF3 with AES-256
- **WHEN** FPE_CTX_init is called with FPE_MODE_FF3, FPE_ALGO_AES, valid AES-256 key, bits=256, and valid radix
- **THEN** the function SHALL return 0 (success)
- **AND** the context SHALL be initialized with FF3 algorithm

#### Scenario: Initialize FF3-1 with AES-192
- **WHEN** FPE_CTX_init is called with FPE_MODE_FF3_1, FPE_ALGO_AES, valid AES-192 key, bits=192, and valid radix
- **THEN** the function SHALL return 0 (success)
- **AND** the context SHALL be initialized with FF3-1 algorithm

#### Scenario: Initialize with NULL key
- **WHEN** FPE_CTX_init is called with NULL key pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Initialize with invalid radix
- **WHEN** FPE_CTX_init is called with radix < 2 or > 65536
- **THEN** the function SHALL return -1 (error)

#### Scenario: Initialize AES with invalid key length
- **WHEN** FPE_CTX_init is called with FPE_ALGO_AES and bits not in {128, 192, 256}
- **THEN** the function SHALL return -1 (error)

#### Scenario: Initialize SM4 with invalid key length
- **WHEN** FPE_CTX_init is called with FPE_ALGO_SM4 and bits != 128
- **THEN** the function SHALL return -1 (error)

#### Scenario: Initialize SM4 on unsupported OpenSSL
- **WHEN** FPE_CTX_init is called with FPE_ALGO_SM4 on OpenSSL version < 1.1.1
- **THEN** the function SHALL return -1 (error)

### Requirement: Unified encryption API
The library SHALL provide a unified FPE_encrypt function that dispatches to the correct algorithm based on context mode.

#### Scenario: Encrypt with FF1 context
- **WHEN** FPE_encrypt is called with a context initialized for FF1
- **THEN** the function SHALL dispatch to FF1 implementation
- **AND** return 0 on success, -1 on error

#### Scenario: Encrypt with FF3 context
- **WHEN** FPE_encrypt is called with a context initialized for FF3
- **THEN** the function SHALL dispatch to FF3 implementation
- **AND** return 0 on success, -1 on error

#### Scenario: Encrypt with FF3-1 context
- **WHEN** FPE_encrypt is called with a context initialized for FF3-1
- **THEN** the function SHALL dispatch to FF3-1 implementation
- **AND** return 0 on success, -1 on error

#### Scenario: Encrypt with NULL input
- **WHEN** FPE_encrypt is called with NULL input pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Encrypt with NULL output
- **WHEN** FPE_encrypt is called with NULL output pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Encrypt with valid input/output
- **WHEN** FPE_encrypt is called with valid input and output arrays of length len
- **THEN** the function SHALL encrypt the input
- **AND** store result in output array
- **AND** input array SHALL remain unchanged

### Requirement: Unified decryption API
The library SHALL provide a unified FPE_decrypt function that dispatches to the correct algorithm based on context mode.

#### Scenario: Decrypt with FF1 context
- **WHEN** FPE_decrypt is called with a context initialized for FF1
- **THEN** the function SHALL dispatch to FF1 implementation
- **AND** return 0 on success, -1 on error

#### Scenario: Decrypt with FF3 context
- **WHEN** FPE_decrypt is called with a context initialized for FF3
- **THEN** the function SHALL dispatch to FF3 implementation
- **AND** return 0 on success, -1 on error

#### Scenario: Decrypt with FF3-1 context
- **WHEN** FPE_decrypt is called with a context initialized for FF3-1
- **THEN** the function SHALL dispatch to FF3-1 implementation
- **AND** return 0 on success, -1 on error

#### Scenario: Decrypt with NULL input
- **WHEN** FPE_decrypt is called with NULL input pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Decrypt with NULL output
- **WHEN** FPE_decrypt is called with NULL output pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Decrypt with valid input/output
- **WHEN** FPE_decrypt is called with valid input and output arrays of length len
- **THEN** the function SHALL decrypt the input
- **AND** store result in output array
- **AND** input array SHALL remain unchanged

### Requirement: String encryption API
The library SHALL provide a string-based encryption API that maps characters to/from integer indices using a custom alphabet.

#### Scenario: Encrypt string with numeric alphabet
- **WHEN** FPE_encrypt_str is called with alphabet "0123456789" and a numeric string
- **THEN** the function SHALL map each character to its index
- **AND** encrypt using the underlying integer array
- **AND** map result back to characters
- **AND** output SHALL be same length as input

#### Scenario: Encrypt string with alphanumeric alphabet
- **WHEN** FPE_encrypt_str is called with alphabet containing alphanumeric characters
- **THEN** the function SHALL correctly map and encrypt
- **AND** output SHALL contain only characters from the alphabet

#### Scenario: Encrypt string with invalid character
- **WHEN** FPE_encrypt_str is called with input string containing characters not in alphabet
- **THEN** the function SHALL return -1 (error)

#### Scenario: Encrypt string with NULL alphabet
- **WHEN** FPE_encrypt_str is called with NULL alphabet pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Encrypt string with NULL input
- **WHEN** FPE_encrypt_str is called with NULL input pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Encrypt string with NULL output
- **WHEN** FPE_encrypt_str is called with NULL output pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: Encrypt string with radix mismatch
- **WHEN** FPE_encrypt_str is called with alphabet of length N but context initialized with radix M where N != M
- **THEN** the function SHALL return -1 (error)

### Requirement: String decryption API
The library SHALL provide a string-based decryption API that maps characters to/from integer indices using a custom alphabet.

#### Scenario: Decrypt string with numeric alphabet
- **WHEN** FPE_decrypt_str is called with alphabet "0123456789" and a numeric ciphertext string
- **THEN** the function SHALL map each character to its index
- **AND** decrypt using the underlying integer array
- **AND** map result back to characters
- **AND** output SHALL be same length as input

#### Scenario: Decrypt string with alphanumeric alphabet
- **WHEN** FPE_decrypt_str is called with alphabet containing alphanumeric characters
- **THEN** the function SHALL correctly map and decrypt
- **AND** output SHALL contain only characters from the alphabet

#### Scenario: Decrypt string with invalid character
- **WHEN** FPE_decrypt_str is called with input string containing characters not in alphabet
- **THEN** the function SHALL return -1 (error)

#### Scenario: Decrypt string reversibility
- **WHEN** a string is encrypted with FPE_encrypt_str
- **AND** then decrypted with FPE_decrypt_str with the same parameters
- **THEN** the result SHALL equal the original string

### Requirement: One-shot encryption API (integer arrays)
The library SHALL provide a stateless one-shot encryption function for integer arrays.

#### Scenario: One-shot encrypt with FF1 and AES
- **WHEN** FPE_encrypt_oneshot is called with FPE_MODE_FF1, FPE_ALGO_AES, valid key, radix, and input/output arrays
- **THEN** the function SHALL create a temporary context
- **AND** initialize it with specified parameters
- **AND** encrypt the input
- **AND** clean up the context
- **AND** return 0 on success, -1 on error

#### Scenario: One-shot encrypt with FF3-1 and SM4
- **WHEN** FPE_encrypt_oneshot is called with FPE_MODE_FF3_1, FPE_ALGO_SM4, valid key, radix, and input/output arrays
- **THEN** the function SHALL create a temporary context
- **AND** initialize it with specified parameters
- **AND** encrypt the input
- **AND** clean up the context
- **AND** return 0 on success, -1 on error

#### Scenario: One-shot encrypt with NULL input
- **WHEN** FPE_encrypt_oneshot is called with NULL input pointer
- **THEN** the function SHALL return -1 (error)

#### Scenario: One-shot encrypt with invalid key
- **WHEN** FPE_encrypt_oneshot is called with invalid key parameters
- **THEN** the function SHALL return -1 (error)

### Requirement: One-shot decryption API (integer arrays)
The library SHALL provide a stateless one-shot decryption function for integer arrays.

#### Scenario: One-shot decrypt with FF1 and AES
- **WHEN** FPE_decrypt_oneshot is called with FPE_MODE_FF1, FPE_ALGO_AES, valid key, radix, and input/output arrays
- **THEN** the function SHALL create a temporary context
- **AND** initialize it with specified parameters
- **AND** decrypt the input
- **AND** clean up the context
- **AND** return 0 on success, -1 on error

#### Scenario: One-shot decrypt with NULL input
- **WHEN** FPE_decrypt_oneshot is called with NULL input pointer
- **THEN** the function SHALL return -1 (error)

### Requirement: One-shot string encryption API
The library SHALL provide a stateless one-shot encryption function for strings.

#### Scenario: One-shot encrypt string with numeric alphabet
- **WHEN** FPE_encrypt_str_oneshot is called with FPE_MODE_FF1, FPE_ALGO_AES, valid key, alphabet="0123456789", and input/output strings
- **THEN** the function SHALL create a temporary context
- **AND** initialize it with specified parameters
- **AND** encrypt the string
- **AND** clean up the context
- **AND** return 0 on success, -1 on error

#### Scenario: One-shot encrypt string with invalid character
- **WHEN** FPE_encrypt_str_oneshot is called with input containing characters not in alphabet
- **THEN** the function SHALL return -1 (error)

#### Scenario: One-shot encrypt string with NULL alphabet
- **WHEN** FPE_encrypt_str_oneshot is called with NULL alphabet pointer
- **THEN** the function SHALL return -1 (error)

### Requirement: One-shot string decryption API
The library SHALL provide a stateless one-shot decryption function for strings.

#### Scenario: One-shot decrypt string with numeric alphabet
- **WHEN** FPE_decrypt_str_oneshot is called with FPE_MODE_FF1, FPE_ALGO_AES, valid key, alphabet="0123456789", and input/output strings
- **THEN** the function SHALL create a temporary context
- **AND** initialize it with specified parameters
- **AND** decrypt the string
- **AND** clean up the context
- **AND** return 0 on success, -1 on error

#### Scenario: One-shot decrypt string reversibility
- **WHEN** a string is encrypted with FPE_encrypt_str_oneshot
- **AND** then decrypted with FPE_decrypt_str_oneshot with the same parameters
- **THEN** the result SHALL equal the original string

### Requirement: In-place encryption/decryption
The library SHALL support in-place operations where input and output pointers point to the same buffer.

#### Scenario: In-place encryption with integer arrays
- **WHEN** FPE_encrypt is called with input and output pointers pointing to the same array
- **THEN** the function SHALL successfully encrypt in-place
- **AND** the array SHALL contain the ciphertext after the call

#### Scenario: In-place decryption with integer arrays
- **WHEN** FPE_decrypt is called with input and output pointers pointing to the same array
- **THEN** the function SHALL successfully decrypt in-place
- **AND** the array SHALL contain the plaintext after the call

#### Scenario: In-place string encryption
- **WHEN** FPE_encrypt_str is called with input and output pointers pointing to the same string
- **THEN** the function SHALL successfully encrypt in-place
- **AND** the string SHALL contain the ciphertext after the call

#### Scenario: In-place string decryption
- **WHEN** FPE_decrypt_str is called with input and output pointers pointing to the same string
- **THEN** the function SHALL successfully decrypt in-place
- **AND** the string SHALL contain the plaintext after the call

### Requirement: Thread safety
The library SHALL be thread-safe when multiple contexts are used concurrently.

#### Scenario: Concurrent encryption with separate contexts
- **WHEN** multiple threads call FPE_encrypt with different context pointers simultaneously
- **THEN** all operations SHALL complete correctly without race conditions
- **AND** the results SHALL be consistent with sequential execution

#### Scenario: Concurrent encryption with shared context
- **WHEN** multiple threads call FPE_encrypt with the same context pointer simultaneously
- **THEN** the behavior SHALL be undefined (caller must use separate contexts or external synchronization)
- **AND** documentation SHALL warn against this usage

#### Scenario: Concurrent one-shot operations
- **WHEN** multiple threads call one-shot functions simultaneously
- **THEN** all operations SHALL complete correctly (each creates its own context)

### Requirement: Return value consistency
All library functions SHALL use consistent return value semantics.

#### Scenario: Success return value
- **WHEN** any function completes successfully
- **THEN** the function SHALL return 0

#### Scenario: Error return value
- **WHEN** any function encounters an error
- **THEN** the function SHALL return -1

#### Scenario: Context creation return value
- **WHEN** FPE_CTX_new succeeds
- **THEN** it SHALL return a non-NULL pointer

#### Scenario: Context creation failure
- **WHEN** FPE_CTX_new fails
- **THEN** it SHALL return NULL

### Requirement: Integer array validation
The library SHALL validate that integer array inputs contain values within the valid range for the radix.

#### Scenario: Valid integer array
- **WHEN** FPE_encrypt is called with an integer array where all values are in range [0, radix-1]
- **THEN** the function SHALL proceed with encryption

#### Scenario: Invalid integer array (value >= radix)
- **WHEN** FPE_encrypt is called with an integer array containing a value >= radix
- **THEN** the function SHALL return -1 (error)

### Requirement: Opaque pointer encapsulation
The FPE_CTX structure SHALL be opaque to hide implementation details from the user.

#### Scenario: User cannot access FPE_CTX internals
- **WHEN** user code tries to access fields of FPE_CTX structure
- **THEN** compilation SHALL fail (structure defined but not exposed in header)

#### Scenario: ABI stability
- **WHEN** internal FPE_CTX structure changes between library versions
- **THEN** binary compatibility SHALL be maintained (opaque pointer)
- **AND** users SHALL not need to recompile their code

### Requirement: C++ compatibility
The library SHALL provide C++ compatibility through extern "C" linkage.

#### Scenario: C++ code includes fpe.h
- **WHEN** C++ code includes the fpe.h header
- **THEN** all function declarations SHALL have C linkage
- **AND** C++ code SHALL be able to call all library functions
- **AND** C++ name mangling SHALL not interfere with function calls
