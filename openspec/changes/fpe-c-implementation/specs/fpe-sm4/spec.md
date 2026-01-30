## ADDED Requirements

### Requirement: SM4 algorithm support
The library SHALL support SM4 (国密) cryptographic algorithm for all FPE modes (FF1, FF3, FF3-1). SM4 is specified in GB/T 32907-2016.

#### Scenario: SM4 key length validation
- **WHEN** a key is provided for SM4
- **THEN** key length MUST be exactly 128 bits (16 bytes)
- **AND** providing any other key length SHALL result in error return value -1

#### Scenario: SM4 in FF1 mode
- **WHEN** FF1 mode is used with FPE_ALGO_SM4
- **THEN** library SHALL use SM4-CMAC for round function
- **AND** library SHALL derive subkeys using SM4

#### Scenario: SM4 in FF3 mode
- **WHEN** FF3 mode is used with FPE_ALGO_SM4
- **THEN** library SHALL use SM4-ECB for round function
- **AND** library SHALL derive subkeys using SM4

#### Scenario: SM4 in FF3-1 mode
- **WHEN** FF3-1 mode is used with FPE_ALGO_SM4
- **THEN** library SHALL use SM4-ECB for round function
- **AND** library SHALL derive subkeys using SM4

### Requirement: SM4 algorithm availability detection
The library SHALL detect whether SM4 is available in the current OpenSSL installation and report unavailability appropriately.

#### Scenario: SM4 available (OpenSSL 3.0+)
- **WHEN** library is compiled with OpenSSL 3.0 or later
- **THEN** FPE_ALGO_SM4 SHALL be available
- **AND** using SM4 SHALL work correctly

#### Scenario: SM4 available (OpenSSL 1.1.1+)
- **WHEN** library is compiled with OpenSSL 1.1.1 or later
- **THEN** FPE_ALGO_SM4 SHALL be available (experimental support)
- **AND** using SM4 SHALL work correctly

#### Scenario: SM4 unavailable (OpenSSL < 1.1.1)
- **WHEN** library is compiled with OpenSSL version older than 1.1.1
- **THEN** FPE_ALGO_SM4 SHALL NOT be available
- **AND** attempting to use SM4 SHALL return error -1

### Requirement: SM4 in unified API
The library SHALL support SM4 through the unified FPE_encrypt/FPE_decrypt API.

#### Scenario: Unified API with SM4 and FF1
- **WHEN** FPE_CTX_init is called with FPE_MODE_FF1 and FPE_ALGO_SM4
- **THEN** FPE_encrypt SHALL correctly dispatch to FF1 implementation with SM4
- **AND** FPE_decrypt SHALL correctly dispatch to FF1 implementation with SM4

#### Scenario: Unified API with SM4 and FF3
- **WHEN** FPE_CTX_init is called with FPE_MODE_FF3 and FPE_ALGO_SM4
- **THEN** FPE_encrypt SHALL correctly dispatch to FF3 implementation with SM4
- **AND** FPE_decrypt SHALL correctly dispatch to FF3 implementation with SM4

#### Scenario: Unified API with SM4 and FF3-1
- **WHEN** FPE_CTX_init is called with FPE_MODE_FF3_1 and FPE_ALGO_SM4
- **THEN** FPE_encrypt SHALL correctly dispatch to FF3-1 implementation with SM4
- **AND** FPE_decrypt SHALL correctly dispatch to FF3-1 implementation with SM4

### Requirement: SM4 in one-shot API
The library SHALL support SM4 through one-shot (stateless) API.

#### Scenario: One-shot encryption with SM4
- **WHEN** FPE_encrypt_oneshot is called with FPE_ALGO_SM4
- **THEN** function SHALL create a temporary context
- **AND** initialize it with SM4
- **AND** perform encryption
- **AND** clean up context
- **AND** return success or error

#### Scenario: One-shot decryption with SM4
- **WHEN** FPE_decrypt_oneshot is called with FPE_ALGO_SM4
- **THEN** function SHALL create a temporary context
- **AND** initialize it with SM4
- **AND** perform decryption
- **AND** clean up context
- **AND** return success or error

#### Scenario: One-shot string encryption with SM4
- **WHEN** FPE_encrypt_str_oneshot is called with FPE_ALGO_SM4
- **THEN** function SHALL create a temporary context
- **AND** initialize it with SM4
- **AND** perform string encryption
- **AND** clean up context
- **AND** return success or error

### Requirement: SM4 compatibility with FPE modes
SM4 SHALL work identically to AES in terms of FPE mode behavior, only differing in the underlying cryptographic primitive.

#### Scenario: SM4 FF1 produces deterministic output
- **WHEN** same SM4 key, plaintext, and tweak are encrypted multiple times using FF1
- **THEN** all ciphertext outputs SHALL be identical

#### Scenario: SM4 FF3 produces deterministic output
- **WHEN** same SM4 key, plaintext, and tweak are encrypted multiple times using FF3
- **THEN** all ciphertext outputs SHALL be identical

#### Scenario: SM4 FF3-1 produces deterministic output
- **WHEN** same SM4 key, plaintext, and tweak are encrypted multiple times using FF3-1
- **THEN** all ciphertext outputs SHALL be identical

#### Scenario: SM4 encryption/decryption is reversible
- **WHEN** plaintext is encrypted with SM4
- **AND** resulting ciphertext is decrypted with SM4
- **THEN** result SHALL equal to original plaintext

### Requirement: SM4 test vectors
The library SHALL provide test vectors for SM4-based FPE operations to verify correctness.

#### Scenario: FF1 with SM4-128 test vectors (all 4 vectors from tests/vectors.h)
- **WHEN** library is tested with FF1 test vectors using SM4 with same key/tweak/plaintext as AES tests
- **THEN** all test vectors SHALL pass
- **AND** ciphertext SHALL be different from AES (different cipher algorithm)
- **AND** decryption SHALL be reversible

#### Scenario: FF3 with SM4-128 test vectors (all 3 vectors from tests/vectors.h)
- **WHEN** library is tested with FF3 test vectors using SM4 with same key/tweak/plaintext as AES tests
- **THEN** all test vectors SHALL pass
- **AND** ciphertext SHALL be different from AES (different cipher algorithm)
- **AND** decryption SHALL be reversible

#### Scenario: FF3-1 with SM4-128 test vector (1 vector from tests/vectors.h)
- **WHEN** library is tested with FF3-1 test vector using SM4 with same key/tweak/plaintext as AES tests
- **THEN** test vector SHALL pass
- **AND** ciphertext SHALL be different from AES (different cipher algorithm)
- **AND** decryption SHALL be reversible
- **AND** output SHALL be different from FF3 (due to security fixes)

#### Scenario: SM4 performance measurement
- **WHEN** SM4 performance is measured with FF1 mode
- **THEN** tests SHALL report encryption time per operation
- **AND** tests SHALL report decryption time per operation
- **AND** tests SHALL report throughput (operations per second)

#### Scenario: SM4 performance comparison with AES
- **WHEN** SM4 and AES performance are compared with same algorithm mode and parameters
- **THEN** tests SHALL report relative performance (SM4 vs AES)
- **AND** differences SHALL be documented (if any significant)

#### Scenario: SM4 multi-threaded TPS measurement
- **WHEN** SM4 is tested with multiple threads (e.g., 4, 8, 16 threads)
- **THEN** tests SHALL measure and report Transactions Per Second (TPS)
- **AND** tests SHALL verify TPS scales with thread count (until CPU saturation)
- **AND** tests SHALL use separate contexts per thread
- **AND** tests SHALL verify no race conditions or data corruption

### Requirement: SM4 key size restriction
SM4 SHALL only support 128-bit keys as specified in the GB/T 32907-2016 standard.

#### Scenario: Attempt 192-bit SM4 key
- **WHEN** FPE_CTX_init is called with FPE_ALGO_SM4 and bits=192
- **THEN** function SHALL return error -1

#### Scenario: Attempt 256-bit SM4 key
- **WHEN** FPE_CTX_init is called with FPE_ALGO_SM4 and bits=256
- **THEN** function SHALL return error -1

#### Scenario: Valid 128-bit SM4 key
- **WHEN** FPE_CTX_init is called with FPE_ALGO_SM4 and bits=128
- **THEN** function SHALL return success (0)
- **AND** context SHALL be initialized correctly
