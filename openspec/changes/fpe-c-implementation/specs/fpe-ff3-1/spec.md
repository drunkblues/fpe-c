## ADDED Requirements

### Requirement: FF3-1 algorithm implementation
The FF3-1 implementation SHALL implement FF3 format-preserving encryption algorithm as specified in NIST SP 800-38G Rev 1. FF3-1 is the recommended algorithm over FF3 due to security fixes.

#### Scenario: FF3-1 encryption with AES
- **WHEN** FF3-1 algorithm is used to encrypt a 20-digit numeric plaintext with AES-128
- **THEN** ciphertext SHALL be a 20-digit numeric value
- **AND** ciphertext SHALL be deterministic for same key and tweak

#### Scenario: FF3-1 encryption with SM4
- **WHEN** FF3-1 algorithm is used to encrypt a 20-digit numeric plaintext with SM4-128
- **THEN** ciphertext SHALL be a 20-digit numeric value
- **AND** ciphertext SHALL be deterministic for same key and tweak

#### Scenario: FF3-1 decryption
- **WHEN** FF3-1 algorithm is used to decrypt a 20-digit numeric ciphertext
- **THEN** plaintext SHALL be original 20-digit numeric value

#### Scenario: FF3-1 with invalid input length
- **WHEN** FF3-1 algorithm is called with input length less than 2
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3-1 key derivation
The library SHALL derive cryptographic keys for FF3-1 using AES-ECB or SM4-ECB as specified in NIST SP 800-38G Rev 1.

#### Scenario: Key derivation with AES-128
- **WHEN** a valid AES-128 key is provided
- **THEN** the library SHALL derive the necessary subkeys using AES-ECB
- **AND** the derived keys SHALL be cached in the context

#### Scenario: Key derivation with AES-192
- **WHEN** a valid AES-192 key is provided
- **THEN** the library SHALL derive the necessary subkeys using AES-ECB

#### Scenario: Key derivation with AES-256
- **WHEN** a valid AES-256 key is provided
- **THEN** the library SHALL derive the necessary subkeys using AES-ECB

#### Scenario: Key derivation with SM4-128
- **WHEN** a valid SM4-128 key is provided
- **THEN** the library SHALL derive the necessary subkeys using SM4-ECB
- **AND** the derived keys SHALL be cached in the context

#### Scenario: Key derivation with invalid key length
- **WHEN** an AES key with unsupported length is provided (not 128, 192, or 256 bits)
- **THEN** the function SHALL return -1 (error)

#### Scenario: SM4 key derivation with wrong length
- **WHEN** a SM4 key with length not equal to 128 bits is provided
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3-1 tweak support
The FF3-1 implementation SHALL support a tweak (additional input) parameter as specified in NIST SP 800-38G Rev 1 with strict length requirements.

#### Scenario: FF3-1 with valid tweak (64 bits)
- **WHEN** FF3-1 algorithm is called with a tweak of exactly 64 bits (8 bytes)
- **THEN** ciphertext SHALL be different for different tweak values with same key and plaintext
- **AND** operation SHALL succeed

#### Scenario: FF3-1 with valid tweak (56 bits)
- **WHEN** FF3-1 algorithm is called with a tweak of exactly 56 bits (7 bytes)
- **THEN** ciphertext SHALL be different for different tweak values with same key and plaintext
- **AND** operation SHALL succeed

#### Scenario: FF3-1 with invalid tweak length
- **WHEN** FF3-1 algorithm is called with a tweak that is not 64 or 56 bits
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3-1 Feistel network
The FF3-1 implementation SHALL use an 8-round Feistel network with round functions based on AES-ECB or SM4-ECB, with modifications to address FF3 security issues.

#### Scenario: FF3-1 round computation
- **WHEN** computing a single FF3-1 round with AES
- **THEN** output SHALL be computed using the round function F
- **AND** F SHALL use AES-ECB with the derived round key and tweak
- **AND** round function SHALL include security fixes specified in NIST SP 800-38G Rev 1

#### Scenario: FF3-1 round computation with SM4
- **WHEN** computing a single FF3-1 round with SM4
- **THEN** output SHALL be computed using the round function F
- **AND** F SHALL use SM4-ECB with the derived round key and tweak
- **AND** round function SHALL include security fixes specified in NIST SP 800-38G Rev 1

### Requirement: FF3-1 radix support
The FF3-1 implementation SHALL support arbitrary radix (base) values from 2 to 65536.

#### Scenario: FF3-1 with radix 10 (decimal)
- **WHEN** FF3-1 is used with radix 10
- **THEN** input and output SHALL consist of decimal digits (0-9)

#### Scenario: FF3-1 with radix 26 (alphabetic)
- **WHEN** FF3-1 is used with radix 26
- **THEN** input and output SHALL consist of alphabetic characters (A-Z or a-z)

#### Scenario: FF3-1 with radix 62 (alphanumeric)
- **WHEN** FF3-1 is used with radix 62
- **THEN** input and output SHALL consist of alphanumeric characters (0-9, A-Z, a-z)

#### Scenario: FF3-1 with invalid radix
- **WHEN** FF3-1 is called with radix less than 2 or greater than 65536
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3-1 test vectors
The FF3-1 implementation SHALL pass all test vectors provided in NIST SP 800-38G Rev 1 and hardcoded in tests/vectors.h.

#### Scenario: FF3-1 AES-128 test vectors (all 5 vectors from tests/vectors.h)
- **WHEN** FF3-1 implementation with AES-128 is tested with all test vectors from tests/vectors.h
- **THEN** 56-bit tweak: "890121234567890000" SHALL encrypt to "814997673314616621"
- **AND** 64-bit tweak: "890121234567890000" SHALL encrypt to "733896897510917587"
- **AND** 56-bit tweak (20-digit): "89012123456789000000789000000" SHALL encrypt to "74700942206520203572429371837"
- **AND** empty tweak: "89012123456789000000789000000" SHALL encrypt to "34695224821734535122613701434"

#### Scenario: FF3-1 AES-192 test vectors (all 5 vectors from tests/vectors.h)
- **WHEN** FF3-1 implementation with AES-192 is tested with all test vectors from tests/vectors.h
- **THEN** 56-bit tweak: "890121234567890000" SHALL encrypt to "088425252487872053"
- **AND** 64-bit tweak: "890121234567890000" SHALL encrypt to "926248174806830704"
- **AND** 56-bit tweak (20-digit): "89012123456789000000789000000" SHALL encrypt to "18912741172273447257239338396"
- **AND** empty tweak: "89012123456789000000789000000" SHALL encrypt to "98083802678820389295041483512"
- **AND** 26-radix input: "0123456789abcdefghi" SHALL encrypt to "bf7872m846567h6b4pm"

#### Scenario: FF3-1 AES-256 test vectors (all 5 vectors from tests/vectors.h)
- **WHEN** FF3-1 implementation with AES-256 is tested with all test vectors from tests/vectors.h
- **THEN** 56-bit tweak: "890121234567890000" SHALL encrypt to "375943975111567310"
- **AND** 64-bit tweak: "890121234567890000" SHALL encrypt to "5295599965780884303"
- **AND** 56-bit tweak (20-digit): "89012123456789000000789000000" SHALL encrypt to "54988118574366877104446093026"
- **AND** empty tweak: "89012123456789000000789000000" SHALL encrypt to "308592399993740538723655822"
- **AND** 26-radix input: "0123456789abcdefghi" SHALL encrypt to "keo739ag6ola81n640k"

#### Scenario: FF3-1 test vector reversibility
- **WHEN** ciphertext from any test vector is decrypted
- **THEN** result SHALL match original plaintext from tests/vectors.h

#### Scenario: FF3-1 performance measurement
- **WHEN** FF3-1 performance is measured with AES-128
- **THEN** tests SHALL report encryption time per operation
- **AND** tests SHALL report decryption time per operation
- **AND** tests SHALL report throughput (operations per second)

#### Scenario: FF3-1 multi-threaded TPS measurement
- **WHEN** FF3-1 is tested with multiple threads (e.g., 4, 8, 16 threads)
- **THEN** tests SHALL measure and report Transactions Per Second (TPS)
- **AND** tests SHALL verify TPS scales with thread count (until CPU saturation)
- **AND** tests SHALL use separate contexts per thread
- **AND** tests SHALL verify no race conditions or data corruption

#### Scenario: FF3-1 security improvements
The FF3-1 implementation SHALL include security improvements specified in NIST SP 800-38G Rev 1 that address to weaknesses in FF3.

#### Scenario: FF3-1 security fix application
- **WHEN** FF3-1 is used instead of FF3
- **THEN** implementation SHALL apply security fixes specified in NIST SP 800-38G Rev 1
- **AND** implementation SHALL be resistant to attacks that affect FF3

#### Scenario: FF3-1 different ciphertext than FF3
- **WHEN** same key, plaintext, and tweak are encrypted with both FF3 and FF3-1
- **THEN** ciphertexts SHALL be different
- **AND** FF3-1 SHALL produce expected output according to revised standard

### Requirement: FF3-1 minimum length requirement
The FF3-1 implementation SHALL enforce the minimum input length of 2 * ceil(log2(radix)).

#### Scenario: FF3-1 with valid minimum length (radix=10)
- **WHEN** FF3-1 is used with radix 10 and input length at least 20
- **THEN** the algorithm SHALL execute without error

#### Scenario: FF3-1 with invalid length below minimum (radix=10)
- **WHEN** FF3-1 is used with radix 10 and input length less than 20
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3-1 with integer array input
The FF3-1 implementation SHALL accept and produce integer arrays as the underlying data representation.

#### Scenario: FF3-1 with valid integer array
- **WHEN** FF3-1 is called with a valid integer array (all values in range [0, radix-1])
- **THEN** output SHALL be an integer array of the same length
- **AND** encryption/decryption SHALL be reversible

#### Scenario: FF3-1 with invalid integer array
- **WHEN** FF3-1 is called with an integer array containing values >= radix
- **THEN** the function SHALL return -1 (error)
