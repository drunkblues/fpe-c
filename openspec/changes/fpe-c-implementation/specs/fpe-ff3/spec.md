## ADDED Requirements

### Requirement: FF3 algorithm implementation (Deprecated)
The library SHALL implement FF3 format-preserving encryption algorithm as specified in NIST SP 800-38G. **This algorithm is deprecated by NIST due to security concerns. FF3-1 should be preferred.**

#### Scenario: FF3 encryption with AES
- **WHEN** FF3 algorithm is used to encrypt a 20-digit numeric plaintext with AES-128
- **THEN** ciphertext SHALL be a 20-digit numeric value
- **AND** ciphertext SHALL be deterministic for same key and tweak

#### Scenario: FF3 encryption with SM4
- **WHEN** FF3 algorithm is used to encrypt a 20-digit numeric plaintext with SM4-128
- **THEN** ciphertext SHALL be a 20-digit numeric value
- **AND** ciphertext SHALL be deterministic for same key and tweak

#### Scenario: FF3 decryption
- **WHEN** FF3 algorithm is used to decrypt a 20-digit numeric ciphertext
- **THEN** plaintext SHALL be original 20-digit numeric value

#### Scenario: FF3 with invalid input length
- **WHEN** FF3 algorithm is called with input length less than 2
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3 key derivation
The library SHALL derive cryptographic keys for FF3 using AES-ECB or SM4-ECB as specified in NIST SP 800-38G.

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

### Requirement: FF3 tweak support
The FF3 implementation SHALL support a tweak (additional input) parameter as specified in NIST SP 800-38G with strict length requirements.

#### Scenario: FF3 with valid tweak (64 bits)
- **WHEN** FF3 algorithm is called with a tweak of exactly 64 bits (8 bytes)
- **THEN** ciphertext SHALL be different for different tweak values with same key and plaintext
- **AND** operation SHALL succeed

#### Scenario: FF3 with valid tweak (56 bits)
- **WHEN** FF3 algorithm is called with a tweak of exactly 56 bits (7 bytes)
- **THEN** ciphertext SHALL be different for different tweak values with same key and plaintext
- **AND** operation SHALL succeed

#### Scenario: FF3 with invalid tweak length
- **WHEN** FF3 algorithm is called with a tweak that is not 64 or 56 bits
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3 Feistel network
The FF3 implementation SHALL use an 8-round Feistel network with round functions based on AES-ECB or SM4-ECB.

#### Scenario: FF3 round computation
- **WHEN** computing a single FF3 round with AES
- **THEN** output SHALL be computed using the round function F
- **AND** F SHALL use AES-ECB with the derived round key and tweak

#### Scenario: FF3 round computation with SM4
- **WHEN** computing a single FF3 round with SM4
- **THEN** output SHALL be computed using the round function F
- **AND** F SHALL use SM4-ECB with the derived round key and tweak

### Requirement: FF3 radix support
The FF3 implementation SHALL support arbitrary radix (base) values from 2 to 65536.

#### Scenario: FF3 with radix 10 (decimal)
- **WHEN** FF3 is used with radix 10
- **THEN** input and output SHALL consist of decimal digits (0-9)

#### Scenario: FF3 with radix 26 (alphabetic)
- **WHEN** FF3 is used with radix 26
- **THEN** input and output SHALL consist of alphabetic characters (A-Z or a-z)

#### Scenario: FF3 with radix 62 (alphanumeric)
- **WHEN** FF3 is used with radix 62
- **THEN** input and output SHALL consist of alphanumeric characters (0-9, A-Z, a-z)

#### Scenario: FF3 with invalid radix
- **WHEN** FF3 is called with radix less than 2 or greater than 65536
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3 test vectors
The FF3 implementation SHALL pass all test vectors provided in NIST SP 800-38G and hardcoded in tests/vectors.h.

#### Scenario: FF3 AES-128 test vectors (all 5 vectors from tests/vectors.h)
- **WHEN** FF3 implementation with AES-128 is tested with all test vectors from tests/vectors.h
- **THEN** 56-bit tweak: "890121234567890000" SHALL encrypt to "750918814058654607"
- **AND** 64-bit tweak: "890121234567890000" SHALL encrypt to "018989839189395384"
- **AND** 56-bit tweak (20-digit): "89012123456789000000789000000" SHALL encrypt to "48598367162252569629397416226"
- **AND** empty tweak: "89012123456789000000789000000" SHALL encrypt to "34695224821734535122613701434"
- **AND** 26-radix input: "0123456789abcdefghi" SHALL encrypt to "g2pk40i992fn20cjakb"

#### Scenario: FF3 AES-192 test vectors (all 5 vectors from tests/vectors.h)
- **WHEN** FF3 implementation with AES-192 is tested with all test vectors from tests/vectors.h
- **THEN** 56-bit tweak: "890121234567890000" SHALL encrypt to "646965393875028755"
- **AND** 64-bit tweak: "890121234567890000" SHALL encrypt to "961610514491424446"
- **AND** 56-bit tweak (20-digit): "89012123456789000000789000000" SHALL encrypt to "53048884065350204541786380807"
- **AND** empty tweak: "89012123456789000000789000000" SHALL encrypt to "98083802678820389295041483512"
- **AND** 26-radix input: "0123456789abcdefghi" SHALL encrypt to "i0ihe2jfj7a9opf9p88"

#### Scenario: FF3 AES-256 test vectors (all 5 vectors from tests/vectors.h)
- **WHEN** FF3 implementation with AES-256 is tested with all test vectors from tests/vectors.h
- **THEN** 56-bit tweak: "890121234567890000" SHALL encrypt to "922011205562777495"
- **AND** 64-bit tweak: "890121234567890000" SHALL encrypt to "504149865578056140"
- **AND** 56-bit tweak (20-digit): "89012123456789000000789000000" SHALL encrypt to "04344343235792599165734622699"
- **AND** empty tweak: "89012123456789000000789000000" SHALL encrypt to "308592399993740538723655822"
- **AND** 26-radix input: "0123456789abcdefghi" SHALL encrypt to "p0b2godfja9bhb7bk38"

#### Scenario: FF3 test vector reversibility
- **WHEN** ciphertext from any test vector is decrypted
- **THEN** result SHALL match original plaintext from tests/vectors.h

#### Scenario: FF3 performance measurement
- **WHEN** FF3 performance is measured with AES-128
- **THEN** tests SHALL report encryption time per operation
- **AND** tests SHALL report decryption time per operation
- **AND** tests SHALL report throughput (operations per second)

#### Scenario: FF3 multi-threaded TPS measurement
- **WHEN** FF3 is tested with multiple threads (e.g., 4, 8, 16 threads)
- **THEN** tests SHALL measure and report Transactions Per Second (TPS)
- **AND** tests SHALL verify TPS scales with thread count (until CPU saturation)
- **AND** tests SHALL use separate contexts per thread
- **AND** tests SHALL verify no race conditions or data corruption

#### Scenario: FF3 SM4 test vectors (all 3 vectors from tests/vectors.h)
- **WHEN** FF3 implementation with SM4-128 is tested with all test vectors from tests/vectors.h
- **THEN** 8-byte tweak: "393837363534333" SHALL encrypt to "4006222465"
- **AND** empty tweak: "393837363534333" SHALL encrypt to "8230614527"
- **AND** decryption SHALL be reversible for all vectors

#### Scenario: FF3 performance comparison
- **WHEN** FF3 performance with AES is compared to FF3 with SM4 using same parameters
- **THEN** tests SHALL report relative performance (SM4 vs AES)
- **AND** differences SHALL be documented (if any significant)

### Requirement: FF3 minimum length requirement
The FF3 implementation SHALL enforce the minimum input length of 2 * ceil(log2(radix)).

#### Scenario: FF3 with valid minimum length (radix=10)
- **WHEN** FF3 is used with radix 10 and input length at least 20
- **THEN** the algorithm SHALL execute without error

#### Scenario: FF3 with invalid length below minimum (radix=10)
- **WHEN** FF3 is used with radix 10 and input length less than 20
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3 with integer array input
The FF3 implementation SHALL accept and produce integer arrays as the underlying data representation.

#### Scenario: FF3 with valid integer array
- **WHEN** FF3 is called with a valid integer array (all values in range [0, radix-1])
- **THEN** output SHALL be an integer array of the same length
- **AND** encryption/decryption SHALL be reversible

#### Scenario: FF3 with invalid integer array
- **WHEN** FF3 is called with an integer array containing values >= radix
- **THEN** the function SHALL return -1 (error)

### Requirement: FF3 deprecation notice
The library SHALL indicate that FF3 is deprecated through documentation and enum values.

#### Scenario: FF3 mode enum value
- **WHEN** user uses FPE_MODE_FF3
- **THEN** enum value SHALL be available for legacy compatibility
- **AND** documentation SHALL clearly state that FF3 is deprecated
- **AND** documentation SHALL recommend using FF3-1 instead
