## ADDED Requirements

### Requirement: FF1 algorithm implementation
The library SHALL implement FF1 format-preserving encryption algorithm as specified in NIST SP 800-38G.

#### Scenario: FF1 encryption with AES
- **WHEN** the FF1 algorithm is used to encrypt a 16-digit numeric plaintext with AES-128
- **THEN** ciphertext SHALL be a 16-digit numeric value
- **AND** ciphertext SHALL be deterministic for same key and tweak

#### Scenario: FF1 encryption with SM4
- **WHEN** the FF1 algorithm is used to encrypt a 16-digit numeric plaintext with SM4-128
- **THEN** ciphertext SHALL be a 16-digit numeric value
- **AND** ciphertext SHALL be deterministic for same key and tweak

#### Scenario: FF1 decryption
- **WHEN** the FF1 algorithm is used to decrypt a 16-digit numeric ciphertext
- **THEN** plaintext SHALL be original 16-digit numeric value

#### Scenario: FF1 with invalid input length
- **WHEN** the FF1 algorithm is called with input length less than 2
- **THEN** the function SHALL return -1 (error)

### Requirement: FF1 key derivation
The library SHALL derive cryptographic keys for FF1 using AES-CMAC or SM4-CMAC as specified in NIST SP 800-38G.

#### Scenario: Key derivation with AES-128
- **WHEN** a valid AES-128 key is provided
- **THEN** the library SHALL derive the necessary subkeys using AES-CMAC
- **AND** the derived keys SHALL be cached in the context

#### Scenario: Key derivation with AES-192
- **WHEN** a valid AES-192 key is provided
- **THEN** the library SHALL derive the necessary subkeys using AES-CMAC

#### Scenario: Key derivation with AES-256
- **WHEN** a valid AES-256 key is provided
- **THEN** the library SHALL derive the necessary subkeys using AES-CMAC

#### Scenario: Key derivation with SM4-128
- **WHEN** a valid SM4-128 key is provided
- **THEN** the library SHALL derive the necessary subkeys using SM4-CMAC
- **AND** the derived keys SHALL be cached in the context

#### Scenario: Key derivation with invalid key length
- **WHEN** an AES key with unsupported length is provided (not 128, 192, or 256 bits)
- **THEN** the function SHALL return -1 (error)

#### Scenario: SM4 key derivation with wrong length
- **WHEN** a SM4 key with length not equal to 128 bits is provided
- **THEN** the function SHALL return -1 (error)

### Requirement: FF1 tweak support
The FF1 implementation SHALL support a tweak (additional input) parameter as specified in NIST SP 800-38G.

#### Scenario: FF1 with tweak
- **WHEN** the FF1 algorithm is called with a tweak value
- **THEN** ciphertext SHALL be different for different tweak values with same key and plaintext

#### Scenario: FF1 with empty tweak
- **WHEN** the FF1 algorithm is called with an empty tweak (tweak_len=0)
- **THEN** the algorithm SHALL proceed without error using a default all-zero tweak

#### Scenario: FF1 with large tweak
- **WHEN** the FF1 algorithm is called with a tweak up to 2^32 bytes
- **THEN** the algorithm SHALL proceed without error

### Requirement: FF1 Feistel network
The FF1 implementation SHALL use a 10-round Feistel network with round functions based on AES-CMAC or SM4-CMAC.

#### Scenario: FF1 round computation
- **WHEN** computing a single FF1 round with AES
- **THEN** output SHALL be computed using the round function F
- **AND** F SHALL use AES-CMAC with the derived round key

#### Scenario: FF1 round computation with SM4
- **WHEN** computing a single FF1 round with SM4
- **THEN** output SHALL be computed using the round function F
- **AND** F SHALL use SM4-CMAC with the derived round key

### Requirement: FF1 radix support
The FF1 implementation SHALL support arbitrary radix (base) values from 2 to 65536.

#### Scenario: FF1 with radix 10 (decimal)
- **WHEN** FF1 is used with radix 10
- **THEN** input and output SHALL consist of decimal digits (0-9)

#### Scenario: FF1 with radix 26 (alphabetic)
- **WHEN** FF1 is used with radix 26
- **THEN** input and output SHALL consist of alphabetic characters (A-Z or a-z)

#### Scenario: FF1 with radix 62 (alphanumeric)
- **WHEN** FF1 is used with radix 62
- **THEN** input and output SHALL consist of alphanumeric characters (0-9, A-Z, a-z)

#### Scenario: FF1 with invalid radix
- **WHEN** FF1 is called with radix less than 2 or greater than 65536
- **THEN** the function SHALL return -1 (error)

### Requirement: FF1 test vectors
The FF1 implementation SHALL pass all test vectors provided in NIST SP 800-38G and hardcoded in tests/vectors.h.

#### Scenario: FF1 AES-128 test vectors (all 3 vectors from tests/vectors.h)
- **WHEN** FF1 implementation with AES-128 is tested with all test vectors from tests/vectors.h
- **THEN** empty tweak: "0123456789" SHALL encrypt to "2433477484"
- **AND** 16-digit tweak: "39383736353433323130" SHALL encrypt to "6124200773"
- **AND** 20-digit input (radix=36): "3737373770717273373737" SHALL encrypt to "a9tv40mll9kdu509eum"

#### Scenario: FF1 AES-192 test vectors (all 3 vectors from tests/vectors.h)
- **WHEN** FF1 implementation with AES-192 is tested with all test vectors from tests/vectors.h
- **THEN** empty tweak: "0123456789" SHALL encrypt to "2830668132"
- **AND** 16-digit tweak: "39383736353433323130" SHALL encrypt to "2496655549"
- **AND** 20-digit input (radix=36): "3737373770717273373737" SHALL encrypt to "xbj3kv35jrawxv32ysr"

#### Scenario: FF1 AES-256 test vectors (all 3 vectors from tests/vectors.h)
- **WHEN** FF1 implementation with AES-256 is tested with all test vectors from tests/vectors.h
- **THEN** empty tweak: "0123456789" SHALL encrypt to "6657667009"
- **AND** 16-digit tweak: "39383736353433323130" SHALL encrypt to "1001623463"
- **AND** 20-digit input (radix=36): "3737373770717273373737" SHALL encrypt to "xs8a0azh2avyalyzuwd"

#### Scenario: FF1 test vector reversibility
- **WHEN** ciphertext from any test vector is decrypted
- **THEN** result SHALL match original plaintext from tests/vectors.h

#### Scenario: FF1 SM4 test vectors (all 4 vectors from tests/vectors.h)
- **WHEN** FF1 implementation with SM4-128 is tested with all test vectors from tests/vectors.h
- **THEN** empty tweak: "39383736353433323130" SHALL encrypt to "3805849473"
- **AND** 16-digit tweak: "3938373635343332" SHALL encrypt to "0244363969"
- **AND** 7-byte tweak: "393837363534333" SHALL encrypt to "7410238304"
- **AND** 20-digit input (radix=36): "0123456789abcdefghi" SHALL encrypt to "vsxvfxa16cjf2utxvlg"
- **AND** encryption/decryption SHALL be reversible

#### Scenario: FF1 performance measurement
- **WHEN** FF1 performance is measured with AES-128
- **THEN** tests SHALL report encryption time per operation
- **AND** tests SHALL report decryption time per operation
- **AND** tests SHALL report throughput (operations per second)

#### Scenario: FF1 multi-threaded TPS measurement
- **WHEN** FF1 is tested with multiple threads (e.g., 4, 8, 16 threads)
- **THEN** tests SHALL measure and report Transactions Per Second (TPS)
- **AND** tests SHALL verify TPS scales with thread count (until CPU saturation)
- **AND** tests SHALL use separate contexts per thread
- **AND** tests SHALL verify no race conditions or data corruption

#### Scenario: FF1 SM4 performance comparison
- **WHEN** FF1 performance with AES is compared to FF1 with SM4 using same parameters
- **THEN** tests SHALL report relative performance (SM4 vs AES)
- **AND** differences SHALL be documented (if any significant)

### Requirement: FF1 with integer array input
The FF1 implementation SHALL accept and produce integer arrays as the underlying data representation.

#### Scenario: FF1 with valid integer array
- **WHEN** FF1 is called with a valid integer array (all values in range [0, radix-1])
- **THEN** output SHALL be an integer array of the same length
- **AND** encryption/decryption SHALL be reversible

#### Scenario: FF1 with invalid integer array
- **WHEN** FF1 is called with an integer array containing values >= radix
- **THEN** the function SHALL return -1 (error)
