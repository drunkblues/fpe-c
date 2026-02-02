# Radix Range Correction - FF3/FF3-1

## Summary

Corrected documentation errors regarding radix support for FF3 and FF3-1 algorithms.

## Problem

Documentation incorrectly stated that FF3 and FF3-1 only support radix values up to 256 (2-256).

## Solution

After comprehensive testing, confirmed that FF3 and FF3-1 **fully support radix values from 2 to 65536**, matching the same range as FF1.

## Test Results

### Testing Method
- Created test program to verify full encryption/decryption cycles
- Tested radix values from 2 to 65536
- Verified initialization, encryption, decryption, and plaintext matching

### Results
| Algorithm | Tested Range | Result |
|-----------|--------------|--------|
| FF1 | 2-65536 | ✅ SUCCESS |
| FF3 | 2-65536 | ✅ SUCCESS |
| FF3-1 | 2-65536 | ✅ SUCCESS |

### Edge Cases
- radix = 1: ✗ Failed (minimum is 2)
- radix = 65536: ✓ Success (maximum)
- radix = 65537: ✗ Failed (exceeds maximum)

## Documentation Changes

### Files Modified

1. **docs/API.md**
   - Line 77: Updated radix parameter description
   - Lines 95-96: Updated constraints section
   - Line 379: Updated FF3-1 recommendation

2. **docs/ALGORITHMS.md**
   - Line 93: Removed incorrect "Limited radix range" constraint
   - Line 99: Updated FF3 radix support
   - Line 165: Updated FF3-1 radix support
   - Lines 344-351: Updated algorithm selection guide

3. **docs/SECURITY.md**
   - Line 119: Removed incorrect "Limited radix support" point

4. **docs/MIGRATION.md**
   - Line 26: Removed incorrect "Limited Radix Support" point

5. **docs/ERROR_HANDLING.md**
   - Line 138: Updated error code table
   - Line 497: Updated common causes section
   - Line 509: Updated code example

## Code Verification

The underlying code in `src/utils.c` already correctly validates radix for all modes:

```c
int fpe_validate_radix(unsigned int radix) {
    if (radix < 2 || radix > 65536) return -1;
    return 0;
}
```

This function is called by `FPE_CTX_init()` for **all modes** (FF1, FF3, FF3-1), not just FF1.

## Impact

- **Users**: Can now confidently use radix values > 256 with FF3/FF3-1
- **Documentation**: Accurate and consistent across all files
- **Code**: No changes needed (already correct)

## Conclusion

The radix limitation of ≤ 256 was a documentation error, not a code limitation. FF3 and FF3-1 support the full range of 2-65536, identical to FF1.

## References

- NIST SP 800-38G (FF1 specification)
- NIST SP 800-38G Rev. 1 (FF3-1 specification)
- Test file: `test_radix_actual.c` (created during verification, then removed)
