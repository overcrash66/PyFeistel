import pytest
import secrets
import numpy as np
from pyfeistel.cipher import FeistelCipher
from pyfeistel.modes import CTRMode

# Check if nistrng is installed
try:
    import nistrng
    from nistrng import pack_sequence, unpack_sequence, check_eligibility_all_battery, run_all_battery, SP800_22R1A_BATTERY
except ImportError as e:
    print(f"DEBUG: nistrng import failed: {e}")
    pytest.skip(f"nistrng not installed: {e}", allow_module_level=True)

def generate_ciphertext_sequence(num_bytes: int) -> bytes:
    """
    Generates a large sequence of ciphertext using CTR mode.
    CTR mode basically turns the block cipher into a CSPRNG.
    """
    key = secrets.token_bytes(32)
    cipher = FeistelCipher(key)
    mode = CTRMode(cipher)
    
    # Encrypt zero-plaintext (which just reveals the keystream)
    # This directly tests the randomness of the cipher's output.
    plaintext = bytes(num_bytes)
    nonce = secrets.token_bytes(8)
    
    ciphertext = mode.encrypt(plaintext, key, nonce)
    # Determine result (CTR output = keystream XOR 0 = keystream)
    # But mode.encrypt prepends Nonce (8 bytes).
    # We should skip the nonce to test the actual cipher output.
    
    return ciphertext[8:]

def test_nist_randomness():
    """
    Runs NIST SP 800-22 Rev 1a tests on the cipher output.
    Note: A full NIST validation requires millions of bits and p-value analysis.
    This is a "sanity check" version running on a smaller subset to verify 
    it doesn't fail catastrophically (e.g. producing all zeros).
    """
    # Generate 100 KB of data (800,000 bits)
    # Recommended is often higher, but this is a unit test.
    # nistrng library documentation suggests standard sequences.
    
    # Nistrng expects a numpy array of packed bits or 8-bit integers?
    # Looking at standard usage: unpack_sequence returns numpy array of bits (0,1).
    
    target_bytes = 20000 # 20KB ~ 160,000 bits. 
    # Some NIST tests demand strict minimum lengths (e.g. > 1000, > 1,000,000 for Rank).
    # We will try to run eligible tests.
    
    ciphertext = generate_ciphertext_sequence(target_bytes)
    
    # Convert bytes to sequence of bits (0, 1) using nistrng helper or numpy
    # nistrng.unpack_sequence takes standard bytes?
    # Let's assume standard numpy unpacking for robustness if doc is unclear
    # But let's try nistrng provided utility.
    
    # Convert bytes to sequence of bits (0, 1) using numpy
    # This is more reliable than nistrng.unpack_sequence in some versions
    byte_array = np.frombuffer(ciphertext, dtype=np.uint8)
    binary_sequence = np.unpackbits(byte_array).astype(np.int8)
    
    # Check eligibility
    eligible_tests = check_eligibility_all_battery(binary_sequence, SP800_22R1A_BATTERY)
    
    print(f"Eligible NIST tests for {len(binary_sequence)} bits: {len(eligible_tests)}")
    
    # Run tests
    results = run_all_battery(binary_sequence, eligible_tests, False)
    
    print("\nNIST SP 800-22 Test Results:")
    passed_count = 0
    # Zip the tests with their results to get names
    for test_instance, result_tuple in zip(eligible_tests, results):
        # result_tuple is (ResultObject, elapsed_time?)
        res_obj = result_tuple[0]
        
        name = str(test_instance)
        passed = res_obj.passed
        score = res_obj.score
        
        status = "PASS" if passed else "FAIL"
        print(f"{name}: {status} (p-value: {score:.4f})")
        
        if passed:
            passed_count += 1
            
    print(f"Passed: {passed_count}/{len(results)}")
    
    # Assert that most tests passed (allow some statistical failures)
    # 50% threshold is very loose but ensures basic functionality.
    if len(results) > 0:
        assert passed_count >= len(results) * 0.5, f"Failed too many NIST tests ({passed_count}/{len(results)})"

if __name__ == "__main__":
    test_nist_randomness()
