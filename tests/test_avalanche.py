import secrets
import statistics
from pyfeistel.cipher import FeistelCipher

def count_set_bits(n):
    return bin(n).count('1')

def hamming_distance(b1: bytes, b2: bytes) -> int:
    # XOR buffers and count bits
    val1 = int.from_bytes(b1, 'big')
    val2 = int.from_bytes(b2, 'big')
    xor_val = val1 ^ val2
    return count_set_bits(xor_val)

def test_avalanche_effect():
    """
    Verifies the Avalanche Effect (Section 7.1).
    Flipping a single input bit should flip approx 50% of output bits.
    For 128-bit block, expect ~64 bits changed.
    """
    key = secrets.token_bytes(32)
    cipher = FeistelCipher(key)
    
    # Run multiple trials
    distances = []
    
    for _ in range(100):
        # Generate random block
        p1 = secrets.token_bytes(16)
        c1 = cipher.encrypt_block(p1)
        
        # Flip random bit in p1
        # Pick a byte index (0-15) and a bit index (0-7)
        byte_idx = secrets.randbelow(16)
        bit_idx = secrets.randbelow(8)
        
        # Create p2
        p2_arr = bytearray(p1)
        p2_arr[byte_idx] ^= (1 << bit_idx)
        p2 = bytes(p2_arr)
        
        c2 = cipher.encrypt_block(p2)
        
        dist = hamming_distance(c1, c2)
        distances.append(dist)
        
    avg_dist = statistics.mean(distances)
    print(f"Average Hamming Distance: {avg_dist} (Target: ~64)")
    
    # Assert tolerance (e.g., +/- 10 bits is very loose, but fine for statistical test in CI)
    # The design doc says "Average H should be close to 64".
    # We'll assert it's between 50 and 78 for reliability.
    assert 50 <= avg_dist <= 78, f"Avalanche effect failed: {avg_dist}"

if __name__ == "__main__":
    test_avalanche_effect()
