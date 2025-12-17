import functools

# Irreducible polynomial for AES/Rijndael: x^8 + x^4 + x^3 + x + 1
# 0x11B = 100011011
irr_poly = 0x11B

def _gf_mult(a: int, b: int) -> int:
    """Multiplication in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= irr_poly
        b >>= 1
    return p & 0xFF

def _gf_pow(a: int, b: int) -> int:
    """Exponentiation in GF(2^8)."""
    res = 1
    while b > 0:
        if b & 1:
            res = _gf_mult(res, a)
        a = _gf_mult(a, a)
        b >>= 1
    return res

def _gf_inverse(a: int) -> int:
    """Multiplicative inverse in GF(2^8)."""
    if a == 0:
        return 0
    # In GF(2^n), a^(2^n - 2) is the inverse
    return _gf_pow(a, 254)

@functools.lru_cache()
def _generate_sbox() -> list[int]:
    """
    Generates an 8x8 S-box using GF(2^8) inversion and affine transform.
    See Section 2.1 and 8.1 of PyFeistel design doc.
    """
    sbox = [0] * 256
    
    for i in range(256):
        # 1. Compute multiplicative inverse in GF(2^8)
        s = _gf_inverse(i)
        
        # 2. Apply Affine Transformation
        # x_i' = x_i + x_{i+4} + x_{i+5} + x_{i+6} + x_{i+7} + c_i
        # This implementation uses the bitwise simulation from the design doc
        res = s ^ ((s << 1) & 0xFF) ^ ((s << 2) & 0xFF) ^ ((s << 3) & 0xFF) ^ ((s << 4) & 0xFF)
        
        # Handle wrapping bits for the affine step (rotation effect)
        # The design doc snippet: res = (res >> 8) ^ (res & 0xFF) ^ 0x63
        # However, checking standard AES affine logic, the shifts above create overflows > 8 bits.
        # The rotation part comes from taking the overflow bits.
        
        # Correct affine transformation logic matching Rijndael/Design Doc intent:
        # The expression `s ^ (s << 1) ^ ...` generates the summation.
        # We need to ensure we are XORing the correct rotated versions.
        # Rotations in byte:
        # rot1 = (s << 1) | (s >> 7)
        # rot2 = (s << 2) | (s >> 6)
        # ...
        # But the design doc snippet was specific:
        # res = s ^ ((s << 1) & 0xFF) ^ ((s << 2) & 0xFF) ^ ((s << 3) & 0xFF) ^ ((s << 4) & 0xFF)
        # res = (res >> 8) ^ (res & 0xFF) ^ 0x63 
        # Wait, the snippets `(s << 1) & 0xFF` throw away the high bit? 
        # If the design doc says specifically:
        # `res = (res >> 8) ^ (res & 0xFF) ^ 0x63`
        # This implies `res` accumulated bits > 8 in previous steps.
        # Let's strictly follow the design doc snippet provided in Section 8.1
        
        # Re-reading Section 8.1 code carefully:
        # res = s ^ ((s << 1) & 0xFF) ^ ((s << 2) & 0xFF) ^ ((s << 3) & 0xFF) ^ ((s << 4) & 0xFF)
        # This implementation discards the wrap-around bits immediately because of `& 0xFF`.
        # Then `(res >> 8)` would be 0.
        # This seems to be a slight bug or simplification in the doc's snippet if it intends to replicate AES exactly.
        # However, I must follow the doc OR correct it if it's "Section 2.1" compliant.
        # Section 2.1 says "Affine transformation (matrix multiplication...)".
        # The code in 8.1 might be pseudo-code.
        # BUT the snippet says: `res = (res >> 8) ^ (res & 0xFF) ^ 0x63`
        # This line suggests `res` *should* have had higher bits. 
        # So I should NOT mask with `& 0xFF` broadly in the intermediate steps if I want to use that final line.
        
        # Let's try to interpret the 8.1 snippet literally:
        # If `s` is 8-bit, `s << 4` can be 12-bit.
        # `(s << 1) & 0xFF` clips it.
        # If the doc clips it *immediately*, then `res >> 8` is always 0.
        # This would imply the Affine transform is missing the rotation parts.
        
        # Decision: The user wants a "Robust" library. The Design Doc mentions AES-like affine.
        # I will implement the *Functionally Correct* Affine Transformation (AES S-Box standard) 
        # which matches the visual description of "rotation" usually implied.
        # OR I can implement the text: "Matrix multiplication...".
        # Let's write the explicit matrix multiplication logic or the proper bitwise rotation.
        
        # Correct approach using proper 8-bit rotation helper:
        def rot(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF
        
        # Matrix: [1 0 0 0 1 1 1 1]... row 0
        # AES affine: y_i = x_i + x_{i+4} + x_{i+5} + x_{i+6} + x_{i+7} + c_i
        
        # Using the standard computation since the doc references Rijndael:
        s_rot1 = rot(s, 1)
        s_rot2 = rot(s, 2)
        s_rot3 = rot(s, 3)
        s_rot4 = rot(s, 4)
        
        # The design doc 8.1 has a comment: 
        # `x_i' = x_i + x_{i+4} + x_{i+5} + x_{i+6} + x_{i+7} + c_i`
        # Note: In the design doc code, it uses `s ^ (s<<1)...`
        # If I strictly follow the doc's logic `res = (res >> 8) ^ ...`, it might be assuming `(s<<1)` without the `& 0xFF` inside the parens?
        # "s ^ ((s << 1) & 0xFF)..." -> The `& 0xFF` is EXPLICIT in the doc.
        # I'll stick to the standard AES affine transform because the doc claims to follow "Rijndael S-box construction logic" (line 42).
        
        res = s ^ s_rot1 ^ s_rot2 ^ s_rot3 ^ s_rot4 ^ 0x63
        sbox[i] = res
        
    return sbox

# Pre-compute the S-Box explicitly
SBOX = _generate_sbox()

def get_sbox_value(val: int) -> int:
    return SBOX[val & 0xFF]
