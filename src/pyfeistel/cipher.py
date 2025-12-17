import secrets
import math
from typing import List
from .sbox import SBOX

class FeistelCipher:
    """
    A specific implementations of a Feistel Network block cipher.
    See Section 8.2 of Design Document.
    """
    def __init__(self, key: bytes, rounds: int = 16):
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        self.rounds = rounds
        self.subkeys = self._expand_key(key)

    def _expand_key(self, key: bytes) -> List[int]:
        """
        Non-linear Key Schedule.
        Expands 256-bit key into 16 64-bit round keys.
        See Section 2.3.
        """
        # Initialization: Divide K into four 64-bit words
        # Big-endian interpretation as standard for network/crypto usually, 
        # but let's stick to consistent endianness. 8.2 uses 'big'.
        w = [
            int.from_bytes(key[0:8], 'big'),
            int.from_bytes(key[8:16], 'big'),
            int.from_bytes(key[16:24], 'big'),
            int.from_bytes(key[24:32], 'big')
        ]
        
        round_keys = []
        
        # Round Constants: Derived from mathematical constants (Pi)
        # Using fraction of Pi to get pseudo-random constants
        # 3.14159...
        # We need 16 64-bit constants.
        # This is an implementation choice as the doc says "Derived from... constants like pi".
        # I'll generate stable constants based on Pi digits for reproducibility.
        # For simplicity in this implementation, I will use a fixed list of constants 
        # that would represent these values to ensure deterministic behavior.
        # (simulated hex digits of pi)
        RC = [
            0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89,
            0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
            0x9216D5D98979FB1B, 0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
            0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16, 0x636920D871574E69
        ]

        for i in range(16):
            # Rotate W[i mod 4] left by 13 bits
            idx = i % 4
            val = w[idx]
            rot_val = ((val << 13) | (val >> (64 - 13))) & 0xFFFFFFFFFFFFFFFF
            
            # Apply S-box to the least significant byte
            lsb = rot_val & 0xFF
            subbed_lsb = SBOX[lsb]
            
            # Replace LSB with subbed value
            rot_val = (rot_val & 0xFFFFFFFFFFFFFF00) | subbed_lsb
            
            # XOR with Round Constant
            k_i = rot_val ^ RC[i]
            round_keys.append(k_i)
            
            # Update state of W (Feistel-like mixing)
            # "Update the state of the words W... to ensure... dependence on all bits"
            # Strategy: W[idx] = W[idx] ^ k_i  (Simple feedback)
            # OR W[idx] = k_i
            # The doc says "Update the state... using a Feistel-like mixing step".
            # I'll implement: W[idx] = W[idx] ^ k_i
            w[idx] = w[idx] ^ k_i
            
        return round_keys

    def _f_function(self, right: int, subkey: int) -> int:
        """
        The Round Function F(R, K).
        See Section 4.1 and 8.2.
        """
        # 1. Key Mixing
        mixed = right ^ subkey
        
        # 2. S-Box Substitution (byte by byte)
        # treating 64-bit integer as 8 bytes
        output = 0
        for i in range(8):
            # Extract byte i
            shift = 8 * i
            byte_val = (mixed >> shift) & 0xFF
            subbed_val = SBOX[byte_val]
            output |= (subbed_val << shift)
            
        # 3. Diffusion (Permutation)
        # Rotate left 11 bits
        rotated = ((output << 11) | (output >> (64 - 11))) & 0xFFFFFFFFFFFFFFFF
        
        # Swap upper and lower 32-bit words
        # Low 32 bits -> High 32 bits
        # High 32 bits -> Low 32 bits
        lower = rotated & 0xFFFFFFFF
        upper = (rotated >> 32) & 0xFFFFFFFF
        swapped = (lower << 32) | upper
        
        return swapped

    def encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypts a single 128-bit block.
        """
        if len(block) != 16:
            raise ValueError("Block size must be 128 bits")
            
        # Convert bytes to two 64-bit integers
        left = int.from_bytes(block[:8], 'big')
        right = int.from_bytes(block[8:], 'big')
        
        for i in range(self.rounds):
            prev_left = left
            left = right
            f_out = self._f_function(right, self.subkeys[i])
            right = prev_left ^ f_out
            
        # Final Swap: Output is R_16 || L_16
        return right.to_bytes(8, 'big') + left.to_bytes(8, 'big')
        
    def decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypts a single 128-bit block.
        """
        if len(block) != 16:
            raise ValueError("Block size must be 128 bits")
            
        # For decryption, the input is ciphertext (R_16, L_16)
        # We interpret it as (L_dec_0, R_dec_0) where L_dec_0 = R_16, R_dec_0 = L_16
        left = int.from_bytes(block[:8], 'big')
        right = int.from_bytes(block[8:], 'big')
        
        for i in range(self.rounds):
            prev_left = left
            left = right
            # Use subkeys in reverse order
            f_out = self._f_function(right, self.subkeys[self.rounds - 1 - i])
            right = prev_left ^ f_out
            
        # Final Swap for decryption to recover L_0 || R_0
        return right.to_bytes(8, 'big') + left.to_bytes(8, 'big')
