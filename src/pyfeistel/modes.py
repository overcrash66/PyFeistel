import secrets
import abc
from typing import Protocol, Union
from .cipher import FeistelCipher

class BlockCipher(Protocol):
    def encrypt_block(self, block: bytes) -> bytes: ...
    def decrypt_block(self, block: bytes) -> bytes: ...

class CipherMode(abc.ABC):
    def __init__(self, cipher: BlockCipher):
        self.cipher = cipher

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes, iv: Union[bytes, None] = None) -> bytes:
        pass

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes, iv: Union[bytes, None] = None) -> bytes:
        pass

def pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS#7 Padding."""
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    PKCS#7 Unpadding.
    Verifies padding in constant-time(ish) to avoid padding oracle leakage.
    Simulated educational constant-time check.
    """
    if not data:
        raise ValueError("Empty data")
    
    padding_len = data[-1]
    if padding_len == 0 or padding_len > block_size:
        raise ValueError("Invalid padding")
        
    # Check all padding bytes
    valid = 0
    for i in range(padding_len):
        # bitwise OR of differences
        valid |= (data[-(i+1)] ^ padding_len)
        
    if valid != 0:
        raise ValueError("Invalid padding")
        
    return data[:-padding_len]

class CBCMode(CipherMode):
    """
    Cipher Block Chaining (CBC) Mode.
    """
    def encrypt(self, plaintext: bytes, key: bytes, iv: Union[bytes, None] = None) -> bytes:
        # Re-initialize cipher with key (assuming key reuse optimization isn't primary goal here)
        # In a real scenario, the cipher object might be stateful or instantiated once.
        # But per design: "mode.encrypt(plaintext, key, iv)" suggests passing key.
        # However, our FeistelCipher takes key in __init__.
        # So we should re-initialize or check if the passed cipher needs re-keying.
        # The design doc pattern: 
        # cipher = PyFeistel(); mode = CBCMode(cipher); mode.encrypt...
        # If cipher was INIT without key, this fails. 
        # But FeistelCipher.__init__ requires key.
        # This implies we might need to update the key on the cipher instance 
        # or the generic `BlockCipher` protocol assumes a set key?
        # The design doc says:
        # `cipher = PyFeistel()` (implying no-arg?) NO, Section 8.2 says `__init__(self, key...)`.
        # Code snippet 36: `cipher = PyFeistel()` -> This contradicts 8.2.
        # I will assume `cipher` is already keyed, OR I should support re-keying.
        # Given `mode.encrypt` signature has `key`, I should use it to re-key `self.cipher`.
        
        # But `BlockCipher` protocol just has encrypt_block.
        # Solution: I will reinstantiate or methods on FeistelCipher.
        # For this implementation: I will assume `self.cipher` is a class or factory, 
        # OR I will just create a new instance using the `key` provided.
        # This is safer.
        cipher_instance = FeistelCipher(key)
        
        # Padding
        padded_pt = pad(plaintext)
        if iv is None:
            # Generate random IV
            iv = secrets.token_bytes(16)
        
        if len(iv) != 16:
            raise ValueError("IV must be 16 bytes")
            
        # Use bytearray for state (Section 3.1)
        ciphertext = bytearray(len(padded_pt) + 16) # First block is IV
        ciphertext[0:16] = iv
        
        prev_block = iv
        
        # Process blocks
        for i in range(0, len(padded_pt), 16):
            chunk = padded_pt[i:i+16]
            # CBC: C_i = E(P_i ^ C_{i-1})
            # Xor chunk with prev_block
            xored_input = bytes(a ^ b for a, b in zip(chunk, prev_block))
            encrypted_block = cipher_instance.encrypt_block(xored_input)
            
            ciphertext[i+16 : i+32] = encrypted_block
            prev_block = encrypted_block
            
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: Union[bytes, None] = None) -> bytes:
        cipher_instance = FeistelCipher(key)
        
        if len(ciphertext) < 16 or len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
            
        # Extract IV (first block)
        # Note: If IV was prepended by encrypt, used it. 
        # The user API `decrypt(..., iv=...)` lets user provide it.
        # But `encrypt` usually prepends it.
        # Design doc: "The IV does not need to be secret... unique... for each encryption".
        # Standard: prepended.
        
        actual_iv = iv
        start_idx = 0
        
        if iv is None:
            # Assume IV is the first block
            actual_iv = ciphertext[:16]
            start_idx = 16
        
        if actual_iv is None or len(actual_iv) != 16:
             raise ValueError("IV must be provided or prepended")
             
        plaintext = bytearray()
        prev_block = actual_iv
        
        for i in range(start_idx, len(ciphertext), 16):
            chunk = ciphertext[i:i+16]
            # CBC Dec: P_i = D(C_i) ^ C_{i-1}
            decrypted_block = cipher_instance.decrypt_block(chunk)
            plain_chunk = bytes(a ^ b for a, b in zip(decrypted_block, prev_block))
            plaintext.extend(plain_chunk)
            prev_block = chunk
            
        return unpad(bytes(plaintext))

class CTRMode(CipherMode):
    """
    Counter (CTR) Mode.
    See Section 5.2.
    """
    def encrypt(self, plaintext: bytes, key: bytes, iv: Union[bytes, None] = None) -> bytes:
        cipher_instance = FeistelCipher(key)
        
        if iv is None:
            iv = secrets.token_bytes(8) # Nonce (usually 1/2 block size for CTR if combining with counter)
        
        # Design Doc 5.2: "E_K(Nonce || Counter_i)"
        # We need a 128-bit input. 
        # If IV is the nonce (say 8 bytes), Counter is 8 bytes.
        if len(iv) != 8:
            # If user provides 16 bytes, we might use it as initial counter state?
            if len(iv) == 16:
                # Use as full block
                 nonce = iv[:8]
                 # But we need to increment.
                 # Let's assume standard: Nonce=8 bytes, Counter=8 bytes (64-bit counter)
                 pass
            else:
                 raise ValueError("CTR Mode requires 8-byte Nonce")
        
        nonce = iv
        
        # Output container
        # Same length as plaintext (stream cipher)
        # But usually we return Nonce + Ciphertext ?
        # The prompt says "Implement... CTRMode". I'll adhere to returning IV + Ciphertext for usability, 
        # or just ciphertext if IV provided.
        # For consistency with CBC encrypt which returned prepended IV:
        # Ill prepend the 8-byte nonce.
        
        ciphertext = bytearray()
        ciphertext.extend(nonce)
        
        # Counter loop
        # We verify we can process byte-by-byte or block-by-block.
        # Block-by-block is efficient.
        
        counter = 0
        num_blocks = (len(plaintext) + 15) // 16
        
        keystream = bytearray()
        
        for i in range(num_blocks):
            # Construct input block: Nonce || Counter
            # Counter is 64-bit big endian
            ctr_bytes = counter.to_bytes(8, 'big')
            input_block = nonce + ctr_bytes
            
            # Encrypt counter block
            # Note: CTR mode uses ENCRYPT for both encryption and decryption
            k_block = cipher_instance.encrypt_block(input_block)
            keystream.extend(k_block)
            
            counter += 1
            
        # XOR keystream with plaintext
        # truncate keystream to plaintext length
        keystream = keystream[:len(plaintext)]
        
        cipher_bytes = bytes(p ^ k for p, k in zip(plaintext, keystream))
        ciphertext.extend(cipher_bytes)
        
        return bytes(ciphertext)

    def decrypt(self, ciphertext: bytes, key: bytes, iv: Union[bytes, None] = None) -> bytes:
        # For CTR, decrypt is same as encrypt (generating keystream).
        # We just need to extract the nonce.
        
        nonce = iv
        data = ciphertext
        
        if iv is None:
            nonce = ciphertext[:8]
            data = ciphertext[8:]
            
        if len(nonce) != 8:
             raise ValueError("Nonce must be 8 bytes")
             
        # Generate keystream again
        cipher_instance = FeistelCipher(key)
        
        counter = 0
        num_blocks = (len(data) + 15) // 16
        keystream = bytearray()
         
        for i in range(num_blocks):
             ctr_bytes = counter.to_bytes(8, 'big')
             input_block = nonce + ctr_bytes
             k_block = cipher_instance.encrypt_block(input_block)
             keystream.extend(k_block)
             counter += 1
             
        keystream = keystream[:len(data)]
        plaintext = bytes(c ^ k for c, k in zip(data, keystream))
        
        return plaintext
