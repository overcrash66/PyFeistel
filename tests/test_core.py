import pytest
import secrets
from pyfeistel.cipher import FeistelCipher

def test_round_trip():
    key = secrets.token_bytes(32)
    cipher = FeistelCipher(key)
    
    plaintext = secrets.token_bytes(16)
    ciphertext = cipher.encrypt_block(plaintext)
    decrypted = cipher.decrypt_block(ciphertext)
    
    assert decrypted == plaintext
    assert ciphertext != plaintext

def test_key_length_validation():
    with pytest.raises(ValueError):
        FeistelCipher(b"shortkey")

def test_block_size_validation():
    key = secrets.token_bytes(32)
    cipher = FeistelCipher(key)
    with pytest.raises(ValueError):
        cipher.encrypt_block(b"shortblock")
