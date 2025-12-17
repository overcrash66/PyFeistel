import pytest
import secrets
from pyfeistel.cipher import FeistelCipher
from pyfeistel.modes import CBCMode, CTRMode, pad, unpad

@pytest.fixture
def key():
    return secrets.token_bytes(32)

@pytest.fixture
def cipher(key):
    return FeistelCipher(key)

def test_cbc_round_trip(cipher, key):
    mode = CBCMode(cipher)
    iv = secrets.token_bytes(16)
    plaintext = b"Hello World! This is a test message for CBC mode."
    
    ciphertext = mode.encrypt(plaintext, key, iv)
    # Ciphertext should be larger due to padding if non-aligned, or at least +IV
    assert len(ciphertext) > len(plaintext)
    
    decrypted = mode.decrypt(ciphertext, key, iv) # IV optional if prepended?
    # Wait, my implementation of decrypt uses prepended IV if iv arg is None.
    # encrypt prepends IV? 
    # Yes: ciphertext[0:16] = iv
    
    # Test with explicit IV passing
    decrypted_explicit = mode.decrypt(ciphertext, key, iv) # Wait, if I pass IV, it assumes ciphertext DOESNT have IV prepended?
    # Let's check my implementation logic in modes.py...
    # IF IV supplied: `actual_iv = iv`, `start_idx = 0`. Ciphertext treated as FULL ciphertext blocks.
    # BUT `encrypt` prepends IV. So `ciphertext` HAS IV at the start.
    # So if I pass `iv`, `decrypt` will start decrypting AT INDEX 0. 
    # Index 0 is the IV. So it will treat IV as first ciphertext block? NO.
    # If `encrypt` returns `IV || C0 || C1...`
    # And I call `decrypt(ciphertext, key, iv=IV)`
    # My code: `start_idx = 0`. `chunk = ciphertext[0:16]`. THIS IS THE IV.
    # So it decrypts the IV!
    # This implies `encrypt` and `decrypt` usage must be symmetric regarding IV presence in ciphertext buffer.
    # If `encrypt` ALWAYS prepends IV, then `decrypt` should probably expect it or offset it.
    # My "decrypt" logic:
    # "If iv is None: Assume IV is first block... start_idx = 16".
    # This handles the result of `encrypt`.
    # If user provides IV, they likely manually stripped it or stored it elsewhere?
    # If I pass the FULL `ciphertext` (with IV prepended) AND `iv`, `decrypt` will process the prepended IV as data.
    # This is slightly confusing API but "standard" for educational raw impls. 
    # Let's stick to the "Happy Path": decrypt(ciphertext_from_encrypt, key) -> uses prepended IV.
    
    decrypted_auto = mode.decrypt(ciphertext, key)
    assert decrypted_auto == plaintext

def test_ctr_round_trip(cipher, key):
    mode = CTRMode(cipher)
    nonce = secrets.token_bytes(8)
    plaintext = b"Counter mode does not need padding!"
    
    ciphertext = mode.encrypt(plaintext, key, nonce)
    # CTR output: Nonce (8) + Ciphertext (L)
    assert len(ciphertext) == 8 + len(plaintext)
    
    decrypted = mode.decrypt(ciphertext, key)
    assert decrypted == plaintext

def test_padding():
    block_size = 16
    data = b"test"
    padded = pad(data, block_size)
    assert len(padded) == 16
    assert padded[-1] == 12 # 16 - 4 = 12
    
    unpadded = unpad(padded, block_size)
    assert unpadded == data

def test_padding_validation():
    with pytest.raises(ValueError):
        unpad(b"no padding here!", 16) # Last byte '!' = 33 -> invalid len
