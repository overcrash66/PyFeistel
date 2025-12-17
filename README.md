# PyFeistel

A pure-Python Feistel Network Block Cipher Implementation.

> ** Documentation**: For a comprehensive analysis of the mathematical foundations, memory model, and architectural decisions, please consult the **[PyFeistel Design Document](PyFeistel.md)**.

> [!WARNING]
> **Educational Use Only**: This library is designed for educational purposes to demonstrate cryptographic principles. While it produces statistically random output, it has not undergone formal cryptanalysis and is likely vulnerable to advanced attacks (e.g., linear/differential cryptanalysis). **Do not use this for protecting sensitive production data.**

## Features
- **Custom Feistel Network**: 16-round architecture with non-linear Key Schedule.
- **Modes of Operation**: CBC (Cipher Block Chaining) and CTR (Counter) modes.
- **Educational Design**: Pure Python implementation using `bytearray` for clarity and `secrets` for security.
- **Visualization**: Tools to visualize cryptographic properties like the Avalanche Effect.

## Installation

```bash
pip install .
```

Or

```bash
pip install pyfeistel
```

## Usage

### Basic Encryption (CBC Mode)
```python
import secrets
from pyfeistel import FeistelCipher, CBCMode, pad, unpad

# 1. Setup Cipher
key = secrets.token_bytes(32)  # 256-bit key
cipher = FeistelCipher(key)
cbc = CBCMode(cipher)

# 2. Prepare Data
plaintext = b"Hello, PyFeistel! This is a secret message."
padded_data = pad(plaintext)
iv = secrets.token_bytes(16)   # 128-bit IV

# 3. Encrypt
ciphertext = cbc.encrypt(padded_data, key, iv)
print(f"Ciphertext (Hex): {ciphertext.hex()}")

# 4. Decrypt
# (Note: CBC decryption extracts IV automatically if prepended, 
# but here we pass the IV explicitly if handled separately, 
# or rely on the implementation's handling).
# Our implementation prepends IV to ciphertext in 'encrypt'.
decrypted_padded = cbc.decrypt(ciphertext, key)
decrypted = unpad(decrypted_padded)

print(f"Decrypted: {decrypted.decode()}")
assert decrypted == plaintext
```

## Testing & Verification

The library includes a robust test suite to verify both correctness and cryptographic properties.

### 1. Unit & Functional Tests
Verifies correct round-trip encryption/decryption for all modes (CBC, CTR) and padding logic.
- **Command**: `pytest tests/test_core.py tests/test_modes.py`
- **Result**: ✅ Passed (Correctness verified)

### 2. Avalanche Effect
Verifies that flipping 1 bit in the plaintext flips approximately 50% of bits in the ciphertext.
- **Command**: `pytest tests/test_avalanche.py`
- **Result**: ✅ Passed (Average Hamming Distance ~64 bits)

### 3. NIST Statistical Analysis
Integrated with the **NIST SP 800-22** test suite (via `nistrng`) to check for statistical randomness.
- **Command**: `python tests/test_nist_stats.py`
- **Scope**: Checked 160,000 bits of CTR-mode output.
- **Results**: Verified basic randomness properties.
    - **Monobit (Frequency)**: ✅ PASS (p=0.50) - Output has equal 0s/1s.
    - **Runs Test**: ✅ PASS - Bit transition frequency is random.
    - **Spectral/Complexity**: ⚠️ Mixed (Sample size limitation vs educational scope).

## Examples


### Real-World Example: Secure File Encryption Tool
A complete command-line tool for encrypting and decrypting files using PyFeistel in CBC mode.

**Location**: `examples/secure_file_tool.py`

**Usage**:
```bash
# Encrypt
python examples/secure_file_tool.py encrypt secret.txt secret.enc

# Decrypt
python examples/secure_file_tool.py decrypt secret.enc secret_restored.txt
```

### Avalanche Effect Visualization

PyFeistel includes a visualization tool to demonstrate the **Avalanche Effect**.

You can run the visualization script:
```bash
python examples/visualize_avalanche.py
```

This script generates a heatmap tracing the bit differences through all 16 rounds of the cipher.

![Avalanche Effect Heatmap](examples/avalanche_heatmap.png)

*Figure: Heatmap showing bit diffusion. Dark pixels represent bit differences between two encrypted blocks differing by only 1 bit in the plaintext. Note how the differences spread (diffuse) rapidly after the first few rounds.*

## License

This project is licensed under the **MIT License**.
