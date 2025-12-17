# Engineering a Modern Cryptographic Library in Python: A Comprehensive Design and Implementation Study of the PyFeistel Algorithm

## Executive Summary

The democratization of cryptography has led to a proliferation of libraries and tools, yet the chasm between theoretical understanding and practical implementation remains significant. This report articulates the comprehensive design, development, and architectural structuring of a new symmetric block cipher library, tentatively named **PyFeistel**, implemented in Python 3. The project serves a dual purpose: to provide a transparent, educational vehicle for understanding modern cipher mechanics and to demonstrate rigorous software engineering practices applicable to cryptographic development.

The analysis begins by deconstructing the fundamental architectures of block ciphers, contrasting the inherent reversibility of Feistel networks with the strict bijective requirements of Substitution-Permutation Networks (SPN). It proceeds to a granular specification of the PyFeistel algorithm, detailing the mathematical construction of Substitution Boxes (S-boxes) using finite field arithmetic and the design of a non-linear key schedule. A significant portion of the report addresses the specific challenges of implementing cryptography in Python 3, analyzing the memory models of `bytes` versus `bytearray`, the implications of arbitrary-precision integers on bitwise operations, and the critical necessity of using the `secrets` module for cryptographically secure pseudo-random number generation (CSPRNG).

Furthermore, the document explores the implementation of essential modes of operation—specifically Cipher Block Chaining (CBC) and Counter (CTR) mode—and the mechanics of PKCS#7 padding, emphasizing the mitigation of padding oracle attacks. The report concludes with a blueprint for a production-grade library architecture, advocating for the `src` layout and `pyproject.toml` configuration to ensure robust packaging, testing, and distribution. Through this exhaustive study, we establish a reference standard for engineering cryptographic software that balances pedagogical clarity with the rigor of modern security practices.

---

## Part I: Theoretical Foundations and Architectural Paradigms

The design of a secure block cipher is a balancing act between security, performance, and implementation complexity. At the highest level of abstraction, block cipher design is dominated by two primary architectures: the Feistel Network and the Substitution-Permutation Network (SPN). Understanding the nuances of these structures is prerequisite to defining the PyFeistel algorithm.

### 1.1 The Feistel Network: Structural Reversibility

The Feistel network, named after IBM cryptographer Horst Feistel, revolutionized modern cryptography by introducing a structure that guarantees invertibility regardless of the round function's internal properties. This architecture was the foundation of the Data Encryption Standard (DES) and remains a prevalent choice for ciphers where component flexibility is paramount.

In a Feistel cipher, the input block of length $2w$ bits is split into two equal halves, $L_0$ and $R_0$, each of $w$ bits. The encryption process proceeds through $r$ rounds. In each round $i$ (where $0 \le i < r$), the new halves $(L_{i+1}, R_{i+1})$ are computed from the previous halves $(L_i, R_i)$ and a round subkey $K_i$ derived from the master key. The defining equations are:

$$L_{i+1} = R_i$$
$$R_{i+1} = L_i \oplus F(R_i, K_i)$$

Here, $\oplus$ denotes the bitwise XOR operation, and $F$ is the round function. The critical insight of the Feistel structure is that the round function $F$ maps $w$ bits to $w$ bits but does not need to be invertible (bijective). Even if $F$ is a many-to-one function that destroys information, the original $L_i$ can be perfectly recovered during decryption because it was preserved in the XOR operation:

$$L_i = R_{i+1} \oplus F(L_{i+1}, K_i)$$
$$R_i = L_{i+1}$$

This property allows the designer of a Feistel cipher to focus almost exclusively on the "confusion" and "diffusion" properties of $F$ without the constraint of mathematical reversibility. This is particularly advantageous for educational implementations, as it permits the use of complex, non-linear transformations (like cryptographic hashing) within the round function without breaking the decryption logic.

Historically, Feistel networks like LUCIFER and DES demonstrated that iterating a relatively simple function sufficient times could produce a ciphertext that appeared statistically random. The "avalanche effect"—where a small change in input propagates to a massive change in output—is achieved by iterating this mixing process over 16 or more rounds.

### 1.2 The Substitution-Permutation Network (SPN)

In contrast to the Feistel network, the Substitution-Permutation Network (SPN) applies transformations to the entire block simultaneously. An SPN consists of alternating layers of S-boxes (Substitution) and P-boxes (Permutation). The Advanced Encryption Standard (AES) is the most prominent example of an SPN.

In an SPN, every component must be strictly invertible. The S-boxes must be bijective mappings (permutations), and the P-boxes must be reversible linear transformations. This requirement imposes significant constraints on the design. If an SPN designer creates a highly non-linear S-box that accidentally maps two different inputs to the same output, the cipher is broken because decryption becomes ambiguous.

While SPNs often achieve faster diffusion (spreading of bits) per round compared to Feistel networks—often requiring fewer rounds (e.g., 10 for AES-128 vs. 16 for DES)—they generally lack the "inherent parallelism" on processors with limited execution units, although they parallelize well on modern CPUs with vector instructions.

### 1.3 Comparative Analysis and Selection Justification

For the PyFeistel project, we select the Feistel network architecture. The primary justification is the decoupling of the round function's complexity from the cipher's invertibility. This allows for a modular design where students and developers can experiment with different S-boxes and mixing functions (e.g., swapping a bit-rotation for a more complex linear feedback shift register) without rendering the cipher undecryptable. Additionally, the Feistel structure naturally supports the concept of "unbalanced" networks or varying block sizes with less mathematical friction than SPNs.

| Feature | Feistel Network | Substitution-Permutation Network (SPN) |
| :--- | :--- | :--- |
| **Invertibility** | Structural (Guaranteed by XOR swap) | Component-based (Requires bijective S-boxes) |
| **Round Function $F$** | Can be non-invertible (One-way) | Must be invertible (Bijective) |
| **Diffusion Rate** | Slower (affects half block per round) | Faster (affects full block per round) |
| **Implementation Complexity** | Lower (Encryption and Decryption are symmetric) | Higher (Requires separate inverse functions) |
| **Space Complexity** | Low (Code reuse for Enc/Dec) | Moderate (Separate tables for Enc/Dec) |
| **Prominent Examples** | DES, CAST-128, Twofish, Camellia | AES, Serpent, PRESENT |

---

## Part II: Mathematical Construction of PyFeistel

Having selected the Feistel architecture, we must now define the mathematical components that populate the structure: the Substitution Boxes (S-boxes) and the Permutation layers. These components are responsible for satisfying Shannon's properties of confusion and diffusion.

### 2.1 Finite Fields and S-Box Generation

The S-box is the primary source of non-linearity in a block cipher. A linear cipher is trivially breakable using Gaussian elimination or linear cryptanalysis. To resist these attacks, the S-box must approximate a highly non-linear boolean function.

The most robust S-boxes are typically constructed using arithmetic over Finite Fields, specifically Galois Fields of order $2^n$, denoted as $GF(2^n)$. For an 8-bit S-box, we operate in $GF(2^8)$. The construction involves two steps:

1.  **Inversion**: Take an input byte $x$. If $x = 0$, map it to $0$. Otherwise, map it to its multiplicative inverse $x^{-1}$ in $GF(2^8)$. This inversion operation provides optimal resistance against linear cryptanalysis because the algebraic degree of the inverse function is high.
2.  **Affine Transformation**: Apply an affine transformation (matrix multiplication followed by vector addition) over $GF(2)$ to the bits of the result. This step complicates the algebraic expression of the S-box, preventing interpolation attacks.

Mathematical representation of the S-box function $S(x)$:

$$S(x) = A \cdot (x^{-1} \mod P(x)) \oplus c$$

Where:
*   $P(x)$ is an irreducible polynomial of degree 8 (e.g., the Rijndael polynomial $x^8 + x^4 + x^3 + x + 1$).
*   $A$ is an $8 \times 8$ constant invertible binary matrix.
*   $c$ is a constant 8-bit vector.
*   $\oplus$ denotes bitwise XOR addition.

While random S-boxes can be generated via stochastic search, they often fail to meet strict criteria like the Strict Avalanche Criterion (SAC) (where flipping one input bit changes output bits with probability 0.5) and the Bit Independence Criterion (BIC). For PyFeistel, we will pre-compute a fixed S-box using the inversion method to ensure cryptographic robustness, rather than relying on a randomly generated table during runtime. This pre-computation also improves performance.

### 2.2 Boolean Functions and Non-Linearity

In the context of block ciphers, an S-box mapping $n$ bits to $m$ bits can be viewed as a collection of $m$ Boolean functions, each mapping $n$ bits to 1 bit. The "non-linearity" of the S-box is defined as the minimum Hamming distance between any linear combination of these Boolean functions and the set of all affine functions. High non-linearity is critical to prevent linear approximation attacks where an attacker tries to model the S-box as a simple system of linear equations.

PyFeistel's round function will utilize an 8x8 S-box (mapping 8 bits to 8 bits). This size is optimal for software implementation on modern processors, as it aligns with the byte size ($2^8 = 256$ entries), allowing the S-box to be implemented as a simple lookup table (array) of 256 bytes.

### 2.3 Key Schedule Design

The key schedule is the algorithm that expands the master key into distinct subkeys for each round. A weak key schedule, such as one that merely repeats the key or applies simple linear shifts, can leave the cipher vulnerable to related-key attacks and slide attacks.

For PyFeistel, we define a non-linear key schedule inspired by the properties of "Type 1B" or "Type 2" schedules, where knowledge of a round key does not trivially reveal the master key.

**PyFeistel Key Schedule Algorithm:**

Given a 256-bit (32-byte) master key $K$:

1.  **Initialization**: Divide $K$ into four 64-bit words $W_0, W_1, W_2, W_3$.
2.  **Expansion**: We need 16 round keys ($K_0 \dots K_{15}$), each 64 bits wide.
3.  **Generation Loop**: For round $i$ from 0 to 15:
    *   Rotate $W_{i \mod 4}$ left by a variable amount (e.g., $13$ bits).
    *   Apply the S-box to the least significant byte of the rotated word to introduce non-linearity.
    *   XOR the result with a round constant $RC_i$ (derived from mathematical constants like $\pi$ or the golden ratio) to eliminate symmetries between rounds.
    *   The result is $K_i$.
    *   Update the state of the words $W$ using a Feistel-like mixing step to ensure that later round keys depend on all bits of the master key.

This design ensures that a single bit flip in the master key propagates to all subkeys (Avalanche in Key Schedule) and that subkeys appear statistically independent.

---

## Part III: Python 3 Implementation Strategy

Implementing a cryptographic primitive in a high-level language like Python 3 presents unique challenges, particularly regarding memory management, immutability, and side-channel leakage.

### 3.1 The Memory Model: bytes vs. bytearray

Python 3 enforces a strict separation between text (str, Unicode) and binary data (bytes). In Python 2, these were often conflated, leading to encoding errors. In Python 3, `bytes` objects are immutable sequences of integers in the range 0–255.

**Immutability Challenge:**
Cryptographic algorithms, especially Feistel networks, involve intensive state modification (XORing halves, swapping, updating registers). Using `bytes` for the internal state would be disastrous for performance. Every XOR operation `L = L ^ R` would force the Python interpreter to allocate a new `bytes` object, copy the data, and garbage collect the old one. In a 16-round cipher processing megabytes of data, this creates massive memory churn.

**The bytearray Solution:**
The solution is to use `bytearray`, the mutable counterpart to `bytes`. `bytearray` allows for in-place modification of elements. For PyFeistel, the internal state of the block will be maintained as a `bytearray`.

```python
# Inefficient (bytes)
L = bytes() 

# Efficient (bytearray)
for i in range(len(L)):
    L[i] ^= R[i]  # In-place modification
```

This approach significantly reduces memory allocation overhead. Furthermore, Python's `bytearray` provides an interface similar to a list of integers, allowing direct index access `data[i]` which returns an integer, facilitating bitwise math without explicit `ord()` conversions.

### 3.2 Integer Precision and Bitwise Arithmetic

Python handles integers with arbitrary precision. A standard CPU register overflows at $2^{32}$ or $2^{64}$, wrapping around to 0. Python integers simply grow, consuming more memory.

**Bitwise Implications:**
Operations like left shift (`<<`) or rotation must be carefully managed. If one shifts a 64-bit integer left by 1 bit in C, the most significant bit is lost (or moved to a carry flag). In Python, the value simply doubles. To simulate fixed-width cryptography (e.g., 64-bit words), every arithmetic operation must be followed by a bitmask.

```python
# Simulating 64-bit rotation in Python
def rotate_left_64(x, n):
    return ((x << n) | (x >> (64 - n))) & 0xFFFFFFFFFFFFFFFF
```

The `& 0xFF...` mask is mandatory to discard bits that strictly exceed the word size, mimicking the behavior of hardware registers and ensuring the algorithm remains deterministic across different platforms.

### 3.3 Cryptographically Secure Randomness: secrets vs. random

The generation of keys and Initialization Vectors (IVs) requires a source of high-entropy randomness. The Python standard library provides two modules: `random` and `secrets`.

**The random Module Risk:**
The `random` module implements the Mersenne Twister (MT19937) algorithm. While it has a long period ($2^{19937}-1$) and excellent statistical distribution, it is a deterministic generator. If an attacker can observe 624 consecutive 32-bit outputs, they can reconstruct the internal state of the generator and predict all future (and past) values. Using `random` for key generation is a critical vulnerability.

**The secrets Module Mandate:**
The `secrets` module, introduced in Python 3.6, is designed specifically for cryptography. It acts as a wrapper around the operating system’s CSPRNG (e.g., `/dev/urandom` on Linux, `CryptGenRandom` on Windows). These sources derive entropy from hardware interrupts, thermal noise, and other unpredictable physical phenomena.

PyFeistel must strictly enforce the use of `secrets` for all security-critical operations:
*   `secrets.token_bytes(32)` for generating 256-bit keys.
*   `secrets.token_bytes(16)` for generating 128-bit IVs.
*   `secrets.randbelow(n)` for any randomized padding or nonce generation.

---

## Part IV: The PyFeistel Algorithm Specification

We now formalize the specification of the PyFeistel block cipher.

**System Parameters:**
*   **Block Size**: 128 bits (16 bytes).
*   **Key Size**: 256 bits (32 bytes).
*   **Rounds**: 16.
*   **S-Box**: 8x8 fixed table (derived from modular inversion in $GF(2^8)$).

### 4.1 The Round Function $F(R, K)$

The round function takes a 64-bit input $R$ (half block) and a 64-bit subkey $K$.

1.  **Key Mixing**: The input $R$ is bitwise XORed with the subkey $K$.
    $$T_1 = R \oplus K$$
2.  **S-Box Substitution**: The 64-bit result $T_1$ is treated as 8 bytes. Each byte is replaced by looking up its value in the S-box.
    $$T_2[j] = S\_BOX[T_1[j]] \quad \text{for } j \in 0..7$$
3.  **Diffusion (Permutation)**: To spread the influence of the bits, we apply a linear transformation. For educational clarity and efficiency, we use a combination of bitwise rotation and byte shuffling.
    *   Rotate the 64-bit integer representation of $T_2$ left by 11 bits.
    *   Swap the upper and lower 32-bit words.
    $$T_3 = \text{SwapHalves}(\text{RotateLeft}(T_2, 11))$$
4.  **Output**: $F(R, K) = T_3$.

This function satisfies confusion (via the S-box) and diffusion (via the rotation and swap).

### 4.2 Encryption and Decryption Workflow

**Encryption:**
*   **Input**: 128-bit Plaintext $P$, 256-bit Key $K$.
*   **Key Schedule**: Derive 16 subkeys $K_0 \dots K_{15}$ from $K$.
*   **Initial Split**: Split $P$ into $L_0$ (first 64 bits) and $R_0$ (last 64 bits).
*   **Rounds**: For $i = 0$ to $15$:
    $$L_{i+1} = R_i$$
    $$R_{i+1} = L_i \oplus F(R_i, K_i)$$
*   **Final Swap**: The output is the concatenation $R_{16} || L_{16}$. (Note the swap: $R$ comes first. This creates the symmetry required for decryption).

**Decryption:**
Decryption uses the exact same algorithm but with the subkeys applied in reverse order ($K_{15} \dots K_0$). The initial input is the ciphertext $(R_{16}, L_{16})$ which is interpreted as $(L_{dec, 0}, R_{dec, 0})$.

For $i = 0$ to $15$:
$$L_{dec, i+1} = R_{dec, i}$$
$$R_{dec, i+1} = L_{dec, i} \oplus F(R_{dec, i}, K_{15-i})$$

The result is $R_{dec, 16} || L_{dec, 16}$, which matches the original plaintext $L_0 || R_0$.

---

## Part V: Modes of Operation and Padding

A block cipher encrypts a single block. To handle messages of arbitrary length, we must employ a Mode of Operation.

### 5.1 The Danger of ECB and the Necessity of CBC

Electronic Codebook (ECB) is the simplest mode: divide the message into blocks and encrypt each independently. This is insecure because identical plaintext blocks produce identical ciphertext blocks, preserving data patterns (e.g., the famous "Tux" penguin image remains visible after ECB encryption).

Cipher Block Chaining (CBC) resolves this by XORing the current plaintext block with the previous ciphertext block before encryption.

*   **Encryption**: $C_i = E_K(P_i \oplus C_{i-1})$.
*   **Decryption**: $P_i = D_K(C_i) \oplus C_{i-1}$.
*   **Initialization Vector (IV)**: The first block requires a random block $C_{-1}$ called the IV. The IV does not need to be secret, but it must be unique and unpredictable for each encryption to prevent dictionary attacks on the first block.

PyFeistel will implement CBC as the default mode. The implementation must handle the "chaining" state meticulously.

### 5.2 Counter (CTR) Mode and Stream Ciphers

PyFeistel will also implement Counter (CTR) mode. In CTR mode, the block cipher turns into a stream cipher. Instead of encrypting the message directly, we encrypt a "counter" value (concatenated with a nonce). The resulting output is XORed with the plaintext to produce ciphertext.

*   **Keystream**: $K_i = E_K(\text{Nonce} || \text{Counter}_i)$
*   **Ciphertext**: $C_i = P_i \oplus K_i$

CTR mode has two major advantages:
1.  **Parallelism**: Unlike CBC, where block $i$ depends on block $i-1$, CTR blocks can be encrypted in parallel.
2.  **No Padding**: Because the keystream can be truncated to the exact length of the message, CTR mode does not require the message to be a multiple of the block size.

### 5.3 PKCS#7 Padding Implementation

For CBC mode, the input must be an exact multiple of the block size (16 bytes). PKCS#7 is the standard padding scheme.

**Mechanism:**
If the data is $L$ bytes long and block size is $B$, we need $P = B - (L \mod B)$ padding bytes. We append $P$ bytes, each having the value $P$.
Example: Message "TEST" (4 bytes), Block 8 bytes. Need 4 bytes. Pad: `"TEST\x04\x04\x04\x04"`.

If the message is already a multiple of $B$, we add a full block of padding ($B$ bytes of value $B$). This ensures the decoder can always unambiguously strip the padding.

**Security Warning (Padding Oracle):**
Naive implementations of unpadding can be vulnerable to Padding Oracle attacks. If the unpadding function returns a different error (or takes a different amount of time) when the padding is invalid versus when the MAC is invalid, an attacker can decrypt the message by sending modified ciphertexts and observing the server's response. While PyFeistel is an educational library, the unpad function should be implemented to verify the padding in constant time (checking all bytes regardless of the first failure) to demonstrate secure coding practices.

---

## Part VI: Library Engineering and Architecture

Writing the algorithm is only half the task; packaging it into a usable, maintainable library is the other. Modern Python development has moved away from ad-hoc scripts and `setup.py` towards declarative configuration and structured layouts.

### 6.1 The src Layout vs. Flat Layout

We adopt the `src` layout for the PyFeistel project. In a flat layout, the package source code resides in the root directory (e.g., `project/pyfeistel/`). In the `src` layout, it resides in `project/src/pyfeistel/`.

**Justification:**
The flat layout suffers from the "import parity" problem. When running tests (e.g., pytest) from the project root, Python adds the current directory to `sys.path`. Tests may inadvertently import the local source files rather than the installed package. This masks installation issues (e.g., missing data files, incorrect metadata). The `src` layout forces the test runner to install the package (in editable mode or built wheel) to run tests, ensuring that the tested artifact matches the distributed artifact.

### 6.2 Configuration with pyproject.toml

The `pyproject.toml` file is the central configuration standard defined by PEP 518/621. It replaces `setup.py`, `setup.cfg`, `requirements.txt`, and tool-specific configs (like `.pylintrc`) with a single TOML file.

**PyFeistel pyproject.toml Structure:**

```toml
[build-system]
requires = ["hatchling"]  # Using a modern build backend
build-backend = "hatchling.build"

[project]
name = "pyfeistel"
version = "0.1.0"
description = "A pure-Python Feistel Network Block Cipher Implementation"
readme = "README.md"
requires-python = ">=3.10"
license = {file = "LICENSE"}
authors = [{name = "CryptoEngineer", email = "dev@example.com"}]
dependencies = [] # No external dependencies for core logic

[project.optional-dependencies]
test = ["pytest", "hypothesis", "coverage"]
dev = ["black", "ruff", "mypy"]

[tool.hatch.build.targets.wheel]
packages = ["src/pyfeistel"]

[tool.pytest.ini_options]
addopts = "--cov=pyfeistel --cov-report=term-missing"
testpaths = ["tests"]
pythonpath = ["src"]
```

This configuration declares the build system (Hatchling is chosen for its simplicity and standard compliance), metadata, dependencies, and tool configurations (pytest, coverage) in one place.

### 6.3 API Design and Patterns

The library API follows the Strategy Pattern for modes of operation, decoupled from the primitive.

**Class Hierarchy:**
*   `BlockCipher` (Protocol/ABC): Defines the contract `encrypt_block(data, key)` and `decrypt_block(data, key)`.
*   `PyFeistel` (Concrete Implementation): Implements the Feistel logic.
*   `CipherMode` (ABC): Defines `encrypt(plaintext, key, iv)` and `decrypt`.
*   `CBCMode`, `CTRMode`: Concrete Strategies implementing the chaining/counter logic using a `BlockCipher` instance.

This design enables "Agility." A user can swap PyFeistel for AES (if wrapped) without changing the surrounding application code that relies on `CBCMode`.

**Example Usage:**
```python
cipher = PyFeistel()
mode = CBCMode(cipher, padding=PKCS7(16))
ciphertext = mode.encrypt(plaintext, key, iv)
```

---

## Part VII: Security Analysis and Metrics

A custom cipher must be evaluated against standard cryptographic metrics. While a full cryptanalysis requires years of peer review, we can perform statistical tests to verify the design properties.

### 7.1 The Avalanche Effect

The Avalanche Effect is the primary metric for diffusion. It dictates that flipping a single bit in the plaintext should result in flipping approximately 50% of the bits in the ciphertext. If the change is significantly lower (e.g., 10%), the cipher has poor diffusion and is vulnerable to statistical attacks.

**Strict Avalanche Criterion (SAC):** If a single input bit $i$ is flipped, every output bit $j$ should change with probability 0.5.

**Testing Methodology:**
We implement a test script `tests/test_avalanche.py`:
1.  Generate a random block $P$ and Key $K$.
2.  Encrypt $C_1 = E(P, K)$.
3.  Flip bit $i$ in $P$ to get $P'$.
4.  Encrypt $C_2 = E(P', K)$.
5.  Calculate Hamming Distance $H = \text{popcount}(C_1 \oplus C_2)$.
6.  Repeat for all 128 input bits and thousands of random blocks.

The average $H$ should be close to 64 (for a 128-bit block). If PyFeistel achieves an average Hamming distance of $64 \pm 2$, it satisfies the avalanche condition.

### 7.2 Side-Channel Considerations in Python

It is critical to document the limitations of this implementation. Python is an interpreted language with automatic memory management and arbitrary precision arithmetic. It is not constant-time.

*   **Timing Attacks**: Operations on larger integers take longer than on smaller ones. Conditional branches in the S-box lookup or padding check can leak information via execution time.
*   **Memory Analysis**: `bytearray` operations may leave copies of the key or plaintext in memory (garbage collection is lazy).

Therefore, PyFeistel is explicitly designated for educational and research purposes, not for protecting classified or high-value financial data. For production, C/Rust extensions (like cryptography library) are mandatory.

---

## Part VIII: Detailed Implementation Code (Key Components)

### 8.1 The S-Box Generation (Pre-computation)

```python
# tools/generate_sbox.py
def generate_sbox():
    """
    Generates an 8x8 S-box using GF(2^8) inversion and affine transform.
    This follows the Rijndael S-box construction logic.
    """
    sbox = [0] * 256
    p = 0x11B  # Irreducible polynomial x^8 + x^4 + x^3 + x + 1
    
    # 1. Compute multiplicative inverse in GF(2^8)
    # (Implementation of Extended Euclidean Algo or Table Log/Exp omitted for brevity)
    #...
    
    # 2. Apply Affine Transformation
    for i in range(256):
        s = inverse[i]
        # Matrix multiplication over GF(2)
        # x_i' = x_i + x_{i+4} + x_{i+5} + x_{i+6} + x_{i+7} + c_i
        res = s ^ ((s << 1) & 0xFF) ^ ((s << 2) & 0xFF) ^ ((s << 3) & 0xFF) ^ ((s << 4) & 0xFF)
        # Handle wrapping bits for the affine step
        res = (res >> 8) ^ (res & 0xFF) ^ 0x63 # 0x63 is the affine constant
        sbox[i] = res
        
    return sbox
```

### 8.2 The Feistel Core

```python
# src/pyfeistel/cipher.py
import secrets
from .sbox import SBOX  # Imported from the generated file

class FeistelCipher:
    def __init__(self, key: bytes, rounds: int = 16):
        if len(key) != 32:
            raise ValueError("Key must be 256 bits (32 bytes)")
        self.rounds = rounds
        self.subkeys = self._expand_key(key)

    def _expand_key(self, key: bytes) -> list[int]:
        # Implementation of the Non-linear Key Schedule
        # Returns list of 16 64-bit integers
        pass

    def _f_function(self, right: int, subkey: int) -> int:
        # 1. Key Mixing
        mixed = right ^ subkey
        
        # 2. S-Box Substitution (byte by byte)
        output = 0
        for i in range(8):
            byte_val = (mixed >> (8 * i)) & 0xFF
            subbed_val = SBOX[byte_val]
            output |= (subbed_val << (8 * i))
            
        # 3. Permutation (Rotation + Swap)
        # Rotate left 11 bits
        rotated = ((output << 11) | (output >> (64 - 11))) & 0xFFFFFFFFFFFFFFFF
        return rotated

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Block size must be 128 bits")
            
        # Convert bytes to two 64-bit integers
        left = int.from_bytes(block[:8], 'big')
        right = int.from_bytes(block[8:], 'big')
        
        for i in range(self.rounds):
            prev_left = left
            left = right
            right = prev_left ^ self._f_function(right, self.subkeys[i])
            
        # Final Swap (R, L)
        return right.to_bytes(8, 'big') + left.to_bytes(8, 'big')
        
    def decrypt_block(self, block: bytes) -> bytes:
        # Identical to encrypt but reverse subkeys
        left = int.from_bytes(block[:8], 'big')
        right = int.from_bytes(block[8:], 'big')
        
        for i in range(self.rounds):
            prev_left = left
            left = right
            # Use subkeys in reverse: rounds - 1 - i
            right = prev_left ^ self._f_function(right, self.subkeys[self.rounds - 1 - i])
            
        return right.to_bytes(8, 'big') + left.to_bytes(8, 'big')
```

---

## Part IX: Conclusion

The development of PyFeistel serves as a case study in the rigorous application of cryptographic theory and software engineering. By choosing the Feistel network architecture, we prioritized structural reversibility, allowing for the integration of strong, non-linear S-boxes without the burden of ensuring component-level bijectivity. The implementation in Python 3 highlights the critical importance of understanding language internals—specifically the distinction between bytes and `bytearray` for memory efficiency, and the non-negotiable requirement of `secrets` for CSPRNG.

Furthermore, by structuring the library with a modern `src` layout and adhering to the Strategy design pattern for modes of operation, we demonstrated how to build cryptographic tools that are not only mathematically sound but also maintainable, testable, and ready for distribution. While the inherent limitations of Python regarding side-channel attacks restrict this library to educational and prototyping domains, the principles established here—strict padding management, secure random number generation, and comprehensive testing for avalanche effects—are universally applicable to secure software development.