import secrets
import sys
import os

# Add src to path to allow importing pyfeistel without installation if needed, 
# though src layout usually requires install. 
# We assume pyfeistel is installed or available.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

try:
    from pyfeistel.cipher import FeistelCipher
except ImportError:
    print("Error: Could not import pyfeistel. Please install the package or run from project root.")
    sys.exit(1)

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("Error: This example requires matplotlib and numpy.")
    print("Please install them: pip install matplotlib numpy")
    sys.exit(1)

class InstrumentedFeistelCipher(FeistelCipher):
    def encrypt_block_trace(self, block: bytes) -> list[bytes]:
        """
        Encrypts a block and returns the state after each round.
        Returns a list of 17 states (Initial + 16 rounds).
        """
        if len(block) != 16:
            raise ValueError("Block size must be 128 bits")
            
        left = int.from_bytes(block[:8], 'big')
        right = int.from_bytes(block[8:], 'big')
        
        trace = []
        # Store initial state (L || R)
        trace.append(left.to_bytes(8, 'big') + right.to_bytes(8, 'big'))
        
        for i in range(self.rounds):
            prev_left = left
            left = right
            right = prev_left ^ self._f_function(right, self.subkeys[i])
            
            # Store state (L || R) - Note: In Feistel, the "next" input is L=old_R, R=new_calc
            # We store it as it appears in the network lines
            trace.append(left.to_bytes(8, 'big') + right.to_bytes(8, 'big'))
            
        # Note: The standard implementation does a "Final Swap" at the very end.
        # The trace captures the internal state *before* that final swap usually, 
        # or we should effectively show the "Final Output" as the last step.
        # The loop ends with (Left=R_15, Right=L_15 ^ F(...)).
        # The true ciphertext is (Right || Left).
        # Let's just track the raw L/R values across the network wires.
        return trace

def main():
    print("Generating Avalanche Effect Visualization...")
    
    # 1. Setup
    key = secrets.token_bytes(32)
    cipher = InstrumentedFeistelCipher(key)
    
    # 2. Pick a random block P1
    p1 = secrets.token_bytes(16)
    
    # 3. Create P2 by flipping exactly 1 bit
    # Pick random byte and bit
    byte_idx = secrets.randbelow(16)
    bit_idx = secrets.randbelow(8)
    
    p2_arr = bytearray(p1)
    p2_arr[byte_idx] ^= (1 << bit_idx)
    p2 = bytes(p2_arr)
    
    print(f"Flipping bit {bit_idx} of byte {byte_idx}...")
    
    # 4. Trace both
    trace1 = cipher.encrypt_block_trace(p1)
    trace2 = cipher.encrypt_block_trace(p2)
    
    # 5. Compute Diff Grid
    # Rows = Rounds (0 to 16)
    # Cols = Bits (0 to 127)
    # Value = 1 if different, 0 if same
    
    grid = []
    
    for r in range(len(trace1)):
        state1 = trace1[r]
        state2 = trace2[r]
        
        # Convert to bit array
        # We'll visualize MSB (bit 0) to LSB (bit 127)
        row_bits = []
        for i in range(16): # 16 bytes
            b1 = state1[i]
            b2 = state2[i]
            diff = b1 ^ b2
            for bit in range(7, -1, -1): # Big Endian bits
                is_diff = (diff >> bit) & 1
                row_bits.append(is_diff)
        grid.append(row_bits)
        
    grid_np = np.array(grid)
    
    # 6. Plotting
    plt.figure(figsize=(12, 8))
    plt.imshow(grid_np, cmap='binary', interpolation='nearest', aspect='auto')
    
    plt.title(f"Avalanche Effect Visualization\nBit Diffusion over 16 Rounds (Diff Map)")
    plt.xlabel("Bit Position (0-127)")
    plt.ylabel("Round Number (0=Input)")
    plt.yticks(range(17))
    
    # Stats
    final_diff_count = np.sum(grid_np[-1])
    plt.figtext(0.5, 0.01, f"Final Round Bit Differences: {final_diff_count}/128 (Target ~64)", ha="center", fontsize=12)
    
    output_file = "avalanche_heatmap.png"
    plt.savefig(output_file)
    print(f"Visualization saved to {output_file}")
    
    # Also show ASCII art for terminal users
    print("\nText-based overview (Hamming Distance per round):")
    for r, row in enumerate(grid):
        hd = sum(row)
        bar = "#" * (hd // 2)
        print(f"Round {r:2d}: {hd:3d} bits diff | {bar}")

if __name__ == "__main__":
    main()
