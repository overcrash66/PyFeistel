import nistrng
import numpy as np

data = [255, 0] # 2 bytes
unpacked = nistrng.unpack_sequence(data)
print(f"Input: {data} (2 bytes)")
print(f"Unpacked len: {len(unpacked)}")
print(f"Unpacked content: {unpacked}")
