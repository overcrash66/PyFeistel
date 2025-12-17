import sys
import os
import secrets
import argparse # For CLI argument parsing
import json

# Add src to path if running from examples root without install
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from pyfeistel import FeistelCipher, CBCMode, pad, unpad

def save_key(key: bytes, filename: str):
    """Saves the key to a file (in a real app, use a Key Management System!)."""
    with open(filename, 'wb') as f:
        f.write(key)
    print(f"[+] Key saved to {filename}")

def load_key(filename: str) -> bytes:
    with open(filename, 'rb') as f:
        return f.read()

def encrypt_file(input_path: str, output_path: str, key_path: str):
    """
    Encrypts a file using PyFeistel CBC Mode.
    Generates a new random key and saves it.
    """
    print(f"[*] Encrypting {input_path}...")
    
    try:
        with open(input_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] Error: File {input_path} not found.")
        return

    # 1. Generate Key (256-bit)
    if os.path.exists(key_path):
        print(f"[*] Using existing key from {key_path}")
        key = load_key(key_path)
    else:
        print(f"[*] Generating new 256-bit key...")
        key = secrets.token_bytes(32)
        save_key(key, key_path)

    # 2. Setup Cipher
    cipher = FeistelCipher(key)
    mode = CBCMode(cipher)

    # 3. Generate IV (128-bit)
    iv = secrets.token_bytes(16)

    # 4. Pad Data (PKCS#7)
    padded_data = pad(data)

    # 5. Encrypt
    # CBCMode.encrypt prepends IV automatically in our implementation
    ciphertext = mode.encrypt(padded_data, key, iv)

    # 6. Save
    with open(output_path, 'wb') as f:
        f.write(ciphertext)
    
    print(f"[+] Encrypted file saved to {output_path}")
    print(f"[+] Original size: {len(data)} bytes")
    print(f"[+] Encrypted size: {len(ciphertext)} bytes (overhead: IV + padding)")

def decrypt_file(input_path: str, output_path: str, key_path: str):
    """
    Decrypts a file using PyFeistel CBC Mode.
    """
    print(f"[*] Decrypting {input_path}...")
    
    try:
        with open(key_path, 'rb') as f:
            key = f.read()
    except FileNotFoundError:
        print(f"[-] Error: Key file {key_path} not found. Cannot decrypt.")
        return

    try:
        with open(input_path, 'rb') as f:
            ciphertext = f.read()
    except FileNotFoundError:
        print(f"[-] Error: File {input_path} not found.")
        return

    # 1. Setup Cipher
    cipher = FeistelCipher(key)
    mode = CBCMode(cipher)

    # 2. Decrypt
    # CBCMode.decrypt handles IV extraction if it was prepended
    try:
        decrypted_padded = mode.decrypt(ciphertext, key)
        
        # 3. Unpad
        plaintext = unpad(decrypted_padded)
        
        # 4. Save
        with open(output_path, 'wb') as f:
            f.write(plaintext)
            
        print(f"[+] Decrypted file saved to {output_path}")
        
    except ValueError as e:
        print(f"[-] Decryption failed: {e}")
        print("    (Check if the key is correct or file is corrupted)")

def main():
    parser = argparse.ArgumentParser(description="PyFeistel Secure File Tool")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Encrypt Command
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt a file")
    enc_parser.add_argument("input_file", help="Path to input file")
    enc_parser.add_argument("output_file", help="Path to save encrypted file")
    enc_parser.add_argument("--key", default="secret.key", help="Path to save/load key (default: secret.key)")

    # Decrypt Command
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt a file")
    dec_parser.add_argument("input_file", help="Path to encrypted file")
    dec_parser.add_argument("output_file", help="Path to save decrypted file")
    dec_parser.add_argument("--key", default="secret.key", help="Path to load key (default: secret.key)")

    args = parser.parse_args()

    if args.command == "encrypt":
        encrypt_file(args.input_file, args.output_file, args.key)
    elif args.command == "decrypt":
        decrypt_file(args.input_file, args.output_file, args.key)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
