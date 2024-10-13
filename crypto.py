#!/usr/bin/env python
"""crypto.py"""
# This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola

import os
import argparse
from base64 import urlsafe_b64encode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

CRYPTO_KEY = 'crypto_key.key'           # File where key is stored

def load_key(key_file):
    """Load the encryption key from the key file"""
    with open(key_file, 'rb') as f:
        return f.read()


def encrypt_file(file_path, key_file):
    """Function to encrypt a file"""
    key = load_key(key_file)    # Load the encryption key
    try:
        fernet = Fernet(key)
    except ValueError:
        print(ValueError)

    with open(file_path, 'rb') as file: # Read the file contents
        original_data = file.read()
    encrypted_data = fernet.encrypt(original_data) # Encrypt the data

    # Write the encrypted data back to the file (or a new file)
    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    print(f"File '{file_path}' encrypted with key '{key_file}' and saved as "
          f"'\033[96m{os.path.abspath(encrypted_file_path)}\033[0m'.")


def decrypt_file(encrypted_file_path, key_file):
    """Function to decrypt an encrypted file"""
    key = load_key(key_file)    # Load the encryption key
    try:
        fernet = Fernet(key)
    except ValueError:
        print(ValueError)

    with open(encrypted_file_path, 'rb') as encrypted_file: # Read the encrypted file contents
        encrypted_data = encrypted_file.read()

    try:                                                # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        print(f"Failed to decrypt file: {e}, perhaps wrong decryption key"
              " or wrong file path.")
        return

    # Write the decrypted data back to the original file (removing the .encrypted suffix)
    original_file_path = encrypted_file_path.replace('.encrypted', '')
    with open(original_file_path, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_data)

    print(f"File '{encrypted_file_path}' decrypted and restored as "
          f"'\033[96m{os.path.abspath(original_file_path)}\033[0m'.")


def generate_key(crypto_key_file):
    """Function to generate and save a symmetric key that can be used for encryption/decryption"""
    salt = os.urandom(16)               # Generate a random string "salt" of char using os.uradom()

    kdf = PBKDF2HMAC(                   # Deriving a key using PBKDF2HMAC
        algorithm=hashes.SHA256(),      # Using SHA-256 hashing algorithm
        length=32,                      # Generate a 256-bit key (32 bytes)
        salt=salt,                      # Use the generated salt
        iterations=480000,              # Number of iterations for key stretching
    )
    # Password to derive the key from
    password = b'my_secret_password'    # Replace this with a dynamic password input if needed
    # Deriving the key
    key = kdf.derive(password)
    encoded_key = urlsafe_b64encode(key)
    # Save the key to a file
    with open(crypto_key_file, 'wb') as key_file:
        key_file.write(encoded_key)
    print(f"Key generated and saved to '\033[96m{os.path.abspath(crypto_key_file)}\033[0m'.")


def main_crypto_tool():
    """Main function to handle command-line arguments"""
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using"
                                       " a symmetric key or generate a cryptokey.")
    group = parser.add_mutually_exclusive_group(required=True)

    # Define arguments for encrypting and decrypting
    parser.add_argument(
        '-key',
        default=CRYPTO_KEY,
        #nargs="?",
        #action="store_true" if ,
        help="The path to the key file(default key: crypto_key.key)."
    )
    group.add_argument(
        '-encrypt',
        action="store_true",
        help="Encrypt a file."
    )
    group.add_argument(
        '-decrypt',
        action="store_true",
        help="Decrypt a file."
    )
    group.add_argument(
        '-keygen',
        action="store_true",
        help="Generate a new key."
    )
    parser.add_argument(
        'file',
        nargs='?',
        help="The path to the file you want to encrypt or decrypt."
    )

    # Parse the arguments
    args = parser.parse_args()

    if args.encrypt or args.decrypt:
        if not args.file:
            print(f"{os.path.basename(__file__)}: error: You must specify file path")
        elif not os.path.exists(args.file):
            print(f"{os.path.basename(__file__)}: error: File '{args.file}' doesn't exist")
        elif not os.path.exists(args.key):
            print(f"{os.path.basename(__file__)}: error: Key '{args.key}' doesn't exist")

    if args.encrypt:
        encrypt_file(args.file, args.key)
    elif args.decrypt:
        decrypt_file(args.file, args.key)
    else:
        if args.file:
            print(f"{os.path.basename(__file__)}: error: '{args.file}' "
                   "file not allowed with option 'keygen'")
        else:
            generate_key(args.key)


if __name__ == "__main__":
    main_crypto_tool()
