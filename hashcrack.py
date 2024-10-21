#!/usr/bin/env python
"""hashcrack.py"""
# This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola
import hashlib
import os
import argparse
import requests

PASSWORD = "pw.txt"   # Default password file  md5 hash to test: bee783ee2974595487357e195ef38ca2
HASH_ALGORITHMS ={ "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256",
                "sha3_384", "sha3_512", "shake_128", "shake_256", "blake2b", "blake2s", "md5"}


def check_hash_algorithm(hash_input):
    """checks if a real hash algorithm"""
    api_address = "https://hashes.com/en/api/identifier?hash="
    api_hash = hash_input
    response = requests.get(f"{api_address}{api_hash}", timeout=20)

    if response.status_code == 200:
        answer = response.json()
        if answer["success"]:
            return str(answer["algorithms"])[2:-2]
    return f"Not found by {api_address}"    # return false if something went wrong


def hash_crack(wordlist, algorithm_input, hash_input):
    """Try to crack hash"""
    if not algorithm_input:   #algorithm_input not added to script when the scripted was called
        algorithm_input = check_hash_algorithm(hash_input).lower()
        if algorithm_input not in HASH_ALGORITHMS:
            print(f"Unsupported hash algorithm: {algorithm_input}")
            #print(f"{os.path.basename(__file__)}: error: Unsupported hash algorithm: {algorithm_input}")
            return
    try:
        with open(wordlist, 'r', encoding='utf-8') as file:
            print(f"Standby, trying to crack '{hash_input}' with file '{wordlist}'")
            for lines in file:
                line = lines.strip().encode()
                try:
                    hash_object = hashlib.new(algorithm_input, line)
                except ValueError:
                    print("Unexpected error")
                    break

                hashed_password = hash_object.hexdigest()
                if hashed_password == hash_input:
                    print(f'Found password: \033[96m{line.decode()}\033[0m '
                          f'(with hash algorithm: {algorithm_input})')
                    break
            else:
                print(f"No match found in the '{wordlist}' password list.")
    except FileNotFoundError:
        print("Unexpected error")


def main_hashcracker():
    """Main hashcracker function to handle commandline arguments"""
    parser = argparse.ArgumentParser(description="Crack a non salted hash.")

    # Define arguments for encrypting and decrypting
    parser.add_argument(
        '-alg',
        help="The hashing algorithm"
    )
    parser.add_argument(
        'hash',
        help="The hash you wish to crack"
    )
    parser.add_argument(
        'file',
        default=PASSWORD,
        nargs='?',
        help=f"The path to the .txt file with passwords (default file '{PASSWORD}')."
    )
    # Parse the arguments
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"{os.path.basename(__file__)}: error: file '{args.file}' doesn't exist")
    elif args.alg not in HASH_ALGORITHMS and args.alg:
        print(f"{os.path.basename(__file__)}: error: Unsupported hashing algorithm: '{args.alg}'")
    else:
        # Perform hashcrack
        hash_crack(args.file, args.alg, args.hash)


if __name__ == "__main__":
    main_hashcracker()
