#!/usr/bin/env python
"""toolbok main menu"""
# This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola

import os
#import subprocess
import crypto
import scan
import hashcrack
import sshcrack

EXIT_COMMAND = {"9", "x", "X", "z", "Z", "q", "Q"}
CRYPTO_KEY = 'crypto_key.key'           # File where key is stored
PASSWORD = "pw.txt"                     # Default password file


def main_scan():
    """ Main scan function """
    def main_menu():
        print("********************Nmap Tool**************************")
        print("*  1 - Run Nmap with <IP> ping scan                   *")
        print("*  2 - Run Nmap with <IP> port and service scan       *")
        print("*  3 - Run Nmap with no guarantees                    *")
        print("*  7 - Read .txt file in current directory            *")
        print("*  8 - List existing .txt files in current directory  *")
        print("*  9 - Exit                                           *")
        print("*******************************************************")

    while True:
        main_menu()
        main_input = input(">>> ")
        if main_input == "1":
            scan.run_nmap("-T4 -sP")
        elif main_input == "2":
            scan.run_nmap("-T4 -Pn -sV")
        elif main_input == "3":
            scan.run_nmap_original()
        elif main_input == "7":
            file_to_read = scan.select_file()
            if file_to_read:
                scan.read_file(file_to_read)
        elif main_input == "8":
            scan.file_list()
        elif main_input in EXIT_COMMAND:
            print("Nmap tool exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")

def main_crypto():
    """Main crypto function"""

    def new_key():
        if os.path.exists(CRYPTO_KEY):
            print("Are you sure you want to generate a new key in file", end =" ")
            print(f"'{CRYPTO_KEY}' in '{os.getcwd()}\\'? (Y/N) \nThe old key will be overwritten.")
            while True:
                command = input(">>> ").lower()
                if command == "y":
                    return crypto.generate_key(CRYPTO_KEY)
                if command == "n":
                    break
                print(f"Invalid command: '{command}'.")
        else:
            return crypto.generate_key(CRYPTO_KEY)
        return False

    def encrypt_file():
        print('Enter filename of the file you want to encrypt.')
        while True:
            file = input(">>> ")
            if os.path.exists(file):
                #subprocess.run(["python", "crypto_tool.py", "encrypt", file,
                #                "--key", CRYPTO_KEY], check=False)
                crypto.encrypt_file(file, CRYPTO_KEY)
                break
            print(f"File not found in {os.getcwd()}. You must specify an existing file to encrypt.")

    def decrypt_file():
        print('Enter filename of the file you want to decrypt.')
        while True:
            file = input(">>> ")
            if os.path.exists(file):
                #subprocess.run(["python", "crypto_tool.py", "decrypt", file,
                #                "--key", CRYPTO_KEY], check=False)
                crypto.decrypt_file(file, CRYPTO_KEY)
                break
            print(f"File not found in {os.getcwd()}. You must specify an existing file to decrypt.")

    def main_menu():
        print("*****************Cryptography tool*********************")
        print("*  1 - Generate new key                               *")
        print("*  2 - Encrypt file                                   *")
        print("*  3 - Decrypt file                                   *")
        print("*  9 - Exit                                           *")
        print("*******************************************************")

    while True:
        main_menu()
        main_input = input(">>> ")
        if main_input == "1":
            new_key()
        elif main_input == "2":
            encrypt_file()
        elif main_input == "3":
            decrypt_file()
        elif main_input in EXIT_COMMAND:
            print("Crypto tool exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")

def main_hashcrack():
    """Main hashcrack function"""

    def main_menu():
        print("*****************Hash cracking tool********************")
        print("*  1 - Crack a hash                                   *")
        print("*  9 - Exit                                           *")
        print("*******************************************************")

    def crack():
        print("Enter the hash you wish to crack.")
        hash_code = input(">>> ")
        print("Enter the password/wordlist file you want to use.")
        print("Leave empty and press Enter if you wish to use default file")
        while True:
            file = input(">>> ")
            if not file=="":
                if not os.path.exists(file):
                    print(f"Filepath '{file}' not found, please enter existing file "
                        "or press enter to use default file.")
                else:
                    hashcrack.hash_crack(file, None, hash_code)
                    break
            else:
                hashcrack.hash_crack(PASSWORD, None, hash_code)
                break

    while True:
        main_menu()
        main_input = input(">>> ")
        if main_input == "1":
            crack()
        elif main_input in EXIT_COMMAND:
            print("Hash cracking tool exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")


def main_sshcrack():
    """Main SSHcrack function"""

    def main_menu():
        print("*****************SSH password cracking tool************")
        print("*  1 - Crack a SSH username                           *")
        print("*  9 - Exit                                           *")
        print("*******************************************************")

    def crack():
        print("Enter the username you wish to crack.")
        while True:
            user_name = input(">>> ")
            if not user_name:
                print("Enter the username you wish to crack.")
            else:
                break
        print("Enter the IP address to the SSH server.")
        while True:
            ip_address = input(">>> ")
            if scan.ip_address_validator(ip_address) and sshcrack.ssh_check(ip_address):
                print("Enter the password/wordlist file you want to use.")
                print("Leave empty and press Enter if you wish to use default file")
                while True:
                    file = input(">>> ")
                    if not file=="":
                        if not os.path.exists(file):
                            print(f"Filepath '{file}' not found, please enter existing file "
                                "or press enter to use default file.")
                        else:
                            sshcrack.ssh_crack(file, user_name, ip_address)
                            return
                    else:
                        sshcrack.ssh_crack(PASSWORD, user_name, ip_address)
                        return
            else:
                print(f"IP address '{ip_address}' is faulty, please enter "
                        "a correct IP.")   

    while True:
        main_menu()
        main_input = input(">>> ")
        if main_input == "1":
            crack()
        elif main_input in EXIT_COMMAND:
            print("SSH cracking tool exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")


def main():
    """Main menu"""

    def main_menu():
        print("******************Toolbox******************************")
        print("*  1 - Cryptography                                   *")
        print("*  2 - Nmap Scan                                      *")
        print("*  3 - Hashcracker                                    *")
        print("*  4 - SSHcracker                                     *")
        print("*  9 - Exit                                           *")
        print("*******************************************************")

    while True:
        main_menu()
        main_input = input(">>> ")
        if main_input == "1":
            main_crypto()
        elif main_input == "2":
            main_scan()
        elif main_input == "3":
            main_hashcrack()
        elif main_input == "4":
            main_sshcrack()
        elif main_input in EXIT_COMMAND:
            print("Toolbox exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")


if __name__ == "__main__":
    main()
