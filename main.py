#!/usr/bin/env python
"""toolbok main menu"""
# This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola

#import subprocess
import os
import ipaddress
import pyfiglet
from termcolor import colored
import crypto
import scan
import hashcrack
import sshcrack
import encrypt_shellcode

EXIT_COMMAND = ("9", "x", "X", "q", "Q")
CURRENT_DIRECTORY = os.path.dirname(__file__)
FILE_PATH = os.path.dirname(__file__) + '/files/'
CRYPTO_KEY = FILE_PATH + 'crypto_key.key'   # File where key is stored
PASSWORD = FILE_PATH +  "pw.txt"            # Default password file
SHELLCODE = FILE_PATH +  "shellcode.raw"    # Default shellcode


def banner_toolbox():
    """Banner function"""
    banner = pyfiglet.figlet_format("PENTESTING\nTOOLBOX", font="big")
    banner_lines = banner.splitlines()  # Split the banner into lines

    rainbow_colors = ['red', 'yellow', 'green', 'cyan', 'blue', 'magenta']

    # Print each line of the banner with a different rainbow color
    for i, line in enumerate(banner_lines):
        color = rainbow_colors[i % len(rainbow_colors)]
        print(colored(line, color))
    print("     \033[1;32m    By Ari Ketola ITHS \033[0m\n\n")


def run_nmap(nmap_options):
    """ Calls python-nmap with flags"""

    def input_ip():
        print("Type target IP address you want to scan:")
        while True:
            try:
                ip_address_to_use = ipaddress.ip_address(input(">>> "))
            except ValueError:
                print("Error, not a valid IP address.")
            except KeyboardInterrupt:
                print("\n Ctrl-C pressed! \n Back to Nmap menu.")
                return False    
            else:
                return ip_address_to_use

    def save_scan(ip_address_file = None):
        """Save scan to file"""
        save_scan_to_file = None
        while True:
            try:
                print("*******************************************************")
                print(f"1. Do want to save the scan to an existing file in {os.getcwd()}.")
                print("2. Do you want to save the scan to a new file.")
                print("3. Not save scan to file.")
                save_input = input(">>> ").lower()
                if save_input == "1":
                    save_scan_to_file = scan.select_file()
                    if save_scan_to_file != ip_address_file:
                        break
                    print(f"Can not use '{ip_address_file}' to save the scan, "
                            "file is already used to read IP data.")
                elif save_input == "2":
                    save_scan_to_file = scan.create_file()
                    break
                elif save_input == "3":
                    break
                print(f"Invalid command: '{save_input}'.")
            except KeyboardInterrupt:
                print("\n Ctrl-C pressed! \n Scan not saved to a file.")
                return None  
        return save_scan_to_file

    def run_nmap_menu():
        print("*******************************************************")
        print("*  1 - Get <IP> addresses from file                   *")
        print("*  2 - Get <IP> address from command prompt           *")
        print("*  9 - Go back to main scan menu                      *")
        print("*******************************************************")

    while True:
        run_nmap_menu()
        choise = input(">>> ")
        if choise == "1":
            ip_address_file = scan.select_file()
            if ip_address_file:
                scan.nmap_scan(save_scan(ip_address_file), nmap_options, ip_address_file, None)
                break
            choise = "9"
        if choise == "2":
            ip_address = input_ip()
            if ip_address:
                scan.nmap_scan(save_scan(), nmap_options, None, ip_address)
                break
            choise = "9"
        if choise in EXIT_COMMAND:
            break                 #print("Back to main menu...")
        print(f"Invalid command: '{choise}'.")


def main_scan():
    """ Main scan function """
    def main_scan_menu():
        print("********************Nmap Tool**************************")
        print("*  1 - Run Nmap with <IP> ping scan                   *")
        print("*  2 - Run Nmap with <IP> port and service scan       *")
        print("*  3 - Run Nmap with no guarantees                    *")
        print("*  7 - View a text file in current directory          *")
        print("*  8 - List existing text files in current directory  *")
        print("*  9 - Back                                           *")
        print("*******************************************************")

    while True:
        main_scan_menu()
        main_input = input(">>> ")
        if main_input == "1":
            run_nmap("-T4 -sP")
        elif main_input == "2":
            run_nmap("-T4 -Pn -sV")
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
            print(f"'{CRYPTO_KEY}'? (Y/N) \nThe old key will be overwritten.")
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
        try:
            while True:
                file = input(">>> ")
                if os.path.exists(f"{file}"):
                    #subprocess.run(["python", "crypto_tool.py", "encrypt", file,
                    #                "--key", CRYPTO_KEY], check=False)
                    crypto.encrypt_file(file, CRYPTO_KEY)
                    break
                print(f"File {file} not found. You must specify an existing file path to encrypt.")
        except KeyboardInterrupt:
            print("\n Ctrl-C pressed! \n Back to Cryptography menu.")
            return    

    def decrypt_file():
        print("Enter filename of the file you want to decrypt.")
        print("Keep in mind the decrypted file will overwrite existing file in "+
              "\npath with same filename but without the '.encrypted' suffix.")
        try:
            while True:
                file = input(">>> ")
                if os.path.exists(f"{file}"):
                    #subprocess.run(["python", "crypto_tool.py", "decrypt", file,
                    #                "--key", CRYPTO_KEY], check=False)
                    crypto.decrypt_file(file, CRYPTO_KEY)
                    break
                print(f"File {file} not found. You must specify an existing file path to decrypt.")
        except KeyboardInterrupt:
            print("\n Ctrl-C pressed! \n Back to Cryptography menu.")
            return       

    def main_crypto_menu():
        print("*****************Cryptography tool*********************")
        print("*  1 - Generate new key                               *")
        print("*  2 - Encrypt file                                   *")
        print("*  3 - Decrypt file                                   *")
        print("*  9 - Back                                           *")
        print("*******************************************************")

    while True:
        main_crypto_menu()
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


def main_encrypt_shellcode():
    """Main encryption of shellcode function"""
    def crack():
        print("Enter the shellcode path you want to use. Generated shellcode must be ")
        print("in '.raw' format, you can use 'msfvenom' to generate new shellcode.")
        print("Leave empty and press Enter if you wish to use default shellcode file.")
        try:
            while True:
                file = input(">>> ")
                if file=="":
                    encrypt_shellcode.shellcode_encrypter(SHELLCODE)
                    break
                if os.path.exists(file) and file.endswith(".raw"):
                    encrypt_shellcode.shellcode_encrypter(SHELLCODE)
                    break
                print("Error, please enter existing '.raw' file path "
                    "or press enter to use default file.")
        except KeyboardInterrupt:
            print("\n Ctrl-C pressed! \n Back to shellcode encryption menu.")
            return

    def main_encrypt_shellcode_menu():
        print("*************Encryption tool for shellcode*************")
        print("*  1 - Encrypt shellcode                              *")
        print("*  9 - Back                                           *")
        print("*******************************************************")

    while True:
        main_encrypt_shellcode_menu()
        main_input = input(">>> ")
        if main_input == "1":
            crack()
        elif main_input in EXIT_COMMAND:
            print("Encrypt shellcode tool exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")


def main_hashcrack():
    """Main hashcrack function"""
    
    def crack():
        try:
            print("Enter the hash you wish to crack.")
            hash_code = input(">>> ")
            while not hash_code:
                print("Please enter the hash you want to crack")
                hash_code = input(">>> ")
            print("Enter the password/wordlist file you want to use.")
            print("Leave empty and press Enter if you wish to use default file")
            while True:
                file = input(">>> ")
                if file=="":
                    hashcrack.hash_crack(PASSWORD, None, hash_code)
                    break
                if os.path.exists(file):
                    hashcrack.hash_crack(file, None, hash_code)
                    break
                print(f"File '{file}' not found, please enter existing file path "
                    "or press enter to use default file.")
        except KeyboardInterrupt:
            print("\n Ctrl-C pressed! \n Back to Hash cracking menu.")
            return          

    def main_hash_menu():
        print("*****************Hash cracking tool********************")
        print("*  1 - Crack a hash                                   *")
        print("*  9 - Back                                           *")
        print("*******************************************************")

    while True:
        main_hash_menu()
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
    def crack():
        try:
            print("Enter the username of the ssh user you wish to crack.")
            user_name = input(">>> ")
            while not user_name:
                print("Please enter the username you wish to crack.")
                user_name = input(">>> ")
            print("Enter the IP address to the SSH server.")
            while True:
                ip_address = input(">>> ")
                if ip_address in EXIT_COMMAND:
                    break
                if scan.ip_address_validator(ip_address):   # ip_address_validator checks if genuine IP
                    if sshcrack.ssh_check(ip_address):      # ssh_check controls if port is open
                        print("Enter the password/wordlist file you want to use.")
                        print("Leave empty and press Enter if you wish to use default file.")
                        while True:
                            file = input(">>> ")
                            if file=="":
                                sshcrack.ssh_crack(PASSWORD, user_name, ip_address)
                                return
                            if os.path.exists(file):
                                sshcrack.ssh_crack(file, user_name, ip_address)
                                return
                            print(f"File '{file}' not found, please enter existing file path "
                                "or press enter to use default file.")
                    else:
                        print("Please choose an IP address with open port "
                            f"{sshcrack.PORT} or '9' to go back.")
                else:
                    print(f"IP address '{ip_address}' is faulty, please enter "
                            "a correct IP or '9' to go back.") 
        except KeyboardInterrupt:
            print("\n Ctrl-C pressed! \n Back to SSH cracking menu.")
            return              

    def main_ssh_menu():
        print("*****************SSH password cracking tool************")
        print("*  1 - Crack a SSH username                           *")
        print("*  9 - Back                                           *")
        print("*******************************************************")

    while True:
        main_ssh_menu()
        main_input = input(">>> ")
        if main_input == "1":
            crack()
        elif main_input in EXIT_COMMAND:
            print("SSH cracking tool exiting...")
            break
        else:
            print(f"Invalid command: '{main_input}'.")


def main():
    """Main menu function"""
    banner_toolbox()

    def main_menu():
        print("******************Toolbox******************************")
        print("*  1 - Cryptography                                   *")
        print("*  2 - Nmap Scan                                      *")
        print("*  3 - Hashcracker                                    *")
        print("*  4 - SSHcracker                                     *")
        print("*  5 - Encrypt shellcode                              *")
        print("*  9 - Exit                                           *")
        print("*******************************************************")

    try:
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
            elif main_input == "5":
                main_encrypt_shellcode()
            elif main_input in EXIT_COMMAND:
                print("Toolbox exiting...")
                break
            else:
                print(f"Invalid command: '{main_input}'.")
    except KeyboardInterrupt:
        print("\n Ctrl-C pressed! \n Toolbox exiting...")


if __name__ == "__main__":
    main()
