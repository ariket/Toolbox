#!/usr/bin/env python
"""scan.py"""
#This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola
import argparse
import os
import ipaddress
import nmap

exit_command = {"9", "x", "X", "z", "Z", "q", "Q"}

def ip_address_validator(ip):
    """ Check if legal IP address """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return False
    return True


def file_list():
    """ Lists all .txt files in current directory """
    file_index_name = {}
    index = 1
    for file in os.listdir():
        if file.endswith(".txt"):
            print(f"{index} - {file}")
            file_index_name[f"{index}"] = f"{file}"
            index += 1
    if len(file_index_name) == 0:
        print(f"No .txt files found in {os.getcwd()}")
        return False
    return file_index_name


def select_file():
    """ Select a .txt file in current directory """
    file_index_name = file_list()
    if file_index_name:
        print("Select file by number:")
        while True:
            try:
                selected_file = int(input(">>> "))
            except ValueError:
                print(f"Select file by number 1 - {len(file_index_name)}.")
            else:
                if selected_file <= len(file_index_name):
                    return file_index_name[f"{selected_file}"]
                print(f"Select file by number 1 - {len(file_index_name)}.")
    return False


def read_file(filename):
    """Read a .txt file and print to command line"""
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as file:
            content = file.readlines()
            print("*******************************************************")
            for line in content:
                print(line.strip())
    else:
        print(f"File doesn`t exist: {filename}")


def run_nmap_original():
    """ Calls original nmap with flags"""
    print("Be careful, no error check of your input")
    ip = input("Enter IP address you want to scan.\n>>> ")  #ip = "45.33.32.156"
    flags = input("Enter Nmap flags you want to use in this scan.\n"
                 +"For example: -A -T4 (aggresive scan).\n>>> ")

    response = os.popen(f"nmap {flags} {ip}")   #response = os.popen(f"nmap -A -T4 {ip}")
    for line in response:
        print(line.rstrip("\n"))

def create_file():
    """Create a new file"""
    print('Enter filename of the new file you want to create.')
    while True:
        new_file = input(">>> ")
        if new_file == "":
            print("You must specify a new non existing filename.")
        elif not os.path.exists(new_file):
            with open(new_file, 'x', encoding='utf-8') as file:
                print(f"File created: {file}.")
            return new_file
        else:
            print(f"{new_file} already exists.")
            print("You must specify a new non existing filename.")


def save_to_file(save_scan_to_file, ip_address_file):
    """Save to file"""
    if save_scan_to_file == "not save":  #Script called from commandline without "save to file" flag
        save_scan_to_file = None
    elif save_scan_to_file:              #Script called from commandline with flag "save to file"
        try:
            with open(save_scan_to_file, 'x', encoding='utf-8'):
                pass
        except:
            pass    #File already exist, no new file created
    else:                               #Script called from main menu
        while True:
            print(f"1. Do want to save the scan to an existing file in {os.getcwd()}.")
            print("2. Do you want to save the scan to a new file.")
            print("3. Not save to file")
            command = input(">>> ").lower()
            if command == "1":
                save_scan_to_file = select_file()
                if save_scan_to_file != ip_address_file:
                    break
                print(f"Can not use '{ip_address_file}' to save the scan.")
                command = "File is already in use to read IP data."
                #print("Do you really want to save scan to file? (Y/N)")
                if not save_scan_to_file:
                    save_scan_to_file = create_file()
                    break
            elif command == "2":
                save_scan_to_file = create_file()
                break
            elif command == "3":
                break
            print(f"Invalid command: '{command}'.")
    return save_scan_to_file


def nmap_start(ip_address, save_scan_to_file, nmap_options):
    """Nmap scan starter"""
    target = str(ip_address) #ip_address, test IP: "45.33.32.156"
    print(f"Scanning {target.rstrip(chr(10))}.....Standby")
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments=nmap_options)
    # print(scanner.command_line()) #print(scanner.csv())
    printdata = ''
    for host in scanner.all_hosts():
        print('--------------------------------------------------------')
        printdata += f"Host: {host} ({scanner[host].hostname()})"
        printdata += f" State: {scanner[host].state()}\n"
        for proto in scanner[host].all_protocols():
            printdata += f"Protocol: {proto}" + chr(10)
            ports = scanner[host][proto].keys()
            for port in ports:
                printdata += f"Port: {port}, State: {scanner[host][proto][port]['state']}, "
                printdata += f"Name: {scanner[host][proto][port] ['name']}, Version: "
                printdata += f"{scanner[host][proto][port]['version']}\n"
    printdata += '--------------------------------------------------------'
    if save_scan_to_file:
        with open(save_scan_to_file, "a", encoding='utf-8') as file_save:
            file_save.write(printdata + chr(10))
    print(printdata)


def nmap_scan(save_scan_to_file, nmap_options, ip_address_file, ip_address):
    """Nmap Scan"""
    save_scan_to_file = save_to_file(save_scan_to_file, ip_address_file)

    print('--------------------------------------------------------')
    print('|                Nmap scan starts                      |')
    print('--------------------------------------------------------')
    if ip_address:
        nmap_start(ip_address, save_scan_to_file, nmap_options)
    else:
        with open(ip_address_file, "r", encoding='utf-8') as data:
            for ip_adress in data:
                if ip_address_validator(ip_adress.rstrip('\n')):
                    nmap_start(ip_adress, save_scan_to_file, nmap_options)
                else:
                    print(f"Not a vaild IP: {ip_adress.rstrip(chr(10))} , skipping this line")
                    print('--------------------------------------------------------')


def run_nmap(nmap_options):
    """ Calls python-nmap with flags"""
    def run_nmap_menu():
        print("*******************************************************")
        print("*  1 - Get <IP> addresses from file                   *")
        print("*  2 - Get <IP> address from command prompt           *")
        print("*  9 - Go back to main menu                           *")
        print("*******************************************************")

    def input_ip():
        print("Fill in IP address you want to scan:")
        while True:
            try:
                ip_address_to_use = ipaddress.ip_address(input(">>> "))
            except ValueError:
                print("Error, not a valid IP address.")
            else:
                return ip_address_to_use

    while True:
        run_nmap_menu()
        command = input(">>> ")
        if command == "1":
            ip_address_file = select_file()
            if ip_address_file:
                nmap_scan(None, nmap_options, ip_address_file, None)
                break
            command = "file missing"
        if command == "2":
            ip_address = input_ip()
            nmap_scan(None, nmap_options, None, ip_address)
            break
        if command in exit_command:
            break                 #print("Back to main menu...")
        print(f"Invalid command: '{command}'.")


def main_scan():
    """Main scan function that handles commandline arguments"""
    parser = argparse.ArgumentParser(description="Scan Ip addresses with Nmap.")
    group = parser.add_mutually_exclusive_group(required=True)
    # Define arguments
    group.add_argument(
        '-ip',
        help="The IP address to the target server."
    )
    group.add_argument(
        '-file',
        help="The path to a file with IP addresses to scan."
    )
    parser.add_argument(
        '-o',
        help="The path to an output file where the scan will be saved."
    )
    parser.add_argument(
        'action',
        choices=['ping', 'port'],
        help="Specify whether to 'ping' or to get 'port' data from an IP."
    )
    # Parse the arguments
    args = parser.parse_args()

    if not args.o:
        args.o = "not save"
    args_error = False
    if args.file:
        if not os.path.exists(args.file):
            print(f"File {os.path.basename(__file__)}: error: '{args.file}' doesn't exist")
            args_error = True
    else:
        if not ip_address_validator(args.ip):
            print(f"File {os.path.basename(__file__)}: error: IP '{args.ip}' doesn't exist")
            args_error = True
    if not args_error:
        if args.action == "ping":
            nmap_scan(args.o ,"-T4 -sP" ,args.file ,args.ip )
        else:
            nmap_scan(args.o ,"-T4 -Pn -sV" ,args.file ,args.ip )


if __name__ == "__main__":
    main_scan()