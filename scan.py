#!/usr/bin/env python
"""scan.py"""
#This script is developed in Windows environment.
# Some testing done in Linux environment, seems to work ok.
# Author: Ari Ketola
import argparse
import os
import ipaddress
import nmap


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
            try:
                with open(new_file, 'x', encoding='utf-8'):
                    print(f"File created: {new_file}.")
                return new_file
            except PermissionError:
                print(f"Permission denied to path: '{new_file}'")
        else:
            print(f"{new_file} already exists.")
            print("You must specify a new non existing filename.")


def nmap_start(ip_address, save_scan_to_file, nmap_options):
    """Nmap scan starter"""
    target = str(ip_address)    #ip_address, test IP: "45.33.32.156"
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
    if printdata == "":
        print(f"     {target} not responding")
    printdata += '--------------------------------------------------------'
    if save_scan_to_file:
        with open(save_scan_to_file, "a", encoding='utf-8') as file_save:
            file_save.write(printdata + chr(10))
    print(printdata)


def nmap_scan(save_scan_to_file, nmap_options, ip_address_file, ip_address):
    """Nmap Scan"""
    print(f"save to filen input: {save_scan_to_file}") #Test purpose

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
    args_error = False
    if args.o:
        try:        #Create a new output file
            with open(args.o, 'x', encoding='utf-8'):
                pass
        except PermissionError:
            print(f"File {os.path.basename(__file__)}: error: "
                  f"permisson to path '{args.o}' denied")
            args_error = True
        except:     #File already exist, no new file created
            pass

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
