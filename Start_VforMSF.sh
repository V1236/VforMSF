#!/bin/bash

# Create a temporary script to hold the exit command
echo "exit" > /tmp/exit_script_$$.sh
chmod +x /tmp/exit_script_$$.sh

# Run the script command with unbuffered output and append to a shared log file
script -q -a -f VforMSF.log -c "stdbuf -oL python3 VforMSF.py; /tmp/exit_script_$$.sh"

# Clean up the temporary exit script
rm /tmp/exit_script_$$.sh
