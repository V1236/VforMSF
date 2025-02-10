# VforMSF
Enhance and automate metasploit console with VforMSF. This script acts an an add-on to enhance msfconsole by adding utilities, automations and additional modules writen in python.

Assistant.py comes included. Run it in a separate window for a helpful AI assistant named Remy (must input your own openai API key)

Check out the sister project: https://github.com/V1236/VforC2 (outdated) & https://github.com/V1236/Remy-Red-Team-Assistant

## Installation
```
clone the repo & navigate to the directory it creates "VforMSF"
```
## Dependencies:
Many python dependencies are utilized and can be installed using the requirements file:
```
pip install -r requirements.txt
```
Some may be missing depending on your environment. Just use pip to install any thats missing when you get the name error or go to the top of VforMSF.py to see which ones are used/missing and install them.

## Usage
After installation, navigate to the directory.
Install the python requirements if needed before issuing:
```
bash Start_VforMSF.sh
```
You will probably need to edit the global variables listed near the top of VforMSF.py to match your file system.

Utilize msfconsole as usual and enter the vhelp command to see extensions.
```
VforMSF.py is the main file. Starting it with "bash Start_VforMSF.sh" enables logging and assist.py accessibility
```
