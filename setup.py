#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
from time import sleep

#---------------------------------------------------------------------------#
#                                                                           #
#        Copyright © 2019 # shell.e00750.                                   #
#                                                                           #
#---------------------------------------------------------------------------#

if not os.geteuid() == 0:
    sys.exit("""\033[1;91m\n[!] SecureCopyPy installer must be run as root.\n\033[1;m""")

print(""" \033[1;36m

SecureCopyPy Installer, By shell.e00750.

\033[1;m""")

def main():
    
    print("\033[1;34m\n[++] Installing NmapPy... \n\033[1;m")
    
    sleep(1)
    
    install = os.system("apt-get update && \
    pip install colorama && \
    pip install termcolor && \
    pip install pyfiglet")
    
    sleep(1)
    
    install1 = os.system("""mkdir -p /opt/scppy && \
    cp scppy.py /opt/scppy/scppy.py && \
    cp run.sh /usr/bin/scppy && \
    chmod +x /usr/bin/scppy && \
    tput setaf 34; echo "SecureCopyPy has been sucessfuly instaled. Execute 'scppy' in your terminal." """)	
	
main()
