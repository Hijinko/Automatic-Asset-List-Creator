#!/usr/bin/env python3

###################################################################################
# Creator: SSG Ellis, Kevin
# Date: 20191118
# Filename: aalc.py
# Program: Automatic Asset List Creator
# Description: Takes in nmap output and places it into a csv file, formated for a 
#   asset list usefull for blueteam operations
###################################################################################

import re
import sys

#get the filename of the nmap results
filename = sys.argv[1]

with open(filename, 'r') as f:
    #store each line in a list to later parse
    lines = f.readlines()

#get regex for ip addresses
ips = re.compile(r'Nmap scan report for (.*) \(+((\d{1,3}\.){3}\d{1,3})\)+')

x = 0
#parse through and find the ips
for line in lines:
    if (ips.search(line)):
        ip = ips.search(line)
        print(f"{x}: hostname: {ip.group(1)}\nip: {ip.group(1)}\n")
        #print(f"{x}: {line[ip.start():ip.end()]}")
        x += 1

