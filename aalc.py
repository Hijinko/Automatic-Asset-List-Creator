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

#get regex for ip addresses and hostnames
ips = re.compile(r'Nmap scan report for (.*)|\s \(+((\d{1,3}\.){3}\d{1,3})\)+')
#get regex to match ports, protocals, and services
pps = re.compile(r'\d*\/(udp|tcp)\s*(open|closed)\s*(\w|\-)*')
#get regex to match mac address and device manufacturer
macs = re.compile(r'MAC Address: (([A-F0-9]{2}:){5}[A-F0-9]{2}) \((.*)\)')

x = 0 #place holder for testing delete later

#begin parsing through scan
for line in lines:
    #set empty list for ports and protocols
    hostname = ''
    host = ''
    mac_addr = ''
    #if the line is the beginining of a hosts information
    if (ips.search(line)):
        ip = ips.search(line)
        hostname = ip.group(1)
        host = ip.group(2)
    if (pps.search(line)):
        ports = pps.search(line)
        print(f'\t{ports.group(0)}')
    if (macs.search(line)):
        mac = macs.search(line)
        mac_addr = mac.group(1)
        print(f'\tMAC: {mac_addr}\n')
    if host != '':
        x += 1
        print(f'\n{x}:\thostname: {hostname}\n\tip: {host}')
        
