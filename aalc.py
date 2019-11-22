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
import csv
import sys

#get the filename of the nmap results
filename = sys.argv[1]

with open(filename, 'r') as f:
    #store each line in a list to later parse
    lines = f.readlines()

#get regex for ip addresses and hostnames
ips = re.compile(r'Nmap scan report for (.*)|\(+((\d{1,3}\.){3}\d{1,3})\)+')
#get regex to match ports, protocals, and services
pps = re.compile(r'\d*\/(udp|tcp)\s*(open|closed)\s*(\w|\-)*')
#get regex to match mac address and device manufacturer
macs = re.compile(r'MAC Address: (([A-F0-9]{2}:){5}[A-F0-9]{2}) \((.*)\)')

x = 0 #place holder for testing delete later
header = ("Host Name", 
          "OS Version",
          "IP Address",
          "MAC Address",
          "Ports Open",
          "Web Address",
          "Purpose of Machine",
          "Critical Services",
          "Abnormal Service",
          "Users",
          "Group e.g. 'Administrators'",
          "Abnormal Applications",
          "Abnormal Processes")

#open csv file to begin writing to
with open('Asset_List.csv', 'w') as asset_list:
    al_writer = csv.writer(asset_list)
    #write the coulumn names in the csv file
    al_writer.writerow(header)
    al_writer = csv.writer(asset_list)

mac_addr = ''
ports_list = []
#begin parsing through scan
for line in lines:
    line = line.strip()
    #set empty list for ports and protocols
    hostname = ''
    host = ''
    #mac_addr = ''
    #if the line is the beginining of a hosts information
    #if (ips.search(line)):
    if "Nmap scan report for" in line:
        if '(' in line:
            hostname = line.split(' ')[4]
            hostname = hostname.rstrip(")")
            host = line.split(' ')[5]
        else:
            hostname = 'n/a'
            host = line.split(' ')[4]
    elif (pps.search(line)):
        ports = pps.search(line)
        ports_list.append(ports.group(0))
        #print(f'\t{ports.group(0)}')
    elif (macs.search(line)):
        mac = macs.search(line)
        mac_addr = mac.group(1)
        #print(f'\tMAC: {mac_addr}')
    if host != '':
        #row = f'{hostname}, "", "", host, "", mac_addr, "", "Ports Open", "", "", "", "", "", "", "", ""' 
        ports_to_list = '\n'.join(ports_list)
        print(ports_to_list)
        with open('Asset_List.csv', 'a') as asset_list:
            al_writer = csv.writer(asset_list)
            al_writer.writerow([hostname, "", host, mac_addr, ports_to_list, "", "", "", "", "", "", "", ""]) 
        mac_addr = ''
        ports_list = []
