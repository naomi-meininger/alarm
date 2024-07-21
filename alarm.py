#!/usr/bin/python3

import base64
from scapy.all import *
import argparse

incident_number = 0
incidents = {
    'NULL Scan': "",
    'FIN Scan': "F",
    'Xmas Scan': "FPU",
    'Nikto Scan': 'Nikto',
    'SMB Scan': 445,
    'RDP Scan': 3389,
    'VNC Scan': 5900
}

def packetcallback(packet):
  global incident_number
  first_incident_num = incident_number
  try:
    incident_detected = ""
    source_IP = ""
    extra = ""
    
    if packet.haslayer(TCP) :
      if packet.haslayer(Raw) :
        load = packet[Raw].load.decode(errors='ignore')
        if 'Nikto' in load:
          incident_detected = 'Nikto Scan'
          source_IP = packet[IP].src
          incident_number = incident_number + 1
          if 'http' in str(packet) :
              extra = "(TCP port 80)"
          else :
              extra = '(TCP)'
        elif 'Authorization: Basic' in load:
          credentials_part = load.split('Authorization: Basic ')[1].strip()
          credentials = credentials_part.split('\n')[0].strip()
          decoded = base64.b64decode(credentials).decode()
          username, password = decoded.split(':')
          incident_detected = f"HTTP credentials"
          source_IP = packet[IP].src
          incident_number = incident_number + 1
          extra = f"(Username: {username}, Password: {password})"
        elif 'USER' in load and 'PASS' in load:
          user_index = load.index('USER') + 5
          pass_index = load.index('PASS') + 5
          username = load[user_index:load.index('\r\n', user_index)]
          password = load[pass_index:load.index('\r\n', pass_index)]
          incident_detected = f"FTP credentials"
          source_IP = packet[IP].src + "on port 21"
          incident_number = incident_number + 1
          extra = f"(Username: {username}, Password: {password})"
        elif 'LOGIN' in load:
          login_index = load.index('LOGIN') + 6
          username = load[login_index:load.index(' ', login_index)]
          password_index = load.index(' ', login_index) + 1
          password = load[password_index:load.index('\r\n', password_index)]
          if (username != 'REFERRALS')  :
              incident_detected = f"IMAP credentials"
              source_IP = packet[IP].src + "on port 143"
              incident_number = incident_number + 1
              extra = f"(Username: {username}, Password: {password})" 
      elif packet[TCP].flags == 0:
        incident_detected = 'NULL Scan'
        source_IP = packet[IP].src
        incident_number += 1
        extra = "(TCP)"
      elif 'F' in packet[TCP].flags:
        incident_detected = "FIN Scan"
        source_IP = packet[IP].src
        incident_number += 1
        extra = "(TCP)"
      elif "FPU" in packet[TCP].flags:
        incident_detected = "Xmas Scan"
        source_IP = packet[IP].src
        incident_number += 1
        extra = "(TCP)"
      elif (packet[TCP].dport == 445 or packet[TCP].dport == 139):
        incident_detected = 'SMB Scan'
        source_IP = packet[IP].src
        incident_number += 1
        extra = "(TCP)"
      elif packet[TCP].dport == incidents['RDP Scan']:
        incident_detected = 'RDP Scan'
        source_IP = packet[IP].src
        incident_number += 1
        extra = "(TCP)"
      elif packet[TCP].dport == incidents['VNC Scan']:
        incident_detected = 'VNC Scan'
        source_IP = packet[IP].src
        incident_number += 1
        extra = "(TCP)"
                
    
    if (first_incident_num + 1 == incident_number) :
      print(f"ALERT #{incident_number}: {incident_detected} is detected from {source_IP} {extra}")
      incident_detected = ""
      source_IP = ""
      extra = ""


  except Exception as e:
    print(f"Error decoding or processing credentials: {e}")

    # Uncomment the below and comment out `pass` for debugging, find error(s)
    #print(e)
    pass

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
