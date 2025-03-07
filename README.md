Network Pentesting Toolkit

Introduction
This is a network pentesting tool written in Python, supporting functionalities such as:
- Network Scanning
- ARP Spoofing Attack
- DNS Spoofing Attack
- Packet Sniffing and Analysis

This tool is intended for security research and network penetration testing purposes.

Installation

1. System Requirements
Runs on Linux OS (Ubuntu/Kali Linux/Parrot OS...)
Root privileges required for network attacks
Python 3.x
Required libraries:
  pip install scapy

2. Clone the Project

git clone https://github.com/stephenson218/network-scanner.git

cd network_scanner

Usage

1. Network Scanning

sudo python3 network_scanner.py -s <IP_RANGE> -i <INTERFACE>

Example:

sudo python3 network_scanner.py -s 192.168.1.0/24 -i eth0

Result: Lists all devices on the network along with their IP and MAC addresses.

---

2. ARP Spoofing Attack

sudo python3 network_scanner.py -a <TARGET_IP> <GATEWAY_IP> -i <INTERFACE>

Example:

sudo python3 network_scanner.py -a 192.168.1.10 192.168.1.1 -i eth0

Result: Tricks the victim's machine and the router for a MITM (Man-In-The-Middle) attack.

Stop the attack: Press `CTRL + C` to restore the ARP table.

---

3. DNS Spoofing Attack

sudo python3 network_scanner.py -d <DOMAIN> <FAKE_IP> -i <INTERFACE>

Example:

sudo python3 network_scanner.py -d "example.com" 1.2.3.4 -i eth0

Result: Redirects victims attempting to visit `example.com` to `1.2.3.4`.

---

4. Packet Sniffing and Analysis

sudo python3 network_scanner.py -p <COUNT> -i <INTERFACE>

Example:

sudo python3 network_scanner.py -p 100 -i eth0

Result: Captures 100 packets on the network and displays HTTP requests, cookies, etc.

---

Warning
- Use only in legally authorized testing environments.
- Do not use for malicious purposes or violate any laws.
- Always obtain permission from the network owner before conducting tests.

License
MIT License. Feel free to use and modify.

