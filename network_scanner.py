import ipaddress
import socket
import argparse
import threading
from scapy.all import srp, Ether, ARP, conf
import re

conf.sniff_promisc = False

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=200))
parser.add_argument("-i", "--iprange", help="Ip range for network scan")
args = parser.parse_args()

ip_range = args.iprange

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def checkIP(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except:
        hostname = "unknown"
    mac_address = get_mac(ip)
    if not mac_address:
        return
    print(f"[+] Hostname: {hostname}, IP Address: {ip}, MAC Address: {mac_address}")

#Get ip subnet and split into array
ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
if ip_add_range_pattern.search(ip_range):
    print(f"[!] Scanning network in range: {ip_range}...")
    threads = []
    for ip in ipaddress.IPv4Network('192.168.1.0/24'):
        ip = str(ip)
        t = threading.Thread(target=checkIP, args=(ip,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print("[!] Network scan completed.")
else:
    print("[-] Invalid ip range, example: 192.168.1.0/24")