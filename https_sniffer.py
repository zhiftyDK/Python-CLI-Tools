import argparse
import subprocess
import shutil
import sys
import os

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=200))
parser.add_argument("-i", "--interface", help="Network interface", required=True)
parser.add_argument("-w", "--whitelist", help="Path to txt file containing urls that should be sniffed", required=True)
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()

interface, whitelistpath = args.interface, args.whitelist

whitelist = None
if whitelistpath:
    with open(whitelistpath, "r") as f:
        whitelist = f.read().splitlines()

tshark_path = None

if "nt" in os.name:
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
    print("[!] Locating tshark")
    if not os.path.exists(tshark_path):
        print("[!] Could not find tshark, download it at: https://www.wireshark.org/download.html")
        sys.exit()
    else:
        print(f"[!] Found tshark.exe at {tshark_path}")
else:
    tshark_path = "tshark"
    print("[!] Locating tshark")
    if not shutil.which("tshark"):
        print("[!] Could not find tshark download it with: apt install wireshark")
        sys.exit()
    else:
        print("[!] Found tshark")
		

command = [tshark_path, "-i", interface, "-T", "fields", "-E", "separator=|"]
fields = ["ip.src", "_ws.col.Protocol", "_ws.col.Info", "http.host", "tls.handshake.extensions_server_name", "frame.time_epoch"]
for field in fields:
	command.append("-e")
	command.append(field)

process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

print("[!] Sniffing http & https packets.")

def print_packet(columns):
    src_ip = columns[0]
    protocol = columns[1]
    info = columns[2].split(" ")
    http_host = columns[3]
    https_host = columns[4]
    epoch_time = columns[5]

    if "HTTP" in protocol:
        if "GET" in info:
            url = http_host + info[1]
            print(f"[+] Time: {epoch_time}, Source: {src_ip}, Protocol: {protocol}, Method: {info[0]}, URL: {url}")

    if "TLS" in protocol:
        if https_host:
            print(f"[+] Time: {epoch_time}, Source: {src_ip}, Protocol: {protocol}, URL: {https_host}")

try:
    for line in iter(process.stdout.readline, b""):
        columns = line.decode().strip().split("|")
        try:
            http_host = columns[3]
            https_host = columns[4]

            if whitelist:
                if len([True for url in whitelist for word in http_host.split(".")[1:-1] if word in url.split(".")[:-1]]) > 0:
                    print_packet(columns)
                if len([True for url in whitelist for word in https_host.split(".")[1:-1] if word in url.split(".")[:-1]]) > 0:
                    print_packet(columns)
            else:
                print_packet(columns)
        except:
            continue
except KeyboardInterrupt:
    print("[!] Sniffing stopped.")
    sys.exit()