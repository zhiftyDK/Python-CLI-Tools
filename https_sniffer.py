import argparse
import subprocess
import shutil
import sys
import os

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=200))
parser.add_argument("-i", "--interface", help="Network interface", required=True)
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()

interface = args.interface


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

try:
    for line in iter(process.stdout.readline, b""):
        columns = line.decode().strip().split("|")
        try:
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
        except:
            continue
except KeyboardInterrupt:
    print("[!] Sniffing stopped.")
    sys.exit()