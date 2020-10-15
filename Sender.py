#sender.py
import json as JS
import dicttoxml
import xml.etree.ElementTree as ET
import socket

import base64
import hashlib
import os
import pickle

# encryption
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from codecs import open

from Crypto.Cipher import AES

from Crypto import Random
import random
import string
#
# used to get Random PassKey for AES #
#
def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

#
# Uses AES to encrypt the file with Key and IV #
#
def encrypt(raw, key):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))
#
# padding for raw data to fit block size #
#
def pad(s):
    return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)


#
HOST = '127.0.0.1'                                              # loopback
PORT = 9897                                                     # listen on

                                                        
jsonFile = 'JsonExample.json'                                   # declarations
xmlFile = 'XMLExample.xml'
data = ''

with open(jsonFile, "r") as json_file:                          # loading JSON file
    data = JS.load(json_file);

data = dicttoxml.dicttoxml(data)                                # converting it to XML

with open(xmlFile, 'w', encoding="utf-8") as f:                 # Writing new XML file
  f.write(data.decode('utf-8'))
f.close()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    # Socket
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:

        st = "Client: OK"
        byts = st.encode('utf-8')
        conn.sendall(byts)

        serverString = conn.recv(1024).decode('utf-8')              # Receiving publicKey
        # remove extra characters
        serverString = serverString.replace("public_key=", '')
        serverString = serverString.replace("\r\n", '')
        # convert String to a key
        serverPublicKey = RSA.importKey(serverString)               # Creating RSAkey


        fileData = ""
        with open(xmlFile,  "rb", encoding="utf-8") as file:        # Reading XML file
            fileData = file.read()
            print(fileData)
        file.close()

        passwordKeyToFile = get_random_string(16)                   # Create randomPasswordKey string to encrypt and send

        cipherFile = encrypt(fileData, passwordKeyToFile)           

        encrypted = serverPublicKey.encrypt(passwordKeyToFile.encode('utf-8'), 32)      # Encrypt passwordKey for AES file
        conn.sendall(("encrypted_message="+str(encrypted)).encode('utf-8'))             # Sending passwordKey
        conn.sendall(cipherFile)                                                        # Sending AES encrypted file

        response = conn.recv(1024)                                  #   Receiving confirmation of decryption
        response = response.decode()
        response = response.replace("\r\n", '')
        if response == "Server: OK":
            print ("Server decrypted message successfully")

        #Tell server to finish connection
        conn.sendall(("Quit").encode())


        conn.close()

    s.close()