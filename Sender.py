#sender.py

import json as JS
import dicttoxml
import xml.etree.ElementTree as ET
import socket

import hashlib
import os
import pickle

# encryption
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from codecs import open

HOST = '127.0.0.1'  # loopback
PORT = 9897   # listen on


#converting the JSON to XML
jsonFile = 'JsonExample.json'
xmlFile = 'XMLExample.xml'
data = ''

with open(jsonFile, "r") as json_file:
	data = JS.load(json_file);

# data = readfromstring(data)
data = dicttoxml.dicttoxml(data)
# data = json2xml.Json2xml(data).to_xml()


#-------------- REQUIRED -------------
# with open(xmlFile, 'w', encoding="utf-8") as f:
# 	f.write(data.decode('utf-8'))
# f.close()


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
	s.bind((HOST, PORT))
	s.listen()
	conn, addr = s.accept()
	with conn:

		st = "Client: OK"
		byts = st.encode('utf-8')
		conn.sendall(byts)

		serverString = conn.recv(1024).decode('utf-8')
		# remove extra characters
		serverString = serverString.replace("public_key=", '')
		serverString = serverString.replace("\r\n", '')

		# convert String to a key
		serverPublicKey = RSA.importKey(serverString)


		fileData = ""
		with open(xmlFile,  "rb", encoding="utf-8") as file:
			fileData = file.read()
			print(fileData)


		#conn.sendall(fileData)
		file.close()
		# print("\n" + fileData)
		# message = pickle.dumps(fileData)
		message = fileData
		# encodedMessage = message.encode()
		# print(str(message) + "\n")
		# print(message.decode())
		message = str(fileData)
		# message = "Why hello there buddy"
		# message = str(fileData)
		print(message.encode().decode())
		encrypted = serverPublicKey.encrypt(message.encode('utf-8'), 32)


		# with open("newXMLencryptedFile.xml", "wb", encoding="utf-8") as file:
		# 	file.write(str(encrypted))
		# file.close()
		# encrypted = serverPublicKey.encrypt(message, 32)
		# encryptedString = str(encrypted).encode()
		print("\n")
		print(encrypted)
		conn.sendall(("encrypted_message="+str(encrypted)).encode('utf-8'))
		# conn.sendall(("encrypted_message="+str(encrypted)).encode())           	




		conn.close()

	s.close()