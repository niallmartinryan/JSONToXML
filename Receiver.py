#receiver.py
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import random
import socket
import pickle

random_generator = Random.new().read
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

encrypt_str = "encrypted_message="
from codecs import open
HOST = '127.0.0.1'  
PORT = 9897



with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    # s.sendall('Hello, world. IPC success!')

    while True:
    	# wait for data to be received
    	originalData = s.recv(1024).decode('utf-8')
    	copy = originalData
    	newData = originalData.replace("\r\n", '')  # remove new line char

    	if newData == "Client: OK":
    		pubKeyString = "public_key=" + public_key.exportKey().decode('utf-8') + "\r"
    		s.send(pubKeyString.encode('utf8'))
    		print("Public key sent")

    	elif encrypt_str in copy:	# encrypted message is received
    		copy = copy.replace(encrypt_str, '')
    		print("Received:\nEncrypted message = "+str(copy))


    		encrypted = eval(str(copy))
    		decrypted = private_key.decrypt(encrypted)
    		# f = open('DecryptedReceiverFile', 'wb')
    		# f.write(decrypted)
    		# f.close()

    		print("Decrypted message = " + str(decrypted))
    		print("Decrypted message = " + decrypted.decode('utf-8', 'ignore'))
    		print("Decrypted and decoded = " + str(decrypted) +"\n")
    		# print(pickle.loads(decrypted))
    		s.send("Server: OK".encode('utf-8'))



    		

    	elif newData == "Quit": break

    s.send("Server stopped\n".encode('utf-8'))
    print ("Server stopped")
    # f.close()
    s.close()
