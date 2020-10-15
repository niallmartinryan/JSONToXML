#receiver.py
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from Crypto import Random
import ast
import random
import socket
import pickle
import base64

from Crypto.Cipher import AES
#
#   Decrypt AES file
#
def decrypt( enc, key):
    enc = base64.b64decode(enc)
    iv = enc[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
#
#   Unpad raw file
#
def unpad(s):
    return s[:-ord(s[len(s)-1:])]


random_generator = Random.new().read                                            # Generate Keys Public Private key pair for swap
private_key = RSA.generate(1024, random_generator)
public_key = private_key.publickey()

# declarations
xmlFile = "DecryptedXMLFile.xml"
encrypt_str = "encrypted_message="
from codecs import open

# need to edit these within the containers as they have different host
HOST = '127.0.0.1'  
PORT = 9897

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    while True:
        # wait for data to be received
        transferredMessage = s.recv(1024).decode('utf-8')
        alteredMessage = transferredMessage.replace("\r\n", '')                        # remove new line char

        if alteredMessage == "Client: OK":
            pubKeyString = "public_key=" + public_key.exportKey().decode('utf-8') + "\r"
            s.send(pubKeyString.encode('utf8'))
            print("Public key sent")


        elif encrypt_str in transferredMessage:                                 # encrypted message is received
            
            transferredMessage = transferredMessage.replace(encrypt_str, '')    # removing starting encryption string
            print("Received:\nEncrypted message = "+str(transferredMessage))

            encrypted = eval(str(transferredMessage))                           # evaluate
            decryptedPassKey = private_key.decrypt(encrypted)                   # decrypt the passKey

            print("Decrypted message = " + str(decryptedPassKey))               
            cipherFile = s.recv(1024)                                           # receive the AES encrypted file
            secretFile = decrypt(cipherFile,decryptedPassKey)                   # decrypt the file with the passKey

            with open(xmlFile,  "wb", encoding="utf-8") as file:                # Write secret XMLfile which is decrypted
                file.write(secretFile)
            file.close()

            print("SecretFile :" + str(secretFile))                             # print to console for visuals
            s.send("Server: OK".encode('utf-8'))                                # send confirmation of decryption

        elif alteredMessage == "Quit": break

    s.send("Server stopped\n".encode('utf-8'))
    print ("Server stopped")
    s.close()
