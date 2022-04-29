#!/usr/bin/env python3
__author__ = 'RetR0'

VERSION = "1.3"

#importing lib
from hashlib import sha256
from os import urandom
import hashlib
import os
import sys
import shutil
from datetime import datetime

from hamcrest import none
import blowfish
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from Crypto import Random
import base64

#color console
W = '\033[0m' #white
R = '\033[31m' #red
G = '\033[32m' #green
O = '\033[33m' #orange
B = '\033[34m' #blue
P = '\033[35m' #purple
C = '\033[36m' #cyan
GR = '\033[37m' #grey

#creating important var
cwd = os.getcwd()

#def printing the logo
def LOGO():
    os.system("clear")
    print (B + " ___________________________________________________________")
    print (P + "*************************************************************")
    print (B + """ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗███████╗██╗███████╗
██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔════╝██║██╔════╝
██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ███████╗██║███████╗
██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ╚════██║██║╚════██║
╚██████╗██║  ██║   ██║   ██║        ██║   ███████║██║███████║
 ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   ╚══════╝╚═╝╚══════╝""")
    print (P + "*************************************************************")
    print (O + " Encrypt/Decrpyt Using different Ciphers, Version rebirth 1.0")
    print (B + " -----------------------------------------------------------" + W)

#def creating backup folder for encrypted files
def createBackup(existing_folders):
    try:
        os.mkdir(cwd + "/backup/")
    except:
        print(P + "[+]" + GR +" - Backup folder already exists" + W)
    timestamp = datetime.now()
    shutil.move(existing_folders, cwd + str(timestamp) + "-" + existing_folders)

#def main selection
def main():
    LOGO()
    print (P + "\n\n[+]" + GR +" - Select a Cipher.")
    print (C + "\n  [1]" + GR +" - SHA256/utf-8")
    print (C + "  [2]" + GR +" - Blowfish")
    print (C + "  [3]" + GR +" - AES-256-CBC")
    print (C + "  [4]" + GR +" - RSAxxxx")
    print (C + "  [5]" + GR +" - AES-256-CBC + RSAxxxx")
    print (G + "\n  [77]" + GR +" - Help")
    print (G + "  [99]" + GR +" - Exit")
    to_do = input (B + "\n[?]" + GR +" - Please enter a number : " + W)
    if to_do == "1":
        verion1cipher()
    if to_do in ["99", "exit", "quit", "bye"]:
        exit(-1)
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()

def verion1cipher ():
    os.system("clear")
    print ("\n**********************" + B + "SHA256/utf-8" + W + "***************************")
    print ("*************************************************************")
    print (P + "\n\n[+]" + GR +" - Select an option.")
    print (C + "\n  [1]" + GR +" - Encrypt/Decrypt")
    print (G + "\n  [77]" + GR +" - Help")
    print (G + "  [99]" + GR +" - Return to previous menu")
    to_do = input (B + "\n[?]" + GR +" - Please enter a number : " + W)
    if to_do == "1":
        encdec()
    if to_do == "77":
        os.system("clear")
        print(help_sha)
        input (GR + "\n(press enter to continue)" + W)
        verion1cipher()
    if to_do == "99":
        main()
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()

    def encdec():
        i = 0
        file_to_crypt = input (B + "\n\n[?]" + GR + " - Enter the name of the file to encrypt/decrypt : " + W)
        output = input (B + "\n\n[+]" + GR + "Enter the output file name : " + W)
        word_key = input (B + "\n\n[?]" + GR + "Enter the key in raw text : " + W)
        pre_keys = sha256(word_key.encode('utf-8')).digest()
        hash_keys = hashlib.sha256(pre_keys)
        hash_digest = hash_keys.hexdigest()
        keys = sha256(hash_digest.encode('utf-8')).digest()
        with open (file_to_crypt, 'rb') as f_file_to_crypt:
            text_block = f_file_to_crypt.read()
            text_block_2 = bytes()
        for i in range (len(text_block)):
            c = text_block[i]
            j = i % len(keys)
            b = bytes ([c^keys[j]])
            text_block_2 = text_block_2 + b
        with open (output, 'wb') as f_output:
            f_output.write(text_block_2)
            print ("\n")
            print (P + "###########DATA ENCRYPTED/DECRYPTED###########")
            input (GR + "\n(press enter to continue)" + W)
            main()



def version2cipher():
    os.system("clear")
    print ("\n**********************" + B + "Blowfish" + W + "***************************")
    print ("*************************************************************")
    print (P + "\n\n[+]" + GR +" - Select an option.")
    print (C + "\n  [1]" + GR +" - Encryption")
    print (C + "\n  [1]" + GR +" - Decryption")
    print (G + "\n  [77]" + GR +" - Help")
    print (G + "  [99]" + GR +" - Return to previous menu")
    to_do = input (B + "\n[?]" + GR +" - Please enter a number : " + W)
    if to_do == "1":
        encrypt_blow()
    if to_do == "2":
        decrypt_blow()
    if to_do == "77":
        os.system("clear")
        print(help_blow)
        input (GR + "\n(press enter to continue)" + W)
        verion1cipher()
    if to_do == "99":
        main()
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()

    def encrypt_blow():
        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to crypt : " + W)
        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)
        keyfile = input (B + "\n\n[?]" + GR + "Import a key file to use or leave empty to create one : " + W)
        if len(keyfile) > 0:
            iv = os.urandom(8)                
            key = os.urandom(56)
            keyfile = keyfile
            try :
                with open (keyfile, 'rb') as f_keyfile:
                    rawkey = f_keyfile.read()
                iv = bytes(rawkey[:8])
                key = bytes(rawkey [8:])
            except EnvironmentError:
                input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
                version2cipher()    
        elif len(keyfile) == 0 :
            iv = os.urandom(8)                
            key = os.urandom(56)

            keyfile = input (B + "\n[?]" + GR + "Enter the name of the key file to create : ")
            try:
                with open (keyfile, 'wb') as f_keyfile:
                    f_keyfile.write(iv + key)
            except EnvironmentError:
                input (R + "\n[!]" + GR + "Error : Invalid filename (press enter to continue)")
                version2cipher()  
        hashnsalt = blowfish.Cipher(key)
        with open (text, 'rb') as f_file_to_crypt:
            text_block = f_file_to_crypt.read()
        data_result = b"".join(hashnsalt.encrypt_cfb(text_block, iv))
        print ("\n")
        print (P +  "################DATA ENCRYPTED################")
        input ("\n(press enter to continue)")
        with open (output, 'wb') as f_output:
            f_output.write(data_result)
        version2cipher()


    def decrypt_blow():
        print("EDFKJKMFGJRGMD")


























#help pages
help_sha = (G + """\n                       SHA256/utf-8
╔═══════════════════════════════════════════════════════════╗
║ Two way encryption using simple XOR operation with a      ║
║ raw text key and SHA256/utf-8 encoding.                   ║
║                                                           ║ 
║                                                           ║ 
║ For decryption, remake the same process, this script is   ║
║ only using XOR opertaion, to make it simple ;             ║
║                                                           ║ 
║      raw_text = 1 0 1 0 0 1 (random binary value)         ║
║           key = 0 1 1 0 1 0 (random binary value)         ║
║  encrypt_text = 0 0 1 1 0 0 (1;1=1 0;0=1 1;0=0 0;1=0)     ║
║           key = 0 1 1 0 1 0 (random binary value)         ║
║  decrypt_text = 1 0 1 0 0 1 (same math)                   ║
║                                                           ║ 
║ As you can see, data came back to it original state by    ║
║ being run through the key a second time.                  ║
║                                                           ║ 
║                                                           ║ 
║ Usage :                                                   ║ 
║ First, you got to specify wich file you want to encrypt,  ║
║ then you specify the name of the output file,             ║
║ last you got to enter the key you want to use in raw text ║
║ (you can't save the key).                                 ║
║ [more info in README.md]                                  ║
╚═══════════════════════════════════════════════════════════╝\n""")

help_blow =  (G + """\n                       Blowfish
╔═══════════════════════════════════════════════════════════╗
║ Encryption/Decryption using the Blowfish Cipher.          ║
║ (no Authentification).                                    ║
║                                                           ║ 
║ Blowfish a block cipher, meaning that it divides a        ║
║ message up into fixed length blocks during encryption     ║
║ and decryption.                                           ║
║                                                           ║ 
║ Usage :                                                   ║ 
║ First, you got to specify wich file you want to encrypt,  ║
║ then you specify the name of the output file,             ║
║ last you got to create a key file or use an existant key  ║
║ file.                                                     ║
║ [more info in README.md]                                  ║
╚═══════════════════════════════════════════════════════════╝\n""")








































main()
