#!/usr/bin/env python3
__author__ = 'RetR0'

VERSION = "1.6"

#importing lib
from hashlib import sha256
from os import urandom
import hashlib
import os
import sys
import shutil
from datetime import date, datetime

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
    print (O + f" Encrypt/Decrpyt Using different Ciphers, Version rebirth {VERSION}")
    print (B + " -----------------------------------------------------------" + W)

#def creating backup folder for encrypted files
def createBackup(file):
    try:
        os.mkdir(cwd + "/backup/")
    except:
        print(P + "[+]" + GR +" - Backup folder already exists" + W)    
    timestamp = str(datetime.now())[:-7]
    da = timestamp[:10]
    ti = timestamp[-8:]
    hdr = f"{da}_{ti}"
    shutil.copyfile(file, f"backup/{file}_{hdr}")

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
        version1cipher()
    if to_do == "2":
        version2cipher()
    if to_do == "3":
        version3cipher()
    if to_do == "4":
        version4cipher()
    if to_do == "5":
        version5cipher()
    if to_do in ["99", "exit", "quit", "bye"]:
        exit(-1)
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()


def version1cipher ():
    def encdec():
        i = 0
        file_to_crypt = input (B + "\n\n[?]" + GR + " - Enter the name of the file to encrypt/decrypt : " + W)
        createBackup(file_to_crypt)
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
        version1cipher()
    if to_do == "99":
        main()
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()


def version2cipher():

    def encrypt_blow():

        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to crypt : " + W)
        createBackup(text)
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

            keyfile = input (B + "\n[-]" + GR + "Enter the name of the key file to create : ")
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

        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to decrypt : " + W)
        createBackup(text)
        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)
        keyfile = input (B + "\n\n[?]" + GR + "Import a key file to use : " + W)

        try:
            with open (keyfile, 'rb') as f_key:
                rawkey = f_key.read()
                iv = bytes(rawkey[:8])
                key = bytes(rawkey [8:])
        except EnvironmentError:
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version2cipher()  
        hashnsalt = blowfish.Cipher(key)
        with open (text, 'rb') as f_file_to_crypt:
            text_block = f_file_to_crypt.read()
        data_result = b"".join(hashnsalt.decrypt_cfb(text_block, iv))
        print ("\n")
        print (P +  "################DATA DECRYPTED################")
        input ("\n(press enter to continue)")
        with open (output, 'wb') as f_output:
            f_output.write(data_result)
        version2cipher()

    os.system("clear")
    print ("\n**********************" + B + "Blowfish" + W + "***************************")
    print ("*************************************************************")
    print (P + "\n\n[+]" + GR +" - Select an option.")
    print (C + "\n  [1]" + GR +" - Encryption")
    print (C + "  [2]" + GR +" - Decryption")
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
        version2cipher()
    if to_do == "99":
        main()
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()

    
def version3cipher():

    def encrypt_aes():

        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to crypt : " + W)
        createBackup(text)
        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)
        keyfile = input (B + "\n\n[?]" + GR + "Import a key file to use or leave empty to create one : " + W)

        if len(keyfile) > 0:
            try:
                with open (keyfile, 'rb') as f_key:
                    key = f_key.read()
            except:
                print ("\n")
                input (R + "\n[!]" + GR + "Error : Keyfile not found (press enter to continue)")
                version3cipher()  
        if len(keyfile) == 0:
            key = get_random_bytes(32)
            keyfile = input (B + "\n[-]" + GR + "Enter the name of the key file to create : " + W)
            try:
                with open (keyfile, 'wb') as f_keyfile:
                    f_keyfile.write(key)
            except: 
                print ("\n")
                input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
                version3cipher()  
        try:
            with open (text, 'rb') as f_file_to_encrypt:
                text_block = f_file_to_encrypt.read()
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version3cipher() 

        cipher = AES.new(key, AES.MODE_CBC)
        data_result = cipher.encrypt(pad(text_block, AES.block_size))

        try:
            with open(output, 'wb') as f_output:
                f_output.write(cipher.iv)
                f_output.write(data_result)
                print ("\n")
                print (P +  "################DATA ENCRYPTED################")
                input ("\n(press enter to continue)")
        except: 
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version3cipher() 
        version3cipher()

    def decrypt_aes():

        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to decrypt : " + W)
        createBackup(text)
        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)
        keyfile = input (B + "\n\n[?]" + GR + "Import a key file to use : " + W)

        try:
            with open (keyfile, 'rb') as f_key:
                key = f_key.read()
        except:
            input (R + "\n[!]" + GR + "Error : Keyfile not found (press enter to continue)")
            exit (-1)
        try:
            with open (text, 'rb') as f_file_to_decrypt:
                text_block = f_file_to_decrypt.read()
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version3cipher() 

        iv = text_block [:16]
        encrypted_data = text_block [16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        data_result = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        try:
            with open(output, 'wb') as f_output:
                f_output.write(data_result)
                print ("\n")
                print (P +  "################DATA DECRYPTED################")
                input ("\n(press enter to continue)")
        except:
            print ("\n")
            input ("Error : Input/Output (press enter to continue)")
            version3cipher() 
        version3cipher()

    os.system("clear")
    print ("\n******************" + B + "AES-256-CBC (cryptodome)" + W + "*******************")
    print ("*************************************************************")
    print (P + "\n\n[+]" + GR +" - Select an option.")
    print (C + "\n  [1]" + GR +" - Encryption")
    print (C + "  [2]" + GR +" - Decryption")
    print (G + "\n  [77]" + GR +" - Help")
    print (G + "  [99]" + GR +" - Return to previous menu")
    to_do = input (B + "\n[?]" + GR +" - Please enter a number : " + W)

    if to_do == "1":
        encrypt_aes()
    if to_do == "2":
        decrypt_aes()
    if to_do == "77":
        os.system("clear")
        print(help_aes)
        input (GR + "\n(press enter to continue)" + W)
        version3cipher()
    if to_do == "99":
        main()
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()


def version4cipher():

    def encrypt_rsa():
        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to crypt : " + W)
        createBackup(text)

        try:
            with open (text, 'rb') as f_file_to_encrypt:
                text_block = f_file_to_encrypt.read()
                print ("\n\n" + G + "---Target locked---" + W)
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version4cipher() 

        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)
        password = input (B + "\n\n[?]" + GR + "Import a public key file to use : " + W)

        with open(password, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        def encryption():
            global encrypted
            encrypted = public_key.encrypt(text_block,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )        
        encryption()
        data_result = encrypted
        
        try:
            with open(output, 'wb') as f_output:
                f_output.write(data_result)
                print ("\n")
                print (P +  "################DATA ENCRYPTED################")
                input ("\n(press enter to continue)" + W)
        except: 
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version4cipher() 
        version4cipher()

    def decrypt_rsa():
        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to crypt : " + W)
        createBackup(text)
    
        try:
            with open (text, 'rb') as f_file_to_encrypt:
                text_block = f_file_to_encrypt.read()
                print ("\n\n" + G + "---Target locked---" + W)
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version4cipher() 

        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)
        password = input (B + "\n\n[?]" + GR + "Import a private key file to use : " + W)

        try:
            with open (password, 'rb') as f_keyfile:
                private_key = serialization.load_pem_private_key(
                    f_keyfile.read(),
                    password=None,
                    backend=default_backend()
                )
                print ("\n\n" + G + "---Target locked---" + W)
        except:
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")

        def decryption():
            global original_message
            original_message = private_key.decrypt(text_block,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        
        decryption()
        data_result = original_message

        try:
            with open(output, 'wb') as f_output:
                f_output.write(data_result)
                print ("\n")
                print (P +  "################DATA DECRYPTED################")
                input ("\n(press enter to continue)" + W)
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version4cipher() 
        version4cipher()

    def keygen_rsa():

        os.system("clear")
        print ("\n****************************" + B + "RSA" + W + "******************************")
        print ("*************************************************************")

        print (P + "\n\n[+]" + GR +" - Select an option.")
        print (C + "\n  [1]" + GR +" - 1024 bits")
        print (C + "  [2]" + GR +" - 2048 bits")
        print (C + "  [3]" + GR +" - 3072 bits")
        print (C + "  [4]" + GR +" - 4096 bits")
        print (G + "\n  [99]" + GR +" - Return to previous menu")
        key_type = input (B + "\n[?]" + GR +" - Please enter a number : " + W)

        if key_type == "1":
            size = 1024

        if key_type == "2":
            size = 2048

        if key_type == "3":
            size = 3072

        if key_type == "4":
            size = 4096
    
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        key_input = input (B + "\n[-]" + GR + "Enter the name of the key file to create : " + W)
        priv_key_file = (key_input + "_private_key.pem")
        publ_key_file = (key_input + "_public_key.pem")

        if key_type == "99":
            version4cipher()

        try:
            with open (priv_key_file, 'wb') as f_privkeyfile:
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                f_privkeyfile.write(pem)

            with open (publ_key_file, 'wb') as f_publkeyfile:
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                f_publkeyfile.write(pem)
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid Keyfile name (press enter to continue)")
            version4cipher()

        print ("\n")
        print (P +  "################KEYFILE CREATED###############")
        input ("\n(press enter to continue)")

    os.system("clear")
    print ("\n****************************" + B + "RSA" + W + "******************************")
    print ("*************************************************************")
    print (P + "\n\n[+]" + GR +" - Select an option.")
    print (C + "\n  [1]" + GR +" - Encryption")
    print (C + "  [2]" + GR +" - Decryption")
    print (C + "  [3]" + GR +" - KeyGen")
    print (G + "\n  [77]" + GR +" - Help")
    print (G + "  [99]" + GR +" - Return to previous menu")
    to_do = input (B + "\n[?]" + GR +" - Please enter a number : " + W)

    if to_do == "1":
        encrypt_rsa()
    if to_do == "2":
        decrypt_rsa()
    if to_do == "3":
        keygen_rsa()
    if to_do == "77":
        os.system("clear")
        print(help_rsa)
        input (GR + "\n(press enter to continue)" + W)
        version4cipher()
    if to_do == "99":
        main()
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()
    

def version5cipher():

    def encrypt_aesrsa():

        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to crypt : " + W)
        createBackup(text)

        try:
            with open (text, 'rb') as f_file_to_encrypt:
                text_block = f_file_to_encrypt.read()
                print ("\n\n" + G + "---Target locked---" + W)
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version5cipher() 

        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)
        aes_keyfile = input (B + "\n\n[?]" + GR + "Import a AES key file to use : " + W)
        name_aes_keyfile = (aes_keyfile + ".crypt")

        try:
            with open (aes_keyfile, 'rb') as f_key:
                key = f_key.read()
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Keyfile not found (press enter to continue)")
            version5cipher()
            
        rsa_public_keyfile = input (B + "\n\n[?]" + GR + "Import a RSA public key file to use : " + W)

        with open(rsa_public_keyfile, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

        cipher = AES.new(key, AES.MODE_CBC)
        data_result = cipher.encrypt(pad(text_block, AES.block_size))

        def encryption():
            global encrypted
            encrypted = public_key.encrypt(key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )        
        encryption()
        encypt_aes_key_file = encrypted
        
        try:
            with open(name_aes_keyfile, 'wb') as f_aescrypt:
                f_aescrypt.write(encypt_aes_key_file)
                print ("\n")
                print (C + "----------------KEY ENCRYPTED-----------------")
        except: 
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Key encryption falied (press enter to continue)")
            version5cipher() 

        try:
            with open(output, 'wb') as f_output:
                f_output.write(cipher.iv)
                f_output.write(data_result)
                print ("\n")
                print (P + "################DATA ENCRYPTED################")
                input ("\n(press enter to continue)" + W)
        except: 
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Encryption falied (press enter to continue)")
            version5cipher() 
        version5cipher()

    def decrypt_aesrsa():
        
        text = input (B + "\n\n[?]" + GR + "Enter the name of the file to crypt : " + W)
        createBackup(text)
        
        try:
            with open (text, 'rb') as f_file_to_decrypt:
                text_block = f_file_to_decrypt.read()
                print ("\n\n" + G + "---Target locked---" + W)
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version5cipher() 

        output = input (B + "\n\n[?]" + GR + "Enter the output file name : " + W)

        rsa_private_keyfile = input (B + "\n\n[?]" + GR + "Import a RSA private key file to use : " + W)

        with open (rsa_private_keyfile, 'rb') as f_keyfile:
            private_key = serialization.load_pem_private_key(
                f_keyfile.read(),
                password=None,
                backend=default_backend()
            )

        aes_keyfile = input (B + "\n\n[?]" + GR + "Import a " + O + "/!\ CRYPTED /!\ " + GR + "AES key file to use : " + W)

        try:
            with open (aes_keyfile, 'rb') as f_key:
                key = f_key.read()
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Keyfile not found (press enter to continue)")
            version5cipher()

        def decryption():
            global original_message
            original_message = private_key.decrypt(key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        
        decryption()
        aes_key_decrypted = original_message

        iv = text_block [:16]
        encrypted_data = text_block [16:]
        cipher = AES.new(aes_key_decrypted, AES.MODE_CBC, iv=iv)
        data_result = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        try:
            with open(output, 'wb') as f_output:
                f_output.write(data_result)
                print ("\n")
                print (P + "################DATA DECRYPTED################")
                input ("\n(press enter to continue)")
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
            version5cipher() 
        version5cipher()


    def keygen_aesrsa():
        os.system("clear")
        print ("\n****************************" + B + "RSA" + W + "******************************")
        print ("*************************************************************")

        print (P + "\n\n[+]" + GR +" - Select an option.")
        print (C + "\n  [1]" + GR +" - 1024 bits")
        print (C + "  [2]" + GR +" - 2048 bits")
        print (C + "  [3]" + GR +" - 3072 bits")
        print (C + "  [4]" + GR +" - 4096 bits")
        print (G + "\n  [99]" + GR +" - Return to previous menu")
        key_type = input (B + "\n[?]" + GR +" - Please enter a number : " + W)

        if key_type == "1":
            size = 1024

        if key_type == "2":
            size = 2048

        if key_type == "3":
            size = 3072

        if key_type == "4":
            size = 4096
    
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        key_input = input (B + "\n[-]" + GR + "Enter the name of the key file to create : " + W)
        priv_key_file = (key_input + "_private_key.pem")
        publ_key_file = (key_input + "_public_key.pem")
        aes_key_file = (key_input + "_aes.key")
        aes_key = get_random_bytes(32)
        with open (aes_key_file, 'wb') as f_keyfile:
            f_keyfile.write(aes_key)

        if key_type == "99":
            version4cipher()

        try:
            with open (priv_key_file, 'wb') as f_privkeyfile:
                pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                f_privkeyfile.write(pem)

            with open (publ_key_file, 'wb') as f_publkeyfile:
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                f_publkeyfile.write(pem)
        except:
            print ("\n")
            input (R + "\n[!]" + GR + "Error : Invalid Keyfile name (press enter to continue)")
            version4cipher()

        print ("\n")
        print (P +  "################KEYFILE CREATED###############")
        input ("\n(press enter to continue)")
    
    os.system("clear")
    print ("\n**************************" + B +"AES + RSA" + W + "**************************")
    print ("*************************************************************")
    print (P + "\n\n[+]" + GR +" - Select an option.")
    print (C + "\n  [1]" + GR +" - Encryption")
    print (C + "  [2]" + GR +" - Decryption")
    print (C + "  [3]" + GR +" - KeyGen")
    print (G + "\n  [77]" + GR +" - Help")
    print (G + "  [99]" + GR +" - Return to previous menu")
    to_do = input (B + "\n[?]" + GR +" - Please enter a number : " + W)

    if to_do == "1":
        encrypt_aesrsa()
    if to_do == "2":
        decrypt_aesrsa()
    if to_do == "3":
        keygen_aesrsa()
    if to_do == "77":
        os.system("clear")
        print(help_aesrsa)
        input (GR + "\n(press enter to continue)" + W)
        version5cipher()
    if to_do == "99":
        main()
    else:
        input (R + "\n[!]" + GR + "Error : Invalid Option (press enter to continue)")
        main()
    
        
























#help pages
global help_sha
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

global help_blow
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

global help_aes
help_aes =  (G + """\n                       AES-256-CBC
╔═══════════════════════════════════════════════════════════╗
║ Encryption/Decryption using AES-256-CBC by pyCryptodome.  ║
║ (no Authentification).                                    ║
║                                                           ║ 
║ The AES algorithm (also known as the Rijndael algorithm)  ║
║ is a symmetrical block cipher algorithm that takes plain  ║
║ text in blocks of 128 bits and converts them to           ║ 
║ ciphertext using different size keys.                     ║
║                                                           ║ 
║ Usage :                                                   ║ 
║ First, you got to specify wich file you want to encrypt,  ║
║ then you specify the name of the output file,             ║
║ last you got to create a key file or use an existant key  ║
║ file.                                                     ║
║ [more info in README.md]                                  ║
╚═══════════════════════════════════════════════════════════╝\n""")

global help_rsa
help_rsa = ( G + """\n                       RSA-XXXX
╔═══════════════════════════════════════════════════════════╗
║ Encryption/Decryption using three RSA private/public key  ║
║                                                           ║
║ 1024 bits key = 62 bytes data                             ║
║ 2048 bits key = 190 bytes data                            ║
║ 3072 bits key = 318 bytes data                            ║
║ 4096 bits key = 446 bytes data                            ║
║                                                           ║ 
║ The RSA algorithm is an asymmetric cryptography algorithm;║
║ this means that it uses a public key and a private key    ║
║ (i.e two different, mathematically linked keys). As their ║
║ names suggest, a public key is shared publicly, while a   ║
║ private key is secret and must not be shared with anyone. ║ 
║                                                           ║
║ Usage :                                                   ║ 
║ First, you got to specify wich file you want to encrypt,  ║
║ then you specify the name of the output file,             ║
║ last you got to specify public key to encrypt             ║
║ or private key decrypt.                                   ║
║ [more info in README.md]                                  ║
╚═══════════════════════════════════════════════════════════╝\n""")

global help_aesrsa
help_aesrsa = ( G + """\n                       AES+RSA
╔═══════════════════════════════════════════════════════════╗
║ Encryption/Decryption using AES-256-CBC key and RSA       ║
║ encryption for the AES key.                               ║
║                                                           ║ 
║ The AES algorithm (also known as the Rijndael algorithm)  ║
║ is a symmetrical block cipher algorithm that takes plain  ║
║ text in blocks of 128 bits and converts them to           ║ 
║ ciphertext using different size keys.                     ║
║                                                           ║ 
║ The RSA algorithm is an asymmetric cryptography algorithm;║
║ this means that it uses a public key and a private key    ║
║ (i.e two different, mathematically linked keys). As their ║
║ names suggest, a public key is shared publicly, while a   ║
║ private key is secret and must not be shared with anyone. ║ 
║                                                           ║ 
║ Usage :                                                   ║ 
║                                                           ║
║ First, you got to generate an AES key a RSA private and a ║
║ RSA public key.                                           ║
║                                                           ║
║ For encryption, you got to specify the name of the file   ║
║ you want to encrypt, select the AES key to encrypt the    ║
║ data, and then select the RSA public key to encrypt the   ║
║ AES key.                                                  ║
║                                                           ║
║ For decryption, you got to specify the name of the file   ║
║ you want to decrypt, select the encrypted AES key, and    ║
║ then select the RSA private key to decrypt the AES key.   ║
║ [more info in README.md]                                  ║
╚═══════════════════════════════════════════════════════════╝\n""")






























if __name__ == "__main__":
    main()
