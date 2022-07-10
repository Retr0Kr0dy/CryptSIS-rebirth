#!/usr/bin/env python3
__author__ = 'RetR0'

VERSION = "2.0"

#importing lib
from hashlib import sha256
import hashlib
import os
import sys
import shutil
from datetime import datetime
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

def XorEncDec(file, key, output):
    i = 0
    file_to_crypt = file
    createBackup(file_to_crypt)
    output = output
    word_key = key
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
        exit(-1)

def BlowEncrypt(file, key, output):
    text = file
    createBackup(text)
    keyfile = key
    output = output
    try :
        with open (keyfile, 'rb') as f_keyfile:
            rawkey = f_keyfile.read()
        iv = bytes(rawkey[:8])
        key = bytes(rawkey [8:])
    except EnvironmentError:
        input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
        exit(-1)
    hashnsalt = blowfish.Cipher(key)
    
    with open (text, 'rb') as f_file_to_crypt:
        text_block = f_file_to_crypt.read()
    data_result = b"".join(hashnsalt.encrypt_cfb(text_block, iv))
    print ("\n")
    print (P +  "################DATA ENCRYPTED################")
    input ("\n(press enter to continue)")
    with open (output, 'wb') as f_output:
        f_output.write(data_result)
    exit(-1)

def BlowDecrypt(file, key, output):
    text = file
    createBackup(text)
    output = output
    keyfile = key

    try:
        with open (keyfile, 'rb') as f_key:
            rawkey = f_key.read()
            iv = bytes(rawkey[:8])
            key = bytes(rawkey [8:])
    except EnvironmentError:
        input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
        exit(-1)  
    hashnsalt = blowfish.Cipher(key)
    with open (text, 'rb') as f_file_to_crypt:
        text_block = f_file_to_crypt.read()
    data_result = b"".join(hashnsalt.decrypt_cfb(text_block, iv))
    print ("\n")
    print (P +  "################DATA DECRYPTED################")
    input ("\n(press enter to continue)")
    with open (output, 'wb') as f_output:
        f_output.write(data_result)
    exit(-1)

def BlowKeyGen(name):
    iv = os.urandom(8)                
    key = os.urandom(56)
    keyfile = name
    try:
        with open (keyfile, 'wb') as f_keyfile:
            f_keyfile.write(iv + key)
        exit(-1)
    except EnvironmentError:
        input (R + "\n[!]" + GR + "Error : Invalid filename (press enter to continue)")
        exit(-1)

def AesEncrypt(file, key, output):
    text = file
    createBackup(text)
    output = output
    keyfile = key
    try:
        with open (keyfile, 'rb') as f_key:
            key = f_key.read()
    except:
        print ("\n")
        input (R + "\n[!]" + GR + "Error : Keyfile not found (press enter to continue)")
        exit(-1)  
    try:
        with open (text, 'rb') as f_file_to_encrypt:
            text_block = f_file_to_encrypt.read()
    except:
        print ("\n")
        input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
        exit(-1) 

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
        exit(-1) 
    exit(-1)

def AesDecrypt(file, key, output):
    text = file
    createBackup(text)
    output = output
    keyfile = key

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
        exit(-1) 

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
        exit(-1) 
    exit(-1)

def AesKeyGen(name):
    key = get_random_bytes(32)
    keyfile = name
    try:
        with open (keyfile, 'wb') as f_keyfile:
            f_keyfile.write(key)
    except: 
        print ("\n")
        input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
        exit(-1)  

def RsaEncrypt(file, key, output):
    text = file
    createBackup(text)
    try:
        with open (text, 'rb') as f_file_to_encrypt:
            text_block = f_file_to_encrypt.read()
            print ("\n\n" + G + "---Target locked---" + W)
    except:
        print ("\n")
        input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
        exit(-1) 

    output = output
    password = key

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
        exit(-1) 
    exit(-1)

def RsaDecrypt(file, key, output):
    text = file
    createBackup(text)
    try:
        with open (text, 'rb') as f_file_to_encrypt:
            text_block = f_file_to_encrypt.read()
            print ("\n\n" + G + "---Target locked---" + W)
    except:
        print ("\n")
        input (R + "\n[!]" + GR + "Error : Invalid input/output (press enter to continue)")
        exit(-1)

    output = output
    password = key

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
        exit(-1) 
    exit(-1)

def RsaKeyGen(name, size):
    if size == '1024':
        size = 1024
    elif size == '2048':
        size = 2048
    elif size == '3072':
        size = 3072
    elif size == '4096':
        size = 4096
    else:
        print(R+"\n[!]"+W+" Wrong key size")
        exit(-1)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    key_input = name
    priv_key_file = (key_input + "_private_key.pem")
    publ_key_file = (key_input + "_public_key.pem")

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
        exit(-1)
    print ("\n")
    print (P +  "################KEYFILE CREATED###############")
    input ("\n(press enter to continue)")
    exit(-1)















def main():
    if sys.argv[1] == '-c' or sys.argv[1] == '-h' or sys.argv[1] == '-u':
        if sys.argv[1] == '-u' and len(sys.argv) == 2:
            print(usage_main)
            exit(-1)    
        if sys.argv[1] == '-c':
            if sys.argv[2] == 'XOR':
                if sys.argv[3] == '-h':
                    print(help_xor)
                    exit(-1)
                elif sys.argv[3] == '-u':
                    print(usage_xor)
                    exit(-1)
                if sys.argv[3] == '-i':
                    infile = sys.argv[4]
                    if sys.argv[5] == '-o':
                        outfile = sys.argv[6]
                        if sys.argv[7] == '-k':
                            key = sys.argv[8]
                            XorEncDec(infile, key, outfile)

            if sys.argv[2] == 'BLOW':
                if sys.argv[3] == '-h':
                    print(help_blow)
                    exit(-1)
                elif sys.argv[3] == '-u':
                    print(usage_blow)
                    exit(-1)
                elif sys.argv[3] == '-e' or sys.argv[3] == '-d':
                    if sys.argv[4] == '-i':
                        infile = sys.argv[5]
                        if sys.argv[6] == '-o':
                            outfile = sys.argv[7]
                            if sys.argv[8] == '-k':
                                key = sys.argv[9]
                                if sys.argv[3] == '-e':
                                    BlowEncrypt(infile, key, outfile)
                                if sys.argv[3] == '-d':
                                    BlowDecrypt(infile, key, outfile)
                elif sys.argv[3] == '-kG':
                    if sys.argv[4] == '-o':
                        name = sys.argv[5]
                        BlowKeyGen(name)
                        exit(-1)

            if sys.argv[2] == 'AES':
                if sys.argv[3] == '-h':
                    print(help_aes)
                    exit(-1)
                elif sys.argv[3] == '-u':
                    print(usage_aes)
                    exit(-1)
                elif sys.argv[3] == '-e' or sys.argv[3] == '-d':
                    if sys.argv[4] == '-i':
                        infile = sys.argv[5]
                        if sys.argv[6] == '-o':
                            outfile = sys.argv[7]
                            if sys.argv[8] == '-k':
                                key = sys.argv[9]
                                if sys.argv[3] == '-e':
                                    AesEncrypt(infile, key, outfile)
                                if sys.argv[3] == '-d':
                                    AesDecrypt(infile, key, outfile)
                elif sys.argv[3] == '-kG':
                    if sys.argv[4] == '-o':
                        name = sys.argv[5]
                        AesKeyGen(name)
                        exit(-1)

            if sys.argv[2] == 'RSA':
                if sys.argv[3] == '-h':
                    print(help_rsa)
                    exit(-1)
                elif sys.argv[3] == '-u':
                    print(usage_rsa)
                    exit(-1)
                elif sys.argv[3] == '-e' or sys.argv[3] == '-d':
                    if sys.argv[4] == '-i':
                        infile = sys.argv[5]
                        if sys.argv[6] == '-o':
                            outfile = sys.argv[7]
                            if sys.argv[8] == '-k':
                                key = sys.argv[9]
                                if sys.argv[3] == '-e':
                                    RsaEncrypt(infile, key, outfile)
                                if sys.argv[3] == '-d':
                                    RsaDecrypt(infile, key, outfile)
                elif sys.argv[3] == '-kG':
                    if sys.argv[4] == '-o':
                        name = sys.argv[5]
                        if sys.argv[6] == '-s':
                            size = sys.argv[7]
                            RsaKeyGen(name, size)
            print(usage_main)
            exit(-1)    
        else:
            print("CACA")
    else:
        print("not good")












#Usage page
global usage_main
usage_main = (G + """
  Usage ;

        options :
            -c      Ciphers selections ( XOR | BLOW | AES | RSA )
            -e      Encrypt 
            -d      Decrypt 
            -k      Key file name
            -kG     KeyGen generate key
            -s      Size for key generation
            -i      Input file name
            -o      Output file name
            -h      Print help pages
            -u      Print usage pages

        exemple :
            cryptsis -c AES -kG -o test                             Generate AES key file named 'test'
            cryptsis -c RSA -d -i fileA -o fileB -k key.k           Decrypt RSA 'fileA' using key.key public key, name the output 'fileB'
            cryptsis -c BLOW -h|-u                                  Print specific help/usage pages
            cryptsis -h|-u                                          Print main help/usage pages

    CrYpTsIs """ + W)

global usage_xor
usage_xor = (G + """
  Usage ;

        options :
            -k      Key word
            -i      Input file name
            -o      Output file name
            -h      Print help pages
            -u      Print usage pages
            no specific options

        exemple :
            cryptsis -c XOR -i fileA -o fileB -k bang            Encrypt/Decrypt 'fileA' to 'fileB' using secret word 'bang'
            
    CrYpTsIs """ + W)

global usage_blow
usage_blow = (G + """
  Usage ;

        options :
            -e      Encrypt 
            -d      Decrypt 
            -k      Key file name
            -kG     KeyGen generate key
            -i      Input file name
            -o      Output file name
            -h      Print help pages
            -u      Print usage pages

        exemple :
            cryptsis -c AES -kG -o test                             Generate AES key file named 'test'
            cryptsis -c AES -d -i fileA -o fileB -k key.k           Decrypt AES 'fileA' using key.key key, name the output 'fileB'
            cryptsis -c AES -h|-u                                   Print specific help/usage pages

    CrYpTsIs """ + W)

global usage_aes
usage_aes = (G + """
  Usage ;

        options :
            -e      Encrypt 
            -d      Decrypt 
            -k      Key file name
            -kG     KeyGen generate key
            -i      Input file name
            -o      Output file name
            -h      Print help pages
            -u      Print usage pages

        exemple :
            cryptsis -c AES -kG -o test                             Generate AES key file named 'test'
            cryptsis -c AES -d -i fileA -o fileB -k key.k           Decrypt AES 'fileA' using key.key key, name the output 'fileB'
            cryptsis -c AES -h|-u                                   Print specific help/usage pages

    CrYpTsIs """ + W)


global usage_rsa
usage_rsa = (G + """
  Usage ;

        options :
            -e      Encrypt 
            -d      Decrypt 
            -k      Key file name
            -kG     KeyGen generate key
            -s      Size of the key ( 1024 | 2048 | 3072 | 4096 )
            -i      Input file name
            -o      Output file name
            -h      Print help pages
            -u      Print usage pages

        exemple :
            cryptsis -c RSA -kG -o test                             Generate RSA key file named 'test'
            cryptsis -c RSA -d -i fileA -o fileB -k key.k           Decrypt RSA 'fileA' using key.key key, name the output 'fileB'
            cryptsis -c RSA -h|-u                                   Print specific help/usage pages

    CrYpTsIs """ + W)















#Help page
global help_xor
help_xor = (G + """\n                       SHA256/utf-8
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
