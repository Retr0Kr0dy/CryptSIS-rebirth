# <b><u>THIS REPO IS DEPRECATED.</b></u>

# CryptSIS-rebirth

## Last Updates

Adding Args comprehension

## Summary

- ### [What is it ?](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#what-is-it)

- ### [Requirements](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#requirements)

- ### [Ciphers](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#ciphers-1)

  - #### [SHA256/utf-8](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#sha256utf-8-1)
  
  - #### [Blowfish](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#blowfish-1)
  
  - #### [AES-256-CBC](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#aes-256-cbc-1)
  
  - #### [RSA](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#rsa-1)

  - #### [AES-RSA](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#aes-rsa)

- ### [Working with folder](https://github.com/Retr0Kr0dy/CryptSIS-rebirth#aes-rsa)

# What is it

CryptSIS is a project that serve one cause, and it's the encryption/decryption process.

The main goal of this project is for me to create a " module " that I can use to improve
my developers, cryptography, blue teaming (or red, it depends on the mood) skills.


And in a second time as an encryption tool for working with data as ssh keypair or any 
delicate data.


#### ⚠️⚠️This module should never be used as production encryptor and never be trusted as fully-sercured; sandboxing purpose only.⚠️⚠️

## Requirements

  - [Python 3.9](https://www.python.org/downloads/)
  
  - [Blowfish lib](https://pypi.org/project/blowfish/)
  
  - [PyCryptodome lib](https://pypi.org/project/pycryptodome/)
  
  - [Cryptography lib](https://pypi.org/project/cryptography/)

# Commands

## Options :
``` 
-c              Ciphers selections ( XOR | BLOW | AES | RSA )
-e              Encrypt 
-d              Decrypt 
-k              Key file name
-kG             KeyGen generate key
-s              Size for key generation ( 1024 | 2048 | 3072 | 4096 )
-i              Input file name
-o              Output file name
-h              Print help pages
-u              Print usage pages
```

## Usage :

### For main()

Main can only print usage or hop to cipher selection.

So, `cryptsis -u` for printing the main usage of the script, and `cryptsis -c < XOR | BLOW | AES | RSA >` followed by specific options depending on the cipher.

### For Xor()

XOR-SHA256/utf-8 by it's way of working don't need to generate keyfile so simply type `cryptsis -c XOR -i <input file to encrypt/decrypt> -o <output file name> -k <key as word>`, you just got to remind about the word you used to encrypt your file.

### For Blow()

For BLOWFISH, you firstly need to generate key file with `cryptsis -c BLOW -kG -o <output file name>`, then simply use this key to encrypt `cryptsis -c BLOW -e -i <input file to encrypt/decrypt> -o <output file name> -k <key as word>` or to decrypt `cryptsis -c BLOW -d -i <input file to encrypt/decrypt> -o <output file name> -k <key as word>`.

### For Aes()

Same as BLOWFISH, for AES, you firstly need to generate key file with `cryptsis -c AES -kG -o <output file name>`, then simply use this key to encrypt `cryptsis -c AES -e -i <input file to encrypt/decrypt> -o <output file name> -k <key as word>` or to decrypt `cryptsis -c AES -d -i <input file to encrypt/decrypt> -o <output file name> -k <key as word>`.

### For Aes()

For RSA, you need to generate key files but you also have to choose key leght size ( [more info](https://github.com/Retr0Kr0dy/CryptSIS-rebirth/#rsa-1) ) with `cryptsis -c RSA -kG -o <output file name> -s < 1024 | 2048 | 3072 | 4096 >`, then simply use this key to encrypt `cryptsis -c RSA -e -i <input file to encrypt/decrypt> -o <output file name> -k <public key>` or to decrypt `cryptsis -c RSA -d -i <input file to encrypt/decrypt> -o <output file name> -k <private key>`.

# Ciphers

## SHA256/utf-8

### Usage :

```
First, you got to specify wich file you want to encrypt, then you specify 
the name of the output file, last you got to enter the key you want to use 
in raw text (you can't save the key).
```

### Functioning :

```
Simple XOR operation;

      raw_text = 1 0 1 0 0 1 (random binary value)    
           key = 0 1 1 0 1 0 (random binary value)    
  encrypt_text = 0 0 1 1 0 0 (1;1=1 0;0=1 1;0=0 0;1=0)
           key = 0 1 1 0 1 0 (random binary value)    
  decrypt_text = 1 0 1 0 0 1 (same math)              
                                                       
As you can see, data came back to it's original state by being run through 
the key a second time.     
```

## Blowfish

### Usage :

```
First, you got to specify wich file you want to encrypt,then you specify 
the name of the output file, last you got to create a key file or use an 
existant key file.  
```

### Functioning :

```
Blowfish a block cipher, meaning that it divides a message up into fixed 
length blocks during encryption and decryption. 
```

## AES-256-CBC

### Usage :

```
First, you got to specify wich file you want to encrypt, then you specify 
the name of the output file, last you got to create a key file or use an 
existant key file.    
```

### Functioning :

```
The AES algorithm (also known as the Rijndael algorithm) is a symmetrical block 
cipher algorithm that takes plain text in blocks of 128 bits and converts them to 
ciphertext using different size keys.
```

## RSA

### Usage :

```
[1024 bits key = 62 bytes data]
[2048 bits key = 190 bytes data]
[3072 bits key = 318 bytes data]
[4096 bits key = 446 bytes data]

First, you got to generate a RSA private and a RSA public key.

For encryption, you got to specify the name of the file you want to encrypt, 
select the RSA public key to encrypt the data.

For decryption, you got to specify the name of the file you want to decrypt, 
select the RSA private key to decrypt the data.
```

### Functioning :

```
The RSA algorithm is an asymmetric cryptography algorithm; this means that it uses 
a public key and a private key (i.e two different, mathematically linked keys). 
As their names suggest, a public key is shared publicly, while a private key is secret 
and must not be shared with anyone.
```

## AES-RSA

### Usage :

```
First, the receiver of the future encrypted data got to generate an AES key, 
a RSA private and a RSA public key.

For encryption, you got to specify the name of the file you want to encrypt, 
select the AES key to encrypt the data, and then select the RSA public key 
to encrypt the AES key.

For decryption, you got to specify the name of the file you want to decrypt, 
select the encrypted AES key, and then select the RSA private key to decrypt 
the AES key.
```

### Functioning :

 #### Key Generation :
  
```
When generating keys, you got to input a name (exemple : test), then 3 file
will be create;

test_aes.key = the AES key, 32 random bytes generated by the Crypto.Random utils by pycryptodome lib

test_private_key.pem = the RSA private key, generated by crpytography lib (.PEM format (----BEGIN PRIVATE KEY-----))

test_public_key.pem = the RSA public key, generated with the RSA private key by crpytography lib (.PEM format (----BEGIN PUBLIC KEY-----))
```

#### File Encryption :
  
```
When encrypting a file, the file is encrypted with the AES-256-CBC cipher, 
then the AES key used is encrpyted with the RSA public key of the receiver
(previously send by the receiver).

The sender push the encrypted data and the encrypted AES key to the receiver.
```

   #### File Decryption :
  
```
When decrypting, the AES key is decrypted with the receiver's RSA private key
Then the encrypted data is decrypted by the AES key.
```

# Working with folder :

```
There is different way to work with encrypting a folder, for now, CryptSIS only 
proposing a target by target working environement (it means it would list all 
files in a folder and work with each of them idependently).

Other way to do it are faster and much more secure, but it's only a time miner 
for people who need to fastly encrypt a bunch of key.
In the case you have a lot of data to work with (like 1Tb to encrypt), 
a better way is to make an archive of the folder want to encrypt, 
and then encrypt the archive.
```
