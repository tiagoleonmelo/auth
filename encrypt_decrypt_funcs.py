import os
import sys
from getpass import getpass
import json
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES3
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import SHA256, SHA512


## Adapts pwd to a key of a certain size
def keyGen(size, pwd, salt=None):

	backend = default_backend()
	
	if salt==None:
		salt=b'10'
	# derive
	
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=size, salt=salt, iterations=100000, backend=backend)
	key = kdf.derive(pwd)
	return key


## Decrypts txt using algoritmo in mode mode, with IV iv and key pwd
def decrypt(algoritmo, mode, txt, iv, pwd):
	
	if algoritmo == '3DES':
		key= keyGen(24, pwd)
		if mode=='CBC':
			m=DES3.MODE_CBC
			cipher = DES3.new(key, m,iv)
		if mode=='ECB':
			m=DES3.MODE_ECB
			cipher = DES3.new(key, m)
		data = unpad(cipher.decrypt(txt), DES3.block_size)

			
	elif algoritmo == 'AES-128':
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key=keyGen(16, pwd)
		cipher = AES.new(key, m, iv)
		data = unpad(cipher.decrypt(txt), AES.block_size)
		
			
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)	
				
	return data


## Encrypts txt using algoritmo in mode mode and key pwd, returns encrypted data and IV
def encrypt(algoritmo, mode, txt, pwd):
	
	iv = secrets.token_bytes(16)

	if algoritmo == '3DES':
		key= keyGen(24, pwd)
		iv = secrets.token_bytes(8)
		if mode=='CBC':
			m=DES3.MODE_CBC
			cipher = DES3.new(key, m,iv)
		if mode=='ECB':
			m=DES3.MODE_ECB
			cipher = DES3.new(key, m)
		text= pad(txt,DES3.block_size)


			
	elif algoritmo == 'AES-128':
		if mode=='CBC':
			m=AES.MODE_CBC
		if mode=='GCM':
			m=AES.MODE_GCM
		key= keyGen(16, pwd)
		cipher = AES.new(key, m, iv)
		text=pad(txt,AES.block_size)
	
	else:
		print("Algoritmo nao suportado. Aborting..")
		sys.exit(0)


	encrypted = cipher.encrypt(text)
	
	return encrypted, iv


## Hashes data using algoritmo
def sintese(algoritmo, data):

	if algoritmo == "SHA-256":
		h = SHA256.new(data)

	elif algoritmo == "SHA-512":
		h = SHA512.new(data)

	else:
		print("ERROR: Unsupported algorithm")
		sys.exit(0)

	return h.hexdigest()