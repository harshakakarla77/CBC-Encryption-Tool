'''
author: @harshakakarla77
'''

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
import Crypto.Util.Padding as padder
from Crypto.Random import get_random_bytes

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
import read_inputs
import constants
import binascii
import base64
import time
import os

#Method for encryption
def encrypt_file(filename: str, byteFile_for_encrypt: bytes, encrypt_password: str, iterations: int, hashing_algo: str , cipher: str):
    
    print("\n")
    print("Encrypting...")
    print("Cipher:", cipher,"; " "HMAC:", hashing_algo)

    start = time.perf_counter()
  
    #Get the block size and key size defined in constants.py
    blockSize_KeySize = get_blocksize_keysize_from_cipher(cipher)

    #Generating salts for creating master, hmac, and encryption keys by generating random base64 (ASCII)
    #characters and coverting them to hexadecimal. The sizes of salts generated is 16 bytes.
    master_key_salt = binascii.hexlify(get_random_bytes(constants.SALT_SIZE)).decode() #binascii.hexlify(base64.b64encode(os.urandom(constants.SALT_SIZE))).decode()
    hmac_key_salt = binascii.hexlify(get_random_bytes(constants.SALT_SIZE)).decode() #binascii.hexlify(base64.b64encode(os.urandom(constants.SALT_SIZE))).decode()
    encryption_key_salt = binascii.hexlify(get_random_bytes(constants.SALT_SIZE)).decode() #binascii.hexlify(base64.b64encode(os.urandom(constants.SALT_SIZE))).decode()

    #Generating master key using PBKDF2
    master_key_intermediate = PBKDF2(encrypt_password, master_key_salt, blockSize_KeySize[1], count = iterations, hmac_hash_module = hashType(hashing_algo))
    master_key = binascii.hexlify(master_key_intermediate).decode()

    #Generating encryption key using PBKDF2
    encryption_key_intermediate = PBKDF2(master_key, encryption_key_salt , blockSize_KeySize[1], count = 1, hmac_hash_module = hashType(hashing_algo))
    encryption_key= binascii.hexlify(encryption_key_intermediate).decode()
        
    #Generating hmac key using PBKDF2
    hmac_key_intermediate = PBKDF2(master_key, hmac_key_salt , blockSize_KeySize[1], count = 1, hmac_hash_module = hashType(hashing_algo))
    hmac_key = binascii.hexlify(hmac_key_intermediate).decode()

    #Getting the cipher object from inputted cipher and generated encryption key
    encryption_cipher = cipherType(cipher, encryption_key)

    #Generating a random IV(initialization vector)
    ini_vec = encryption_cipher.iv

    #Padding
    padded_data = padder.pad(byteFile_for_encrypt, blockSize_KeySize[0], "pkcs7")

    #Encrypting the data
    encrypted_data = encryption_cipher.encrypt(padded_data)

    #HMAC
    iv_data_encrypted  = ini_vec + encrypted_data
    hmac = HMAC.HMAC(binascii.unhexlify(hmac_key), iv_data_encrypted, hashType(hashing_algo))
    hmac_iv_data_encrypted = hmac.digest() + iv_data_encrypted

    #Creating header
    header_combined_str = "~".join([cipher, constants.PBKDF2, hashing_algo, str(iterations), master_key_salt, hmac_key_salt, encryption_key_salt])  
    header = binascii.hexlify(header_combined_str.encode())
    encrypted_data_with_header =  header + constants.HEADER_SEPERATOR + hmac_iv_data_encrypted
        
    #Opening the file with extension and writing the encrypted byte stream into it
    file_data = open(filename + constants.FILE_EXTENSION, "wb")
    file_data.write(encrypted_data_with_header)

    encrypt_latency = time.perf_counter() - start
    print("Number of iterations:", iterations)
    print("Encryption latency:", encrypt_latency)
    print("Encryption Completed. Encrypted file name:", filename + constants.FILE_EXTENSION)
    print("\n")

#Method that returns the hashing algorithm
def hashType(hashing_algo):
    if hashing_algo == "SHA256":
        return SHA256
    else:
        return SHA512

#Method that creates the cipher object 
def cipherType(cipher, key ):
    if cipher == "AES128" or cipher == "AES256":
        return AES.new(key = binascii.unhexlify(key), mode=AES.MODE_CBC)
    else:
        return DES3.new(key = binascii.unhexlify(key), mode=DES3.MODE_CBC)


#Method that returns the block size and key size for the inputted cipher 
def get_blocksize_keysize_from_cipher(cipher: str):
    if(cipher == "AES128" or cipher == "AES256"):
        cipher_type = cipher[:3]
        cipher_length = cipher[3:]
    else:
        cipher_type = cipher[:4]
        cipher_length = cipher[4:]

    blockSize_KeySize = []

    if cipher_type=="AES":
        blockSize_KeySize.append(constants.AES_BLOCK)
    else:
        blockSize_KeySize.append(constants.DES_BLOCK)
        

    if cipher_type == "AES":
        if cipher_length == "128":
            blockSize_KeySize.append(16) #128 bits
        else:
            blockSize_KeySize.append(32) #256 bits
    else:
        blockSize_KeySize.append(24) #192 bits

    return blockSize_KeySize

if __name__ == '__main__':

    read_inputs.inp_obj.gui_encrypt() 