'''
author: @harshakakarla77
'''

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
import Crypto.Util.Padding as padder
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

from Crypto.Cipher import AES
from Crypto.Cipher import DES3
import read_inputs
import constants
import binascii
import time

#Method for decryption
def decrypt_file(decryption_input_filename: str, byteFile_for_decrypt: bytes, decrypt_password: str):
    
    print("\n")
    print("Decrypting...")

    start = time.perf_counter()

    #Getting all parameters from the encrypted file by splitting and converting back to byte stream
    header_payload = byteFile_for_decrypt.split(constants.HEADER_SEPERATOR)

    header_bytes = binascii.unhexlify(header_payload[0])
    headers = header_bytes.split(constants.HEADER_DELIMITER)

    #Header parameters
    cipher = headers[0].decode()
    kdf = headers[1].decode()
    hashing_algo = headers[2].decode()
    iterations = int(headers[3].decode())
    master_key_salt = headers[4].decode()
    hmac_key_salt = headers[5].decode()
    encryption_key_salt = headers[6].decode()

    if hashing_algo == "SHA256":
        hmac_hash = SHA256
    else:
        hmac_hash = SHA512

    if cipher == "AES128" or cipher == "AES256":
        cipher_impl = AES
    else:
        cipher_impl = DES3

    blockSize, opMode, keySize = get_blocksize_keysize_opmode_from_cipher(cipher)
    
    #Generating master, decryption, and HMAC keys
    master_key_intermediate = PBKDF2(decrypt_password, master_key_salt, keySize, count = iterations, hmac_hash_module = hmac_hash)
    master_key = binascii.hexlify(master_key_intermediate).decode()

    decryption_key_intermediate = PBKDF2(master_key, encryption_key_salt , keySize, count = 1, hmac_hash_module = hmac_hash)
    decryption_key = binascii.hexlify(decryption_key_intermediate).decode()

    hmac_key_intermediate = PBKDF2(master_key, hmac_key_salt , keySize, count = 1, hmac_hash_module = hmac_hash)
    hmac_key = binascii.hexlify(hmac_key_intermediate).decode()

    #Get payload
    payload = header_payload[1]

    #Extracting HMAC, IV, and data_encrypted
    extracted_hmac = payload[0:hmac_hash.digest_size]
    iv_data_encrypted = payload[hmac_hash.digest_size:]
    iv = iv_data_encrypted[:blockSize]
    data_encrypted = iv_data_encrypted[len(iv):]

    #Calculating HMAC
    derived_hmac = HMAC.HMAC(binascii.unhexlify(hmac_key), iv_data_encrypted, hmac_hash)

    #Validating HMAC
    if derived_hmac.digest() != extracted_hmac:
        raise ValueError("Incorrect password. Could not decrypt!")

    #Creating decryption cipher object
    dec_cipher = cipher_impl.new(key=binascii.unhexlify(decryption_key), mode=opMode, iv=iv)

    #Decrypting data
    decrypted_data_pad = dec_cipher.decrypt(data_encrypted)

    #Unpadding decrypted data
    decrypted_data = unpad(decrypted_data_pad, blockSize, "pkcs7")

    #Writing decrypted data into the file
    with open(constants.FILE_PREFIX + decryption_input_filename[0:-len(constants.FILE_EXTENSION)], "wb") as fw:
        fw.write(decrypted_data)

    decrypt_latency = time.perf_counter() - start
    
    print("Cipher:", cipher,"; " "HMAC:", hashing_algo)
    print("Number of iterations:", iterations)
    print("Decryption latency:", decrypt_latency)
    print("Decryption Completed. Decrypted file name:", constants.FILE_PREFIX + decryption_input_filename[0:-len(constants.FILE_EXTENSION)])
    print("\n")

    
#Given the cipher, this method returns the block size, key size, and operation mode
def get_blocksize_keysize_opmode_from_cipher(cipher: str):
    if(cipher == "AES128" or cipher == "AES256"):
        cipher_type = cipher[:3]
        cipher_length = cipher[3:]
    
    else:
        cipher_type = cipher[:4]
        cipher_length = cipher[4:]
    
    blockSize_KeySize_OpMode = []

    if cipher_type == "AES":
        blockSize_KeySize_OpMode.append(constants.AES_BLOCK)
        blockSize_KeySize_OpMode.append(AES.MODE_CBC)
    else:
        blockSize_KeySize_OpMode.append(constants.DES_BLOCK)
        blockSize_KeySize_OpMode.append(DES3.MODE_CBC)
    

    if cipher_type == "AES":
        if cipher_length == "128":
            blockSize_KeySize_OpMode.append(16)
        else:
            blockSize_KeySize_OpMode.append(32)
    else:
        blockSize_KeySize_OpMode.append(24)

    return blockSize_KeySize_OpMode

if __name__ == '__main__':

    read_inputs.inp_obj.gui_decrypt()