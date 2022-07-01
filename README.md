# CBC Encryption Tool
An end-to-end Cipher Block Chaining encryption tool that supports three ciphers (AES128, AES256, and 3DES) and two HMACs (SHA256 and SHA512). All kinds of files (.txt, .pdf, .jpeg, .png, and so on) can be encrypted and decrypted using this tool.
## Prerequisites:
- pycryptodome Module
    - `pip install pycryptodome`
- tkinter Module
    - `pip install tk`
- Download all the files in the folder and keep them in the same workspace

## Working:
-Encryption
    - Run the `python file_encrypt.py` file on your python IDE to encrypt the input file
    - A tkinter GUI should appear with fields to enter the input
    - Select any file from disk that needs to be encrypted
    - Enter password of any length
    - Select cipher from the dropdown list
    - Select the hashing algorithm 
    - Enter the number of iterations (keep it within 10000000)
    - A .enc file will be created in the same workspace 

-Decryption
    - Run the `python file_decrypt.py` file on your python IDE to decrypt the encrypted file
    - Select the .enc file to be decrypted
    - Enter the password used for encryption
    - A dec_ prefixed file will be created in the same workspace


Iterations	    Latency(seconds)
10	            0.003636481
100	            0.004364325
1000	        0.005067538
10000	        0.013703174
100000	        0.087710984
1000000	        0.682675394
1500000	        0.995806905 (almost a second)
2000000	        1.333945136
5000000	        3.278383414
10000000	    6.561811736
