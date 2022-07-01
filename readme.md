****Harshavardhan Kakarla****
****CBC Encryption Tool****

Required packages:
- pycryptodome
- tkinter

***********************ENCRYPTION*********************
Run "python file_encrypt.py" to encrypt
- Select any file from disk that needs to be encrypted
- Enter password of any length
- Select cipher from the dropdown list
- Select the hashing algorithm 
- Enter the number of iterations (keep it within 10000000)
- A .enc file will be created in the same directory 

***********************DECRYPTION*********************
Run "python file_decrypt.py" to decrypt
- Select the .enc file to be decrypted
- Enter the password used for encryption
- A dec_ prefixed file will be created in the same directory


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
