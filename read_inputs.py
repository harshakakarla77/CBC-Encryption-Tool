'''
author: @harshakakarla77
'''

import os
import file_encrypt
import file_decrypt
from tkinter import *
from tkinter import ttk
from tkinter.ttk import Combobox
from tkinter.messagebox import showinfo
from tkinter import filedialog as fd
from tkinter.filedialog import askopenfilename

class Read_inputs:
  
    encrypt_file_path = ""
    decrypt_file_path = ""

    encryption_input_filename = ""
    decryption_input_filename = ""

    byteFile_for_encrypt = ""
    byteFile_for_decrypt = ""

    #Method to extract the filename and read contents of the inputted file to encrypt
    def get_encryption_file_name(self):
        
        self.confirm_lbl=Label(self.window1, text="File selected", fg='orange', font=("Helvetica", 13))
        self.confirm_lbl.place(x=400, y=52)
        
        #Copying the entire path of the selected file
        self.encrypt_file_path = fd.askopenfilename(initialdir = "/")

        #Copying the name of the file to encrypt from the path
        self.encryption_input_filename = os.path.basename(self.encrypt_file_path)

        #Reading contents of the file by opening it in read mode
        with open(self.encrypt_file_path, "rb") as f:
            self.byteFile_for_encrypt = f.read()

        #The dialogbox that displays the selected file
        showinfo(
            title='Selected File',
            message=self.encrypt_file_path
        )

    #Method to extract the filename and read contents of the inputted file to decrypt
    def get_decryption_file_name(self):
        
        self.confirm_lbl1=Label(self.window2, text="File selected", fg='orange', font=("Helvetica", 13))
        self.confirm_lbl1.place(x=400, y=52)
        
        #Copying the entire path of the selected file
        self.decrypt_file_path = fd.askopenfilename(initialdir = "/")

        #Copying the name of the file to decrypt from the path
        self.decryption_input_filename = os.path.basename(self.decrypt_file_path)

        #Reading contents of the file by opening it in read mode
        with open(self.decrypt_file_path, "rb") as f:
            self.byteFile_for_decrypt = f.read()
        
        #The dialogbox that displays the selected file
        showinfo(
            title='Selected File',
            message=self.decrypt_file_path
        )

    #Method that reads all inputs required for encryption from the GUI
    def read_inputs_for_encryption(self):
        
        encrypt_password = self.pass_txtfld.get()
        cipher = self.cip_cb.get()
        algoHash = self.hash_cb.get()
        itr = int(self.iter_txtfld.get())

        self.window1.destroy()

        #Calling the encrypt_file method to perform encryption
        file_encrypt.encrypt_file(self.encryption_input_filename, self.byteFile_for_encrypt, encrypt_password, itr, algoHash, cipher)

    
    #Method that reads all inputs required for decryption from the GUI
    def read_input_for_decryption(self):

        decrypt_password = self.pass_txtfld1.get()

        self.window2.destroy()

        #Calling the decrypt_file method to perform decryption
        file_decrypt.decrypt_file(self.decryption_input_filename, self.byteFile_for_decrypt, decrypt_password)

    #Encryption GUI 
    def gui_encrypt(self):
        self.window1=Tk()
        self.window1.title('CBC Encryption')
        
        open_button1 = ttk.Button(self.window1, text='Input a File', command=inp_obj.get_encryption_file_name)
        open_button1.place(x=280 , y=50)

        btn1=Button(self.window1, text="Encrypt", fg='green', command=inp_obj.read_inputs_for_encryption)
        btn1.place(x=240, y=335)

        enc_lbl=Label(self.window1, text="Select the file for encryption:", fg='green', font=("Helvetica", 16))
        enc_lbl.place(x=60, y=50)

        pass_lbl=Label(self.window1, text="Enter the Password:", fg='green', font=("Helvetica", 16))
        pass_lbl.place(x=60, y=100)

        cip_lbl=Label(self.window1, text="Select the cipher suite:", fg='green', font=("Helvetica", 16))
        cip_lbl.place(x=60, y=150)

        hash_lbl=Label(self.window1, text="Select the hashing algorithm:", fg='green', font=("Helvetica", 16))
        hash_lbl.place(x=60, y=200)

        iter_lbl=Label(self.window1, text="Enter the number of iterations:", fg='green', font=("Helvetica", 16))
        iter_lbl.place(x=60, y=265)

        self.pass_txtfld=Entry(self.window1, show='*', bg='black', fg='white', bd=5)
        self.pass_txtfld.place(x=225, y=98)

        self.iter_txtfld=Entry(self.window1, bg='black',fg='white', bd=5)
        self.iter_txtfld.place(x=290, y=260)

        var1 = StringVar()
        var1.set("AES128")
        data=("AES128", "AES256", "3DES")
        self.cip_cb=Combobox(self.window1, values=data)
        self.cip_cb.place(x=245, y=150)

        var2 = StringVar()
        var2.set("SHA256")
        data=("SHA256", "SHA512")
        self.hash_cb=Combobox(self.window1, values=data)
        self.hash_cb.place(x=290,y=200)

        self.window1.geometry("550x400+10+20")
        self.window1.mainloop()

    #Decryption GUI
    def gui_decrypt(self):
        self.window2=Tk()
        self.window2.title('CBC Decryption')

        open_button2 = ttk.Button(self.window2, text='Input a File', command=inp_obj.get_decryption_file_name)
        open_button2.place(x=280 , y=50)

        btn2=Button(self.window2, text="Decrypt", fg='green', command=inp_obj.read_input_for_decryption)
        btn2.place(x=200, y=185)

        decr_lbl=Label(self.window2, text="Select the file for decryption:", fg='green', font=("Helvetica", 16))
        decr_lbl.place(x=70, y=50)

        pass_lb2=Label(self.window2, text="Enter the Password:", fg='green', font=("Helvetica", 16))
        pass_lb2.place(x=70, y=125)

        self.pass_txtfld1=Entry(self.window2, show='*', bg='black',fg='white', bd=5)
        self.pass_txtfld1.place(x=225, y=123)

        self.window2.geometry("510x280+10+20")
        self.window2.mainloop()

#Creating an instance of the Read_inputs class
inp_obj = Read_inputs()