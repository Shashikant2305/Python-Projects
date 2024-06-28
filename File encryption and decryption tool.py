import os
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import *
from tkinter import filedialog, messagebox

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    with open(file_path, 'wb') as file:
        file.write(salt + encrypted_data)
    messagebox.showinfo("Success", "File encrypted successfully")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    salt = file_data[:16]
    encrypted_data = file_data[16:]
    key = generate_key(password, salt)
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path, 'wb') as file:
            file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted successfully")
    except Exception as e:
        messagebox.showerror("Error", "Invalid password or file is not encrypted")

def browse_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, END)
    file_entry.insert(0, file_path)

def encrypt():
    file_path = file_entry.get()
    password = password_entry.get()
    encrypt_file(file_path, password)

def decrypt():
    file_path = file_entry.get()
    password = password_entry.get()
    decrypt_file(file_path, password)

def hide_password():
    password_entry.config(show="*")

def unhide_password():
    password_entry.config(show="")

root = Tk()
root.title("File Encryption and Decryption Tool")

# Set background color
root.configure(background='#f0f0f0')

# Set font
font = ('Arial', 12)

# Create labels and entries
file_label = Label(root, text="File Path:", font=font, bg='#f0f0f0')
file_label.grid(row=0, column=0, padx=5, pady=5)

file_entry = Entry(root, width=50, font=font)
file_entry.grid(row=0, column=1, padx=5, pady=5)

browse_button = Button(root, text="Browse", command=browse_file, font=font, bg='#007bff', fg='white')
browse_button.grid(row=0, column=2, padx=5, pady=5)

password_label = Label(root, text="Password:", font=font, bg='#f0f0f0')
password_label.grid(row=1, column=0, padx=5, pady=5)

password_entry = Entry(root, width=50, font=font, show="*")
password_entry.grid(row=1, column=1, padx=5, pady=5)

hide_button = Button(root, text="Hide", command=hide_password, font=font, bg='#007bff', fg='white')
hide_button.grid(row=1, column=2, padx=5, pady=5)

unhide_button = Button(root, text="Unhide", command=unhide_password, font=font, bg='#007bff', fg='white')
unhide_button.grid(row=1, column=3, padx=5, pady=5)

encrypt_button = Button(root, text="Encrypt", command=encrypt, font=font, bg='#007bff', fg='white')
encrypt_button.grid(row=2, column=0, padx=5, pady=5)

decrypt_button = Button(root, text="Decrypt", command=decrypt, font=font, bg='#007bff', fg='white')
decrypt_button.grid(row=2, column=1, padx=5, pady=5)

# Add watermark text
watermark_label = Label(root, text="Created by Shashikant Kesharwani", font=('Arial', 10), bg='#f0f0f0', fg='#808080')
watermark_label.grid(row=3, column=0, columnspan=4, padx=5, pady=5)

root.mainloop()