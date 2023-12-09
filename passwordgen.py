import random
import string
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox as mb
import secrets 
import sqlite3
import bcrypt
import os
import base64
from cryptography.fernet import Fernet as f
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# global variables for the data
user_id = None
generated_password = None
db = "passwordgen.db"

# Database setup
def initialize_database(db):
    try:
        with sqlite3.connect(db) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL
                );
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    encrypted_data TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(username)
                );
            """)
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"Exception in _query: {e}")
initialize_database(db)


def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_pass = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pass, salt

def generate_salt_key(password):
    salt = os.urandom(32)  # 32-byte salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    k = kdf.derive(password.encode())
    key = base64.urlsafe_b64encode(k)
    return key, salt

def check_password(username, password):
    try:
        with sqlite3.connect(db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            stored_password = cursor.fetchone()
            if stored_password and bcrypt.checkpw(password.encode('utf-8'), stored_password[0]):
                return True
            else:
                return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def encrypt_data(data, key):
    fer = f(key)
    encrypted = fer.encrypt(data.encode('utf-8'))
    return encrypted
def decrypt_data(encrypted_data, key):
    fer = f(key)
    decrypted = fer.decrypt(encrypted_data)
    logs = decrypted.decode('utf-8').replace(' ', '\n')
    return logs

def create(username, password):
    password_hash, salt = hash_password(password)
    try:
        with sqlite3.connect(db) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                           (username, password_hash, salt))
            conn.commit()
    except sqlite3.IntegrityError:
        print("Username already exists")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
def save(username, password, data):
    key, _ = generate_salt_key(password)
    encrypted_data = encrypt_data(data, key)
    user_id = get_user_id(username)
    if user_id is None:
        print("User not found")
        return
    with sqlite3.connect(db) as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO logins (encrypted_data, user_id) VALUES (?, ?)",
                       (encrypted_data, user_id))
        conn.commit()
def get_user_id(username):
    try:
        with sqlite3.connect(db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            result = cursor.fetchone()
            return result[0] if result else None
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None
def get():
    with sqlite3.connect(db) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM logins")
        data = cursor.fetchall()
        return data
    
# App setup
root = ctk.CTk()
root.title("PassKeep")
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

# Define Frames
home_frame = ctk.CTkFrame(root)
login_frame = ctk.CTkFrame(root)
create_frame = ctk.CTkFrame(root)
password_frame = ctk.CTkFrame(root)
saved_frame = ctk.CTkFrame(root)
frames = [home_frame, login_frame, create_frame, password_frame, saved_frame]

# Helper functions for widgets
def create_and_place_button(frame, text, command, row, column, columnspan=3, pady=10, padx=10):
    button = ctk.CTkButton(frame, text=text, command=command)
    button.grid(row=row, column=column, columnspan=columnspan, pady=pady, padx=padx)
    return button
def create_and_place_entry(frame, placeholder, row, column, columnspan=3, padx=20, pady=10, show=None):
    entry = ctk.CTkEntry(frame, placeholder_text=placeholder, show=show)
    entry.grid(row=row, column=column, columnspan=columnspan, padx=padx, pady=pady)
    return entry
def create_and_place_label(frame, text, row, column, columnspan=3, padx=20, pady=10):
    label = ctk.CTkLabel(frame, text=text)
    label.grid(row=row, column=column, columnspan=columnspan, padx=padx, pady=pady)
    return label

def switch_frame(frame):
    frame.grid(row=0, column=1, sticky="nsew")
    for f in frames:
        if f != frame:
            f.grid_forget()

# Password Generation
def generate_random_string(length=25):
    characters = string.ascii_letters + string.digits + '!@#$%^&*'
    return ''.join(secrets.choice(characters) for i in range(length))
def update_password_label():
    result_label.configure(text=generate_random_string())

def handle_create_account():
    username = username_entry_create.get()
    password = password_entry_create.get()
    if username and password:
        create(username, password)
        mb.showinfo("Account", "Account created successfully!")
def handle_save_password():
    username = username_save.get()
    if username and generated_password:
        save(username, generated_password, generated_password) 
        mb.showinfo("Success", "Password saved successfully!")
    else:
        mb.showerror("Error", "Username or password is missing.")

def show_save_password_frame(key):
    username_entry = create_entry_widget(password_frame, "Username", 0, 0)
    generated_password_label = ctk.CTkLabel(password_frame, text=generated_password, font=("Arial", 20))
    generated_password_label.grid(row=1, column=0, columnspan=3, pady=5)
    data = str(username_entry.get()) + str(generated_password)
    encrypted_data = encrypt_data(data, key)
    if encrypted_data:
        mb.showinfo("Login saved successfully!\n" + data)
    switch_frame(password_frame)
save_password_button = ctk.CTkButton(home_frame, text="Save", command=save)
save_password_button.grid(row=2, column=0, columnspan=3, pady=10, padx=10)

def login(username, password):
    try:
        with sqlite3.connect(db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
            stored_hash = cursor.fetchone()
            if stored_hash and bcrypt.checkpw(password.encode('utf-8'), stored_hash[0]):
                return True
            else:
                return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
def show_login_popup():
    login_popup = ctk.CTkToplevel(root)
    login_popup.title("Login")
    login_popup.geometry("300x200")
    username_entry = create_and_place_entry(login_popup, "Username", 1, 0)
    password_entry = create_and_place_entry(login_popup, "Password", 3, 0, show="*")
    # Login Button
    def on_login():
        username = username_entry.get()
        password = password_entry.get()
        if login(username, password):
            login_popup.destroy()
            switch_frame(home_frame)
        else:
            mb.showerror("Login Failed", "Incorrect username or password")
    login_button = create_button(login_popup, "Login", on_login, 4, 1)

    # Create Account Button
    def on_create_account():
        username = username_entry.get()
        password = password_entry.get()
        if username and password:
            create(username, password)
            mb.showinfo("Account", "Account created successfully!")
        else:
            mb.showerror("Error", "Username or password is missing.")
    create_account_button = create_button(login_popup, "Create Account", on_create_account, 5, 0, columnspan=2)

# Home Frame Widgets
result_label = ctk.CTkLabel(home_frame, text=generate_random_string(), font=("Arial", 20))
result_label.grid(row=0, column=0, columnspan=2,)
gen_password_button = ctk.CTkButton(home_frame, text="Generate New Password", command=update_password_label)
gen_password_button.grid(row=1, column=0, pady=10, padx=10)
save_password_button = ctk.CTkButton(home_frame, text="Save Password", command=show_login_popup)
save_password_button.grid(row=1, column=1, pady=10, padx=10)

# Create Account Frame Widgets
username_entry_create = ctk.CTkEntry(create_frame, placeholder_text="Username")
username_entry_create.grid(row=0, column=0, padx=20, pady=5)
password_entry_create = ctk.CTkEntry(create_frame, show="*", placeholder_text="Password")
password_entry_create.grid(row=1, column=0, padx=20, pady=5)
create_account_button = ctk.CTkButton(create_frame, text="Create Account", command=create)
create_account_button.grid(row=2, column=0, padx=10, pady=10)

# Password Save Frame Widgets
username_save_label = ctk.CTkLabel(password_frame, text="Save Logins")
username_save_label.grid(row=0, column=0, padx=20, pady=5)
username_save = ctk.CTkEntry(password_frame, placeholder_text="Username")
username_save.grid(row=1, column=0, padx=20, pady=5)

def this(key):
    username = username_save.get()
    save(username, key,generated_password) 
    switch_frame(saved_frame)
password_label = ctk.CTkLabel(password_frame, text="Password:")
password_label.grid(row=2, column=0, padx=20, pady=5)
generated_password_label = ctk.CTkLabel(password_frame, text=generated_password, font=("Arial", 20))
confirm_save_button = ctk.CTkButton(login_popup, text="Save", command=handle_save_password)
confirm_save_button.grid(row=4, column=0, padx=20, pady=10)

mylist = get()
nice_list = "\n".join(str(item) for item in mylist)
print(nice_list)


# Initialize the application on the login frame
switch_frame(home_frame)

# Run the application
root.mainloop()

/home/neo/snap/brave/common/.cache/BraveSoftware/Brave-Browser/Default/Cache/Cache_Data
