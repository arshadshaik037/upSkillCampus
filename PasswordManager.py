import sqlite3
import base64
import os
import sys
from getpass import getpass
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# --- SECURITY CONFIGURATION ---
DB_NAME = "vault.db"
ph = PasswordHasher()

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derives a Fernet-compatible key from the master password."""
    # We use SHA256 KDF to ensure the key is exactly 32 bytes for Fernet
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

# --- DATABASE OPERATIONS ---
def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        # master_hash: to verify the user
        # salt: to derive the encryption key
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS config (
                master_hash TEXT,
                salt BLOB
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS secrets (
                site TEXT,
                username TEXT,
                encrypted_password TEXT
            )
        """)
        conn.commit()

def setup_account():
    print("--- Initialize Your Vault ---")
    mp = getpass("Create a Master Password: ")
    confirm = getpass("Confirm Master Password: ")
    
    if mp != confirm:
        print("Passwords do not match!")
        return
        
    salt = os.urandom(16)
    master_hash = ph.hash(mp)
    
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT INTO config VALUES (?, ?)", (master_hash, salt))
    print("Vault initialized successfully.")

def get_vault_config():
    with sqlite3.connect(DB_NAME) as conn:
        return conn.execute("SELECT master_hash, salt FROM config").fetchone()

# --- CORE FEATURES ---
def add_password(fernet):
    site = input("Enter Website: ")
    user = input("Enter Username: ")
    pwd = getpass("Enter Password to Save: ")
    
    encrypted = fernet.encrypt(pwd.encode()).decode()
    
    with sqlite3.connect(DB_NAME) as conn:
        conn.execute("INSERT INTO secrets VALUES (?, ?, ?)", (site, user, encrypted))
    print(f"Stored credentials for {site}!")

def list_passwords(fernet):
    with sqlite3.connect(DB_NAME) as conn:
        rows = conn.execute("SELECT site, username, encrypted_password FROM secrets").fetchall()
    
    if not rows:
        print("No passwords saved yet.")
        return

    print("\n--- Your Saved Passwords ---")
    for site, user, enc_pwd in rows:
        try:
            decrypted = fernet.decrypt(enc_pwd.encode()).decode()
            print(f"Site: {site:15} | User: {user:15} | Password: {decrypted}")
        except Exception:
            print(f"Error decrypting {site}")

# --- MAIN LOOP ---
def main():
    init_db()
    config = get_vault_config()

    if not config:
        setup_account()
        return

    stored_hash, salt = config
    master_pwd = getpass("Enter Master Password: ")

    try:
        ph.verify(stored_hash, master_pwd)
        print("Access Granted.")
    except VerifyMismatchError:
        print("Access Denied: Incorrect Password.")
        return

    # Create the encryption tool using the master password
    key = derive_key(master_pwd, salt)
    fernet = Fernet(key)

    while True:
        print("\n1. Add Password\n2. View Passwords\n3. Exit")
        choice = input("Choice: ")
        if choice == "1":
            add_password(fernet)
        elif choice == "2":
            list_passwords(fernet)
        elif choice == "3":
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
