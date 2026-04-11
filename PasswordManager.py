import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog
from argon2 import PasswordHasher, exceptions

ph = PasswordHasher()

class SecureVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass Vault")
        self.root.geometry("400x400")
        self.init_db()
        self.login_screen()

    def init_db(self):
        conn = sqlite3.connect('vault.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL,
                username TEXT NOT NULL,
                hashed_password TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def login_screen(self):
        self.clear_screen()
        tk.Label(self.root, text="Master Vault Login", font=("Arial", 14, "bold")).pack(pady=20)
        self.master_entry = tk.Entry(self.root, show="*")
        self.master_entry.pack(pady=10)
        tk.Button(self.root, text="Unlock", command=self.verify_master).pack(pady=20)

    def verify_master(self):
        if self.master_entry.get() == "Arshad_2026":
            self.main_menu()
        else:
            messagebox.showerror("Denied", "Incorrect Master Password")

    def main_menu(self):
        self.clear_screen()
        tk.Label(self.root, text="Credential Manager", font=("Arial", 14)).pack(pady=10)
        tk.Button(self.root, text="Add New Entry", command=self.add_entry).pack(fill='x', padx=50, pady=5)
        tk.Button(self.root, text="Search Vault", command=self.search_vault).pack(fill='x', padx=50, pady=5)
        tk.Button(self.root, text="Logout", command=self.login_screen).pack(fill='x', padx=50, pady=20)

    def add_entry(self):
        service = simpledialog.askstring("Input", "Service Name:")
        user = simpledialog.askstring("Input", "Username:")
        pwd = simpledialog.askstring("Input", "Password:", show="*")
        
        if service and user and pwd:
            hashed = ph.hash(pwd)
            conn = sqlite3.connect('vault.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO credentials (service, username, hashed_password) VALUES (?, ?, ?)', 
                           (service, user, hashed))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", f"Saved {service} details!")

    def search_vault(self):
        query = simpledialog.askstring("Search", "Enter Service Name:")
        if query:
            conn = sqlite3.connect('vault.db')
            cursor = conn.cursor()
            cursor.execute('SELECT username FROM credentials WHERE service LIKE ?', ('%' + query + '%',))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                messagebox.showinfo("Result", f"Username for {query}: {result}")
            else:
                messagebox.showwarning("Not Found", "No matching service found.")

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureVaultApp(root)
    root.mainloop()
