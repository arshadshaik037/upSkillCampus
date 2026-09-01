from argon2 import PasswordHasher

ph = PasswordHasher()

user_password = "my_super_secret_password"
hashed_password = ph.hash(user_password)

print(f"Stored Hash: {hashed_password}")

user_login_attempt = "my_super_secret_password"

try:
    ph.verify(hashed_password, user_login_attempt)
    print("Login successful!")
except Exception:
    print("Invalid password.")
