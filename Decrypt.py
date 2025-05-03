import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Global Settings
SEGMENTS_DIR = os.path.join(os.getcwd(), "Segments")
INFOS_DIR = os.path.join(os.getcwd(), "Infos")
ALLOWED_USERS_FILE = 'allowed_users.txt'

# Utilities
def is_user_allowed(user_email):
    if not os.path.exists(ALLOWED_USERS_FILE):
        return False
    with open(ALLOWED_USERS_FILE, 'r') as f:
        allowed = [line.strip() for line in f.readlines()]
    return user_email in allowed

def load_key(key_path):
    if not os.path.exists(key_path):
        raise FileNotFoundError(f"Key file not found: {key_path}")
    with open(key_path, 'rb') as f:
        return f.read()

def decrypt_file(filepath, algorithm, key, iv=None):
    with open(filepath, "rb") as f:
        content = f.read()

    if algorithm != 'Fernet':
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(content) + decryptor.finalize()
    else:
        fer = Fernet(key)
        decrypted = fer.decrypt(content)

    with open(filepath, "wb") as f:
        f.write(decrypted)

# Decrypt Functions for Segments
def decrypt_segments(key, iv):
    segments_algorithms = [
        (0, algorithms.AES),
        (1, algorithms.Blowfish),
        (2, algorithms.TripleDES),
        (3, algorithms.IDEA),
        (4, 'Fernet')
    ]

    for index, algo in segments_algorithms:
        filepath = os.path.join(SEGMENTS_DIR, str(index))
        if os.path.exists(filepath):
            if algo == 'Fernet':
                decrypt_file(filepath, 'Fernet', key)
            else:
                decrypt_file(filepath, algo, key, iv)
        else:
            print(f"[!] Warning: Segment file {index} not found!")

def DAES(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "0")
    with open(path, "rb") as f:
        content = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(content) + decryptor.finalize()

    with open(path, "wb") as f:
        f.write(decrypted)

def DBlowFish(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "1")
    with open(path, "rb") as f:
        content = f.read()

    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(content) + decryptor.finalize()

    with open(path, "wb") as f:
        f.write(decrypted)

def DTrippleDES(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "2")
    with open(path, "rb") as f:
        content = f.read()

    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(content) + decryptor.finalize()

    with open(path, "wb") as f:
        f.write(decrypted)

def DIDEA(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "3")
    with open(path, "rb") as f:
        content = f.read()

    cipher = Cipher(algorithms.IDEA(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(content) + decryptor.finalize()

    with open(path, "wb") as f:
        f.write(decrypted)

def DFernet(key):
    path = os.path.join(os.getcwd(), "Segments", "4")
    with open(path, "rb") as f:
        content = f.read()

    fer = Fernet(key)
    decrypted = fer.decrypt(content)

    with open(path, "wb") as f:
        f.write(decrypted)

def HybridDeCryptKeys(key):
    if not os.path.exists(INFOS_DIR):
        raise FileNotFoundError(f"Infos directory not found: {INFOS_DIR}")

    fer = Fernet(key)
    for filename in os.listdir(INFOS_DIR):
        filepath = os.path.join(INFOS_DIR, filename)
        with open(filepath, "rb") as file:
            content = file.read()

        decrypted = fer.decrypt(content)

        with open(filepath, "wb") as file:
            file.write(decrypted)

# Main Execution
def main():
    print("🔒 Welcome to Secure Decryption Portal 🔒")

    user_email = input("📧 Enter your registered email: ").strip()

    if not is_user_allowed(user_email):
        print("[🚫] Access Denied: You are not authorized to decrypt this file.")
        return

    key_path = input("🗝️ Enter the path to your downloaded key file (e.g., ./path/Original.key): ").strip()

    try:
        key = load_key(key_path)
        iv = bytes.fromhex(input("🔑 Enter the IV (Initialization Vector) in hex (e.g., '00112233445566778899aabbccddeeff'): ").strip())

        print("\n[🔓] Starting Decryption Process...")
        decrypt_segments(key, iv)
        HybridDeCryptKeys(key)
        print("\n✅ Decryption Completed Successfully!")

    except Exception as e:
        print(f"[❌] Error during decryption: {e}")

if __name__ == "__main__":
    main()
