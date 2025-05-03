import os
import smtplib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

# Global Settings
SEGMENTS_DIR = os.path.join(os.getcwd(), "Segments")
INFOS_DIR = os.path.join(os.getcwd(), "Infos")
KEY_FILE = 'Original.key'
ACCESS_LIST = 'allowed_users.txt'

EMAIL_SETTINGS = {
    'sender_email': 'your_email@example.com',
    'sender_password': 'your_email_password',  # App password recommended
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587
}

# Utility Functions
def pad(content, block_size):
    padding_needed = block_size - (len(content) % block_size)
    return content + (b' ' * padding_needed)

def encrypt_file(filepath, algorithm, key, iv=None, block_size=16):
    with open(filepath, "rb") as f:
        content = f.read()

    if algorithm != 'Fernet':
        content = pad(content, block_size)
        cipher = Cipher(algorithm(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(content) + encryptor.finalize()
    else:
        fer = Fernet(key)
        encrypted = fer.encrypt(content)

    with open(filepath, "wb") as f:
        f.write(encrypted)

def send_key_via_email(recipient_email):
    msg = MIMEMultipart()
    msg["From"] = EMAIL_SETTINGS['sender_email']
    msg["To"] = recipient_email
    msg["Subject"] = "Your Encryption Key"
    msg.attach(MIMEText("Please find attached your encryption key for decryption.", "plain"))

    with open(KEY_FILE, "rb") as f:
        part = MIMEApplication(f.read(), Name=os.path.basename(KEY_FILE))
    part['Content-Disposition'] = f'attachment; filename="{os.path.basename(KEY_FILE)}"'
    msg.attach(part)

    try:
        with smtplib.SMTP(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port']) as server:
            server.starttls()
            server.login(EMAIL_SETTINGS['sender_email'], EMAIL_SETTINGS['sender_password'])
            server.sendmail(EMAIL_SETTINGS['sender_email'], recipient_email, msg.as_string())
            print(f"[+] Key sent successfully to {recipient_email}")
    except Exception as e:
        print(f"[!] Failed to send email to {recipient_email}: {e}")

def AES(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "0")
    with open(path, "rb") as f:
        content = f.read()

    content = pad(content, 16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(content) + encryptor.finalize()

    with open(path, "wb") as f:
        f.write(encrypted)

def BlowFish(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "1")
    with open(path, "rb") as f:
        content = f.read()

    content = pad(content, 8)
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(content) + encryptor.finalize()

    with open(path, "wb") as f:
        f.write(encrypted)

def TrippleDES(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "2")
    with open(path, "rb") as f:
        content = f.read()

    content = pad(content, 8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(content) + encryptor.finalize()

    with open(path, "wb") as f:
        f.write(encrypted)

def IDEA(key, iv):
    path = os.path.join(os.getcwd(), "Segments", "3")
    with open(path, "rb") as f:
        content = f.read()

    content = pad(content, 8)
    cipher = Cipher(algorithms.IDEA(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(content) + encryptor.finalize()

    with open(path, "wb") as f:
        f.write(encrypted)

def EFernet(key):
    path = os.path.join(os.getcwd(), "Segments", "4")
    with open(path, "rb") as f:
        content = f.read()

    fer = Fernet(key)
    encrypted = fer.encrypt(content)

    with open(path, "wb") as f:
        f.write(encrypted)

# Main Hybrid Encryption Flow
def HybridCryptKeys():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)

    if not os.path.exists(INFOS_DIR):
        os.makedirs(INFOS_DIR)

    fer = Fernet(key)
    for filename in os.listdir(INFOS_DIR):
        filepath = os.path.join(INFOS_DIR, filename)
        encrypt_file(filepath, algorithm='Fernet', key=key)

    if os.path.exists(ACCESS_LIST):
        with open(ACCESS_LIST, 'r') as file:
            authorized_emails = file.read().splitlines()

        for email in authorized_emails:
            send_key_via_email(email)

# Specific Encryptors for Segments
def Segment(key, iv):
    segments_algorithms = [
        (0, algorithms.AES, 16),
        (1, algorithms.Blowfish, 8),
        (2, algorithms.TripleDES, 8),
        (3, algorithms.IDEA, 8),
        (4, 'Fernet', None)
    ]

    for index, algo, block_size in segments_algorithms:
        filepath = os.path.join(SEGMENTS_DIR, str(index))
        if os.path.exists(filepath):
            if algo == 'Fernet':
                encrypt_file(filepath, algorithm='Fernet', key=key)
            else:
                encrypt_file(filepath, algorithm=algo, key=key, iv=iv, block_size=block_size)
        else:
            print(f"[!] Warning: Segment file {index} not found!")

