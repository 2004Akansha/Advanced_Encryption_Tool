import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

BLOCK_SIZE = 16
KEY_SIZE = 32  # AES-256 = 256 bits = 32 bytes
SALT_SIZE = 16

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding]) * padding

def unpad(data):
    return data[:-data[-1]]

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=100000)

def encrypt_file(filename, password):
    with open(filename, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(BLOCK_SIZE)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    output_file = filename + ".enc"
    with open(output_file, 'wb') as f:
        f.write(salt + iv + ciphertext)

    print(f"[+] Encrypted: {output_file}")

def decrypt_file(filename, password):
    with open(filename, 'rb') as f:
        raw = f.read()

    salt = raw[:SALT_SIZE]
    iv = raw[SALT_SIZE:SALT_SIZE + BLOCK_SIZE]
    ciphertext = raw[SALT_SIZE + BLOCK_SIZE:]

    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    output_file = filename.replace(".enc", ".dec")
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"[+] Decrypted: {output_file}")

def main():
    print("""
Advanced AES-256 File Encryption Tool
1. Encrypt a file
2. Decrypt a file
0. Exit
""")
    choice = input("Choose an option: ")

    if choice == '1':
        file = input("Enter file path to encrypt: ").strip()
        password = input("Enter password: ").strip()
        encrypt_file(file, password)
    elif choice == '2':
        file = input("Enter file path to decrypt: ").strip()
        password = input("Enter password: ").strip()
        decrypt_file(file, password)
    elif choice == '0':
        print("Exiting...")
    else:
        print("Invalid option.")

if __name__ == "__main__":
    main()
