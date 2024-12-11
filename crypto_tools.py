from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
import os


# ======== 1. KRIPTOGRAFI SIMETRIS (Fernet/AES) ========
# Generate symmetric key
def generate_symmetric_key():
    key = Fernet.generate_key()
    with open("symmetric.key", "wb") as key_file:
        key_file.write(key)
    return key


# Load symmetric key
def load_symmetric_key():
    return open("symmetric.key", "rb").read()


# Encrypt a message using symmetric key
def symmetric_encrypt(message):
    key = load_symmetric_key()
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    return encrypted_message


# Decrypt a message using symmetric key
def symmetric_decrypt(encrypted_message):
    key = load_symmetric_key()
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()


# ======== 2. KRIPTOGRAFI ASIMETRIS (RSA) ========
# Generate RSA keys (public and private)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key
    with open("private_key.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Save public key
    with open("public_key.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return private_key, public_key


# Load RSA keys
def load_rsa_keys():
    with open("private_key.pem", "rb") as private_file:
        private_key = serialization.load_pem_private_key(
            private_file.read(), password=None
        )
    with open("public_key.pem", "rb") as public_file:
        public_key = serialization.load_pem_public_key(public_file.read())
    return private_key, public_key


# Encrypt a message using public key
def rsa_encrypt(message):
    _, public_key = load_rsa_keys()
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return encrypted_message


# Decrypt a message using private key
def rsa_decrypt(encrypted_message):
    private_key, _ = load_rsa_keys()
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    return decrypted_message.decode()


# ======== 3. HASHING ========
# Generate a hash of a message
def generate_hash(message):
    hash_object = hashlib.sha256(message.encode())
    return hash_object.hexdigest()


# ======== MAIN PROGRAM ========
if __name__ == "__main__":
    print("=== Pilih Jenis Kriptografi ===")
    print("1. Kriptografi Simetris (AES)")
    print("2. Kriptografi Asimetris (RSA)")
    print("3. Hashing")
    choice = input("Masukkan pilihan (1/2/3): ")

    if choice == "1":
        print("\n=== KRIPTOGRAFI SIMETRIS ===")
        action = input("(1) Generate Key, (2) Encrypt, atau (3) Decrypt? ")
        if action == "1":
            generate_symmetric_key()
            print("Kunci simetris berhasil dibuat!")
        elif action == "2":
            message = input("Masukkan pesan untuk dienkripsi: ")
            encrypted = symmetric_encrypt(message)
            print("Pesan terenkripsi:", encrypted)
        elif action == "3":
            encrypted_message = input("Masukkan pesan terenkripsi: ").encode()
            decrypted = symmetric_decrypt(encrypted_message)
            print("Pesan terdekripsi:", decrypted)
        else:
            print("Pilihan tidak valid!")

    elif choice == "2":
        print("\n=== KRIPTOGRAFI ASIMETRIS ===")
        action = input("(1) Generate Keys, (2) Encrypt, atau (3) Decrypt ")
        if action == "1":
            generate_rsa_keys()
            print("Kunci RSA (public/private) berhasil dibuat!")
        elif action == "2":
            message = input("Masukkan pesan untuk dienkripsi: ")
            encrypted = rsa_encrypt(message)
            print("Pesan terenkripsi:", encrypted)
        elif action == "3":
            encrypted_message = input("Masukkan pesan terenkripsi (dalam byte): ").encode()
            decrypted = rsa_decrypt(eval(encrypted_message))
            print("Pesan terdekripsi:", decrypted)
        else:
            print("Pilihan tidak valid!")

    elif choice == "3":
        print("\n=== HASHING ===")
        message = input("Masukkan pesan untuk di-hash: ")
        hashed = generate_hash(message)
        print("Hash SHA-256:", hashed)

    else:
        print("Pilihan tidak valid!")
