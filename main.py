from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def pad(data):
    "Pads the data to be encrypted"
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

def unpad(data):
    "Removes padding from decrypted data"
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

def generate_key():
    return os.urandom(32)

def AES_encrypt(key, data):
    "Encrypt data using AES algorithm"
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padded_data = pad(data)
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data

def AES_decrypt(key, data):
    backend = default_backend()
    iv = data[:16]  # Initialization Vector (IV) is the first 16 bytes
    encrypted_data = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadded_data = unpad(decrypted_data)
    return unpadded_data

def main():
    while True:
        print("AES encryptor and decryptor.\n[1] Encrypt\n[2] Decrypt\n[3] Exit Program")
        choice = input("Enter your choice: ")
        os.system("cls")
        if choice == "1":
            key = generate_key()
            msg = input("Enter message to encrypt: ").encode()
            encrypt_message = AES_encrypt(key, msg)
            print(f"Encrypted Message: {encrypt_message.hex()}")
            print(f"Encryption Key: {key.hex()}")
        elif choice == "2":
            encrypted_message_hex = input("Enter the encrypted message (in hex): ")
            try:
                encrypted_message = bytes.fromhex(encrypted_message_hex)
                key = bytes.fromhex(input("Enter the encryption key (in hex): "))
                decrypted_message = AES_decrypt(key, encrypted_message)
                print("Decrypted message:", decrypted_message.decode())
            except ValueError:
                print("Invalid hexadecimal input.")
            except Exception as e:
                print("Decryption error:", e)
        elif choice == "3":
            print("Exiting Programs")
            exit()
        else:
            print("Invalid numbers!")

if __name__ == "__main__":
    main()