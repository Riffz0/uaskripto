from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt(key, plaintext):
    iv = os.urandom(8)  # Generate random IV (Initialization Vector)
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(64).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:8]  # Extract IV from ciphertext
    ciphertext = ciphertext[8:]
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(64).unpadder()
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext

# Contoh penggunaan
key = input("Masukkan kunci (32-448 bit): ").encode()
plaintext = input("Masukkan plaintext: ").encode()

encrypted_data = encrypt(key, plaintext)
decrypted_data = decrypt(key, encrypted_data)

print('Plaintext:', plaintext.decode())
print('Encrypted Data:', encrypted_data)
print('Decrypted Data:', decrypted_data.decode())
