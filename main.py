from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
import base64
import hashlib
import os
load_dotenv()

# Variables for KEYS
key_a = os.getenv('KEY_A')
key_b = os.getenv('KEY_B')
key_c = os.getenv('KEY_C')
key_d = os.getenv('KEY_D')
key_e = os.getenv('KEY_E')
key_f = os.getenv('KEY_F')
key_g = os.getenv('KEY_G')
# Salt used by crypto-js (fixed value)
CRYPTOJS_SALT = b"Salted__"

# Key and IV derivation function (matches crypto-js behavior)
def derive_key_and_iv(key, salt):
    # Derive key and IV using OpenSSL's EVP_BytesToKey function
    derived = b''
    while len(derived) < 48:  # 32 bytes for key + 16 bytes for IV
        md5 = hashlib.md5()
        md5.update(derived[-16:] + key.encode('utf-8') + salt)
        derived += md5.digest()
    return derived[:32], derived[32:48]  # 32-byte key, 16-byte IV

# Encrypt text using AES (compatible with crypto-js)
def encrypt_aes(text, key):
    # Generate a random 8-byte salt
    salt = get_random_bytes(8)
    # Derive key and IV
    derived_key, iv = derive_key_and_iv(key, salt)
    # Create AES cipher in CBC mode
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    # Pad the text to be a multiple of 16 bytes
    padded_text = pad(text.encode('utf-8'), AES.block_size)
    # Encrypt the text
    encrypted_bytes = cipher.encrypt(padded_text)
    # Combine salt and encrypted text, then encode in Base64
    combined = CRYPTOJS_SALT + salt + encrypted_bytes
    return base64.b64encode(combined).decode('utf-8')

# Decrypt text using AES (compatible with crypto-js)
def decrypt_aes(encrypted_base64, key):
    try:
        # Decode the Base64-encoded string
        combined = base64.b64decode(encrypted_base64)
        # Extract the salt (8 bytes after "Salted__")
        salt = combined[8:16]
        # Extract the encrypted text
        encrypted_bytes = combined[16:]
        # Derive key and IV
        derived_key, iv = derive_key_and_iv(key, salt)
        # Create AES cipher in CBC mode
        cipher = AES.new(derived_key, AES.MODE_CBC, iv)
        # Decrypt the text
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        # Unpad the decrypted text
        unpadded_text = unpad(decrypted_bytes, AES.block_size)
        return unpadded_text.decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}"

def get_started():
    print("Choose the key you want to use below: \nA = " + key_a + "\nB = " + key_b + "\nC = " + key_c + "\nD = " + key_d + "\nFor Avega, please choose below:\nE = " + key_e + "\nF = " + key_f + "\nG = " + key_g +"")
    while True:
        selected = input("Select:")
        if selected == "A":
            key = key_a
            break
        elif selected == "B":
            key = key_b
            break
        elif selected == "C":
            key = key_c
            break
        elif selected == "D":
            key = key_d
            break
        elif selected == "E":
            key = key_e
            break
        elif selected == "F":
            key = key_f
            break
        elif selected == "G":
            key = key_g
            break
        else:
            print("Invalid input!")
    while True:
        selected_2 = input("Choose 1 - Encrypt , 2 - Decrypt: ")
        if selected_2 == "1":
            plaintext = input("Enter plaintext:")
            encrypted_text = encrypt_aes(plaintext,key)
            print("\nEncrypted: ", encrypted_text)
            break
        elif selected_2 == "2":
            ciphertext = input("Enter ciphertext:")
            decrypted_text = decrypt_aes(ciphertext,key)
            print("\nDecrypted: ", decrypted_text)
            break
        else:
            print("Invalid input!")


get_started()