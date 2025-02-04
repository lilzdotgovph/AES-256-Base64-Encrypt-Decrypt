from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from dotenv import load_dotenv
import re,requests
import base64
import hashlib
import os
import pyfiglet
import validators
import signal
import sys
from colorama import Fore,init
load_dotenv()

init(autoreset=True)
title_banner = pyfiglet.figlet_format("Base64 AES-256")

# Variables for KEYS
key_a = os.getenv('KEY_A')
key_b = os.getenv('KEY_B')
key_c = os.getenv('KEY_C')
key_d = os.getenv('KEY_D')
key_e = os.getenv('KEY_E')
key_f = os.getenv('KEY_F')
key_g = os.getenv('KEY_G')
key_h = os.getenv('KEY_H')
key_i = os.getenv('KEY_I')
key_j = os.getenv('KEY_J')
key_k = os.getenv('KEY_K')
key_l = os.getenv('KEY_L')
key_m = os.getenv('KEY_M')
key_n = os.getenv('KEY_N')
key_o = os.getenv('KEY_O')
key_p = os.getenv('KEY_P')
key_q = os.getenv('KEY_Q')
key_r = os.getenv('KEY_R')
key_s = os.getenv('KEY_S')
key_t = os.getenv('KEY_T')
key_u = os.getenv('KEY_U')
key_v = os.getenv('KEY_V')

note_1 = os.getenv('NOTE_1')
note_2 = os.getenv('NOTE_2')
note_3 = os.getenv('NOTE_3')
note_4 = os.getenv('NOTE_4')
note_5 = os.getenv('NOTE_5')
# Salt used by crypto-js (fixed value)
CRYPTOJS_SALT = b"Salted__"

def print_keys():
    print(f"Choose the key you want to use below: \nA = {key_a}\nB = {key_b}\nC = {key_c}\nD = {key_d}\nFor {note_1}, please choose below:\nE = {key_e}\nF = {key_f}\nG = {key_g}\nFor {note_2}, please choose below:\nH = {key_h}\nI = {key_i}\nJ = {key_j}\nK = {key_k}\nFor {note_3}\nL = {key_l}\nM = {key_m}\nN = {key_n}\n{note_4}\nO = {key_o}\nP = {key_p}\n{note_5}\nQ = {key_q}\nR = {key_r}\nS = {key_s}\nT = {key_t}\nU = {key_u}\nV = {key_v}")

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
    
def check_file(input_file):
    # Check if the file exists
    if not os.path.exists(input_file):
        print(f"{Fore.RED}Error: The file '{input_file}' does not exist.")
        return False

    # Check if the file is empty
    if os.path.getsize(input_file) == 0:
        print(f"{Fore.RED}Error: The file '{input_file}' is empty.")
        return False
    return True

def extract_encrypted_strings():
    while True:
        url = input("Provide URL:").strip()
        if not url:
            print(Fore.RED + "Error: No URL provided.")
        elif not validators.url(url):
            print(Fore.RED + "Error: Invalid URL provided.")
        else:
            print(f"URL: {url}")
            try:
                response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
                response.raise_for_status()  # Raise an error for bad status codes
                content = response.text
                print(content)
                print(Fore.GREEN + "Fetching JavaScript file successfully.")
                matches = re.findall(r'U2FsdGVkX18[A-Za-z0-9+/=]+', content)
                output_file = "Extracted_Encrypted_Strings.txt"
                o_path = os.path.abspath(output_file)
                if matches:
                    with open(output_file, 'w', encoding='utf-8') as outfile:
                        outfile.write('\n'.join(matches) + '\n')
                    print(f"{Fore.GREEN}Extracted {len(matches)} strings. Saved to {output_file}")
                    print(f"Path:{Fore.YELLOW}{o_path}")
                    exit(1)
                else:
                    print(f"{Fore.RED}No matching strings found.")

            except requests.exceptions.RequestException as e:
                print(f"{Fore.RED}Error downloading the file from the URL: {e}")
                
def set_key(selected):
    while True:
        if selected == "A":
            key = key_a
            return key
        elif selected == "B":
            key = key_b
            return key
        elif selected == "C":
            key = key_c
            return key
        elif selected == "D":
            key = key_d
            return key
        elif selected == "E":
            key = key_e
            return key
        elif selected == "F":
            key = key_f
            return key
        elif selected == "G":
            key = key_g
            return key
        elif selected == "H":
            key = key_h
            return key
        elif selected == "I":
            key = key_i
            return key
        elif selected == "J":
            key = key_j
            return key
        elif selected == "K":
            key = key_k
            return key
        elif selected == "L":
            key = key_l
            return key
        elif selected == "M":
            key = key_m
            return key
        elif selected == "N":
            key = key_n
            return key
        elif selected == "O":
            key = key_o
            return key
        elif selected == "P":
            key = key_p
            return key
        elif selected == "Q":
            key = key_q
            return key
        elif selected == "R":
            key = key_r
            return key
        elif selected == "S":
            key = key_s
            return key
        elif selected == "T":
            key = key_t
            return key
        elif selected == "U":
            key = key_u
            return key
        elif selected == "V":
            key = key_v
            return key
        elif selected == "W":
            key = key_w
            return key
        else:
            print("Invalid input!")

def encrypt_multiple():
    while True:
        input_file = input(f"Enter file name (e.g, strings.txt):")
        if check_file(input_file):
            output_file = input("Enter output file name (e.g, output.txt):")
            o_path = os.path.abspath(output_file)
            print_keys()
            choice_key = input("Select Key:")
            key = set_key(choice_key)
            try:
                with open(input_file, 'r', encoding='utf-8') as infile:
                    with open(output_file, 'w', encoding='utf-8') as outfile:
                        for line in infile:
                            encrypted_line = encrypt_aes(line.strip(), key) 
                            outfile.write(encrypted_line + '\n')  
                print(f"{Fore.GREEN}Encryption successful! Encrypted strings saved to {output_file}")
                print(f"Path:{Fore.YELLOW}{o_path}")
                exit(1)
            except Exception as e:
                print(f"{Fore.RED}Error occurred: {e}")

def decrypt_multiple():
    while True:
        input_file = input(f"Enter file name (e.g, encrypted.txt):")
        if check_file(input_file):
            output_file = input("Enter output file name (e.g, output.txt):")
            o_path = os.path.abspath(output_file)
            print_keys()
            choice_key = input("Select a Key:")
            key = set_key(choice_key)
            try:
                with open(input_file, 'r', encoding='utf-8') as infile:
                    with open(output_file, 'w', encoding='utf-8') as outfile:
                        for line in infile:
                            decrypted_line = decrypt_aes(line.strip(), key) 
                            outfile.write(decrypted_line + '\n')
                if "Error" in decrypted_line:
                    print(f"{Fore.LIGHTRED_EX}Warning: Some of the decrypted value contains error. Please try using other keys instead.")
                print(f"{Fore.GREEN}Decryption successful! Decrypted strings saved to {output_file}")
                print(f"Path:{Fore.YELLOW}{o_path}")
                exit(1)
            except Exception as e:
                print(f"{Fore.RED}Error occurred: {e}")

def encrypt_only():
    print_keys()
    choice_key = input("Select a Key:")
    key = set_key(choice_key)
    plaintext = input("Enter plaintext:")
    encrypted_text = encrypt_aes(plaintext,key)
    print(f"{Fore.LIGHTRED_EX}Warning: Please be mindful of choosing the right key for your encryption.")
    print(f"{Fore.GREEN}Encryption Successful...")
    print(f"Encrypted Text:{Fore.YELLOW}{encrypted_text}")

def decrypt_only():
    print_keys()
    choice_key = input("Select a Key:")
    key = set_key(choice_key)
    ciphertext = input("Enter ciphertext:")
    decrypted_text = decrypt_aes(ciphertext,key)
    if "Error" in decrypted_text:
        print(f"{Fore.RED}{decrypted_text} You may want to try other key instead.")
        decrypt_only()
    print(f"{Fore.GREEN}Decryption Successful...")
    print(f"Decrypted Text:{Fore.YELLOW}{decrypted_text}")
    decrypt_only()

            

def start_menu():
    print(title_banner)
    print(f"\nDisclaimer: This tool is for educational and research purposes only.\nThe developer is not liable for any damages, data loss, or other consequences resulting from its use.\nUsers are responsible for ensuring compliance with applicable laws. The tool may be updated or discontinued at any time without notice.")
    print("\nSelect options:\n1.Extract Encrypted Strings from URL\n2.Encrypt multiple strings and output in a text file.\n3.Decrypt multiple encrypted strings and output in a text file.\n4.Encrypt\n5.Decrypt\n6.Exit")
    while True:
        choice = input("Choice:")
        match choice:
            case "1":
                extract_encrypted_strings()
            case "2":
                encrypt_multiple()
            case "3":
                decrypt_multiple()
            case "4":
                encrypt_only()
            case "5":
                decrypt_only()
            case "6":
                print("Exiting Program....")
                break
            case _:
                print("Invalid input, please try again.")


def handle_keyboard_interrupt(signal, frame):
    print("\nExiting program...")
    sys.exit(0)

def handle_ctrl_z(signal, frame):
    print("\nExiting program...")
    sys.exit(0)

if __name__ == "__main__":
    try:
        while True:
            if os.path.exists('.env'):
                start_menu()
                pass
            else:
                print(f"{Fore.RED}Error: .env file does not exist inside the folder.")
                exit(1)
    except KeyboardInterrupt:
        print("\nExiting program...")
        sys.exit(0)