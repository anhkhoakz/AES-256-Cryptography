import os
import sys
import getpass
from tqdm import tqdm
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def decrypt_file():
    # Get filename and password from user
    filename = input("Enter filename to decrypt (with extension): ")
    password = getpass.getpass("Enter password to use for decryption: ")

    # Extract the original filename from the encrypted filename
    original_filename, extension = os.path.splitext(filename)
    if extension != ".enc":
        print(f"Error: File '{filename}' does not have the '.enc' extension.")
        return

    # Read the encrypted data, salt, tag, and nonce from the file
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' does not exist.")
        return
    filesize = os.path.getsize(filename)
    with open(filename, "rb") as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    # Read the key from a separate file
    key_filename = original_filename + ".key"
    if not os.path.exists(key_filename):
        print(f"Error: Key file '{key_filename}' does not exist.")
        return
    with open(key_filename, "rb") as f:
        key = f.read()

    # Derive key from password using scrypt
    derived_key = scrypt(password.encode(), salt,
                         key_len=32, N=2**14, r=8, p=1)

    # Decrypt the data and save it to a new file
    with tqdm(total=filesize, unit="B", unit_scale=True, desc="Decrypting", file=sys.stdout) as pbar:
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(salt)
        try:
            plaintext = b""
            for i in range(0, len(ciphertext), 4096):
                chunk = ciphertext[i:i+4096]
                plaintext_chunk = unpad(
                    cipher.decrypt_and_verify(chunk, tag), AES.block_size)
                plaintext += plaintext_chunk
                pbar.update(len(chunk))
            with open(original_filename, "wb") as f:
                f.write(plaintext)
            print(
                f"{filename} decrypted successfully. Data saved to {original_filename}")
        except ValueError:
            print("Error: Decryption failed. Invalid password?")
            return
