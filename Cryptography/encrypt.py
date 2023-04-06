import os
import sys
import getpass
from tqdm import tqdm
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes


def encrypt_file():
    # Get filename and password from user
    filename = input("Enter filename to encrypt (with extension): ")
    password = getpass.getpass("Enter password to use for encryption: ")

    # Generate a random salt and derive key from password using scrypt
    salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)

    # Read the plaintext from file and encrypt it
    if not os.path.exists(filename):
        print(f"Error: File '{filename}' does not exist.")
        return
    filesize = os.path.getsize(filename)
    with open(filename, "rb") as f:
        plaintext = f.read()
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(salt)
    with tqdm(total=filesize, unit="B", unit_scale=True, desc="Encrypting", file=sys.stdout) as pbar:
        ciphered_data, tag = b"", b""
        for i in range(0, len(plaintext), 4096):
            chunk = plaintext[i:i+4096]
            ciphertext_chunk, tag = cipher.encrypt_and_digest(
                pad(chunk, AES.block_size))
            ciphered_data += ciphertext_chunk
            pbar.update(len(chunk))

    # Save the encrypted data, along with the salt and tag, to a new file
    encrypted_filename = filename + ".enc"
    with open(encrypted_filename, "wb") as f:
        f.write(salt)
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphered_data)

    # Save the key to a separate file
    key_filename = filename + ".key"
    with open(key_filename, "wb") as f:
        f.write(key)

    print(f"{filename} encrypted successfully. Key saved to {key_filename}")
