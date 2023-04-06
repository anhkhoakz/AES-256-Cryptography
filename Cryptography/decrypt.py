import os
import sys
import getpass
from tqdm import tqdm
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def read_encrypted_data(filename):
    """
    Read the encrypted data, salt, tag, and nonce from the file
    """
    if not os.path.exists(filename):
        raise ValueError(f"Error: File '{filename}' does not exist.")

    filesize = os.path.getsize(filename)
    with open(filename, "rb") as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    return filesize, salt, nonce, tag, ciphertext


def read_key(key_filename):
    """
    Read the key from a separate file
    """
    if not os.path.exists(key_filename):
        raise ValueError(f"Error: Key file '{key_filename}' does not exist.")

    with open(key_filename, "rb") as f:
        key = f.read()

    return key


def extract_original_filename(filename):
    """
    Extract the original filename from an encrypted filename
    """
    original_filename, extension = os.path.splitext(filename)
    if extension != ".enc":
        raise ValueError(
            f"Error: File '{filename}' does not have the '.enc' extension.")
    return original_filename


def decrypt_file_data(ciphertext, derived_key, salt, nonce, tag):
    """
    Decrypt the file data
    """
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(salt)
    plaintext = b""
    with tqdm(total=len(ciphertext), unit="B", unit_scale=True, desc="Decrypting", file=sys.stdout) as pbar:
        for i in range(0, len(ciphertext), 4096):
            chunk = ciphertext[i:i+4096]
            plaintext_chunk = unpad(
                cipher.decrypt_and_verify(chunk, tag), AES.block_size)
            plaintext += plaintext_chunk
            pbar.update(len(chunk))
    return plaintext


def delete_encrypted_files(filename):
    """
    Delete the encrypted and key files
    """
    original_filename = extract_original_filename(filename)
    key_filename = original_filename + ".key"
    os.remove(filename)
    os.remove(key_filename)
    print(f"{filename} and {key_filename} deleted successfully.")


def decrypt_data(filename, password):
    """
    Decrypt the data and save it to a new file
    """
    try:
        # Extract the original filename from the encrypted filename
        original_filename = extract_original_filename(filename)

        # Read encrypted data
        filesize, salt, nonce, tag, ciphertext = read_encrypted_data(filename)

        # Read key
        key = read_key(original_filename + ".key")

        # Derive key from password using scrypt
        derived_key = scrypt(password.encode(), salt,
                             key_len=32, N=2**14, r=8, p=1)

        # Decrypt the data and save it to a new file
        with tqdm(total=filesize, unit="B", unit_scale=True, desc="Decrypting", file=sys.stdout) as pbar:
            plaintext = decrypt_file_data(
                ciphertext, derived_key, salt, nonce, tag)
            with open(original_filename, "wb") as f:
                f.write(plaintext)
            print(
                f"{filename} decrypted successfully. Data saved to {original_filename}")

        # Delete the encrypted and key files
        delete_encrypted_files(filename)
    except ValueError as e:
        print(str(e))


def decrypt_file():
    # Get filename and password from user
    filename = input("Enter filename to decrypt (with extension): ")
    password = getpass.getpass("Enter password to use for decryption: ")

    decrypt_data(filename, password)


def main():
    try:
        decrypt_file()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
