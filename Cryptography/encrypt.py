import os
import sys
import getpass
from tqdm import tqdm
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

PASSWORD_LENGTH = 32  # length of the password in bytes


def generate_password():
    return get_random_bytes(PASSWORD_LENGTH).hex()


def enter_password():
    user_input = getpass.getpass(
        "Enter password or type '0' to generate a secure password: ")

    if user_input == "0":
        password = generate_password()

        print("Generated password:", password)
        print("Please make note of this password as it cannot be recovered once lost.")
        return password
    else:
        return user_input


def get_filename():
    filename = input("Enter filename to encrypt (with extension): ")
    if not os.path.exists(filename):
        raise FileNotFoundError(f"File '{filename}' does not exist.")
    return filename


def read_plaintext(filename):
    with open(filename, "rb") as f:
        plaintext = f.read()
    return plaintext


def derive_key_and_salt(password):
    salt = get_random_bytes(16)
    key = scrypt(password.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    return key, salt


def encrypt_data(key, salt, plaintext):
    """
    Encrypt the plaintext data and return the ciphertext, nonce, and tag
    """
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(salt)
    plaintext_padded = pad(plaintext, AES.block_size)
    ciphertext = b""
    with tqdm(total=len(plaintext_padded), unit="B", unit_scale=True) as pbar:
        for i in range(0, len(plaintext_padded), 4096):
            chunk = plaintext_padded[i:i+4096]
            ciphertext_chunk = cipher.encrypt(chunk)
            ciphertext += ciphertext_chunk
            pbar.update(len(chunk))
    tag = cipher.digest()
    nonce = cipher.nonce
    return nonce, tag, ciphertext


def save_encrypted_data_and_key(filename, salt, nonce, tag, ciphered_data, key):
    encrypted_filename = filename + ".enc"
    with open(encrypted_filename, "wb") as f:
        f.write(salt)
        f.write(nonce)
        f.write(tag)
        f.write(ciphered_data)
    key_filename = filename + ".key"
    with open(key_filename, "wb") as f:
        f.write(key)
    return encrypted_filename, key_filename


def delete_file(filename):
    os.remove(filename)
    print(f"{filename} deleted successfully.")


def encrypt_file():
    filename = get_filename()
    password = enter_password()
    key, salt = derive_key_and_salt(password)
    plaintext = read_plaintext(filename)
    nonce, tag, ciphered_data = encrypt_data(key, salt, plaintext)
    encrypted_filename, key_filename = save_encrypted_data_and_key(
        filename, salt, nonce, tag, ciphered_data, key)
    delete_file(filename)
    print(f"{filename} encrypted successfully. Key saved to {key_filename}.")
    print(f"Encrypted data saved to {encrypted_filename}.")


def main():
    try:
        encrypt_file()
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
