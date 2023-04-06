#! /usr/bin/env python3

from Cryptography.encrypt import encrypt_file
from Cryptography.decrypt import decrypt_file


def main():
    while True:
        # Display menu options and get user choice
        print("\nMENU")
        print("1. Encrypt file")
        print("2. Decrypt file")
        print("3. Exit")
        choice = input("Enter choice (1, 2, or 3): ")

        if choice == "1":
            encrypt_file()
        elif choice == "2":
            decrypt_file()
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
