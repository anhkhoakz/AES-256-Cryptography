#! /usr/bin/env python3

from Cryptography.encrypt import encrypt_file
from Cryptography.decrypt import decrypt_file


def main():
    options = {
        "1": encrypt_file,
        "2": decrypt_file,
        "3": exit
    }

    while True:
        # Display menu options and get user choice
        print("\nMENU")
        print("1. Encrypt file")
        print("2. Decrypt file")
        print("3. Exit")
        choice = input("Enter choice (1, 2, or 3): ")

        # Call the corresponding function based on user's choice
        func = options.get(choice)
        if func:
            func()
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
