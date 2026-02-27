from src.password import *


if __name__ == '__main__':
    with open("public_key", "r") as f:
        master_key = f.read()
    user_key = input("Enter your user key: ")
    site_key = input("Enter your site key: ")

    entropy = derive_password(master_key, user_key, site_key)
    print(sanitize_password(entropy))

