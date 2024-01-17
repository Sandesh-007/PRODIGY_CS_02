from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from PIL import Image
import numpy as np
import os

def encrypt_image(image_path, key):
    original_image = Image.open(image_path)
    image_array = np.array(original_image)

    # Flattening the image array and convert to bytes
    plaintext = image_array.flatten().tobytes()

    # Padding the plaintext to a multiple of the block size
    block_size = algorithms.AES.block_size // 8
    padded_plaintext = plaintext + b'\0' * (block_size - len(plaintext) % block_size)

    # Encrypting the padded plaintext
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Saving the encrypted image
    encrypted_image_path = "encrypted_image.png"
    with open(encrypted_image_path, 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

    print(f"Image encrypted successfully. Encrypted image saved at: {encrypted_image_path}")
    exit()

def decrypt_image(encrypted_image_path, key):
    with open(encrypted_image_path, 'rb') as encrypted_file:
        ciphertext = encrypted_file.read()

    # Decrypting the ciphertext
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Reshaping the plaintext to the original image array shape
    image_array = np.frombuffer(decrypted_plaintext, dtype=np.uint8)
    image_array = image_array.reshape((512, 512, 3))  # Adjust the shape based on your image dimensions

    # Creating a new image from the decrypted array
    decrypted_image = Image.fromarray(image_array)

    # Saving the decrypted image
    decrypted_image_path = "decrypted_image.png"
    decrypted_image.save(decrypted_image_path)
    print(f"Image decrypted successfully. Decrypted image saved at: {decrypted_image_path}")
    exit()

def main():
    while True:
        print("Select an option:")
        print("e - Encrypt image")
        print("d - Decrypt image")
        print("q - Quit")
        choice = input("Your choice: ")

        if choice == 'e':
            encrypt_choice()
        elif choice == 'd':
            decrypt_choice()
        elif choice == 'q':
            print("Quitting the program.")
            exit()
        else:
            print("Invalid choice. Please choose 'e' for encryption, 'd' for decryption, or 'q' to quit.")

def encrypt_choice():
    key = os.urandom(32)  # Generate a random 256-bit key
    image_location = input("Enter the location of the image: ")

    try:
        encrypt_image(image_location, key)
    except FileNotFoundError:
        print("Invalid location. Image not found. Please try again.")
        encrypt_choice()

def decrypt_choice():
    key = input("Enter the decryption key (256 bits in hexadecimal format): ").encode('utf-8')
    encrypted_image_location = input("Enter the location of the encrypted image: ")

    try:
        decrypt_image(encrypted_image_location, key)
    except FileNotFoundError:
        print("Invalid location. Encrypted image not found. Please try again.")
        decrypt_choice()

if __name__ == "__main__":
    main()
