#!/usr/bin/env python3
"""
HideGuard - Secure File Hiding in PNG Images
"""

import os
import lzma
import base64
import struct
import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import time

def generate_key():
    """Generate a random 256-bit (32-byte) AES key"""
    return secrets.token_bytes(32)

def encrypt_data(data, key):
    """Encrypt data using AES-256 in CBC mode"""
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext

def compress_data(data):
    """Compress data using LZMA algorithm"""
    return lzma.compress(data)

def embed_simple(image_path, file_path, output_path=None, key=None):
    """Hide a file within a PNG image using LSB steganography"""
    if key is None:
        raise ValueError("Encryption key is required")
        
    with open(file_path, "rb") as f:
        file_data = f.read()
    
    encrypted_data = encrypt_data(file_data, key)
    compressed_data = compress_data(encrypted_data)
    
    # Create data packet with signature and length header
    signature = b"HIDEGUARD"
    data_with_header = signature + struct.pack(">I", len(compressed_data)) + compressed_data
    
    # Convert data to binary bits
    binary_data = []
    for byte in data_with_header:
        for bit_idx in range(8):
            binary_data.append((byte >> (7 - bit_idx)) & 1)
    
    # Open and prepare the image
    img = Image.open(image_path)
    img = img.convert("RGB")
    width, height = img.size
    
    # Check if image is large enough
    if len(binary_data) > width * height * 3:
        print(f"Error: Image too small. Need {len(binary_data)} bits, but image can only store {width * height * 3} bits.")
        return None
    
    # Embed the data in the image
    pixels = list(img.getdata())
    new_pixels = []
    bit_index = 0
    
    for pixel in pixels:
        r, g, b = pixel
        
        if bit_index < len(binary_data):
            r = (r & 0xFE) | binary_data[bit_index]
            bit_index += 1
        
        if bit_index < len(binary_data):
            g = (g & 0xFE) | binary_data[bit_index]
            bit_index += 1
        
        if bit_index < len(binary_data):
            b = (b & 0xFE) | binary_data[bit_index]
            bit_index += 1
        
        new_pixels.append((r, g, b))
        
        if bit_index >= len(binary_data):
            break
    
    # Fill remaining pixels with original data
    while len(new_pixels) < width * height:
        new_pixels.append(pixels[len(new_pixels)])
    
    # Save the new image
    new_img = Image.new("RGB", (width, height))
    new_img.putdata(new_pixels)
    
    if output_path is None:
        file_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = f"{file_name}_hidden.png"
    
    new_img.save(output_path, "PNG")
    print(f"\n[+] Data hidden successfully in {output_path}")
    return output_path

def extract_simple(image_path):
    """Extract hidden data from a PNG image"""
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())
    
    # Extract LSBs from all pixels
    extracted_bits = []
    for pixel in pixels:
        r, g, b = pixel
        extracted_bits.append(r & 1)
        extracted_bits.append(g & 1)
        extracted_bits.append(b & 1)
    
    # Convert bits to bytes
    extracted_bytes = bytearray()
    for i in range(0, len(extracted_bits), 8):
        if i + 8 <= len(extracted_bits):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | extracted_bits[i + j]
            extracted_bytes.append(byte)
    
    # Find the data packet
    signature = b"HIDEGUARD"
    signature_len = len(signature)
    
    for i in range(len(extracted_bytes) - signature_len):
        if extracted_bytes[i:i+signature_len] == signature:
            length_bytes = extracted_bytes[i+signature_len:i+signature_len+4]
            data_length = struct.unpack(">I", bytes(length_bytes))[0]
            
            data_start = i + signature_len + 4
            data_end = data_start + data_length
            
            if data_end <= len(extracted_bytes):
                return bytes(extracted_bytes[data_start:data_end])
    
    return None

def decompress_data(data):
    """Decompress LZMA compressed data"""
    return lzma.decompress(data)

def decrypt_data(encrypted_data, key):
    """Decrypt AES-256 CBC encrypted data"""
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted

def derive_key_from_passphrase(passphrase):
    """Derive a 256-bit key from a passphrase using SHA-256"""
    return hashlib.sha256(passphrase.encode()).digest()

def clear_screen():
    """Clear the terminal screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    """Print the program banner"""
    banner = r"""
 ██╗  ██╗██╗██████╗ ███████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗     
 ██║  ██║██║██╔══██╗██╔════╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗    
 ███████║██║██║  ██║█████╗      ██║  ███╗██║   ██║███████║██████╔╝██║  ██║    
 ██╔══██║██║██║  ██║██╔══╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║    
 ██║  ██║██║██████╔╝███████╗    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝   
    
    Secure File Hiding in PNG Images
    """
    print(banner)

def main():
    clear_screen()
    print_banner()
    
    while True:
        print("\n===== Main Menu =====")
        print("1. Encrypt & Hide a File")
        print("2. Extract & Decrypt a File")
        print("3. Exit")
        choice = input("\nSelect an option (1/2/3): ")

        if choice == "1":
            clear_screen()
            print("\n===== Hide File =====")
            image_path = input("\nEnter path to PNG image: ").strip()
            file_path = input("Enter path to file to hide: ").strip()
            
            if not os.path.exists(image_path) or not os.path.exists(file_path):
                print("\n[!] Error: File or image not found!")
                time.sleep(2)
                clear_screen()
                continue
            
            print("\nKey Options:")
            print("1. Generate new random key")
            print("2. Use a passphrase")
            key_option = input("Select key option (1/2): ").strip()
            
            if key_option == "1":
                key = generate_key()
                key_file = input("\nEnter filename to save key: ").strip()
                try:
                    with open(key_file, "wb") as f:
                        f.write(key)
                    print(f"\n[+] Key saved to {key_file}")
                    print("IMPORTANT: Keep this key secure! You'll need it to extract the file.")
                except Exception as e:
                    print(f"\n[!] Error saving key: {e}")
                    time.sleep(2)
                    continue
            elif key_option == "2":
                passphrase = input("\nEnter a strong passphrase: ").strip()
                if not passphrase:
                    print("\n[!] Passphrase cannot be empty!")
                    time.sleep(1)
                    continue
                key = derive_key_from_passphrase(passphrase)
                print("\n Key generated from passphrase")
            else:
                print("\n[!] Invalid option")
                time.sleep(1)
                clear_screen()
                continue
            
            result = embed_simple(image_path, file_path, key=key)
            if result:
                input("\nPress Enter to return to main menu...")
            clear_screen()
        
        elif choice == "2":
            clear_screen()
            print("\n===== Extract File =====")
            image_path = input("\nEnter path to PNG image: ").strip()
            
            if not os.path.exists(image_path):
                print("\n[!] Error: Image file not found!")
                time.sleep(2)
                clear_screen()
                continue
            
            print("\nKey Options:")
            print("1. Load key from file")
            print("2. Enter passphrase")
            key_option = input("Select key option (1/2): ").strip()
            
            if key_option == "1":
                key_file = input("\nEnter path to key file: ").strip()
                try:
                    with open(key_file, "rb") as f:
                        key = f.read()
                except Exception as e:
                    print(f"\n[!] Error loading key: {e}")
                    time.sleep(2)
                    continue
            elif key_option == "2":
                passphrase = input("\nEnter the passphrase: ").strip()
                key = derive_key_from_passphrase(passphrase)
            else:
                print("\n[!] Invalid option")
                time.sleep(1)
                clear_screen()
                continue
            
            extracted_data = extract_simple(image_path)
            
            if extracted_data:
                try:
                    decompressed_data = decompress_data(extracted_data)
                    decrypted_data = decrypt_data(decompressed_data, key)
                    
                    # Suggest output filename
                    base_name = os.path.splitext(os.path.basename(image_path))[0]
                    default_output = f"{base_name}_extracted"
                    output_file = input(f"\nEnter output filename [{default_output}]: ").strip()
                    output_file = output_file if output_file else default_output
                    
                    with open(output_file, "wb") as f:
                        f.write(decrypted_data)
                    print(f"\n[+] File extracted successfully to {output_file}")
                except Exception as e:
                    print(f"\n[!] Error during processing: {e}")
                    print("This usually means the wrong key/passphrase was used.")
            else:
                print("\n[!] Error: No valid hidden data found in the image")
            
            input("\nPress Enter to return to main menu...")
            clear_screen()
        
        elif choice == "3":
            print("\n HideGuard has exited successfully. Goodbye!")
            break
        
        else:
            print("\n[!] Invalid choice! Please enter 1, 2, or 3.")
            time.sleep(1)
            clear_screen()

if __name__ == "__main__":
    main()