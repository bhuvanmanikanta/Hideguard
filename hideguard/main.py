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
import sys
import mimetypes

def generate_key():
    return secrets.token_bytes(32)

def encrypt_data(data, key):
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext

def compress_data(data):
    return lzma.compress(data)

def embed_simple(image_path, file_path, output_path=None, key=None):
    if key is None:
        raise ValueError("Encryption key is required")
        
    with open(file_path, "rb") as f:
        file_data = f.read()
    
    # Store file extension in the hidden data for extraction
    file_ext = os.path.splitext(file_path)[1].lower()
    file_data_with_ext = file_ext.encode() + b'\0' + file_data
    
    encrypted_data = encrypt_data(file_data_with_ext, key)
    compressed_data = compress_data(encrypted_data)
    
    signature = b"HIDEGUARD"
    data_with_header = signature + struct.pack(">I", len(compressed_data)) + compressed_data
    
    binary_data = []
    for byte in data_with_header:
        for bit_idx in range(8):
            binary_data.append((byte >> (7 - bit_idx)) & 1)
    
    img = Image.open(image_path)
    img = img.convert("RGB")
    width, height = img.size
    
    if len(binary_data) > width * height * 3:
        print(f"Error: Image too small. Need {len(binary_data)} bits, but image can only store {width * height * 3} bits.")
        return None
    
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
    
    while len(new_pixels) < width * height:
        new_pixels.append(pixels[len(new_pixels)])
    
    new_img = Image.new("RGB", (width, height))
    new_img.putdata(new_pixels)
    
    if output_path is None:
        file_name = os.path.splitext(os.path.basename(file_path))[0]
        output_path = f"{file_name}_hidden.png"
    
    new_img.save(output_path, "PNG")
    
    # Calculate percentage of image capacity used
    capacity_used = (len(binary_data) / (width * height * 3)) * 100
    print(f"Data hidden successfully in {output_path}")
    print(f"Used {capacity_used:.2f}% of available image capacity")
    return output_path

def extract_simple(image_path):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())
    
    extracted_bits = []
    for pixel in pixels:
        r, g, b = pixel
        extracted_bits.append(r & 1)
        extracted_bits.append(g & 1)
        extracted_bits.append(b & 1)
    
    extracted_bytes = bytearray()
    for i in range(0, len(extracted_bits), 8):
        if i + 8 <= len(extracted_bits):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | extracted_bits[i + j]
            extracted_bytes.append(byte)
    
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
    return lzma.decompress(data)

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted

def derive_key_from_passphrase(passphrase):
    return hashlib.sha256(passphrase.encode()).digest()

def validate_image_file(file_path):
    """Validate if the file is a supported image format"""
    try:
        img = Image.open(file_path)
        img.verify()  # Verify it's a valid image
        return True
    except:
        return False

def get_file_mime_type(file_path):
    """Get the MIME type of a file"""
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type

def display_banner():
    hideguard_ascii = """
██╗  ██╗██╗██████╗ ███████╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗     
██║  ██║██║██╔══██╗██╔════╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗    
███████║██║██║  ██║█████╗      ██║  ███╗██║   ██║███████║██████╔╝██║  ██║    
██╔══██║██║██║  ██║██╔══╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║    
██║  ██║██║██████╔╝███████╗    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝   
"""
    print(hideguard_ascii)
    print("Secure File Hiding in PNG Images")
    print("=" * 50)

def display_supported_formats():
    print("\nSupported Container Formats:")
    print("  - PNG images (recommended)")
    print("  - JPEG/JPG images (not recommended - may lose data during compression)")
    print("  - BMP images")
    print("  - TIFF images")
    
    print("\nFiles You Can Hide:")
    print("  - Any file type can be hidden (text, PDF, audio, video, ZIP, images, etc.)")
    print("  - File size is limited by container image dimensions")

def main():
    display_banner()
    
    while True:
        print("\nSelect an option:")
        print("1. Encrypt & Hide a File")
        print("2. Extract & Decrypt a File")
        print("3. View Supported File Formats")
        print("4. Exit")
        
        choice = input("\nEnter your choice (1/2/3/4): ").strip()

        if choice == "1":
            image_path = input("\nEnter the path of the container image: ").strip()
            if not os.path.exists(image_path):
                print("Error: Image file not found!")
                continue
                
            if not validate_image_file(image_path):
                print("Error: The selected file is not a valid image.")
                continue
                
            file_path = input("Enter the path of the file to hide: ").strip()
            if not os.path.exists(file_path):
                print("Error: File not found!")
                continue
            
            # Get file size and check if it's reasonable to hide
            file_size = os.path.getsize(file_path)
            img = Image.open(image_path)
            width, height = img.size
            max_bits = width * height * 3
            max_bytes = max_bits // 8
            
            # Account for overhead (signature, length, encryption)
            effective_max_bytes = max_bytes - 100  # Approximate overhead
            
            if file_size > effective_max_bytes:
                print(f"Warning: The file ({file_size} bytes) might be too large for this image.")
                print(f"This image can store approximately {effective_max_bytes} bytes.")
                proceed = input("Do you want to proceed anyway? (y/n): ").strip().lower()
                if proceed != 'y':
                    continue
            
            key_option = input("Select key option (1: Generate new key, 2: Enter passphrase): ").strip()
            
            if key_option == "1":
                key = generate_key()
                key_file = input("Enter filename to save encryption key (required to extract later): ").strip()
                with open(key_file, "wb") as f:
                    f.write(key)
                print(f"Key saved to {key_file}")
                print("IMPORTANT: Keep this key secure! You'll need it to decrypt your files.")
            elif key_option == "2":
                passphrase = input("Enter a strong passphrase (will be hashed to create key): ").strip()
                key = derive_key_from_passphrase(passphrase)
                print("Key derived from passphrase!")
            else:
                print("Invalid option. Returning to main menu.")
                continue
                
            output_path = input("Enter output image path (or press Enter for default): ").strip() or None
            embed_simple(image_path, file_path, output_path, key=key)
        
        elif choice == "2":
            image_path = input("\nEnter the path of the PNG image to extract data from: ").strip()
            
            if not os.path.exists(image_path):
                print("Error: Image file not found!")
                continue
                
            if not validate_image_file(image_path):
                print("Error: The selected file is not a valid image.")
                continue
            
            key_option = input("Select key option (1: Load key from file, 2: Enter passphrase): ").strip()
            
            if key_option == "1":
                key_file = input("Enter path to the key file: ").strip()
                try:
                    with open(key_file, "rb") as f:
                        key = f.read()
                except Exception as e:
                    print(f"Error loading key: {str(e)}")
                    continue
            elif key_option == "2":
                passphrase = input("Enter the passphrase used for encryption: ").strip()
                key = derive_key_from_passphrase(passphrase)
            else:
                print("Invalid option. Returning to main menu.")
                continue
            
            extracted_data = extract_simple(image_path)
            
            if extracted_data:
                try:
                    decompressed_data = decompress_data(extracted_data)
                    decrypted_data = decrypt_data(decompressed_data, key)
                    
                    # Extract the file extension
                    null_index = decrypted_data.find(b'\0')
                    if null_index != -1:
                        file_ext = decrypted_data[:null_index].decode('utf-8')
                        file_data = decrypted_data[null_index+1:]
                        default_filename = os.path.splitext(image_path)[0] + "_extracted" + file_ext
                    else:
                        file_data = decrypted_data
                        default_filename = os.path.splitext(image_path)[0] + "_extracted"
                    
                    output_file = input(f"Enter name for the extracted file (default: {default_filename}): ").strip() or default_filename
                    
                    with open(output_file, "wb") as f:
                        f.write(file_data)
                    print(f"Data extracted and saved as {output_file}")
                except Exception as e:
                    print(f"Error during processing: {str(e)}")
                    print("Make sure you're using the correct key for decryption.")
            else:
                print("Error: No valid data found in the image.")
        
        elif choice == "3":
            display_supported_formats()
            
        elif choice == "4":
            print("\nExiting HideGuard.")
            sys.exit(0)
        
        else:
            print("Invalid choice! Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    try:
        # Initialize mimetypes
        mimetypes.init()
        main()
    except KeyboardInterrupt:
        print("\n\nProgram interrupted. Exiting safely...")
        sys.exit(0)