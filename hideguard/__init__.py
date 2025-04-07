"""
HideGuard - Secure steganography tool for hiding files in PNG images with AES encryption.

Features:
- Hide files within PNG images using LSB steganography.
- Encrypt data with AES-256 before hiding.
- Extract and decrypt hidden files securely.

Author: Your Name
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Bhuvan"
__license__ = "MIT"

from .main import (
    generate_key,
    encrypt_data,
    compress_data,
    embed_simple,
    extract_simple,
    decompress_data,
    decrypt_data,
    derive_key_from_passphrase,
    main
)

__all__ = [
    'generate_key',
    'encrypt_data',
    'compress_data',
    'embed_simple',
    'extract_simple',
    'decompress_data',
    'decrypt_data',
    'derive_key_from_passphrase',
    'main',
    '__version__',
    '__author__',
    '__license__'
]

