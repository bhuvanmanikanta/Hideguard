# HideGuard

**HideGuard** is a Python tool that securely hides sensitive files inside PNG images using strong AES-256 encryption and LZMA compression. Perfect for privacy-focused users and security researchers, HideGuard provides a simple terminal interface to embed and extract confidential data.

---

## 🔐 Features

- AES-256 encryption for strong security
- LZMA compression for better efficiency than Huffman coding
- Steganography via PNG images
- Terminal-based interface — no GUI, fast and lightweight
- Support for key files or passphrases
- Detects invalid keys or extraction failures

---

## 🛠️ Installation

Clone the repository and install using `pip`:

```bash
git clone https://github.com/bhuvanmanikanta/hideguard.git
cd hideguard
pip install .
