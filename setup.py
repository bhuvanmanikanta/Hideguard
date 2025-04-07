from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="hideguard",
    version="1.0.0",
    author="Bhuvan",
    author_email="computingknowledge06@gmail.com",
    description="Secure file hiding in PNG images using steganography and encryption",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bhuvanmanikanta/HideGuard",
    packages=find_packages(),
    install_requires=[
        "pillow>=8.0.0",
        "pycryptodome>=3.9.0",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "hideguard=hideguard.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security :: Cryptography",
        "Topic :: Multimedia :: Graphics",
    ],
    keywords="steganography encryption security png",
)