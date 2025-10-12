# PAdES Digital Signature Application

A Python application for creating and verifying **PAdES-based digital signatures** on PDF files using **RSA-PSS**.

## Features

- **Key Generation**: Generate asymmetric RSA key pairs for signing and verification.
- **PDF Signing**: Apply a digital signature to PDF documents using the PAdES standard with RSA-PSS.
- **Signature Verification**: Verify the validity of signed PDF files using the corresponding public key.

## Implementation

- Built in **Python**, focusing on secure cryptographic operations.
- Uses **RSA-PSS** for probabilistic, secure digital signatures.
- Manual handling of key generation, signing, and verification ensures transparency and learning of cryptographic principles.

## Usage

1. Generate an RSA key pair.
2. Sign a PDF file with your private key using RSA-PSS.
3. Verify a signed PDF file using the public key.
