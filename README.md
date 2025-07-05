EGE University EEE 2024-25 Computer Networks 2 Final Project - PGP SIMULATION FOR SECURING EMAIL SYSTEM
Prepared by: Ersan Ergin 052100000667@ogrenci.ege.edu.tr - Barışcan İlter 052000000485@ogrenci.ege.edu.tr

Implementing on Python
# PGP Simulation for Securing E-mail System in Python
This project simulates secure e-mail transmission between sender and receiver using PGP(Pretty Good Privacy) methods over TCP connection.
It contains hashing, digital signature, compressing - decompressing, encryption - decryption, Base64 encoding - decoding and verification of message using pycryptodome and zlib libraries in Python.
## Project Overview
Insecure email communication is one of the biggest problems in today’s interconnected digital world. This project implements a PGP based secure e-mail system that performs the following operations:
- Hashing and signing using MD5 and RSA algorithms for message integrity.
- Symmetric encryption and decryption using IDEA algorithm.
- TCP communication for transmitting the messages.
- Base64 encoding for safe transmission.
## Technologies Used
- Programming Language: Python
- Cryptography Library: pycryptodome(Python)
- TCP Socket Communication: socket(Python)
## How It Works
1. ## Generating Keys for Sender and Receiver:
   - Specify the folders where keys will be saved.
   - Generate 2048-bit RSA key pairs.
   - Creating private and public key files (.pem).
2. ## Sender Side:
   - Reads the plaintext message which is .txt file.
   - Hashes the message using MD5 and generates a digital signature using sender's private RSA key.
   - Compresses the signed message.
   - Encrypts the message symmetrically using IDEA algorithm.
   - Base64 encodes the encrypted message for converting to ASCII format.
   - Sends the encrypted message to the receiver with the help of TCP.
3. ## Receiver Side:
   - Listens for sender's TCP connection.
   - Base64 decodes the encrypted message to revert the message from ASCII format to its original format.
   - Decompressing for seperation of message and digital signature.
   - Decrypts the digital signature using receiver's private RSA key and encrypted message using IDEA algorithm.
   - Calculates hash using MD5 algorithm and verifies the message.
   - Displays the decrpyted message if the hashes are same and the signature is valid.
## Compilation
# Generating Sender and Receiver Keys Compilation
python generate_sender_keys_pgp.py

python generate_sender_keys_pgp.py
# Sender Compilation
python sender_pgp.py
# Receiver Compilation
python receiver_pgp.py
