import socket
import json
import os
import base64
import zlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15

# IDEA implementasyonu (sender ile aynı)
class IDEA:
    def __init__(self, key):
        """IDEA için 128-bit anahtar (16 byte)"""
        if len(key) != 16:
            raise ValueError("IDEA anahtarı 16 byte olmalı")
        self.key = key
    
    def encrypt(self, data):
        """Veriyi şifrele - basit XOR tabanlı benzetim"""
        encrypted = bytearray()
        key_len = len(self.key)
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.key[i % key_len])
        return bytes(encrypted)
    
    def decrypt(self, data):
        """Veriyi çöz - XOR işlemi simetrik"""
        return self.encrypt(data)

# === Dosya yolları ===
PRIV_KEY_FILE = "receiver_keys/recv_priv.pem"
PUB_KEY_FILE = "receiver_keys/recv_pub.pem"
SND_PUB_KEY_FILE = "receiver_keys/snd_pub.pem"
PACK_FILE = "receiver_keys/encrypted_package.json"
DECRYPT_OUT = "receiver_keys/dekripte_mesaj.txt"

# === TCP ayarlamaları ===
host = "127.0.0.1"
port = 10000

# === Anahtarları yükle ===
def load_private_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def load_public_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

# === PGP Çözümleme İşlemi ===
def decrypt_pgp_message():
    with open(PACK_FILE, "r") as f:
        package_data = json.load(f)

    recv_priv_key = load_private_key(PRIV_KEY_FILE)
    snd_pub_key = load_public_key(SND_PUB_KEY_FILE)

    # Base64 decode
    encrypted_combined = base64.b64decode(package_data["ascii_message"])
    
    # Şifrelenmiş anahtar ve veriyi ayır
    encrypted_key_size = package_data["encrypted_key_size"]
    encrypted_key = encrypted_combined[:encrypted_key_size]
    encrypted_data = encrypted_combined[encrypted_key_size:]

    # RSA ile IDEA anahtarını çöz
    rsa_cipher = PKCS1_OAEP.new(recv_priv_key)
    idea_key = rsa_cipher.decrypt(encrypted_key)

    # IDEA ile veriyi çöz
    idea_cipher = IDEA(idea_key)
    compressed_data = idea_cipher.decrypt(encrypted_data)

    # zlib ile aç
    decompressed_data = zlib.decompress(compressed_data).decode('utf-8')

    # Mesaj ve imzayı ayır
    parts = decompressed_data.split("\n---SIGNATURE---\n")
    if len(parts) != 2:
        raise ValueError("Mesaj formatı hatalı!")
    
    original_message = parts[0]
    signature_b64 = parts[1]
    signature = base64.b64decode(signature_b64)

    # Mesajın MD5 hash'ini hesapla
    md5_hash = MD5.new()
    md5_hash.update(original_message.encode('utf-8'))
    calculated_hash = md5_hash.hexdigest()
    stored_hash = package_data["md5_hash"]
    if calculated_hash == stored_hash:
        print("    ✓ MD5 hash doğrulandı!")
    else:
        print("    ❌ MD5 hash uyuşmuyor!")

    # İmzayı doğrula
    try:
        verifier = pkcs1_15.new(snd_pub_key)
        verifier.verify(MD5.new(original_message.encode('utf-8')), signature)
        print("    ✓ Dijital imza geçerli!")
        signature_valid = True
    except (ValueError, TypeError):
        print("    ❌ Dijital imza geçersiz!")
        signature_valid = False

    # Çözülmüş mesajı kaydet
    with open(DECRYPT_OUT, "w", encoding="utf-8") as f:
        f.write(original_message)

    print("\n" + "="*60)
    print("🔓 PGP MESAJI BAŞARIYLA ÇÖZÜLDÜ")
    print("="*60)
    print("\n📨 Mesaj İçeriği:")
    print("-" * 60)
    print(original_message)
    print("-" * 60)
    
    return signature_valid and (calculated_hash == stored_hash)

# === TCP üzerinden sender'a bağlan ===
def connect_to_sender():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"[🔌] Sender'a bağlandı: {host}:{port}")

        print("[📥] Sender'ın public key'i alınıyor...")
        # Step 1: snd_pub.pem al
        sender_key_data = b""
        while not sender_key_data.endswith(b"<END_KEY>"):
            sender_key_data += s.recv(1024)
        sender_key_data = sender_key_data.replace(b"<END_KEY>", b"")

        with open(SND_PUB_KEY_FILE, "wb") as f:
            f.write(sender_key_data)
        print("[✓] snd_pub.pem alındı")

        print("[📤] Receiver'ın public key'i gönderiliyor...")
        # Step 2: recv_pub.pem gönder
        with open(PUB_KEY_FILE, "rb") as f:
            s.sendall(f.read() + b"<END_KEY>")
        print("[✓] recv_pub.pem gönderildi")

        print("[📥] Şifrelenmiş paket alınıyor...")
        # Step 3: encrypted_package.json al
        package_data = b""
        while not package_data.endswith(b"<END_JSON>"):
            package_data += s.recv(1024)
        package_data = package_data.replace(b"<END_JSON>", b"")

        with open(PACK_FILE, "wb") as f:
            f.write(package_data)
        print("[✓] encrypted_package.json alındı")

    print("\n" + "="*50)
    print("🔍 PGP ÇÖZÜMLEME BAŞLATILIYOR")
    print("="*50)
    
    # Step 4: PGP mesajını çöz
    success = decrypt_pgp_message()
    
    if success:
        print("\n🎉 Tüm güvenlik kontrolleri başarılı!")
    else:
        print("\n⚠️  Güvenlik kontrolleri başarısız! Mesaj tehlikeye girmiş olabilir.")

# === Çalıştır ===
if __name__ == "__main__":
    print("=== PGP RECEIVER ===")
    connect_to_sender()