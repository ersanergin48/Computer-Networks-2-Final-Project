import socket
import os
import base64
import json
import zlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes

# IDEA implementasyonu (basit bir blok şifreleme benzetimi)
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
SND_PRIV_KEY = "sender_keys/snd_priv.pem"
SND_PUB_KEY = "sender_keys/snd_pub.pem"
RECV_PUB_KEY = "sender_keys/recv_pub.pem"
MESSAGE_FILE = "sender_keys/mesaj.txt"
PACK_FILE = "sender_keys/encrypted_package.json"

# === TCP ayarlamaları ===
host = "127.0.0.1"
port = 10000

# === Anahtar yükleme fonksiyonları ===
def load_private_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def load_public_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

# === PGP Şifreleme ve İmzalama ===
def prepare_pgp_package():
    snd_priv_key = load_private_key(SND_PRIV_KEY)
    recv_pub_key = load_public_key(RECV_PUB_KEY)

    with open(MESSAGE_FILE, "r", encoding="utf-8") as f:
        plaintext_message = f.read()

    # MD5 hash hesapla
    md5_hash = MD5.new()
    md5_hash.update(plaintext_message.encode('utf-8'))
    message_digest = md5_hash.hexdigest()

    # Hash'i gönderenin private key'i ile imzala
    signer = pkcs1_15.new(snd_priv_key)
    signature = signer.sign(MD5.new(plaintext_message.encode('utf-8')))

    # Mesaj + İmza birleştir
    combined_data = plaintext_message + "\n---SIGNATURE---\n" + base64.b64encode(signature).decode()

    # zlib ile sıkıştır
    compressed_data = zlib.compress(combined_data.encode('utf-8'))

    # IDEA için 128-bit (16 byte) rastgele anahtar
    idea_key = get_random_bytes(16)

    # IDEA ile şifrele
    idea_cipher = IDEA(idea_key)
    encrypted_data = idea_cipher.encrypt(compressed_data)

    # IDEA anahtarını alıcının public key'i ile RSA şifrele
    rsa_cipher = PKCS1_OAEP.new(recv_pub_key)
    encrypted_key = rsa_cipher.encrypt(idea_key)

    # Şifrelenmiş anahtar + şifrelenmiş veri birleştir
    final_data = encrypted_key + encrypted_data

    # Base64 encode
    ascii_message = base64.b64encode(final_data).decode()

    # Paket bilgilerini kaydet
    package = {
        "encrypted_key_size": len(encrypted_key),
        "encrypted_data_size": len(encrypted_data),
        "ascii_message": ascii_message,
        "original_size": len(plaintext_message),
        "compressed_size": len(compressed_data),
        "md5_hash": message_digest
    }

    with open(PACK_FILE, "w") as f:
        json.dump(package, f, indent=2)

    print("[✓] PGP paketi hazırlandı!")
    print(f"    Final ASCII mesaj uzunluğu: {len(ascii_message)} karakter")

# === TCP sunucu başlatılıyor ===
def start_sender_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((host, port))
        server.listen(1)
        print(f"[🔌] PGP Sender dinleniyor: {host}:{port}")
        print("Receiver'ın bağlanması bekleniyor...\n")
        
        conn, addr = server.accept()
        with conn:
            print(f"[🟢] Receiver bağlandı: {addr}")

            print("[📤] Sender'ın public key'i gönderiliyor...")
            # Step 1: Sender'ın public key'ini gönder
            with open(SND_PUB_KEY, "rb") as f:
                conn.sendall(f.read() + b"<END_KEY>")

            print("[📥] Receiver'ın public key'i alınıyor...")
            # Step 2: recv_pub.pem al
            recv_key_data = b""
            while not recv_key_data.endswith(b"<END_KEY>"):
                recv_key_data += conn.recv(1024)
            recv_key_data = recv_key_data.replace(b"<END_KEY>", b"")

            with open(RECV_PUB_KEY, "wb") as f:
                f.write(recv_key_data)
            print("[✓] recv_pub.pem alındı")

            # Step 3: PGP paketini hazırla
            prepare_pgp_package()

            print("[📤] Şifrelenmiş paket gönderiliyor...")
            # Step 4: encrypted_package.json gönder
            with open(PACK_FILE, "rb") as f:
                conn.sendall(f.read() + b"<END_JSON>")
            print("[✓] encrypted_package.json gönderildi")
            
            print("\n🎉 PGP mesajı başarıyla gönderildi!")

# === Çalıştır ===
if __name__ == "__main__":
    print("=== PGP SENDER ===")
    
    # Mesaj dosyasının varlığını kontrol et
    if not os.path.exists(MESSAGE_FILE):
        print(f"❌ Hata: {MESSAGE_FILE} dosyası bulunamadı!")
        exit(1)
    
    start_sender_server()