import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Anahtarların kaydedileceği klasör
key_file = "sender_keys"
os.makedirs(key_file, exist_ok=True)

# RSA 2048-bit key çifti üret
key = RSA.generate(2048)

# PRIVATE KEY: snd_priv.pem
with open(os.path.join(key_file, "snd_priv.pem"), "wb") as f:
    f.write(key.export_key('PEM'))

# PUBLIC KEY: snd_pub.pem  
with open(os.path.join(key_file, "snd_pub.pem"), "wb") as f:
    f.write(key.publickey().export_key('PEM'))

print("[✓] Sender için RSA anahtar çifti oluşturulmuştur.")