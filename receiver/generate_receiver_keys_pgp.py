import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Anahtarların kaydedileceği klasör
key_file = "receiver_keys"
os.makedirs(key_file, exist_ok=True)

# RSA 2048-bit key çifti üret
key = RSA.generate(2048)

# PRIVATE KEY: recv_priv.pem
with open(os.path.join(key_file, "recv_priv.pem"), "wb") as f:
    f.write(key.export_key('PEM'))

# PUBLIC KEY: recv_pub.pem
with open(os.path.join(key_file, "recv_pub.pem"), "wb") as f:
    f.write(key.publickey().export_key('PEM'))

print("[✓] Receiver için RSA anahtar çifti oluşturulmuştur.")