# solve.py
# Script solver otomatis untuk Ghost XOR

ciphertext_hex = "02091b08180938337c3d1c7a3f10303e3c7c31147f7b3032133d722c243b1c2a74297a287e32"
ciphertext = bytes.fromhex(ciphertext_hex)

# 1. Tebak 4 karakter pertama karena format flag selalu diawali "NFXC"
known_prefix = b"NFXC"
key = bytes([ciphertext[i] ^ known_prefix[i] for i in range(4)])
print(f"[+] Key = {key.decode()}")

# 2. Dekripsi seluruh flag dengan key yang ditemukan
flag = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
print(f"[+] Flag = {flag.decode()}")
