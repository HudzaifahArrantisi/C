# chall.py
# Challenge: Ghost XOR
# Category: Crypto (Easy)
# Format Flag: NFXCTF{...}

def xor(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

# Kunci rahasia 4 karakter
# KEY = b"????" 

# Flag asli dienkripsi menggunakan fungsi xor di atas:
# ciphertext = xor(FLAG, KEY)

# Hasil ciphertext yang berhasil didapatkan (format hexadecimal):
ciphertext_hex = "02091b08180938337c3d1c7a3f10303e3c7c31147f7b3032133d722c243b1c2a74297a287e32"

if __name__ == "__main__":
    print("[*] Challenge: Ghost XOR")
    print(f"[*] Ciphertext (hex): {ciphertext_hex}")
    print("[*] Good luck decoding the flag!")
