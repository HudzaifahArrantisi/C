# chall.py
# Kategori: Cryptography (Medium)
# Nama: Broken Stream (LFSR)
# Format Flag: NFXCTF{...}

class LFSR:
    def __init__(self, seed: int, mask: int = 0b1101100000000001, size: int = 16):
        self.state = seed & ((1 << size) - 1)
        self.mask = mask
        self.size = size

    def step(self) -> int:
        output = self.state & 1
        feedback = bin(self.state & self.mask).count("1") % 2
        self.state = (self.state >> 1) | (feedback << (self.size - 1))
        return output

    def get_byte(self) -> int:
        byte = 0
        for i in range(8):
            byte |= (self.step() << i)
        return byte

def encrypt(data: bytes, lfsr: LFSR) -> bytes:
    return bytes([b ^ lfsr.get_byte() for b in data])

# CATATAN PANITIA:
# Flag asli telah dienkripsi dengan kunci rahasia 16-bit (seed di antara 1 s/d 65535):
# cipher = LFSR(secret_seed, mask=0b1101100000000001)
# ciphertext = encrypt(FLAG, cipher)

# Hasil ciphertext yang didapat (dalam format hexadecimal):
ciphertext_hex = "f945dc55a74070a7b6cf9db111812837330768c7e1bc3a854d9203c9eb47180e035e5ef01a75"

if __name__ == "__main__":
    print("=== NFX SECURE STREAM CIPHER v1.0 ===")
    print(f"[*] Ciphertext (hex): {ciphertext_hex}")
    print("[*] Temukan seed 16-bit dan dekripsi flag-nya!")
