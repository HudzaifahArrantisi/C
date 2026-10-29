import struct
import zlib
import time
import random

def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Membuat chunk PNG standar: [Length: 4B][Type: 4B][Data][CRC32: 4B]"""
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

# ==========================================
# Implementasi ZipCrypto Standar (PKZIP)
# ==========================================
def crc32_update(old_crc: int, char: int) -> int:
    return zlib.crc32(bytes([char]), ~old_crc & 0xFFFFFFFF) ^ 0xFFFFFFFF

class ZipCrypto:
    def __init__(self, password: bytes):
        self.key0 = 0x12345678
        self.key1 = 0x23456789
        self.key2 = 0x34567890
        for b in password:
            self.update_keys(b)

    def update_keys(self, char: int):
        self.key0 = crc32_update(self.key0, char)
        self.key1 = ((self.key1 + (self.key0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        self.key2 = crc32_update(self.key2, (self.key1 >> 24) & 0xFF)

    def decrypt_byte(self) -> int:
        temp = (self.key2 | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    def encrypt_byte(self, char: int) -> int:
        c = char ^ self.decrypt_byte()
        self.update_keys(char)
        return c

def create_multi_entry_zip(entries: list) -> bytes:
    """
    Membuat file ZIP standar dengan multiple entries.
    entries: list of dict(name=str, data=bytes, password=str/None)
    Jika password=None, file tidak dienkripsi (bisa di-unzip tanpa password).
    Jika password diberikan, file dienkripsi menggunakan ZipCrypto standar.
    """
    local_headers_and_data = []
    central_directory_entries = []
    current_offset = 0

    for item in entries:
        filename = item["name"]
        file_data = item["data"]
        password = item.get("password")

        file_crc = zlib.crc32(file_data) & 0xFFFFFFFF
        fname_bytes = filename.encode("ascii")

        if password:
            # File terenkripsi ZipCrypto
            cipher = ZipCrypto(password.encode("ascii"))
            dummy_header = bytes([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, (file_crc >> 24) & 0xFF])
            encrypted_header = bytes([cipher.encrypt_byte(b) for b in dummy_header])
            encrypted_data = bytes([cipher.encrypt_byte(b) for b in file_data])
            payload = encrypted_header + encrypted_data
            flags = 1  # Bit 0 = Encrypted
            compressed_size = len(payload)
        else:
            # File uncompressed / plaintext (tidak berpassword)
            payload = file_data
            flags = 0  # Bit 0 = Not encrypted
            compressed_size = len(file_data)

        uncompressed_size = len(file_data)

        # Local File Header
        local_hdr = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,        # Signature
            20,                # Version needed (2.0)
            flags,             # Bit flags
            0,                 # Compression: Stored (0)
            0x4B21,            # Mod time
            0x56DC,            # Mod date
            file_crc,          # CRC32
            compressed_size,
            uncompressed_size,
            len(fname_bytes),
            0                  # Extra field length
        ) + fname_bytes + payload

        local_headers_and_data.append(local_hdr)

        # Central Directory Header
        cd_entry = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,        # Signature
            20,                # Version made by
            20,                # Version needed
            flags,             # Flags
            0,                 # Compression
            0x4B21,
            0x56DC,
            file_crc,
            compressed_size,
            uncompressed_size,
            len(fname_bytes),
            0,                 # Extra field length
            0,                 # Comment length
            0,                 # Disk start
            0,                 # Internal attrs
            0x81A40000,        # External attrs (-rw-r--r--)
            current_offset     # Offset of local header
        ) + fname_bytes

        central_directory_entries.append(cd_entry)
        current_offset += len(local_hdr)

    all_local = b"".join(local_headers_and_data)
    all_cd = b"".join(central_directory_entries)

    # End of Central Directory (EOCD)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0, 0,
        len(entries), len(entries),
        len(all_cd),
        len(all_local),
        0
    )

    return all_local + all_cd + eocd

def generate_1000_passwords(target_password: str) -> str:
    """Membuat 1000 kata sandi realistis yang memuat target_password di dalamnya."""
    random.seed(20261029)
    bases = [
        "shadow", "hunter", "cipher", "phantom", "dragon", "falcon", "matrix",
        "cyber", "phoenix", "crypto", "viper", "delta", "knight", "ranger",
        "storm", "blaze", "ghost", "stealth", "sentinel", "vector", "bastion",
        "quantum", "nexus", "omega", "titan", "hydra", "vortex", "pulse"
    ]
    connectors = ["_", "-", ".", ""]
    numbers = ["123", "2024", "2025", "2026", "77", "99", "007", "42", "88", "101", "360", "777"]
    words = ["sec", "pass", "access", "root", "corp", "lab", "key", "admin", "core", "shield"]

    wordlist = set()
    while len(wordlist) < 999:
        b = random.choice(bases)
        c = random.choice(connectors)
        w = random.choice(words)
        n = random.choice(numbers)
        choice = random.randint(1, 4)
        if choice == 1:
            pwd = f"{b}{c}{w}{n}"
        elif choice == 2:
            pwd = f"{b}{c}{n}"
        elif choice == 3:
            pwd = f"{w}{c}{b}_{n}"
        else:
            pwd = f"{b}_{w}"
        if pwd != target_password:
            wordlist.add(pwd)

    # Masukkan target_password di posisi acak yang deterministik
    full_list = list(wordlist)
    insert_pos = 428  # Posisi acak di tengah-tengah
    full_list.insert(insert_pos, target_password)

    return "\n".join(full_list) + "\n"

# ==========================================
# Generator Gambar Challenge (PNG + ZIP + Wordlist)
# ==========================================
def create_challenge_image(filename: str = "evidence.png"):
    width = 600
    height = 300
    flag = "NFXCTF{h4shc4t_cr4ck1ng_z1p_succ3ssfu11y}"
    target_password = "cyber_shield_2026"

    # 1. Signature PNG resmi (8 bytes)
    png_signature = b"\x89PNG\r\n\x1a\n"

    # 2. IHDR Chunk
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_chunk = make_chunk(b"IHDR", ihdr_data)

    # 3. tEXt Chunks (Metadata pengecoh - bersih dari flag)
    metadata = {
        "Title": "Investigative Evidence Asset #4029",
        "Author": "DFIR Incident Handler",
        "Software": "SecureCam OS v4.2"
    }

    text_chunks = b""
    for key, val in metadata.items():
        data = key.encode("latin-1") + b"\x00" + val.encode("utf-8")
        text_chunks += make_chunk(b"tEXt", data)

    # 4. Generate Raw Pixel Scanlines
    raw_scanlines = []
    for y in range(height):
        line = bytearray([0])  # Filter type 0
        for x in range(width):
            r = int(12 + (30 * x / width))
            g = int(24 + (50 * y / height))
            b = int(60 + (110 * (x + y) / (width + height)))
            line.extend([r, g, b])
        raw_scanlines.append(bytes(line))

    flattened_pixels = b"".join(raw_scanlines)
    compressed_pixels = zlib.compress(flattened_pixels, level=9)
    idat_chunk = make_chunk(b"IDAT", compressed_pixels)

    # 5. IEND Chunk
    iend_chunk = make_chunk(b"IEND", b"")

    # 6. Buat wordlist 1000 password yang memuat target_password
    passwords_text = generate_1000_passwords(target_password)

    # 7. Buat arsip ZIP tersembunyi yang berisi:
    #    - passwords.txt (UNENCRYPTED -> otomatis keluar saat binwalk/unzip)
    #    - flag.txt      (ENCRYPTED   -> meminta password)
    zip_entries = [
        {
            "name": "passwords.txt",
            "data": passwords_text.encode("utf-8"),
            "password": None  # Tidak dienkripsi!
        },
        {
            "name": "flag.txt",
            "data": (flag + "\n").encode("utf-8"),
            "password": target_password  # Terenkripsi dengan target_password
        }
    ]

    hidden_zip_data = create_multi_entry_zip(zip_entries)

    # Gabungkan PNG + Hidden ZIP pada trailing bytes
    full_payload = png_signature + ihdr_chunk + text_chunks + idat_chunk + iend_chunk + hidden_zip_data

    with open(filename, "wb") as f:
        f.write(full_payload)

    print(f"[+] Berhasil membuat gambar challenge: '{filename}'")
    print(f"[+] Ukuran total file: {len(full_payload)} bytes")
    print(f"[+] Hidden ZIP berisi 2 file:")
    print(f"    1. passwords.txt (1000 kombinasi kata sandi, tidak berpassword)")
    print(f"    2. flag.txt (Terenkripsi)")
    print(f"[+] Password benar: {target_password}")
    print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    create_challenge_image("evidence.png")
