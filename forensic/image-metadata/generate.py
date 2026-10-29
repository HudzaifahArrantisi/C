import struct
import zlib
import time

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

def create_encrypted_zip(filename_in_zip: str, file_data: bytes, password: str) -> bytes:
    cipher = ZipCrypto(password.encode("ascii"))
    file_crc = zlib.crc32(file_data) & 0xFFFFFFFF

    # 12-byte header ZipCrypto (11 bytes dummy + 1 byte verification dari CRC32 high byte)
    dummy_header = bytes([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, (file_crc >> 24) & 0xFF])
    encrypted_header = bytes([cipher.encrypt_byte(b) for b in dummy_header])
    encrypted_data = bytes([cipher.encrypt_byte(b) for b in file_data])

    full_encrypted = encrypted_header + encrypted_data
    compressed_size = len(full_encrypted)
    uncompressed_size = len(file_data)

    fname_bytes = filename_in_zip.encode("ascii")

    # Local file header
    local_header = struct.pack(
        "<IHHHHHIIIHH",
        0x04034B50,  # Signature
        20,          # Version needed
        1,           # Flags: Bit 0 = Encrypted
        0,           # Compression: 0 (Stored)
        0x4B21,      # Mod time (dummy)
        0x56DC,      # Mod date (dummy)
        file_crc,    # CRC32
        compressed_size,
        uncompressed_size,
        len(fname_bytes),
        0            # Extra field len
    ) + fname_bytes + full_encrypted

    # Central Directory
    central_dir = struct.pack(
        "<IHHHHHHIIIHHHHHII",
        0x02014B50,  # Signature
        20,          # Version made by
        20,          # Version needed
        1,           # Flags: Encrypted
        0,           # Compression: Stored
        0x4B21,
        0x56DC,
        file_crc,
        compressed_size,
        uncompressed_size,
        len(fname_bytes),
        0,           # Extra field len
        0,           # Comment len
        0,           # Disk start
        0,           # Internal attrs
        0x81A40000,  # External attrs (-rw-r--r--)
        0            # Offset of local header
    ) + fname_bytes

    # End of Central Directory (EOCD)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,  # Signature
        0, 0,        # Disk numbers
        1, 1,        # Entry counts
        len(central_dir),
        len(local_header),
        0            # Comment len
    )

    return local_header + central_dir + eocd

# ==========================================
# Generator Gambar PNG dengan LSB + Carving
# ==========================================
def create_challenge_image(filename: str = "evidence.png"):
    width = 600
    height = 300
    flag = "NFXCTF{c4rv1ng_4nd_l5b_st3g4n0_m4st3r}"
    zip_password = "p1x3l_d1g1t4l_f0r3ns1cs"

    # Pesan yang disembunyikan di LSB pixel
    lsb_secret = f"HINT: The carved archive password is '{zip_password}'\n".encode("utf-8")

    # 1. Signature PNG resmi (8 bytes)
    png_signature = b"\x89PNG\r\n\x1a\n"

    # 2. IHDR Chunk
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_chunk = make_chunk(b"IHDR", ihdr_data)

    # 3. tEXt Chunks (Metadata pengecoh - TIDAK ADA FLAG DI SINI!)
    metadata = {
        "Title": "Security Incident Report #4029 - Image Asset",
        "Author": "DFIR Team Alpha",
        "Software": "GIMP 2.10.34",
        "Notice": "Confidential investigative material. Cleared for internal case review."
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
        raw_scanlines.append(line)

    # 5. Embed LSB Steganography ke channel RGB (Metode b1,rgb,lsb,xy sesuai standar zsteg)
    bit_stream = []
    for byte in lsb_secret:
        for bit_idx in range(8):
            bit_stream.append((byte >> bit_idx) & 1)

    bit_pos = 0
    total_bits = len(bit_stream)

    for y in range(height):
        # Scanline index: line[0] adalah filter byte, data piksel mulai dari line[1]
        line = raw_scanlines[y]
        for i in range(1, len(line)):
            if bit_pos < total_bits:
                # Modifikasi bit paling rendah (LSB)
                line[i] = (line[i] & 0xFE) | bit_stream[bit_pos]
                bit_pos += 1
            else:
                break
        if bit_pos >= total_bits:
            break

    # 6. IDAT Chunk (Kompresi data piksel dengan zlib)
    flattened_pixels = b"".join([bytes(l) for l in raw_scanlines])
    compressed_pixels = zlib.compress(flattened_pixels, level=9)
    idat_chunk = make_chunk(b"IDAT", compressed_pixels)

    # 7. IEND Chunk
    iend_chunk = make_chunk(b"IEND", b"")

    # 8. Trailing Bytes: Buat ZIP file berpassword yang memuat flag.txt
    encrypted_zip_data = create_encrypted_zip("flag.txt", flag.encode("utf-8") + b"\n", zip_password)

    # Gabungkan semua komponen: PNG Image + Hidden Encrypted ZIP di akhir file
    full_payload = png_signature + ihdr_chunk + text_chunks + idat_chunk + iend_chunk + encrypted_zip_data

    with open(filename, "wb") as f:
        f.write(full_payload)

    print(f"[+] Berhasil membuat gambar challenge: '{filename}'")
    print(f"[+] Ukuran file: {len(full_payload)} bytes")
    print(f"[+] Metadata EXIF/tEXt : Bersih (Tidak ada flag/password)")
    print(f"[+] LSB Secret         : {lsb_secret.strip().decode()}")
    print(f"[+] ZIP Password       : {zip_password}")
    print(f"[+] Flag di flag.txt   : {flag}")

if __name__ == "__main__":
    create_challenge_image("evidence.png")
