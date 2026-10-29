import struct
import zlib

def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Membuat chunk PNG standar: [Length: 4B][Type: 4B][Data][CRC32: 4B]"""
    crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

def create_challenge_image(filename: str = "evidence.png"):
    width = 600
    height = 300
    flag = "NFXCTF{m3t4d4t4_4nd_chv0nk5_n3v3r_l13}"

    # 1. Signature PNG resmi (8 bytes)
    png_signature = b"\x89PNG\r\n\x1a\n"

    # 2. IHDR Chunk (Image Header): 13 bytes data
    # Width (4B), Height (4B), Bit Depth (1B)=8, Color Type (1B)=2 (Truecolor RGB),
    # Compression (1B)=0, Filter (1B)=0, Interlace (1B)=0
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    ihdr_chunk = make_chunk(b"IHDR", ihdr_data)

    # 3. tEXt Chunks (Metadata teks tersembunyi)
    metadata = {
        "Title": "Operation Dark Shadow - Field Asset",
        "Author": "Investigator-7",
        "Camera": "CyberShot Pro Alpha",
        "Software": "SecureCam OS v4.2",
        "Description": "Confidential transmission. Ensure channels are cleared.",
        "Comment": flag
    }

    text_chunks = b""
    for key, val in metadata.items():
        # Format tEXt: keyword (1-79 bytes Latin-1) + null byte (0x00) + text data (UTF-8/Latin-1)
        data = key.encode("latin-1") + b"\x00" + val.encode("utf-8")
        text_chunks += make_chunk(b"tEXt", data)

    # 4. IDAT Chunk (Pixel Data Gambar Asli)
    # Membuat gambar abstrak bertema investigasi malam (dark navy gradient)
    raw_scanlines = []
    for y in range(height):
        line = bytearray([0])  # Filter type 0 (None)
        for x in range(width):
            # Gradasi warna biru gelap - cyan
            r = int(10 + (25 * x / width))
            g = int(20 + (45 * y / height))
            b = int(50 + (100 * (x + y) / (width + height)))
            line.extend([r, g, b])
        raw_scanlines.append(bytes(line))

    compressed_pixels = zlib.compress(b"".join(raw_scanlines), level=9)
    idat_chunk = make_chunk(b"IDAT", compressed_pixels)

    # 5. IEND Chunk (End of Image)
    iend_chunk = make_chunk(b"IEND", b"")

    # Gabungkan semua bagian menjadi file PNG yang utuh dan valid
    full_png = png_signature + ihdr_chunk + text_chunks + idat_chunk + iend_chunk

    with open(filename, "wb") as f:
        f.write(full_png)

    print(f"[+] Berhasil membuat gambar challenge: '{filename}'")
    print(f"[+] Ukuran: {width}x{height} piksel ({len(full_png)} bytes)")
    print(f"[+] Flag yang disisipkan: {flag}")

if __name__ == "__main__":
    create_challenge_image("evidence.png")
