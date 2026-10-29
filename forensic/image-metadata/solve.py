#!/usr/bin/env python3
"""
solve.py
Script solver otomatis untuk challenge CTF Forensic (Medium):
1. Mendeteksi dan mengekstrak LSB steganography dari piksel PNG (simulasi zsteg).
2. Melakukan carving ZIP file tersembunyi setelah chunk IEND (simulasi binwalk/foremost).
3. Membuka arsip ZIP menggunakan password yang ditemukan di LSB untuk memperoleh flag.
"""

import struct
import zlib
import zipfile
import io
import re
from pathlib import Path

def extract_lsb_secret(raw_scanlines_bytes: bytes, width: int, height: int) -> bytes:
    """Mengekstrak bit LSB (b1,rgb,lsb,xy) dari data scanlines PNG yang sudah didekompresi."""
    bytes_per_row = 1 + width * 3
    extracted_bits = []

    for y in range(height):
        row_offset = y * bytes_per_row
        # line[0] adalah filter byte, data channel RGB mulai dari offset 1
        row_channels = raw_scanlines_bytes[row_offset + 1 : row_offset + bytes_per_row]
        for b in row_channels:
            extracted_bits.append(b & 1)

    # Susun tiap 8 bit menjadi 1 byte (LSB first)
    recovered_bytes = bytearray()
    for i in range(0, len(extracted_bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val |= (extracted_bits[i + bit_idx] << bit_idx)
        if byte_val == 0:  # Berhenti jika menemukan null byte
            break
        recovered_bytes.append(byte_val)

    return bytes(recovered_bytes)

def solve(image_path: str = "evidence.png"):
    p = Path(image_path)
    if not p.exists():
        print(f"[-] File '{image_path}' belum dibuat. Jalankan 'python generate.py' terlebih dahulu.")
        return

    data = p.read_bytes()
    print(f"[*] Menganalisis berkas: {image_path} ({len(data)} bytes)")

    # 1. Parsing chunk PNG
    offset = 8
    idat_data = bytearray()
    width, height = 0, 0
    iend_end_offset = 0

    while offset < len(data):
        if offset + 8 > len(data):
            break
        length, chunk_type = struct.unpack(">I4s", data[offset:offset+8])
        chunk_name = chunk_type.decode("ascii", errors="ignore")
        chunk_payload = data[offset+8 : offset+8+length]

        if chunk_name == "IHDR":
            width, height = struct.unpack(">II", chunk_payload[:8])
            print(f"[+] Dimensi gambar: {width}x{height}")
        elif chunk_name == "IDAT":
            idat_data.extend(chunk_payload)
        elif chunk_name == "IEND":
            iend_end_offset = offset + 12 + length
            print(f"[+] Chunk IEND selesai pada offset: {iend_end_offset} (0x{iend_end_offset:X})")
            break

        offset += 12 + length

    # 2. Steganography: Ekstrak LSB dari IDAT
    print("\n[*] Langkah 1: Mengekstrak LSB Steganografi dari data piksel (simulasi zsteg)...")
    decompressed = zlib.decompress(bytes(idat_data))
    lsb_text = extract_lsb_secret(decompressed, width, height)
    lsb_str = lsb_text.decode("utf-8", errors="ignore").strip()
    print(f"[+] String tersembunyi dari LSB: \"{lsb_str}\"")

    # Ambil password dari string LSB menggunakan regex
    pwd_match = re.search(r"password is '([^']+)'", lsb_str)
    if not pwd_match:
        print("[-] Gagal mendeteksi password dari LSB.")
        return
    discovered_password = pwd_match.group(1)
    print(f"[+] Password arsip yang diperoleh: {discovered_password}")

    # 3. Carving: Ambil data ZIP di belakang IEND
    print("\n[*] Langkah 2: Memeriksa data terlampir di akhir berkas (simulasi binwalk)...")
    trailing_data = data[iend_end_offset:]
    if not trailing_data.startswith(b"PK\x03\x04"):
        print("[-] Header ZIP tidak ditemukan setelah IEND.")
        return

    print(f"[+] Ditemukan ZIP archive tersembunyi ({len(trailing_data)} bytes).")

    # 4. Buka ZIP dengan password
    print("\n[*] Langkah 3: Membuka ZIP dengan password yang ditemukan...")
    try:
        with zipfile.ZipFile(io.BytesIO(trailing_data)) as zf:
            namelist = zf.namelist()
            print(f"[+] Berkas di dalam arsip: {namelist}")
            flag_content = zf.read("flag.txt", pwd=discovered_password.encode("ascii")).decode().strip()
            print("\n" + "="*50)
            print(f"[🎯 FLAG BERHASIL DIDAPATKAN]: {flag_content}")
            print("="*50)
    except Exception as e:
        print(f"[-] Gagal mengekstrak ZIP: {e}")

if __name__ == "__main__":
    solve("evidence.png")
