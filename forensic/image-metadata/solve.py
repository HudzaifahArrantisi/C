#!/usr/bin/env python3
"""
solve.py
Script solver otomatis untuk mengekstrak metadata dan flag dari file PNG (tEXt chunks).
"""

import struct
import re
from pathlib import Path

def parse_png_chunks(file_path: str):
    data = Path(file_path).read_bytes()

    if data[:8] != b"\x89PNG\r\n\x1a\n":
        print("[-] Error: Bukan file PNG yang valid.")
        return

    offset = 8
    print(f"[*] Menganalisis chunk pada file: {file_path}")
    print("-" * 50)

    found_flag = None

    while offset < len(data):
        if offset + 8 > len(data):
            break

        length, chunk_type = struct.unpack(">I4s", data[offset:offset+8])
        chunk_name = chunk_type.decode("ascii", errors="ignore")
        chunk_data = data[offset+8 : offset+8+length]

        if chunk_name == "tEXt":
            # Pisahkan keyword dan isinya berdasarkan null byte (0x00)
            if b"\x00" in chunk_data:
                keyword, text_val = chunk_data.split(b"\x00", 1)
                k_str = keyword.decode("latin-1", errors="ignore")
                v_str = text_val.decode("utf-8", errors="ignore")
                print(f"[METADATA] {k_str:<12} : {v_str}")

                if "NFXCTF{" in v_str:
                    found_flag = v_str

        # Loncat ke chunk berikutnya (+4 bytes untuk CRC32)
        offset += 12 + length

    print("-" * 50)
    if found_flag:
        print(f"[+] Flag berhasil ditemukan: {found_flag}")
    else:
        # Fallback regex search
        match = re.search(rb"NFXCTF\{[^\}]+\}", data)
        if match:
            print(f"[+] Flag ditemukan via pattern search: {match.group().decode('utf-8')}")
        else:
            print("[-] Flag tidak ditemukan.")

if __name__ == "__main__":
    parse_png_chunks("evidence.png")
