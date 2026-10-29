#!/usr/bin/env python3
"""
solve.py
Script solver otomatis untuk challenge CTF Forensic (Medium):
1. Menemukan dan mengekstrak ZIP tersembunyi dari file PNG (trailing bytes).
2. Mengekstrak wordlist passwords.txt (1000 kata sandi).
3. Melakukan brute-force/cracking menggunakan wordlist tersebut (simulasi hashcat / john).
4. Menampilkan password dan flag yang didapatkan.
"""

import struct
import zipfile
import io
from pathlib import Path

def solve(image_path: str = "evidence.png"):
    p = Path(image_path)
    if not p.exists():
        print(f"[-] File '{image_path}' belum dibuat. Jalankan 'python generate.py' terlebih dahulu.")
        return

    data = p.read_bytes()
    print(f"[*] Menganalisis berkas: {image_path} ({len(data)} bytes)")

    # 1. Cari chunk IEND untuk menemukan titik akhir file PNG
    iend_pos = data.find(b"IEND")
    if iend_pos == -1:
        print("[-] Chunk IEND tidak ditemukan.")
        return

    iend_end_offset = iend_pos + 8  # 'IEND' (4 bytes) + CRC (4 bytes)
    trailing_data = data[iend_end_offset:]

    if not trailing_data.startswith(b"PK\x03\x04"):
        print("[-] Header ZIP tidak ditemukan setelah IEND.")
        return

    print(f"[+] Ditemukan ZIP archive tersembunyi pada offset: {iend_end_offset} (0x{iend_end_offset:X})")

    # 2. Buka ZIP
    with zipfile.ZipFile(io.BytesIO(trailing_data)) as zf:
        file_list = zf.namelist()
        print(f"[+] Berkas di dalam arsip: {file_list}")

        # passwords.txt tidak terenkripsi
        if "passwords.txt" not in file_list:
            print("[-] passwords.txt tidak ditemukan di dalam ZIP.")
            return

        passwords_content = zf.read("passwords.txt").decode("utf-8")
        password_list = [line.strip() for line in passwords_content.splitlines() if line.strip()]
        print(f"[+] Berhasil mengekstrak 'passwords.txt' berisi {len(password_list)} kata sandi!")

        # 3. Cracking flag.txt menggunakan wordlist
        print("\n[*] Menjalankan dictionary attack pada 'flag.txt' (simulasi Hashcat)...")
        found_password = None
        flag = None

        for pwd in password_list:
            try:
                flag = zf.read("flag.txt", pwd=pwd.encode("ascii")).decode().strip()
                found_password = pwd
                break
            except (RuntimeError, zipfile.BadZipFile):
                continue

        if found_password:
            print("\n" + "=" * 55)
            print(f"[+] KATA SANDI BERHASIL DITEMUKAN : {found_password}")
            print(f"[🎯 FLAG BERHASIL DIDAPATKAN]     : {flag}")
            print("=" * 55)
        else:
            print("[-] Gagal menemukan password yang cocok dari wordlist.")

if __name__ == "__main__":
    solve("evidence.png")
