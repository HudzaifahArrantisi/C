# Solusi Resmi: Shadow Pixel (Piksel Bayangan)

## Analisis Masalah

Tantangan ini dirancang untuk tingkat **Medium** dengan menggabungkan dua teknik digital forensik & steganografi:
1. **File Carving (Trailing Bytes Archive):** Terdapat berkas arsip `.zip` yang ditempelkan di belakang chunk penutup PNG (`IEND`).
2. **LSB Steganography (Pixel Bit Manipulation):** Arsip ZIP tersebut dilindungi password. Password tidak disimpan dalam teks polos (sehingga lolos dari `strings` dan `exiftool`), melainkan disematkan pada **Least Significant Bit (LSB)** saluran warna RGB di dalam data piksel (`IDAT`).

---

## Langkah demi Langkah Penyelesaian

### 1. Tahap Investigasi Awal (Menyadari Pengecoh)

Jika peserta menjalankan tool metadata standar:
```bash
exiftool evidence.png
```
Output hanya menampilkan data normal seperti:
```text
Title    : Security Incident Report #4029 - Image Asset
Author   : DFIR Team Alpha
Software : GIMP 2.10.34
```
Pencarian teks langsung via `strings`:
```bash
strings evidence.png | grep -i "NFXCTF"
```
Hasil: **Nihil (Kosong)**, karena flag berada di dalam ZIP yang terenkripsi ZipCrypto.

---

### 2. Tahap File Carving (Ekstraksi Arsip Tersembunyi)

Gunakan **binwalk** untuk memeriksa apakah ada berkas tambahan yang digabungkan ke gambar:

```bash
binwalk evidence.png
```

**Output:**
```text
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 600 x 300, 8-bit/color RGB, non-interlaced
...
1892          0x764           Zip archive data, encrypted at least v2.0 to extract, compressed size: 57, uncompressed size: 45, name: flag.txt
2004          0x7D4           End of Zip archive
```

Terdapat berkas ZIP pada offset `0x764`! Ekstrak arsip tersebut:

```bash
binwalk -e evidence.png
# Atau gunakan foremost: foremost -i evidence.png
```

Masuk ke folder hasil ekstraksi (`_evidence.png.extracted/`):
```bash
cd _evidence.png.extracted/
unzip 764.zip
```
Sistem akan meminta password:
```text
[764.zip] flag.txt password: 
```

---

### 3. Tahap Analisis Steganografi (Menemukan Password Arsip)

Karena password disembunyikan di dalam bit piksel RGB, gunakan tool analisis LSB gambar PNG yaitu **`zsteg`**:

```bash
zsteg -a evidence.png
```

Perhatikan bagian `b1,rgb,lsb,xy`:
```text
b1,rgb,lsb,xy       .. text: "HINT: The carved archive password is 'p1x3l_d1g1t4l_f0r3ns1cs'\n"
```

Password berhasil didapatkan:  
🔑 **`p1x3l_d1g1t4l_f0r3ns1cs`**

---

### 4. Tahap Dekripsi & Mengambil Flag

Buka berkas arsip menggunakan password yang ditemukan:

```bash
unzip -P p1x3l_d1g1t4l_f0r3ns1cs 764.zip
cat flag.txt
```

Atau menggunakan Python:
```python
import zipfile
with zipfile.ZipFile("764.zip") as zf:
    print(zf.read("flag.txt", pwd=b"p1x3l_d1g1t4l_f0r3ns1cs").decode())
```

---

### 5. Cara Cepat via Script Solver Otomatis

Jalankan script `solve.py` yang disediakan:

```bash
python solve.py
```

**Output:**
```text
[*] Menganalisis berkas: evidence.png (2026 bytes)
[+] Dimensi gambar: 600x300
[+] Chunk IEND selesai pada offset: 1892 (0x764)

[*] Langkah 1: Mengekstrak LSB Steganografi dari data piksel (simulasi zsteg)...
[+] String tersembunyi dari LSB: "HINT: The carved archive password is 'p1x3l_d1g1t4l_f0r3ns1cs'"
[+] Password arsip yang diperoleh: p1x3l_d1g1t4l_f0r3ns1cs

[*] Langkah 2: Memeriksa data terlampir di akhir berkas (simulasi binwalk)...
[+] Ditemukan ZIP archive tersembunyi (134 bytes).

[*] Langkah 3: Membuka ZIP dengan password yang ditemukan...
[+] Berkas di dalam arsip: ['flag.txt']

==================================================
[🎯 FLAG BERHASIL DIDAPATKAN]: NFXCTF{c4rv1ng_4nd_l5b_st3g4n0_m4st3r}
==================================================
```

---

## Flag Resmi

```text
NFXCTF{c4rv1ng_4nd_l5b_st3g4n0_m4st3r}
```
