# Solusi Resmi: Jejak Tak Kasat Mata (Hidden in The Pixels)

## Analisis Soal

Diberikan sebuah file gambar berekstensi `.png` bernama `evidence.png`. 

Struktur spesifikasi berkas PNG (Portable Network Graphics) menggunakan konsep **Chunks**. Selain chunk wajib seperti:
* `IHDR` (Header informasi resolusi & color depth)
* `IDAT` (Data piksel terkompresi zlib)
* `IEND` (Penanda akhir file)

Terdapat chunk tambahan (*ancillary chunks*) bernama **`tEXt`** yang berfungsi menyimpan informasi tekstual seperti *Author*, *Software*, *Title*, *Description*, maupun *Comment*. Penulis menyembunyikan flag di dalam chunk teks tersebut.

---

## Berbagai Metode Penyelesaian

### 1. Menggunakan ExifTool (Rekomendasi Utama)

Exiftool adalah tool standar digital forensik untuk membaca metadata gambar:

```bash
exiftool evidence.png
```

**Output:**
```text
File Name                       : evidence.png
Directory                       : .
File Size                       : 1682 bytes
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 600
Image Height                    : 300
Bit Depth                       : 8
Color Type                      : RGB
Title                           : Operation Dark Shadow - Field Asset
Author                          : Investigator-7
Camera                          : CyberShot Pro Alpha
Software                        : SecureCam OS v4.2
Description                     : Confidential transmission. Ensure channels are cleared.
Comment                         : NFXCTF{m3t4d4t4_4nd_chv0nk5_n3v3r_l13}
```

Flag langsung terlihat pada atribut **Comment**.

---

### 2. Menggunakan Utilitas `strings` (Metode Cepat CLI)

Karena data chunk `tEXt` ditulis dalam format karakter ASCII/UTF-8 polos:

```bash
# Di Linux / Mac / Git Bash:
strings evidence.png | grep "NFXCTF"
```

**Output:**
```text
CommentNFXCTF{m3t4d4t4_4nd_chv0nk5_n3v3r_l13}
```

---

### 3. Menggunakan `zsteg` (Tool Steganografi Populer di CTF)

```bash
zsteg -a evidence.png
```

Tool `zsteg` akan langsung mendeteksi chunk metadata `tEXt`:
```text
meta Description   : text: "Confidential transmission. Ensure channels are cleared."
meta Comment       : text: "NFXCTF{m3t4d4t4_4nd_chv0nk5_n3v3r_l13}"
```

---

### 4. Menggunakan Python Solver Otomatis

Jalankan script `solve.py`:

```bash
python solve.py
```

**Output:**
```text
[*] Menganalisis chunk pada file: evidence.png
--------------------------------------------------
[METADATA] Title        : Operation Dark Shadow - Field Asset
[METADATA] Author       : Investigator-7
[METADATA] Camera       : CyberShot Pro Alpha
[METADATA] Software     : SecureCam OS v4.2
[METADATA] Description  : Confidential transmission. Ensure channels are cleared.
[METADATA] Comment      : NFXCTF{m3t4d4t4_4nd_chv0nk5_n3v3r_l13}
--------------------------------------------------
[+] Flag berhasil ditemukan: NFXCTF{m3t4d4t4_4nd_chv0nk5_n3v3r_l13}
```

---

## Flag

```text
NFXCTF{m3t4d4t4_4nd_chv0nk5_n3v3r_l13}
```
