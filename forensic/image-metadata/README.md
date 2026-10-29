# Jejak Tak Kasat Mata (Hidden in The Pixels)

- Kategori: Digital Forensics, Image & Metadata Analysis
- Kesulitan: Easy
- Topik: PNG Metadata & Chunks Analysis (tEXt Chunks)
- Format flag: `NFXCTF{...}`
- Nilai yang disarankan: 100 poin

## Deskripsi Soal

Sebuah flashdisk milik informan rahasia ditemukan di lokasi kejadian perkara. Di dalamnya hanya terdapat satu file gambar pemandangan digital bernama `evidence.png`. 

Tim digital forensik meyakini bahwa gambar tersebut tidak sekadar file grafis biasa, melainkan media penyampaian pesan rahasia yang disisipkan sebelum informan tersebut menghilang. 

Bantu penyidik memeriksa artefak file `evidence.png` dan temukan pesan tersembunyi (flag) di dalamnya!

## Berkas Peserta

- `evidence.png` (Dapat diunduh oleh peserta)

> **Catatan untuk Author/Panitia:** Jika file `evidence.png` belum ada, buat file tersebut dengan menjalankan:
> ```bash
> python generate.py
> ```

## Hint Bertingkat

Gunakan hint secara berurutan apabila mengalami kesulitan:

1. Sebuah file gambar menyimpan informasi lebih dari sekadar piksel warna. Periksa informasi metadata yang melekat pada file tersebut.
2. File PNG menyimpan informasi teks di dalam struktur blok yang disebut **tEXt chunks** (Textual Data Chunks).
3. Anda dapat menggunakan tool CLI seperti `exiftool evidence.png`, utility `strings`, atau tool analisis gambar seperti `zsteg` / website metadata viewer online.

## Catatan Distribusi

* Panitia **hanya membagikan** file `README.md` (atau deskripsinya di portal CTF) dan file `evidence.png` kepada peserta.
* File `generate.py`, `solve.py`, dan `SOLVE.md` adalah dokumen internal panitia.
