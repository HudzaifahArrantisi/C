# Shadow Pixel (Piksel Bayangan)

- Kategori: Digital Forensics & Steganography
- Kesulitan: Medium
- Topik: File Carving & LSB Steganography
- Format flag: `NFXCTF{...}`
- Nilai yang disarankan: 250 - 300 poin

## Deskripsi Soal

Tim DFIR (Digital Forensics and Incident Response) menyita sebuah gambar bukti dari laptop seorang pelaku spionase industri bernama `evidence.png`. 

Pelaku mengklaim bahwa file tersebut hanyalah gambar aset biasa yang bersih. Analis awal yang hanya memeriksa metadata menggunakan `exiftool` dan mencari teks dengan `strings` tidak menemukan kejanggalan apa pun.

Namun, tim intelijen meyakini ada dokumen rahasia penting yang disembunyikan di dalam struktur internal berkas gambar tersebut melalui teknik berlapis. 

Bantu tim investigasi menggali lebih dalam dari sekadar metadata dan temukan flag yang tersembunyi!

## Berkas Peserta

- `evidence.png` (Dapat diunduh oleh peserta)

> **Catatan untuk Author/Panitia:** Jika file `evidence.png` belum ada, buat file tersebut dengan menjalankan:
> ```bash
> python generate.py
> ```

## Hint Bertingkat

Gunakan hint secara berurutan jika peserta mengalami kebuntuan:

1. **Hint 1:** Jangan hanya mengandalkan `exiftool` atau `strings`. Metadata gambar telah dibersihkan oleh pelaku. Analisis struktur berkas gambar dan data pikselnya.
2. **Hint 2:** Gunakan teknik **File Carving** menggunakan tool seperti `binwalk` atau `foremost` untuk melihat apakah ada berkas arsip yang disisipkan di luar batas normal gambar (*trailing bytes*).
3. **Hint 3:** Jika arsip hasil ekstraksi meminta kata sandi (password), periksa nilai bit terkecil (**LSB / Least Significant Bit**) dari saluran warna RGB pada gambar tersebut menggunakan tool seperti `zsteg` atau `stegsolve`.

## Catatan Distribusi

* Panitia **hanya membagikan** file `README.md` (atau deskripsinya di portal CTF) dan file `evidence.png` kepada peserta.
* File `generate.py`, `solve.py`, dan `SOLVE.md` adalah dokumen internal panitia.
