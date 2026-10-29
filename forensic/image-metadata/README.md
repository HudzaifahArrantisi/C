# Shadow Archive (Wordlist & ZIP Cracking)

- Kategori: Digital Forensics & Password Cracking
- Kesulitan: Medium
- Topik: File Carving, Wordlist Dictionary Attack & Hashcat Cracking
- Format flag: `NFXCTF{...}`
- Nilai yang disarankan: 250 - 300 poin

## Deskripsi Soal

Sebuah gambar bukti investigasi digital bernama `evidence.png` diamankan dari tersangka peretasan. 

Pemeriksaan awal terhadap metadata tidak menemukan apa pun. Analis forensik mendeteksi adanya berkas arsip rahasia yang ditempelkan di belakang gambar tersebut. Ketika arsip diekstrak, terdapat dokumen `flag.txt` yang terkunci dengan kata sandi kuat, beserta file petunjuk `passwords.txt` yang memuat 1000 kandidat kata sandi.

Gunakan keahlian forensik dan teknik password cracking (menggunakan **Hashcat** atau **John the Ripper**) untuk membuka arsip tersebut dan mendapatkan flag!

## Berkas Peserta

- `evidence.png` (Dapat diunduh oleh peserta)

> **Catatan Author/Panitia:** Jalankan perintah berikut untuk menghasilkan berkas soal:
> ```bash
> python generate.py
> ```

## Hint Bertingkat

1. **Hint 1:** Periksa bagian *trailing bytes* dari `evidence.png` menggunakan tool file carving seperti `binwalk` (`binwalk -e evidence.png`).
2. **Hint 2:** Di dalam folder hasil ekstraksi, Anda akan menemukan file arsip `.zip`. Saat diekstrak, file `passwords.txt` dapat dibuka tanpa password.
3. **Hint 3:** Ekstrak hash dari file zip menggunakan `zip2john <nama_file.zip> > zip.hash`, kemudian gunakan **Hashcat** (mode `-m 17200`) atau **John the Ripper** bersama daftar kata sandi `passwords.txt`.

## Catatan Distribusi

* Panitia **hanya membagikan** file `README.md` dan file `evidence.png` kepada peserta.
* File `generate.py`, `solve.py`, dan `SOLVE.md` adalah dokumen internal panitia.
