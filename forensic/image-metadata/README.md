# Shadow Archive (Wordlist & ZIP Cracking)

- **Kategori:** Digital Forensics
- **Kesulitan:** Medium
- **Topik:** File Carving, Wordlist Dictionary Attack, Password Cracking
- **Format Flag:** `NFXCTF{...}`
- **Nilai yang Disarankan:** 250 - 300 poin

---

## 📋 Pertanyaan Soal (Deskripsi untuk Web / Platform CTF)

> *Salin teks di bawah ini ke form deskripsi soal pada platform CTF (CTFd/lainnya):*

```markdown
### Deskripsi Soal

Dalam sebuah operasi penindakan kasus spionase siber, tim DFIR berhasil menyita sebuah media penyimpanan milik pelaku. Di dalamnya ditemukan berkas gambar bukti bernama `evidence.png`.

Pemeriksaan awal menggunakan tool metadata standar tidak menemukan kejanggalan apa pun. Namun, analisis integritas file menunjukkan ukuran berkas yang tidak wajar untuk format gambar sejenisnya—mengindikasikan adanya artefak rahasia yang sengaja disisipkan di luar struktur berkas gambar resmi (*trailing bytes*).

Saat berhasil diekstrak, artefak tersebut menyimpan berkas rahasia `flag.txt` yang terkunci dengan kata sandi kuat, bersama berkas petunjuk `passwords.txt` berisi daftar 1.000 kandidat kata sandi.

Gunakan keahlian digital forensik dan teknik password cracking untuk membongkar proteksi arsip tersebut dan dapatkan isi dokumen `flag.txt`!

**Format Flag:** `NFXCTF{...}`
```

---

## 📎 Berkas Lampiran Peserta

- [`evidence.png`](evidence.png)

---

## 💡 Hint Bertingkat (Untuk Platform CTF)

1. **Hint 1:** Jangan hanya terpaku pada metadata gambar. Periksa bagian akhir file (*trailing bytes*) setelah chunk penutup gambar menggunakan tool file carving seperti `binwalk` (`binwalk -e evidence.png`) atau `foremost`.
2. **Hint 2:** Di dalam folder hasil ekstraksi terdapat berkas arsip `.zip`. Saat diekstrak, berkas `passwords.txt` dapat dibuka langsung tanpa kata sandi sebagai kamus wordlist.
3. **Hint 3:** Ekstrak hash PKZIP dari file arsip tersebut menggunakan `zip2john <nama_zip>.zip > zip.hash`, lalu gunakan **John the Ripper** (`john --wordlist=passwords.txt zip.hash`) atau **Hashcat** dengan mode `-m 17210` bersama kamus `passwords.txt` untuk memecahkan kata sandi `flag.txt`.
