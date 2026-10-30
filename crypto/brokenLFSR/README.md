# Broken Stream (LFSR)

- **Kategori:** Cryptography
- **Kesulitan:** Medium
- **Topik:** Stream Cipher, LFSR (Linear Feedback Shift Register), Known-Plaintext Attack (KPA)
- **Format Flag:** `NFXCTF{...}`
- **Nilai yang Disarankan:** 200 - 250 poin

---

## 📋 Pertanyaan Soal (Deskripsi untuk Web / Platform CTF)

> *Salin teks di bawah ini ke form deskripsi soal pada platform CTF (CTFd/lainnya):*

```markdown
### Deskripsi Soal

Seorang pengembang sistem keamanan lokal mengklaim telah menciptakan algoritma stream cipher kustom yang "tidak dapat dipecahkan" berbasis Linear Feedback Shift Register (LFSR) 16-bit. Sang pembuat mengklaim aliran keystream yang keluar bersifat acak sempurna dan mustahil ditebak tanpa mengetahui nilai kunci awal (*seed*).

Sebuah dokumen rahasia terenkripsi berhasil disadap dalam bentuk string heksadesimal bersama kode generator stream cipher di dalam file `chall.py`.

Apakah klaim keamanan pengembang tersebut terbukti benar? Analisis algoritma LFSR tersebut, temukan celah pada ruang pencarian kuncinya (*keyspace*), pulihkan nilai seed awal, dan dekripsi flag rahasia di dalamnya!

**Format Flag:** `NFXCTF{...}`
```

---

## 📎 Berkas Lampiran Peserta

- [`chall.py`](chall.py)

Cara menjalankan skrip:
```bash
python chall.py
```

---

## 💡 Hint Bertingkat (Untuk Platform CTF)

1. **Hint 1:** Enkripsi stream menggabungkan setiap byte teks asli dengan byte keystream menggunakan operasi XOR (`ciphertext = plaintext ^ keystream`).
2. **Hint 2:** Anda mengetahui 7 karakter pertama dari teks asli karena format flag selalu diawali dengan `NFXCTF{` (*Known-Plaintext Attack*).
3. **Hint 3:** Register internal LFSR ini hanya berukuran 16-bit. Artinya, nilai seed yang mungkin hanya berkisar antara `1` sampai `65535` ($2^{16} - 1$). Ruang pencarian ini sangat kecil sehingga dapat di-*brute-force* dalam hitungan detik menggunakan skrip Python untuk mencocokkan 7 byte pertama!
