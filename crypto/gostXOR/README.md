# Ghost XOR

- **Kategori:** Cryptography
- **Kesulitan:** Easy
- **Topik:** Repeated-Key XOR, Known-Plaintext Attack (KPA)
- **Format Flag:** `NFXCTF{...}`
- **Nilai yang Disarankan:** 100 poin

---

## 📋 Pertanyaan Soal (Deskripsi untuk Web / Platform CTF)

> *Salin teks di bawah ini ke form deskripsi soal pada platform CTF (CTFd/lainnya):*

```markdown
### Deskripsi Soal

Tim intelijen keamanan siber berhasil mencegat sebuah transmisi data rahasia dari kanal komunikasi mencurigakan. Berdasarkan hasil analisis awal, pesan tersebut dienkripsi menggunakan operasi XOR berulang dengan kunci sederhana yang hanya terdiri dari 4 karakter ASCII.

Pelaku meninggalkan skrip enkripsi beserta ciphertext hasil cegatan di dalam file `chall.py`.

Sebagai seorang kriptoanalis, bisakah kamu mengungkap kunci rahasia 4 karakter tersebut, mendekripsi pesan yang terkunci, dan mengembalikan flag aslinya?

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

1. **Hint 1:** Enkripsi XOR bersifat simetris dan reversibel: jika `C = P ^ K`, maka `K = C ^ P` dan `P = C ^ K`.
2. **Hint 2:** Anda sudah mengetahui beberapa karakter plaintext di awal pesan karena format flag selalu diawali dengan `NFXCTF{` (*Known-Plaintext Attack*).
3. **Hint 3:** Operasikan XOR antara 4 byte pertama dari ciphertext dengan 4 byte pertama prefix flag (`NFXC`) untuk langsung mendapatkan kunci 4 karakter tersebut!
