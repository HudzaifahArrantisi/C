# Broken Stream (LFSR)

- Kategori: Cryptography
- Kesulitan: Medium
- Topik: Stream Cipher, LFSR (Linear Feedback Shift Register), Known-Plaintext Attack
- Format flag: `NFXCTF{...}`
- Nilai yang disarankan: 200 - 250 poin

## Deskripsi Soal

Seorang pengembang membuat generator enkripsi stream kustom berbasis **Linear Feedback Shift Register (LFSR)** 16-bit. Mereka mengklaim bahwa aliran keystream yang dihasilkan sepenuhnya acak dan tidak mungkin diprediksi tanpa mengetahui seed awal.

Sebuah flag rahasia berhasil dicegat dalam bentuk ciphertext heksadesimal. Karena generator ini hanya menggunakan register berukuran 16-bit, temukan kelemahan pada ruang kuncinya (*keyspace*) dan pulihkan flag aslinya!

## Berkas Peserta

- `chall.py`

Jalankan file dengan:
```bash
python chall.py
```

## Hint Bertingkat

1. **Hint 1:** Enkripsi stream bekerja dengan melakukan operasi XOR antara setiap byte plaintext dan byte keystream (`ciphertext = plaintext ^ keystream`).
2. **Hint 2:** Anda mengetahui 7 karakter pertama dari plaintext karena semua flag diawali dengan `NFXCTF{` (**Known-Plaintext Attack**).
3. **Hint 3:** Register LFSR ini hanya berukuran 16-bit, artinya nilai seed yang mungkin hanya berkisar antara `1` sampai `65535` ($2^{16} - 1$). Ruang pencarian ini sangat kecil sehingga dapat di-*brute-force* dalam hitungan detik menggunakan Python.
