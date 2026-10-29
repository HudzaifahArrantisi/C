# Ghost XOR

Kategori: Cryptography  
Kesulitan: Easy  
Nilai yang disarankan: 100 poin  
Format flag: `NFXCTF{...}`

## Deskripsi

Tim keamanan mencegat sebuah pesan yang dienkripsi menggunakan operasi XOR. Kunci yang dipakai terdiri dari empat karakter dan digunakan berulang kali.

Kode enkripsi dan ciphertext tersedia dalam `chall.py`. Temukan kuncinya, dekripsi pesannya, lalu kirim flag yang kamu dapatkan.

## File peserta

- `chall.py`

Jalankan file dengan:

```bash
python chall.py
```

## Hint

Gunakan hint secara berurutan jika kamu buntu:

1. XOR dapat dibalik dengan operasi XOR yang sama: `ciphertext XOR plaintext = key`.
2. Kamu sudah mengetahui beberapa karakter plaintext karena setiap flag diawali dengan `NFXCTF{`.
3. XOR empat byte pertama ciphertext dengan `NFXC` untuk mendapatkan kunci empat karakter.
