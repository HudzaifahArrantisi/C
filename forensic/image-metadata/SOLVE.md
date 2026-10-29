# Solusi Resmi: Shadow Archive (Wordlist & ZIP Cracking)

## Analisis Masalah

Tantangan ini menggabungkan teknik **File Carving** dengan **Password Cracking**:
1. Sebuah arsip ZIP disembunyikan di akhir file PNG (`evidence.png`).
2. Arsip ZIP tersebut memuat 2 file:
   - `passwords.txt`: Daftar 1000 kemungkinan kata sandi (tidak berpassword / plaintext).
   - `flag.txt`: Dokumen rahasia terenkripsi ZipCrypto.
3. Peserta harus mengekstrak hash dari file ZIP lalu melakukan *dictionary attack* menggunakan tool seperti **Hashcat** atau **John the Ripper** dengan kamus `passwords.txt`.

---

## Panduan Langkah demi Langkah di Kali Linux

### 1. Ekstraksi File Menggunakan Binwalk

Jalankan perintah binwalk untuk mengekstrak data di balik gambar:

```bash
binwalk -e evidence.png
```

Masuk ke folder hasil ekstraksi:

```bash
cd _evidence.png.extracted
ls -la
```

Anda akan melihat file arsip zip (misalnya bernama `7CBC.zip` atau `<offset>.zip`).

---

### 2. Membuka Arsip untuk Mendapatkan `passwords.txt`

Ekstrak file zip:

```bash
unzip 7CBC.zip
```

Output:
```text
Archive:  7CBC.zip
  extracting: passwords.txt
[7CBC.zip] flag.txt password:
```

Tekan **Ctrl + C** untuk membatalkan prompt password `flag.txt`.  
Periksa isi direktori:
```bash
ls -l
wc -l passwords.txt
```
File `passwords.txt` sudah berhasil diekstrak dan berisi **1000 baris password**.

---

### 3. Cracking Password Menggunakan Hashcat (Metode Utama)

#### Langkah 3A: Ekstrak Hash ZIP
Gunakan utility `zip2john` (sudah bawaan Kali Linux):

```bash
zip2john 7CBC.zip > zip.hash
```

#### Langkah 3B: Ambil Hash untuk Hashcat
Filter string hash PKZIP (`$pkzip$...$/pkzip$`):

```bash
grep -o '\$pkzip\$.*\$/pkzip\$' zip.hash > hash_cat.txt
```

#### Langkah 3C: Jalankan Hashcat
Gunakan mode **`-m 17200`** (PKZIP Compressed) atau **`-m 17210`** (PKZIP Uncompressed):

```bash
hashcat -m 17200 -a 0 hash_cat.txt passwords.txt
```

> **Tips:** Jika dijalankan di Virtual Machine (VM) tanpa GPU dedicated, tambahkan flag `--force`:
> ```bash
> hashcat -m 17200 -a 0 hash_cat.txt passwords.txt --force
> ```

Hashcat akan menemukan password dalam hitungan detik:
```text
$pkzip$1*1*2*0*...*$/pkzip$:cyber_shield_2026

Status...........: Cracked
```

Kata sandi yang ditemukan:  
🔑 **`cyber_shield_2026`**

---

### 4. Alternatif: Cracking Menggunakan John the Ripper

Jika lebih menyukai John:

```bash
zip2john 7CBC.zip > zip.hash
john --wordlist=passwords.txt zip.hash
```

Output:
```text
Loaded 1 password hash (PKZIP [32/64])
cyber_shield_2026 (7CBC.zip/flag.txt)
1g 0:00:00:00 DONE 2/3 (2026-10-29 18:45) 100.0g/s 100000p/s 100000c/s
```

---

### 5. Alternatif Cepat: Menggunakan `fcrackzip`

```bash
fcrackzip -u -D -p passwords.txt 7CBC.zip
```

Output:
```text
PASSWORD FOUND!!!!: pw == cyber_shield_2026
```

---

### 6. Membuka `flag.txt`

Gunakan kata sandi yang ditemukan (`cyber_shield_2026`):

```bash
unzip -P cyber_shield_2026 7CBC.zip
cat flag.txt
```

Output:
```text
NFXCTF{h4shc4t_cr4ck1ng_z1p_succ3ssfu11y}
```

---

### 7. Verifikasi via Script Python Solver

Anda juga dapat menjalankan solver otomatis panitia:

```bash
python3 solve.py
```

Output:
```text
[*] Menganalisis berkas: evidence.png
[+] Ditemukan ZIP archive tersembunyi
[+] Berhasil mengekstrak 'passwords.txt' berisi 1000 kata sandi!
[*] Menjalankan dictionary attack pada 'flag.txt' (simulasi Hashcat)...

=======================================================
[+] KATA SANDI BERHASIL DITEMUKAN : cyber_shield_2026
[🎯 FLAG BERHASIL DIDAPATKAN]     : NFXCTF{h4shc4t_cr4ck1ng_z1p_succ3ssfu11y}
=======================================================
```

---

## Flag Resmi

```text
NFXCTF{h4shc4t_cr4ck1ng_z1p_succ3ssfu11y}
```
