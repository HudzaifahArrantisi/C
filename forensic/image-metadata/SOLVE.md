# Solusi Resmi: Shadow Archive (Wordlist & ZIP Cracking)

## Analisis Masalah

Tantangan ini menggabungkan teknik **File Carving** dengan **Password Cracking**:
1. Sebuah berkas arsip ZIP disembunyikan pada *trailing bytes* di akhir file PNG (`evidence.png`).
2. Arsip ZIP tersebut memuat 2 file:
   - `passwords.txt`: Daftar 1000 kemungkinan kata sandi (disimpan tanpa enkripsi/plaintext).
   - `flag.txt`: Dokumen rahasia terenkripsi ZipCrypto.
3. Saat peserta mengekstrak arsip ZIP, file `passwords.txt` otomatis keluar. Peserta kemudian mengekstrak hash PKZIP menggunakan `zip2john` dan memecahkan password-nya menggunakan **John the Ripper** atau **Hashcat (mode 17210)**.

---

## Panduan Langkah demi Langkah di Kali Linux

### 1. Ekstraksi File Menggunakan Binwalk

Jalankan `binwalk` dengan opsi `-e` (*extract*) pada file `evidence.png`:

```bash
binwalk -e evidence.png
```

Masuk ke direktori hasil ekstraksi:

```bash
cd _evidence.png.extracted
ls -la
```

Di dalam direktori ini terdapat berkas zip hasil carving (biasanya bernama `79DD.zip` sesuai offset penemuannya).

---

### 2. Mengekstrak Wordlist `passwords.txt`

Jalankan perintah `unzip`:

```bash
unzip *.zip
```

Output di terminal:
```text
Archive:  79DD.zip
 extracting: passwords.txt           
[79DD.zip] flag.txt password:
```

👉 **Tekan `Ctrl + C`** untuk membatalkan permintaan password `flag.txt`.

Periksa file yang berhasil diekstrak:
```bash
ls -l passwords.txt
wc -l passwords.txt
```
Output:
```text
1000 passwords.txt
```
File `passwords.txt` berisi 1000 kombinasi kata sandi siap pakai sebagai kamus dictionary attack!

---

### 3. Cracking Password

#### Metode A: Menggunakan John the Ripper (Paling Mudah & Cepat di Kali Linux)

1. Ekstrak hash dari file ZIP:
   ```bash
   zip2john *.zip > zip.hash
   ```

2. Jalankan John dengan menyertakan wordlist `passwords.txt`:
   ```bash
   john --wordlist=passwords.txt zip.hash
   ```

Output:
```text
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
cyber_shield_2026 (79DD.zip/flag.txt)     
1g 0:00:00:00 DONE (2026-10-29 11:55) 25.00g/s 25000p/s 25000c/s 25000C/s
Session completed.
```

Password berhasil dipecahkan:  
🔑 **`cyber_shield_2026`**

---

#### Metode B: Menggunakan Hashcat (Mode 17210 - PKZIP Uncompressed)

Jika ingin menggunakan Hashcat, gunakan mode **`-m 17210`** (bukan 17200, karena file disimpan tanpa kompresi deflated):

1. Ambil baris hash PKZIP:
   ```bash
   zip2john *.zip > zip.hash
   grep -o '\$pkzip\$.*\$/pkzip\$' zip.hash > hash.txt
   ```

2. Jalankan Hashcat:
   ```bash
   hashcat -m 17210 -a 0 hash.txt passwords.txt --force
   ```

Output:
```text
$pkzip$1*1*2*0*...*$/pkzip$:cyber_shield_2026

Status...........: Cracked
```

---

#### Metode C: Menggunakan `fcrackzip` (Alternatif CLI Cepat)

```bash
fcrackzip -u -D -p passwords.txt *.zip
```

Output:
```text
PASSWORD FOUND!!!!: pw == cyber_shield_2026
```

---

### 4. Membuka `flag.txt`

Setelah menemukan kata sandinya (`cyber_shield_2026`), ekstrak `flag.txt`:

```bash
unzip -P cyber_shield_2026 *.zip
```

*(Jika muncul konfirmasi `replace passwords.txt?`, pilih `n` atau `no`)*

Tampilkan isi flag:
```bash
cat flag.txt
```

Output:
```text
NFXCTF{h4shc4t_cr4ck1ng_z1p_succ3ssfu11y}
```

---

### 5. Verifikasi via Script Python Solver

Panitia juga dapat menjalankan solver otomatis bawaan:

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
