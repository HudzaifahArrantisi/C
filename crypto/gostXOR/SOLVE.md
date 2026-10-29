## 1. Informasi Soal
* **Nama Soal:** Ghost XOR
* **Kategori:** Crypto
* **Tingkat Kesulitan:** Easy / Low
* **Format Flag:** `NFXCTF{...}`
* **File Diberikan:** `chall.py`

## 2. Dasar yang Perlu Diketahui Pemula

Sebelum mulai, pahami tiga istilah berikut:

- **Byte** adalah bentuk angka dari satu karakter. Sebagai contoh, huruf `N` memiliki nilai desimal 78.
- **Hexadecimal** adalah cara menulis byte memakai karakter `0-9` dan `a-f`. Dua digit hex mewakili satu byte.
- **XOR** adalah operasi pada dua angka. Di Python, operatornya adalah `^`.

XOR memiliki sifat yang berguna untuk dekripsi:

```text
plaintext XOR key        = ciphertext
ciphertext XOR key       = plaintext
ciphertext XOR plaintext = key
```

Pada challenge ini, kuncinya mempunyai empat karakter. Program mengulang kunci itu sepanjang pesan:

```text
KEY1KEY1KEY1KEY1...
```

Karena format flag selalu dimulai dengan `NFXCTF{`, peserta sudah mengetahui sebagian plaintext. Teknik ini disebut known-plaintext attack.

---

## 3. Deskripsi / Cerita Soal (Challenge Prompt)
> Tim cyber kami berhasil mencegat sebuah pesan rahasia yang terenkripsi. Berdasarkan informasi intelijen, enkripsi yang digunakan hanya menggunakan operasi XOR berulang dengan kunci rahasia sepanjang **4 karakter**.
>
> Beruntung bagi kita, mereka meninggalkan kode sumbernya. Bisakah kamu memecahkan kuncinya dan membaca isi pesan rahasia tersebut?
>
> **Format Flag:** `NFXCTF{...}`  
> **Attachment:** `chall.py`

---

## 4. Alur Berpikir & Analisis (Dari Titik Nol)

### Langkah A: Membuka File `chall.py`
Saat membuka file `chall.py`, peserta melihat isi kode:
```python
def xor(data: bytes, key: bytes) -> bytes:
    return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

# Kunci rahasia 4 karakter
# KEY = b"????" 

# Hasil ciphertext yang berhasil didapatkan (format hexadecimal):
ciphertext_hex = "02091b08180938337c3d1c7a3f10303e3c7c31147f7b3032133d722c243b1c2a74297a287e32"
```

Dari kode di atas, kita dapat menyimpulkan:
1. **Algoritma:** Enkripsi menggunakan operasi bitwise **XOR** (`^`).
2. **Kunci (Key):** Terdiri dari **4 karakter** yang diulang-ulang (`key[i % len(key)]`).
3. **Data:** Pesan asli diacak menjadi string heksadesimal `ciphertext_hex`.

---

### Langkah B: Menemukan Celah Keamanan (Known-Plaintext Attack)
Operasi matematika XOR memiliki sifat simetris (bolak-balik):
$$\text{Plaintext} \oplus \text{Key} = \text{Ciphertext}$$
Maka secara matematis:
$$\mathbf{\text{Ciphertext} \oplus \text{Plaintext} = \text{Key}}$$

**Petunjuk Utama:**
Semua flag dalam kompetisi ini selalu diawali dengan format **`NFXCTF{`**.
Artinya, kita sudah **pasti tahu** bahwa 4 karakter pertama dari pesan asli adalah:
* Karakter 1 = `'N'`
* Karakter 2 = `'F'`
* Karakter 3 = `'X'`
* Karakter 4 = `'C'`

Karena kita memiliki 4 byte pertama dari Ciphertext dan 4 karakter pertama Plaintext, kita bisa langsung membongkar kuncinya!

---

## 5. Cara Menyelesaikan (Solusi)

### Cara 1: Menggunakan Script Python Otomatis (`solve.py`)
Buat file baru bernama `solve.py` di folder yang sama:

```python
ciphertext_hex = "02091b08180938337c3d1c7a3f10303e3c7c31147f7b3032133d722c243b1c2a74297a287e32"
ciphertext = bytes.fromhex(ciphertext_hex)

# 1. Tebak 4 karakter kunci dengan XOR 4 byte pertama dengan b"NFXC"
known_prefix = b"NFXC"
key = bytes([ciphertext[i] ^ known_prefix[i] for i in range(4)])
print(f"[+] Key ditemukan: {key.decode()}")  # Output: LOCK

# 2. Dekripsi seluruh isi ciphertext dengan key yang ditemukan
flag = bytes([ciphertext[i] ^ key[i % len(key)] for i in range(len(ciphertext))])
print(f"[+] Flag: {flag.decode()}")
```

Penjelasan bagian penting:

```python
bytes.fromhex(ciphertext_hex)
```

Baris tersebut mengubah teks hexadecimal menjadi kumpulan byte.

```python
ciphertext[i] ^ known_prefix[i]
```

Baris tersebut melakukan XOR antara byte ciphertext dan karakter flag yang sudah diketahui. Hasilnya adalah byte kunci.

```python
key[i % len(key)]
```

Operator `%` membuat indeks kembali ke awal setelah mencapai karakter keempat. Dengan cara ini, kunci `LOCK` terus digunakan berulang kali.

**Jalankan script:**
```bash
python solve.py
```

**Hasil Output:**
```text
[+] Key ditemukan        : LOCK
[+] Flag berhasil didapat: NFXCTF{x0r_1s_sup3r_34sy_r1ght_a8f9c2}
```

---

### Cara 2: Menggunakan CyberChef (Tanpa Koding)
Bagi peserta yang tidak ingin membuat kode pemrograman:

1. Buka [CyberChef](https://gchq.github.io/CyberChef/).
2. Masukkan ciphertext hex ke kolom **Input**:
   ```text
   02091b08180938337c3d1c7a3f10303e3c7c31147f7b3032133d722c243b1c2a74297a287e32
   ```
3. Di kolom **Operations / Recipe**, masukkan urutan berikut:
   * **`From Hex`** (Delimiter: None)
   * **`XOR`** (Key: pilih `UTF8`, lalu ketik `LOCK`)
4. Flag langsung tampil di kolom **Output**:
   ```text
   NFXCTF{x0r_1s_sup3r_34sy_r1ght_a8f9c2}
   ```

---

## 6. Flag Akhir
```text
NFXCTF{x0r_1s_sup3r_34sy_r1ght_a8f9c2}
```
