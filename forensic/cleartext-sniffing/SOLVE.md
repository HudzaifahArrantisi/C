# Solusi Resmi: Cleartext Sniffing

## Analisis Masalah

Tantangan ini memberikan sebuah file rekaman jaringan berformat `.pcap`. Skenario menyebutkan adanya akses portal internal yang tidak terenkripsi, yang mengindikasikan protokol berbasis teks polos seperti HTTP, Telnet, atau FTP.

## Metode Penyelesaian

### Cara 1: Menggunakan Wireshark (GUI)

1. Buka file `traffic.pcap` di **Wireshark**.
2. Masukkan filter protokol pada kolom display filter:
   ```text
   http
   ```
   atau lebih spesifik:
   ```text
   http.request.method == "POST"
   ```
3. Perhatikan paket request HTTP POST ke `/auth`.
4. Periksa bagian **HTML Form URL Encoded** pada panel *Packet Details*:
   ```text
   username = admin
   password = NFXCTF{un3ncrypt3d_tr4ff1c_1s_d4ng3r0us}
   ```
5. Alternatif cepat: Klik kanan paket nomor berapa saja yang bertipe TCP/HTTP, pilih **Follow** -> **TCP Stream**. Di dalam percakapan stream lengkap akan terlihat form login dengan flag tersebut.

---

### Cara 2: Menggunakan CLI (`strings` / `grep`)

Karena flag tersimpan dalam format teks polos (ASCII) di dalam payload paket TCP:

```bash
strings traffic.pcap | grep -E "NFXCTF\{.*?\}"
```

Output:
```text
username=admin&password=NFXCTF{un3ncrypt3d_tr4ff1c_1s_d4ng3r0us}&remember_me=1
```

---

### Cara 3: Menggunakan Python Script

Jalankan `solve.py`:

```bash
python solve.py
```

Output:
```text
[*] Membaca file: traffic.pcap
[+] Flag ditemukan: NFXCTF{un3ncrypt3d_tr4ff1c_1s_d4ng3r0us}
```

## Flag

```text
NFXCTF{un3ncrypt3d_tr4ff1c_1s_d4ng3r0us}
```
