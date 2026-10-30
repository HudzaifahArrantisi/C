# Paket Tanpa Amplop (Cleartext Sniffing)

- **Kategori:** Digital Forensics
- **Kesulitan:** Easy / Warmup
- **Topik:** Network Traffic Analysis, Cleartext Protocol Sniffing (FTP/Telnet/HTTP)
- **Format Flag:** `NFXCTF{...}`
- **Nilai yang Disarankan:** 100 poin

---

## 📋 Pertanyaan Soal (Deskripsi untuk Web / Platform CTF)

> *Salin teks di bawah ini ke form deskripsi soal pada platform CTF (CTFd/lainnya):*

```markdown
### Deskripsi Soal

Pukul 18.05 WIB, sistem monitoring SOC membunyikan alarm anomali dari segmen jaringan laboratorium lama. Sebuah workstation mencurigakan terdeteksi aktif menghubungi beberapa server internal lama yang seharusnya telah dipensiunkan pasca migrasi sistem.

Sebelum workstation tersebut dimatikan secara paksa, analis jaringan sempat menyalakan port mirroring (SPAN port) dan merekam seluruh lalu lintas paket data ke dalam berkas `traffic.pcap`.

Tim investigasi menduga terdapat token autentikasi penting yang bocor akibat penggunaan protokol lama yang tidak dilengkapi enkripsi. Bantulah tim penyelidik menganalisis rekaman paket jaringan tersebut, telusuri percakapan data yang terjadi, dan temukan token rahasia (flag) yang bocor!

**Format Flag:** `NFXCTF{...}`
```

---

## 📎 Berkas Lampiran Peserta

- [`traffic.pcap`](traffic.pcap)

---

## 💡 Hint Bertingkat (Untuk Platform CTF)

1. **Hint 1:** Tidak semua protokol jaringan membungkus data dengan lapisan enkripsi. Carilah percakapan protokol teks polos (*plaintext*) yang datanya dapat dibaca langsung.
2. **Hint 2:** Rekaman jaringan memuat beberapa sesi: HTTP, FTP, dan Telnet. Periksa proses autentikasi (login/password) pada salah satu protokol tersebut.
3. **Hint 3:** Di Wireshark, gunakan display filter `ftp.request.command == "PASS"` untuk langsung melompat ke paket pengiriman password, atau klik kanan salah satu paket FTP lalu pilih **Follow > TCP Stream**.
