# Paket Tanpa Amplop

- Kategori: Digital Forensics, Network Analysis
- Kesulitan: Easy / Warmup
- Topik: Cleartext Sniffing
- Format flag: `NFXCTF{...}`
- Nilai yang disarankan: 100 poin

## Deskripsi soal

Pukul 18.05, SOC menerima peringatan dari segmen laboratorium lama. Satu workstation terlihat menghubungi tiga layanan internal yang seharusnya sudah dipensiunkan setelah migrasi. Teknisi jaringan sempat mengambil rekaman dari SPAN port sebelum workstation tersebut dimatikan.

Tim menduga sebuah token rahasia ikut terkirim tanpa perlindungan enkripsi. Periksa `traffic.pcap`, ikuti percakapan yang relevan, lalu temukan token tersebut.

## Berkas peserta

- `traffic.pcap`

## Hint bertingkat

Buka hint secara berurutan. Setiap hint mengurangi ruang pencarian.

1. Tidak semua protokol melindungi isi paket. Cari percakapan yang masih dapat dibaca sebagai teks biasa.
2. Rekaman memuat HTTP, FTP, dan Telnet. Periksa data autentikasi pada salah satu protokol tersebut.
3. Di Wireshark, gunakan filter `ftp.request.command == "PASS"`, lalu pilih paket hasilnya dan buka **Follow > TCP Stream**.

## Catatan distribusi

Panitia membagikan `README.md` dan `traffic.pcap` kepada peserta. Simpan `generate.py`, `solve.py`, dan `SOLVE.md` sebagai berkas internal panitia.

Untuk membuat ulang artefak challenge:

```bash
python generate.py
```

Generator dan solver hanya memakai Python Standard Library. Tidak ada paket tambahan yang perlu dipasang.
