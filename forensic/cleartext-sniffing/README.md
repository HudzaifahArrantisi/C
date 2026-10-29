# Paket Tanpa Amplop

- Kategori: Digital Forensics, Network Analysis
- Kesulitan: Easy / Warmup
- Topik: Cleartext Sniffing
- Format flag: `NFXCTF{...}`
- Nilai yang disarankan: 100 poin

## Deskripsi Soal

Pukul 18.05, SOC menerima peringatan dari segmen laboratorium lama. Satu workstation terlihat menghubungi tiga layanan internal yang seharusnya sudah dipensiunkan setelah migrasi. Teknisi jaringan sempat mengambil rekaman dari SPAN port sebelum workstation tersebut dimatikan.

Tim menduga sebuah token rahasia ikut terkirim tanpa perlindungan enkripsi. Periksa `traffic.pcap`, ikuti percakapan yang relevan, lalu temukan token tersebut!

## Berkas Peserta

- `traffic.pcap` (Dapat diunduh oleh peserta)

## Hint Bertingkat

1. Tidak semua protokol melindungi isi paket. Cari percakapan yang masih dapat dibaca sebagai teks biasa.
2. Rekaman memuat HTTP, FTP, dan Telnet. Periksa data autentikasi pada salah satu protokol tersebut.
3. Di Wireshark, gunakan filter `ftp.request.command == "PASS"`, lalu pilih paket hasilnya dan buka **Follow > TCP Stream**.
