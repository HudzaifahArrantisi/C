# Cleartext Sniffing

Kategori: Digital Forensics  
Kesulitan: Easy  
Nilai yang disarankan: 100 poin  
Format flag: `NFXCTF{...}`

## Deskripsi

Tim Incident Response mendeteksi lalu lintas mencurigakan pada segmen jaringan internal kantor. Seorang pengguna dilaporkan mengakses portal web tanpa protokol terenkripsi (HTTPS).

Pihak SOC berhasil menangkap berkas paket jaringan (`traffic.pcap`). Analisis berkas rekaman jaringan tersebut dan temukan informasi kredensial atau flag rahasia yang terkirim di dalamnya!

## File peserta

- `traffic.pcap` (Dapat diunduh oleh peserta)

> **Catatan untuk pembuat soal:** Jalankan `python generate.py` untuk meng-generate berkas `traffic.pcap` jika belum dibuat.

## Hint

Gunakan hint secara berurutan jika kamu buntu:

1. Buka file `.pcap` menggunakan tool penganalisis paket seperti **Wireshark** atau **NetworkMiner**.
2. Fokus pada protokol yang mengirimkan data tanpa enkripsi, seperti protokol **HTTP**.
3. Gunakan filter display `http.request.method == "POST"` atau klik kanan salah satu paket HTTP lalu pilih **Follow -> TCP Stream**.

## Catatan panitia

Bagikan hanya file `README.md` dan `traffic.pcap` kepada peserta. File `SOLVE.md`, `generate.py`, dan `solve.py` adalah arsip panitia.
