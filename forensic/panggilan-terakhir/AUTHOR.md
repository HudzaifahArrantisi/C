# Catatan penyelenggara — Panggilan Terakhir

**Flag:** `NFXCTF{ARSIP_MERAH_204}`

Ini adalah rekaman VoIP sintetis untuk latihan CTF, bukan rekaman kejadian nyata. Panggilan SIP berlangsung dari ekstensi Raka (204, `10.24.8.31`) ke ekstensi Dina (231, `10.24.8.24`). SDP menegosiasikan payload type 0: G.711 μ-law pada 8 kHz. Audio Raka dikirim dari UDP 4000 ke 4002; audio Dina dari UDP 4002 ke 4000.

## Langkah penyelesaian

1. Buka `korban.pcap` di Wireshark. Filter `sip` menampilkan INVITE dan `200 OK` beserta SDP. Filter `rtp` menampilkan aliran suaranya.
2. Buka **Telephony → RTP → RTP Streams**. Pilih stream `10.24.8.24:4002 → 10.24.8.31:4000` (SSRC `0xb2310001`), lalu klik **Play Streams**.
3. Raka mempertanyakan bagaimana Dina tahu kode dokumen. Dina mengucapkan kode itu sambil mengancam akan melapor. Setelah itu Raka mengancam akan membunuhnya dan mendatangi ruang arsip. Susun kode yang diucapkan Dina sebagai `NFXCTF{ARSIP_MERAH_204}`.

Flag tidak dimasukkan ke teks SIP atau metadata PCAP. Rekaman audio adalah sumber jawabannya. Dialog memakai dua suara neural bahasa Indonesia: Ardi untuk Raka dan Gadis untuk Dina. Untuk membangun ulang berkas, pasang `edge-tts`, `imageio-ffmpeg`, dan `scapy`, pastikan ada koneksi internet untuk sintesis suara, lalu jalankan `python build_challenge.py`.
