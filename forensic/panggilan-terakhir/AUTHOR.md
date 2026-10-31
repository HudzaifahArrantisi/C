# Catatan penyelenggara — Panggilan Terakhir

**Flag:** `NFXCTF{ARSIP_MERAH_204}`

Ini adalah rekaman VoIP sintetis untuk latihan CTF, bukan rekaman kejadian nyata. Panggilan SIP berlangsung dari ekstensi Raka (204, `10.24.8.31`) ke ekstensi Dina (231, `10.24.8.24`). SDP menegosiasikan payload type 0: G.711 μ-law pada 8 kHz. Audio Raka dikirim dari UDP 4000 ke 4002; audio Dina dari UDP 4002 ke 4000.

## Langkah penyelesaian

1. Buka `korban.pcap` di Wireshark. Filter `sip` menampilkan INVITE dan `200 OK` beserta SDP. Filter `rtp` menampilkan aliran suaranya.
2. Buka **Telephony → RTP → RTP Streams**. Pilih stream `10.24.8.24:4002 → 10.24.8.31:4000` (SSRC `0xb2310001`), lalu buka **Analyze → Play Streams**.
3. Dina mengeja awalan format flag, lalu mengucapkan “ARSIP, garis bawah, MERAH, garis bawah, dua, nol, empat”. Susun sebagai `NFXCTF{ARSIP_MERAH_204}`.

Flag tidak dimasukkan ke teks SIP atau metadata PCAP. Rekaman audio adalah sumber jawabannya. Untuk membangun ulang berkas di Windows, jalankan `python build_challenge.py`; pembuat memerlukan `pywin32`, `scapy`, dan suara Microsoft Andika yang terpasang di Windows.
