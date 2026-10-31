# Panggilan Terakhir

**Kategori:** Digital Forensics  
**Kesulitan:** Easy–Medium  
**Topik:** Analisis VoIP, SIP, RTP, G.711  
**Format flag:** `NFXCTF{...}`  
**Poin yang disarankan:** 200

## Deskripsi soal untuk peserta

> Pukul 01.18 WIB, Raka menelepon Dina melalui telepon meja kantor Cakrawala setelah tahu Dina menemukan kode sebuah dokumen rahasia. Tak lama setelah panggilan itu, Dina ditemukan tewas di ruang arsip. Raka menjadi tersangka, tetapi penyidik belum mengetahui apa yang sempat diucapkan Dina sebelum telepon terputus.
>
> Sistem pemantauan jaringan kantor menyimpan rekaman paket panggilan itu dalam `korban.pcap`. Dengarkan percakapan terakhir Dina dan temukan flag yang ia ucapkan.
>
> Format jawaban: `NFXCTF{...}`. Gunakan huruf kapital dan garis bawah sesuai ucapan korban.

## Berkas yang diberikan kepada peserta

- [korban.pcap](korban.pcap)

Jangan sertakan `AUTHOR.md`, `solve.md`, atau `build_challenge.py` dalam lampiran peserta.

## Hint bertingkat

1. Telepon meja kantor ini memakai VoIP. Cari protokol panggilannya terlebih dahulu.
2. Setelah menemukan SIP, periksa aliran media yang dinegosiasikan, lalu gunakan filter `rtp`.
3. Di Wireshark, buka **Telephony → RTP → RTP Streams**. Pilih aliran dari telepon korban, lalu klik **Play Streams**. Jika menu itu tidak tersedia, simpan payload audio dan dekode sebagai G.711 μ-law, 8 kHz.
