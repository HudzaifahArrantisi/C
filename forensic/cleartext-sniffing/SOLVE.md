# Solusi Resmi: Paket Tanpa Amplop

## Ringkasan

Workstation `192.168.56.23` membuka tiga koneksi teks polos:

- HTTP ke `192.168.56.10:80`
- FTP ke `192.168.56.30:21`
- Telnet ke `192.168.56.40:23`

Flag berada pada argumen perintah `PASS` di sesi FTP. Karena FTP control channel tidak memakai enkripsi, Wireshark dapat menampilkan nilai tersebut langsung dari payload TCP.

## Penyelesaian dengan Wireshark

1. Buka `traffic.pcap` melalui **File > Open**.
2. Mulai dengan filter berikut untuk melihat tiga protokol teks polos:

   ```text
   http || ftp || telnet
   ```

3. Persempit hasil ke request autentikasi FTP:

   ```text
   ftp.request.command == "PASS"
   ```

4. Pilih paket `PASS`. Panel **Packet Details** menampilkan bagian **File Transfer Protocol (FTP)** dengan request command `PASS` dan argumen berupa flag.
5. Klik kanan paket tersebut, lalu pilih **Follow > TCP Stream**. Gunakan tampilan **ASCII**. Percakapan berikut terlihat pada stream:

   ```text
   220 filesrv.nfx.local FTP server ready
   USER backup
   331 Password required for backup
   PASS NFXCTF{cl34rt3xt_pr0t0c0ls_l34k_s3cr3ts}
   230 User backup logged in
   ```

6. Ambil teks yang mengikuti `PASS` dan cocok dengan format flag.

Filter alternatif untuk mencari pola flag langsung pada payload TCP:

```text
tcp contains "NFXCTF{"
```

## Penyelesaian melalui CLI

### strings dan grep

Pada Linux, GNU strings dapat mengambil rangkaian ASCII dari PCAP:

```bash
strings -a traffic.pcap | grep -oE 'NFXCTF\{[A-Za-z0-9_]+\}'
```

Output:

```text
NFXCTF{cl34rt3xt_pr0t0c0ls_l34k_s3cr3ts}
```

PowerShell dapat memakai solver Python yang disertakan, atau `strings.exe` dari Sysinternals jika tersedia.

### tshark

Tampilkan seluruh request FTP:

```bash
tshark -r traffic.pcap -Y ftp.request -T fields -e ip.src -e ftp.request.command -e ftp.request.arg
```

Tampilkan hanya argumen `PASS`:

```bash
tshark -r traffic.pcap -Y 'ftp.request.command == "PASS"' -T fields -e ftp.request.arg
```

Alternatif yang tidak bergantung pada dissector FTP:

```bash
tshark -r traffic.pcap -Y 'tcp contains "NFXCTF{"' -T fields -e tcp.payload
```

Perintah terakhir menghasilkan payload dalam bentuk heksadesimal. Gunakan filter FTP jika ingin output yang langsung terbaca.

## Solver otomatis

Jalankan:

```bash
python solve.py traffic.pcap
```

Solver membaca header PCAP, mengekstrak Ethernet/IPv4/TCP, mengelompokkan payload berdasarkan arah koneksi, lalu menyusunnya berdasarkan TCP sequence number. Solver tidak memerlukan Scapy.

Output yang diharapkan:

```text
Flag: NFXCTF{cl34rt3xt_pr0t0c0ls_l34k_s3cr3ts} (192.168.56.23:51522 -> 192.168.56.30:21)
```

## Flag

```text
NFXCTF{cl34rt3xt_pr0t0c0ls_l34k_s3cr3ts}
```

## Catatan author

`generate.py` menghasilkan PCAP deterministik agar distribusi challenge dapat direproduksi. Semua sesi memiliki TCP three-way handshake, acknowledgment untuk setiap payload, dan four-segment connection teardown. HTTP berfungsi sebagai aktivitas browsing biasa, sedangkan Telnet memberi contoh kedua bahwa kredensial teks polos dapat dibaca tanpa dekripsi.
