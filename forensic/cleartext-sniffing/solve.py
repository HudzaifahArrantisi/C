# solve.py
# Script solver otomatis untuk tantangan Cleartext Sniffing (PCAP Basics)
import re

def solve_with_regex(pcap_path="traffic.pcap"):
    print(f"[*] Membaca file: {pcap_path}")
    with open(pcap_path, "rb") as f:
        data = f.read()

    # Cari pola format flag NFXCTF{...}
    matches = re.findall(rb"NFXCTF\{[^\}]+\}", data)
    if matches:
        for match in matches:
            print(f"[+] Flag ditemukan: {match.decode('utf-8')}")
        return

    # Jika ingin mencari dari string login
    post_matches = re.findall(rb"password=([^&\s]+)", data)
    if post_matches:
        for pwd in post_matches:
            print(f"[+] Ditemukan kredensial password: {pwd.decode('utf-8', errors='ignore')}")
    else:
        print("[-] Flag tidak ditemukan.")

if __name__ == "__main__":
    solve_with_regex("traffic.pcap")
