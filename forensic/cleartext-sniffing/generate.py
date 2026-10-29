import struct
import time

def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def ip_checksum(ip_header: bytes) -> int:
    return checksum(ip_header)

def tcp_checksum(src_ip: bytes, dst_ip: bytes, tcp_segment: bytes) -> int:
    pseudo_hdr = src_ip + dst_ip + struct.pack(">BBH", 0, 6, len(tcp_segment))
    return checksum(pseudo_hdr + tcp_segment)

def make_ethernet(src_mac: bytes, dst_mac: bytes, ethertype: int = 0x0800) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", ethertype)

def make_ip(src_ip: str, dst_ip: str, payload: bytes, proto: int = 6, ident: int = 1) -> bytes:
    src_bytes = bytes(map(int, src_ip.split('.')))
    dst_bytes = bytes(map(int, dst_ip.split('.')))
    ihl = 5
    ver = 4
    v_ihl = (ver << 4) | ihl
    total_len = 20 + len(payload)
    hdr_without_cksum = struct.pack(
        ">BBHHHBBH4s4s",
        v_ihl, 0, total_len, ident, 0x4000, 64, proto, 0, src_bytes, dst_bytes
    )
    cksum = ip_checksum(hdr_without_cksum)
    return struct.pack(
        ">BBHHHBBH4s4s",
        v_ihl, 0, total_len, ident, 0x4000, 64, proto, cksum, src_bytes, dst_bytes
    ) + payload

def make_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    src_bytes = bytes(map(int, src_ip.split('.')))
    dst_bytes = bytes(map(int, dst_ip.split('.')))
    offset = 5
    data_offset_res = (offset << 4)
    hdr_without_cksum = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset_res, flags, 64240, 0, 0
    ) + payload
    cksum = tcp_checksum(src_bytes, dst_bytes, hdr_without_cksum)
    return struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port, seq, ack, data_offset_res, flags, 64240, cksum, 0
    ) + payload

def create_packet(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload=b"", ident=1):
    tcp = make_tcp(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    ip = make_ip(src_ip, dst_ip, tcp, proto=6, ident=ident)
    eth = make_ethernet(src_mac, dst_mac, 0x0800) + ip
    return eth

def write_pcap(filename: str, packets_with_time: list):
    # Global header
    pcap_hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    with open(filename, "wb") as f:
        f.write(pcap_hdr)
        for ts, pkt in packets_with_time:
            sec = int(ts)
            usec = int((ts - sec) * 1000000)
            pkt_hdr = struct.pack("<IIII", sec, usec, len(pkt), len(pkt))
            f.write(pkt_hdr)
            f.write(pkt)

def main():
    client_mac = b"\x00\x0c\x29\x4f\x8e\x12"
    server_mac = b"\x00\x50\x56\xf2\x1a\x33"
    client_ip = "192.168.1.105"
    server_ip = "192.168.1.20"
    client_port = 49152
    server_port = 80

    flag = "NFXCTF{un3ncrypt3d_tr4ff1c_1s_d4ng3r0us}"

    t = 1729000000.0
    packets = []

    # 1. TCP 3-Way Handshake
    # SYN (Client -> Server)
    c_seq = 1000
    s_seq = 5000
    pkt = create_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, c_seq, 0, 0x02, ident=101)
    packets.append((t, pkt))
    t += 0.005
    c_seq += 1

    # SYN-ACK (Server -> Client)
    pkt = create_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, s_seq, c_seq, 0x12, ident=201)
    packets.append((t, pkt))
    t += 0.005
    s_seq += 1

    # ACK (Client -> Server)
    pkt = create_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, c_seq, s_seq, 0x10, ident=102)
    packets.append((t, pkt))
    t += 0.020

    # 2. HTTP GET /login (Normal browsing noise)
    http_get = (
        b"GET /login.html HTTP/1.1\r\n"
        b"Host: portal.internal.corp\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"\r\n"
    )
    pkt = create_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, c_seq, s_seq, 0x18, payload=http_get, ident=103)
    packets.append((t, pkt))
    t += 0.015
    c_seq += len(http_get)

    http_get_res = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Content-Length: 114\r\n"
        b"\r\n"
        b"<html><body><h2>Corporate Employee Portal</h2><form action='/auth' method='POST'>...</form></body></html>"
    )
    pkt = create_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, s_seq, c_seq, 0x18, payload=http_get_res, ident=202)
    packets.append((t, pkt))
    t += 0.030
    s_seq += len(http_get_res)

    # 3. HTTP POST /auth (Login containing the FLAG in form-urlencoded body)
    post_body = f"username=admin&password={flag}&remember_me=1".encode('utf-8')
    http_post = (
        b"POST /auth HTTP/1.1\r\n"
        b"Host: portal.internal.corp\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(post_body)}\r\n"
        b"Referer: http://portal.internal.corp/login.html\r\n"
        b"\r\n"
    ).encode('ascii') + post_body

    pkt = create_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, c_seq, s_seq, 0x18, payload=http_post, ident=104)
    packets.append((t, pkt))
    t += 0.025
    c_seq += len(http_post)

    # Server HTTP 302 Found (Redirect)
    http_res = (
        b"HTTP/1.1 302 Found\r\n"
        b"Server: Apache/2.4.41 (Ubuntu)\r\n"
        b"Location: /dashboard\r\n"
        b"Set-Cookie: session_id=s3cr3t_s3ss10n_t0k3n_9921; HttpOnly; Path=/\r\n"
        b"Content-Length: 0\r\n"
        b"\r\n"
    )
    pkt = create_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, s_seq, c_seq, 0x18, payload=http_res, ident=203)
    packets.append((t, pkt))
    t += 0.010
    s_seq += len(http_res)

    # 4. Connection Teardown (FIN/ACK)
    pkt = create_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, c_seq, s_seq, 0x11, ident=105)
    packets.append((t, pkt))
    t += 0.005
    c_seq += 1

    pkt = create_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, s_seq, c_seq, 0x11, ident=204)
    packets.append((t, pkt))
    t += 0.005
    s_seq += 1

    pkt = create_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, c_seq, s_seq, 0x10, ident=106)
    packets.append((t, pkt))

    output_file = "traffic.pcap"
    write_pcap(output_file, packets)
    print(f"[+] Successfully generated '{output_file}' with {len(packets)} packets.")
    print(f"[+] Flag embedded: {flag}")

if __name__ == "__main__":
    main()
