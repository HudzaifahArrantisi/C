#!/usr/bin/env python3
"""Generate a deterministic PCAP for the Cleartext Sniffing challenge."""

from __future__ import annotations

import argparse
import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path


FLAG = "NFXCTF{cl34rt3xt_pr0t0c0ls_l34k_s3cr3ts}"
DEFAULT_OUTPUT = Path("traffic.pcap")


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_bytes(address: str) -> bytes:
    return ipaddress.IPv4Address(address).packed


def build_tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    offset_and_reserved = 5 << 4
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_and_reserved,
        flags,
        64240,
        0,
        0,
    )
    pseudo_header = (
        ipv4_bytes(src_ip)
        + ipv4_bytes(dst_ip)
        + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    )
    tcp_checksum = internet_checksum(pseudo_header + header + payload)
    header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_and_reserved,
        flags,
        64240,
        tcp_checksum,
        0,
    )
    return header + payload


def build_ipv4_packet(
    src_ip: str, dst_ip: str, payload: bytes, identification: int
) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        identification,
        0x4000,
        64,
        6,
        0,
        ipv4_bytes(src_ip),
        ipv4_bytes(dst_ip),
    )
    checksum = internet_checksum(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + payload


def build_ethernet_frame(
    src_mac: bytes, dst_mac: bytes, payload: bytes
) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + payload


@dataclass
class Capture:
    timestamp: float = 1793271758.0
    identification: int = 100
    packets: list[tuple[float, bytes]] = field(default_factory=list)

    def add_tcp(
        self,
        src_mac: bytes,
        dst_mac: bytes,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes = b"",
        delay: float = 0.004,
    ) -> None:
        segment = build_tcp_segment(
            src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload
        )
        packet = build_ipv4_packet(
            src_ip, dst_ip, segment, self.identification
        )
        self.packets.append(
            (self.timestamp, build_ethernet_frame(src_mac, dst_mac, packet))
        )
        self.timestamp += delay
        self.identification += 1


@dataclass
class TCPFlow:
    capture: Capture
    client_mac: bytes
    server_mac: bytes
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    client_seq: int
    server_seq: int

    def _send(
        self, from_client: bool, flags: int, payload: bytes = b""
    ) -> None:
        if from_client:
            self.capture.add_tcp(
                self.client_mac,
                self.server_mac,
                self.client_ip,
                self.server_ip,
                self.client_port,
                self.server_port,
                self.client_seq,
                self.server_seq,
                flags,
                payload,
            )
        else:
            self.capture.add_tcp(
                self.server_mac,
                self.client_mac,
                self.server_ip,
                self.client_ip,
                self.server_port,
                self.client_port,
                self.server_seq,
                self.client_seq,
                flags,
                payload,
            )

    def handshake(self) -> None:
        self._send(True, 0x02)
        self.client_seq += 1
        self._send(False, 0x12)
        self.server_seq += 1
        self._send(True, 0x10)

    def transmit(self, from_client: bool, payload: bytes) -> None:
        self._send(from_client, 0x18, payload)
        if from_client:
            self.client_seq += len(payload)
        else:
            self.server_seq += len(payload)
        self._send(not from_client, 0x10)

    def close(self) -> None:
        self._send(True, 0x11)
        self.client_seq += 1
        self._send(False, 0x10)
        self._send(False, 0x11)
        self.server_seq += 1
        self._send(True, 0x10)
        self.capture.timestamp += 0.180


def add_http_browsing(capture: Capture, client_mac: bytes, server_mac: bytes) -> None:
    flow = TCPFlow(
        capture,
        client_mac,
        server_mac,
        "192.168.56.23",
        "192.168.56.10",
        51514,
        80,
        1_827_361_004,
        2_031_770_440,
    )
    flow.handshake()
    flow.transmit(
        True,
        b"GET /news.html HTTP/1.1\r\n"
        b"Host: intranet.nfx.local\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        b"AppleWebKit/537.36 Chrome/128.0\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"Connection: keep-alive\r\n\r\n",
    )
    body = (
        b"<html><body><h1>Office News</h1>"
        b"<p>Inventory maintenance starts at 18:00.</p></body></html>"
    )
    flow.transmit(
        False,
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/html\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: keep-alive\r\n\r\n"
        + body,
    )
    flow.transmit(
        True,
        b"GET /assets/site.css HTTP/1.1\r\n"
        b"Host: intranet.nfx.local\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/css,*/*;q=0.1\r\n"
        b"Referer: http://intranet.nfx.local/news.html\r\n"
        b"Connection: close\r\n\r\n",
    )
    css = b"body{font-family:sans-serif;color:#222}h1{font-size:1.5rem}"
    flow.transmit(
        False,
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.24.0\r\n"
        b"Content-Type: text/css\r\n"
        + f"Content-Length: {len(css)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + css,
    )
    flow.close()


def add_ftp_session(capture: Capture, client_mac: bytes, server_mac: bytes) -> None:
    flow = TCPFlow(
        capture,
        client_mac,
        server_mac,
        "192.168.56.23",
        "192.168.56.30",
        51522,
        21,
        3_443_120_000,
        917_002_130,
    )
    flow.handshake()
    flow.transmit(False, b"220 filesrv.nfx.local FTP server ready\r\n")
    flow.transmit(True, b"USER backup\r\n")
    flow.transmit(False, b"331 Password required for backup\r\n")
    flow.transmit(True, f"PASS {FLAG}\r\n".encode("ascii"))
    flow.transmit(False, b"230 User backup logged in\r\n")
    flow.transmit(True, b"SYST\r\n")
    flow.transmit(False, b"215 UNIX Type: L8\r\n")
    flow.transmit(True, b"PWD\r\n")
    flow.transmit(False, b'257 "/incoming" is the current directory\r\n')
    flow.transmit(True, b"QUIT\r\n")
    flow.transmit(False, b"221 Goodbye.\r\n")
    flow.close()


def add_telnet_session(capture: Capture, client_mac: bytes, server_mac: bytes) -> None:
    flow = TCPFlow(
        capture,
        client_mac,
        server_mac,
        "192.168.56.23",
        "192.168.56.40",
        51531,
        23,
        728_440_100,
        2_610_003_007,
    )
    flow.handshake()
    flow.transmit(False, b"\xff\xfb\x01\xff\xfb\x03NFX Router Console\r\nlogin: ")
    capture.timestamp += 1.0
    flow.transmit(True, b"operator\r\n")
    flow.transmit(False, b"Password: ")
    capture.timestamp += 1.2
    flow.transmit(True, b"lab-access-2026\r\n")
    flow.transmit(False, b"Welcome. Type 'help' for available commands.\r\nrouter> ")
    capture.timestamp += 3.2
    flow.transmit(True, b"show clock\r\n")
    flow.transmit(False, b"18:03:14 WIB Thu Oct 29 2026\r\nrouter> ")
    flow.transmit(True, b"exit\r\n")
    flow.transmit(False, b"Connection closed by foreign host.\r\n")
    flow.close()


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, packet in packets:
            seconds = int(timestamp)
            microseconds = round((timestamp - seconds) * 1_000_000)
            handle.write(
                struct.pack("<IIII", seconds, microseconds, len(packet), len(packet))
            )
            handle.write(packet)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the Cleartext Sniffing challenge PCAP."
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"output path (default: {DEFAULT_OUTPUT})",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    capture = Capture()
    workstation_mac = bytes.fromhex("000c294f8e12")
    gateway_mac = bytes.fromhex("005056f21a33")

    add_http_browsing(capture, workstation_mac, gateway_mac)
    capture.timestamp += 10.0
    add_ftp_session(capture, workstation_mac, gateway_mac)
    capture.timestamp += 20.0
    add_telnet_session(capture, workstation_mac, gateway_mac)
    write_pcap(args.output, capture.packets)

    print(f"Generated {args.output} with {len(capture.packets)} packets.")
    print(f"Embedded flag: {FLAG}")


if __name__ == "__main__":
    main()
