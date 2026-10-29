#!/usr/bin/env python3
"""Recover an NFXCTF flag from TCP payloads in a classic PCAP file."""

from __future__ import annotations

import argparse
import ipaddress
import re
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


FLAG_PATTERN = re.compile(rb"NFXCTF\{[A-Za-z0-9_]+\}")


@dataclass(frozen=True, order=True)
class Endpoint:
    address: str
    port: int


def read_pcap(path: Path) -> list[bytes]:
    data = path.read_bytes()
    if len(data) < 24:
        raise ValueError("file is too short to contain a PCAP header")

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("unsupported capture format; expected classic PCAP")

    link_type = struct.unpack_from(f"{endian}I", data, 20)[0]
    if link_type != 1:
        raise ValueError(f"unsupported link type {link_type}; expected Ethernet")

    packets: list[bytes] = []
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("truncated packet header")
        captured_length = struct.unpack_from(f"{endian}I", data, offset + 8)[0]
        offset += 16
        end = offset + captured_length
        if end > len(data):
            raise ValueError("truncated packet data")
        packets.append(data[offset:end])
        offset = end
    return packets


def extract_tcp_segment(
    frame: bytes,
) -> tuple[Endpoint, Endpoint, int, bytes] | None:
    if len(frame) < 14 or frame[12:14] != b"\x08\x00":
        return None

    ip_offset = 14
    if len(frame) < ip_offset + 20:
        return None
    version_ihl = frame[ip_offset]
    if version_ihl >> 4 != 4 or frame[ip_offset + 9] != 6:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    total_length = struct.unpack_from("!H", frame, ip_offset + 2)[0]
    tcp_offset = ip_offset + ip_header_length
    ip_end = min(ip_offset + total_length, len(frame))
    if tcp_offset + 20 > ip_end:
        return None

    src_ip = str(ipaddress.IPv4Address(frame[ip_offset + 12 : ip_offset + 16]))
    dst_ip = str(ipaddress.IPv4Address(frame[ip_offset + 16 : ip_offset + 20]))
    src_port, dst_port, sequence = struct.unpack_from("!HHI", frame, tcp_offset)
    tcp_header_length = (frame[tcp_offset + 12] >> 4) * 4
    payload_offset = tcp_offset + tcp_header_length
    if payload_offset > ip_end:
        return None
    return (
        Endpoint(src_ip, src_port),
        Endpoint(dst_ip, dst_port),
        sequence,
        frame[payload_offset:ip_end],
    )


def reassemble_streams(
    packets: list[bytes],
) -> dict[tuple[Endpoint, Endpoint], bytes]:
    segments: dict[tuple[Endpoint, Endpoint], dict[int, bytes]] = defaultdict(dict)
    for packet in packets:
        parsed = extract_tcp_segment(packet)
        if parsed is None:
            continue
        source, destination, sequence, payload = parsed
        if payload:
            segments[(source, destination)].setdefault(sequence, payload)

    streams: dict[tuple[Endpoint, Endpoint], bytes] = {}
    for direction, sequenced_payloads in segments.items():
        streams[direction] = b"".join(
            payload for _, payload in sorted(sequenced_payloads.items())
        )
    return streams


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Find NFXCTF flags in TCP streams.")
    parser.add_argument(
        "pcap",
        nargs="?",
        type=Path,
        default=Path("traffic.pcap"),
        help="classic PCAP file (default: traffic.pcap)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        streams = reassemble_streams(read_pcap(args.pcap))
    except (OSError, ValueError) as error:
        print(f"Error: {error}")
        return 1

    findings: set[bytes] = set()
    for (source, destination), stream in streams.items():
        for match in FLAG_PATTERN.findall(stream):
            findings.add(match)
            print(
                f"Flag: {match.decode('ascii')} "
                f"({source.address}:{source.port} -> "
                f"{destination.address}:{destination.port})"
            )

    if not findings:
        print("No NFXCTF flag found in TCP payloads.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
