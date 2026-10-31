"""Build the organizer's SIP/RTP capture from natural Indonesian TTS voices."""

from __future__ import annotations

import audioop
import asyncio
import subprocess
import tempfile
from pathlib import Path

import edge_tts
import imageio_ffmpeg
from scapy.all import Ether, IP, UDP, Raw, wrpcap


HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "korban.pcap"
CALL_ID = "c1a84d0e-204@pbx.cakrawala.internal"
BASE_TIME = 1793384280.0  # 2026-10-30 18:18:00 UTC / 2026-10-31 01:18 WIB

LINES = [
    ("raka", "Din, kamu tahu kode dokumen itu dari mana? Aku simpan sendiri di laci. "
     "Kamu buka laci aku?"),
    ("dina", "Nggak. Salinannya kamu tinggal di printer, Rak. Kodenya masih kelihatan. "
     "En ef eks ce te ef, kurung kurawal buka, arsip, garis bawah, merah, "
     "garis bawah, dua nol empat, kurung kurawal tutup. "
     "Kalau besok pagi kamu nggak jelasin, aku kirim semuanya ke kepala kantor."),
    ("raka", "Dina, jangan main-main. Hapus salinan itu sekarang."),
    ("dina", "Nggak. Aku udah simpan salinannya. Kamu kira aku bakal diam aja?"),
    ("raka", "Dengerin aku. Kalau kamu bocorin kode itu, aku bunuh kamu. "
     "Aku ke ruang arsip sekarang."),
    ("dina", "Raka, jangan gila. Kita bisa ngomong baik-baik. "
     "Halo? Rak? Kamu di depan pintu? Raka, jangan!"),
]
VOICES = {"raka": "id-ID-ArdiNeural", "dina": "id-ID-GadisNeural"}


def synthesize(text: str, voice: str, path: Path) -> bytes:
    asyncio.run(edge_tts.Communicate(text, VOICES[voice]).save(str(path)))
    decoded = subprocess.run(
        [imageio_ffmpeg.get_ffmpeg_exe(), "-v", "error", "-i", str(path),
         "-f", "s16le", "-ac", "1", "-ar", "8000", "pipe:1"],
        check=True, capture_output=True,
    ).stdout
    return audioop.lin2ulaw(decoded, 2)


def sip_packet(src: str, dst: str, content: str, offset: float) -> Ether:
    packet = Ether(src=src, dst=dst) / IP(
        src="10.24.8.31" if src.endswith("31") else "10.24.8.24",
        dst="10.24.8.24" if src.endswith("31") else "10.24.8.31",
    ) / UDP(sport=5060, dport=5060) / Raw(load=content.encode("ascii"))
    packet.time = BASE_TIME + offset
    return packet


def signal(start: str, from_tag: str, to_tag: str, cseq: str, body: str = "") -> str:
    headers = [
        start,
        f"Via: SIP/2.0/UDP 10.24.8.31:5060;branch=z9hG4bK-204-{cseq.split()[1]}",
        f"From: <sip:204@pbx.cakrawala.internal>;tag={from_tag}",
        f"To: <sip:231@pbx.cakrawala.internal>{to_tag}",
        f"Call-ID: {CALL_ID}",
        f"CSeq: {cseq}",
        "Contact: <sip:204@10.24.8.31:5060>",
        "Content-Type: application/sdp" if body else "Content-Length: 0",
    ]
    if body:
        headers.append(f"Content-Length: {len(body.encode('ascii'))}")
    return "\r\n".join(headers) + "\r\n\r\n" + body


def sdp(ip: str, port: int, name: str) -> str:
    return (
        "v=0\r\n"
        f"o=- 204 1 IN IP4 {ip}\r\n"
        f"s={name}\r\n"
        f"c=IN IP4 {ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=sendrecv\r\n"
    )


def rtp_packets(audio: bytes, src_ip: str, dst_ip: str, src_mac: str,
                dst_mac: str, src_port: int, dst_port: int,
                ssrc: int, start: float, sequence_start: int) -> list[Ether]:
    result = []
    for i in range(0, len(audio), 160):
        frame = audio[i:i + 160].ljust(160, b"\xff")
        sequence = sequence_start + i // 160
        timestamp = 74000 + round(start * 8000) + i
        header = bytes([0x80, 0x00]) + sequence.to_bytes(2, "big")
        header += timestamp.to_bytes(4, "big") + ssrc.to_bytes(4, "big")
        packet = Ether(src=src_mac, dst=dst_mac) / IP(
            src=src_ip, dst=dst_ip
        ) / UDP(sport=src_port, dport=dst_port) / Raw(load=header + frame)
        packet.time = BASE_TIME + start + i / 8000
        result.append(packet)
    return result


def main() -> None:
    with tempfile.TemporaryDirectory() as temp:
        audio_lines = [
            (speaker, synthesize(text, speaker, Path(temp) / f"line-{i}.mp3"))
            for i, (speaker, text) in enumerate(LINES)
        ]

    mac_a, mac_b = "02:00:00:00:00:31", "02:00:00:00:00:24"
    invite = signal(
        "INVITE sip:231@pbx.cakrawala.internal SIP/2.0", "a204", "",
        "1 INVITE", sdp("10.24.8.31", 4000, "Desk phone 204"),
    )
    ok = signal(
        "SIP/2.0 200 OK", "a204", ";tag=b231", "1 INVITE",
        sdp("10.24.8.24", 4002, "Desk phone 231"),
    )
    ack = signal(
        "ACK sip:231@10.24.8.24:5060 SIP/2.0", "a204", ";tag=b231", "1 ACK"
    )
    packets = [
        sip_packet(mac_a, mac_b, invite, 0.0),
        sip_packet(mac_b, mac_a, ok, 0.12),
        sip_packet(mac_a, mac_b, ack, 0.16),
    ]
    elapsed = 0.40
    next_sequence = {"raka": 3800, "dina": 3800}
    for speaker, audio in audio_lines:
        if speaker == "raka":
            src_ip, dst_ip, src_mac, dst_mac = "10.24.8.31", "10.24.8.24", mac_a, mac_b
            src_port, dst_port, ssrc = 4000, 4002, 0xA2040001
        else:
            src_ip, dst_ip, src_mac, dst_mac = "10.24.8.24", "10.24.8.31", mac_b, mac_a
            src_port, dst_port, ssrc = 4002, 4000, 0xB2310001
        frames = rtp_packets(
            audio, src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port,
            ssrc, elapsed, next_sequence[speaker],
        )
        packets.extend(frames)
        next_sequence[speaker] += len(frames)
        elapsed += len(audio) / 8000 + 0.35
    bye_time = elapsed + 0.3
    bye = signal(
        "BYE sip:231@10.24.8.24:5060 SIP/2.0", "a204", ";tag=b231", "2 BYE"
    )
    bye_ok = signal("SIP/2.0 200 OK", "a204", ";tag=b231", "2 BYE")
    packets.extend([
        sip_packet(mac_a, mac_b, bye, bye_time),
        sip_packet(mac_b, mac_a, bye_ok, bye_time + 0.08),
    ])
    packets.sort(key=lambda packet: packet.time)
    wrpcap(str(OUTPUT), packets)
    print(f"Wrote {OUTPUT.name}: {len(packets)} packets, {bye_time:.1f} seconds")


if __name__ == "__main__":
    main()
