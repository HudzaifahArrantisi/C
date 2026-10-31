"""Build the organizer's SIP/RTP capture. Run on Windows with pywin32 and scapy."""

from __future__ import annotations

import audioop
import tempfile
import wave
from pathlib import Path

import win32com.client
from scapy.all import Ether, IP, UDP, Raw, wrpcap


HERE = Path(__file__).resolve().parent
OUTPUT = HERE / "korban.pcap"
TOKEN = (
    r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Speech_OneCore\Voices\Tokens"
    r"\MSTTS_V110_idID_Andika"
)
CALL_ID = "c1a84d0e-204@pbx.cakrawala.internal"
BASE_TIME = 1793384280.0  # 2026-10-30 18:18:00 UTC / 2026-10-31 01:18 WIB

SUSPECT = (
    "Raka: Kamu kira bisa laporkan aku? Jangan sentuh arsip itu. "
    "Aku ke ruanganmu sekarang."
)
VICTIM = (
    "Dina: Tunggu, Raka! Kalau ada yang mendengar rekaman ini, "
    "catat kode bukti yang kusembunyikan. "
    "Flag-nya: en, ef, eks, ce, te, ef. Buka kurung kurawal. "
    "ARSIP, garis bawah, MERAH, garis bawah, dua, nol, empat. "
    "Tutup kurung kurawal. Ulangi: arsip merah dua nol empat. "
    "Dia sudah di depan pintu."
)


def synthesize(text: str, path: Path, rate: int = 0) -> bytes:
    voice = win32com.client.Dispatch("SAPI.SpVoice")
    token = win32com.client.Dispatch("SAPI.SpObjectToken")
    token.SetId(TOKEN)
    voice.Voice = token
    voice.Rate = rate
    stream = win32com.client.Dispatch("SAPI.SpFileStream")
    stream.Open(str(path), 3)
    voice.AudioOutputStream = stream
    voice.Speak(text)
    stream.Close()
    with wave.open(str(path), "rb") as wav:
        assert wav.getnchannels() == 1 and wav.getsampwidth() == 2
        pcm = wav.readframes(wav.getnframes())
        sample_rate = wav.getframerate()
    pcm_8k, _ = audioop.ratecv(pcm, 2, 1, sample_rate, 8000, None)
    return audioop.lin2ulaw(pcm_8k, 2)


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
                ssrc: int, start: float) -> list[Ether]:
    result = []
    for i in range(0, len(audio), 160):
        frame = audio[i:i + 160].ljust(160, b"\xff")
        sequence = 3800 + i // 160
        timestamp = 74000 + i
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
        suspect = synthesize(SUSPECT, Path(temp) / "raka.wav", rate=-1)
        victim = synthesize(VICTIM, Path(temp) / "dina.wav", rate=1)

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
    packets.extend(rtp_packets(
        suspect, "10.24.8.31", "10.24.8.24", mac_a, mac_b,
        4000, 4002, 0xA2040001, 0.40,
    ))
    victim_start = 0.40 + len(suspect) / 8000 + 0.55
    packets.extend(rtp_packets(
        victim, "10.24.8.24", "10.24.8.31", mac_b, mac_a,
        4002, 4000, 0xB2310001, victim_start,
    ))
    bye_time = victim_start + len(victim) / 8000 + 0.6
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
