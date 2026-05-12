#!/usr/bin/env python3
"""
collector.py  –  Coletor de telemetria para o Trabalho 2
Escuta na interface de h3 por pacotes com EtherType 0x9999,
decodifica o cabeçalho de telemetria e exibe as métricas.

Estrutura do cabeçalho de telemetria (após Ethernet, 10 bytes):
  [0-3]  pkt_count      (uint32, big-endian)
  [4-7]  byte_count     (uint32, big-endian)
  [8]    min_ttl        (uint8)
  [9]    dominant_proto (uint8)
  [10-11] reserved      (uint16, ignorado)

Execução:
  sudo python3 collector.py [--iface eth0] [--log telemetry.log]
"""

import argparse
import struct
import socket
import datetime
import sys

ETH_P_ALL   = 0x0003
TELEM_ETYPE = 0x9999
TELEM_HDR_LEN = 10   # pkt_count(4) + byte_count(4) + min_ttl(1) + proto(1)

PROTO_NAMES = {
    1:  "ICMP",
    6:  "TCP",
    17: "UDP",
}

SEPARATOR = "─" * 60

def parse_ethernet(raw: bytes):
    """Retorna (dst, src, ethertype, payload)."""
    dst  = raw[0:6]
    src  = raw[6:12]
    etype = struct.unpack("!H", raw[12:14])[0]
    return dst, src, etype, raw[14:]

def parse_telemetry(payload: bytes):
    """Decodifica o cabeçalho de telemetria."""
    if len(payload) < TELEM_HDR_LEN:
        raise ValueError("Payload muito curto para cabeçalho de telemetria.")
    pkt_count, byte_count, min_ttl, dom_proto = struct.unpack("!IIBB", payload[:10])
    return pkt_count, byte_count, min_ttl, dom_proto

def mac_str(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)

def proto_name(n: int) -> str:
    return PROTO_NAMES.get(n, f"PROTO({n})")

def display(window: int, pkt_count: int, byte_count: int,
            min_ttl: int, dom_proto: int, logfile=None):
    avg_size = byte_count / pkt_count if pkt_count else 0
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        SEPARATOR,
        f"  📡  Relatório de Telemetria  –  Janela #{window}",
        f"  🕐  Timestamp : {ts}",
        SEPARATOR,
        f"  📦  Pacotes na janela      : {pkt_count}",
        f"  📊  Bytes na janela        : {byte_count}",
        f"  🔺  Tamanho médio (bytes)  : {avg_size:.1f}",
        f"  ⏱️  TTL mínimo observado   : {min_ttl}",
        f"  🌐  Protocolo dominante    : {proto_name(dom_proto)} ({dom_proto})",
        SEPARATOR,
    ]

    text = "\n".join(lines)
    print(text)
    sys.stdout.flush()

    if logfile:
        logfile.write(text + "\n")
        logfile.flush()

def main():
    ap = argparse.ArgumentParser(description="Coletor de Telemetria P4")
    ap.add_argument("--iface", default="eth0",
                    help="Interface de rede para escutar (padrão: eth0)")
    ap.add_argument("--log", default="telemetry.log",
                    help="Arquivo de log (padrão: telemetry.log)")
    args = ap.parse_args()

    print(f"[collector] Iniciando na interface '{args.iface}'")
    print(f"[collector] Log em '{args.log}'")
    print(f"[collector] Aguardando pacotes com EtherType 0x{TELEM_ETYPE:04X}...\n")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                         socket.htons(ETH_P_ALL))
    sock.bind((args.iface, 0))

    window = 0

    with open(args.log, "w") as lf:
        while True:
            raw, _ = sock.recvfrom(65535)
            try:
                dst, src, etype, payload = parse_ethernet(raw)
            except Exception:
                continue

            if etype != TELEM_ETYPE:
                continue

            try:
                pkt_count, byte_count, min_ttl, dom_proto = parse_telemetry(payload)
            except ValueError as e:
                print(f"[collector] Erro ao decodificar telemetria: {e}")
                continue

            window += 1
            display(window, pkt_count, byte_count, min_ttl, dom_proto, lf)

if __name__ == "__main__":
    main()
