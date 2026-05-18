#!/usr/bin/env python3
"""
collector.py  –  Coletor de telemetria P4 (saída em texto)
Escuta na interface de h3 por pacotes com EtherType 0x9999,
decodifica o cabeçalho de telemetria e exibe/salva as métricas.

Estrutura do cabeçalho de telemetria (10 bytes após Ethernet):
  [0-3]  pkt_count      uint32 big-endian  – pacotes na janela
  [4-7]  byte_count     uint32 big-endian  – bytes na janela
  [8]    min_ttl        uint8              – TTL mínimo observado
  [9]    dominant_proto uint8              – protocolo dominante (1/6/17)

Uso (no host h3 dentro do Mininet):
  sudo python3 collector.py --iface h3-eth0
  sudo python3 collector.py --iface h3-eth0 --log telemetry.log
"""

import argparse
import struct
import socket
import sys
from datetime import datetime

ETH_P_ALL   = 0x0003
TELEM_ETYPE = 0x9999

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
SEP = "─" * 58


def parse_telemetry(raw: bytes):
    """Retorna (pkt_count, byte_count, min_ttl, dominant_proto) ou None."""
    if len(raw) < 24:
        return None
    etype = struct.unpack("!H", raw[12:14])[0]
    if etype != TELEM_ETYPE:
        return None
    pkt, byt, ttl, proto = struct.unpack("!IIBB", raw[14:24])
    return pkt, byt, ttl, proto


def proto_name(n: int) -> str:
    return PROTO_NAMES.get(n, f"DESCONHECIDO({n})")


def display(window: int, pkt: int, byt: int, ttl: int, proto: int,
            logfile=None):
    avg = byt / pkt if pkt else 0
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = [
        SEP,
        f"  Janela #{window:04d}   [{ts}]",
        SEP,
        f"  Pacotes na janela      : {pkt}",
        f"  Bytes na janela        : {byt}",
        f"  Tamanho medio (bytes)  : {avg:.1f}",
        f"  TTL minimo observado   : {ttl}",
        f"  Protocolo dominante    : {proto_name(proto)} ({proto})",
        SEP,
    ]

    text = "\n".join(lines)
    print(text, flush=True)

    if logfile:
        logfile.write(text + "\n")
        logfile.flush()


def main():
    ap = argparse.ArgumentParser(
        description="Coletor de telemetria P4 – Trabalho 2 UFSM"
    )
    ap.add_argument("--iface", default="h3-eth0",
                    help="Interface de rede de h3 (padrao: h3-eth0)")
    ap.add_argument("--log",   default=None,
                    help="Arquivo de log opcional (ex: telemetry.log)")
    args = ap.parse_args()

    print(f"[collector] Interface : {args.iface}")
    print(f"[collector] EtherType : 0x{TELEM_ETYPE:04X}")
    if args.log:
        print(f"[collector] Log       : {args.log}")
    print(f"[collector] Aguardando janelas de telemetria...\n")

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_P_ALL))
        sock.bind((args.iface, 0))
    except PermissionError:
        print("ERRO: permissao negada. Execute com sudo.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        sys.exit(1)

    window  = 0
    logfile = open(args.log, "w") if args.log else None

    try:
        while True:
            raw, _ = sock.recvfrom(65535)
            result = parse_telemetry(raw)
            if result is None:
                continue
            pkt, byt, ttl, proto = result
            window += 1
            display(window, pkt, byt, ttl, proto, logfile)
    except KeyboardInterrupt:
        print(f"\n[collector] Encerrado. Total de janelas recebidas: {window}")
    finally:
        if logfile:
            logfile.close()


if __name__ == "__main__":
    main()