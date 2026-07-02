#!/usr/bin/env python3
"""
traffic_gen.py — Trabalho 4 (UFSM)
===================================

Gerador de tráfego usado na demonstração. Produz duas condições:

  --mode normal : baixa taxa de pacotes, permanece abaixo dos limiares
                  da política do controlador (fluxo tratado normalmente).

  --mode burst  : rajada de pacotes do MESMO IP de origem, suficiente
                  para ultrapassar MARK_PKT_THRESHOLD (40) e depois
                  BLOCK_PKT_THRESHOLD (100) definidos em controller.py,
                  evidenciando a decisão automática (marcação e depois
                  bloqueio do fluxo).

Executar dentro do Mininet, a partir de h1 (origem) em direção a h2:

    h1 python3 traffic_gen.py --dst 10.0.2.2 --mode normal
    h1 python3 traffic_gen.py --dst 10.0.2.2 --mode burst

Requer Scapy (já normalmente disponível no ambiente Mininet/P4).
"""

import argparse
import time

from scapy.all import IP, ICMP, UDP, Raw, send


def run_normal(dst: str, count: int, interval: float):
    print(f"[traffic_gen] Tráfego NORMAL -> {dst} "
          f"({count} pacotes, intervalo={interval}s)")
    for i in range(count):
        send(IP(dst=dst) / ICMP(), verbose=False)
        print(f"  pacote {i + 1}/{count} enviado")
        time.sleep(interval)
    print("[traffic_gen] Concluído. Esse fluxo NÃO deve ultrapassar o limiar "
          "de marcação (verifique o log do controller.py).")


def run_burst(dst: str, count: int, interval: float):
    print(f"[traffic_gen] Tráfego em RAJADA -> {dst} "
          f"({count} pacotes, intervalo={interval}s) — deve disparar a "
          f"marcação e, em seguida, o bloqueio automático do fluxo.")
    payload = Raw(load=b"X" * 200)  # aumenta os bytes por pacote
    for i in range(count):
        send(IP(dst=dst) / UDP(dport=9999) / payload, verbose=False)
        if (i + 1) % 10 == 0:
            print(f"  {i + 1}/{count} pacotes enviados")
        time.sleep(interval)
    print("[traffic_gen] Concluído. Verifique no log do controller.py que o "
          "fluxo foi MARCADO e depois BLOQUEADO automaticamente.")


def main():
    ap = argparse.ArgumentParser(description="Gerador de tráfego — Trabalho 4")
    ap.add_argument("--dst", required=True, help="IP de destino (ex.: 10.0.2.2)")
    ap.add_argument("--mode", choices=["normal", "burst"], default="normal")
    ap.add_argument("--count", type=int, default=None,
                    help="Número de pacotes (padrão: 15 no modo normal, "
                         "150 no modo burst)")
    ap.add_argument("--interval", type=float, default=None,
                    help="Intervalo entre pacotes em segundos "
                         "(padrão: 0.5 no modo normal, 0.02 no modo burst)")
    args = ap.parse_args()

    if args.mode == "normal":
        count    = args.count if args.count is not None else 15
        interval = args.interval if args.interval is not None else 0.5
        run_normal(args.dst, count, interval)
    else:
        count    = args.count if args.count is not None else 150
        interval = args.interval if args.interval is not None else 0.02
        run_burst(args.dst, count, interval)


if __name__ == "__main__":
    main()
