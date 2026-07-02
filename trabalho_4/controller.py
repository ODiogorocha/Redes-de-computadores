#!/usr/bin/env python3
"""
controller.py — Trabalho 4 (UFSM)
==================================

Evolução do coletor passivo do Trabalho 3 (collector.py) para um
controlador ATIVO, que fecha o ciclo de controle:

    telemetria -> decisão -> regra no switch -> mudança no tráfego

Responsabilidades deste script:
  1. Instalar as regras ESTÁTICAS iniciais (encaminhamento L3 e a
     sessão de clonagem/mirroring), reaproveitando exatamente o que
     estava em s1-runtime.json do Trabalho 3.
  2. Escutar, na interface de h3, as telemetrias exportadas pelo
     switch P4 (mesmo mecanismo do Trabalho 3), incluindo o NOVO
     alerta de fluxo (flow_alert, EtherType 0x9998) usado para a
     tomada de decisão.
  3. Implementar a POLÍTICA DE DECISÃO (função `decide_state`)
     inteiramente em software, usando as métricas recebidas.
  4. Instalar, atualizar ou remover automaticamente, via
     `simple_switch_CLI` (interface Thrift do BMv2, porta 9090 —
     a mesma já usada no Trabalho 3), a regra da tabela
     `MyIngress.traffic_action` correspondente à decisão.

A comunicação com o switch é feita via `simple_switch_CLI`, o mesmo
utilitário de linha de comando do BMv2 já usado no Trabalho 3 para
inspecionar contadores/tabelas. Não é necessária nenhuma dependência
externa além do Python padrão.

Uso típico (dentro do Mininet):

    h3 sudo python3 controller.py --iface h3-eth0 --thrift-port 9090
"""

from __future__ import annotations  # compatibilidade com Python < 3.10 (tipo "int | None")

import argparse
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime

# ───────────────────────── Constantes de protocolo ──────────────────────────
ETH_P_ALL        = 0x0003
TELEM_ETYPE      = 0x9999   # telemetria de janela global (Trabalho 3)
FLOW_ALERT_ETYPE = 0x9998   # alerta por fluxo (Trabalho 4 - NOVO)

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

# ───────────────────────── Política de decisão ──────────────────────────────
# Limiares explicados no relatório: aplicados sobre o total de PACOTES
# acumulados do fluxo (métrica reaproveitada do Trabalho 3). O alerta de
# fluxo chega a cada 8 pacotes daquele IP de origem (ver telemetria_trabalho4.p4).
MARK_PKT_THRESHOLD  = 40    # acima disso -> marca o fluxo (DSCP)
BLOCK_PKT_THRESHOLD = 100   # acima disso -> descarta o fluxo
IDLE_TIMEOUT_SEC    = 20.0  # sem alertas novos por esse tempo -> remove a regra
MARK_DSCP_VALUE     = 46    # DSCP usado para marcar (EF - apenas um rótulo visível)

STATE_NONE, STATE_MARKED, STATE_BLOCKED = "NONE", "MARKED", "BLOCKED"

# Entradas estáticas reaproveitadas do Trabalho 3 (s1-runtime.json)
STATIC_HOSTS = [
    # ip,          mac,                 porta
    ("10.0.1.1", "00:00:00:00:01:01", 1),
    ("10.0.2.2", "00:00:00:00:02:02", 2),
    ("10.0.3.3", "00:00:00:00:03:03", 3),
]
CLONE_SESSION_ID   = 99
CLONE_EGRESS_PORT  = 3  # porta de h3


# ═══════════════════════ Interface com o switch (thrift) ═══════════════════
class SwitchControl:
    """Encapsula chamadas ao simple_switch_CLI (BMv2 thrift API)."""

    def __init__(self, thrift_port: int, log=print):
        self.thrift_port = thrift_port
        self.log = log

    def _run(self, commands):
        cmd_text = "\n".join(commands) + "\n"
        try:
            proc = subprocess.run(
                ["simple_switch_CLI", "--thrift-port", str(self.thrift_port)],
                input=cmd_text, capture_output=True, text=True, timeout=10,
            )
        except FileNotFoundError:
            self.log("[ERRO] simple_switch_CLI não encontrado no PATH. "
                      "Verifique se o BMv2 está instalado.")
            return ""
        if proc.returncode != 0:
            self.log(f"[AVISO] simple_switch_CLI saiu com código {proc.returncode}: "
                      f"{proc.stderr.strip()}")
        return proc.stdout

    # ---- setup inicial (reaproveita s1-runtime.json do Trabalho 3) ----
    def setup_static_rules(self):
        cmds = []
        for ip, mac, port in STATIC_HOSTS:
            cmds.append(
                f"table_add MyIngress.ipv4_lpm ipv4_forward {ip}/32 => {mac} {port}"
            )
        # sessão de clonagem usada pela telemetria (janela + alertas de fluxo)
        cmds.append(f"mirroring_add {CLONE_SESSION_ID} {CLONE_EGRESS_PORT}")
        out = self._run(cmds)
        self.log("[setup] Regras estáticas de encaminhamento e mirroring instaladas.")
        return out

    # ---- tabela de decisão (traffic_action) — populada dinamicamente ----
    def install_rule(self, src_ip: str, action: str, params: str = "") -> int | None:
        cmd = f"table_add MyIngress.traffic_action {action} {src_ip} => {params}".strip()
        out = self._run([cmd])
        handle = self._parse_handle(out)
        self.log(f"[decisão] INSTALAR  src={src_ip}  ação={action} {params}  "
                  f"(handle={handle})")
        return handle

    def update_rule(self, src_ip: str, handle: int, action: str, params: str = ""):
        cmd = f"table_modify MyIngress.traffic_action {action} {handle} {params}".strip()
        self._run([cmd])
        self.log(f"[decisão] ATUALIZAR src={src_ip}  ação={action} {params}  "
                  f"(handle={handle})")

    def remove_rule(self, src_ip: str, handle: int):
        cmd = f"table_delete MyIngress.traffic_action {handle}"
        self._run([cmd])
        self.log(f"[decisão] REMOVER   src={src_ip}  (handle={handle}) "
                  f"— fluxo voltou ao normal / ficou inativo")

    @staticmethod
    def _parse_handle(cli_output: str):
        m = re.search(r"handle\s+(\d+)", cli_output)
        return int(m.group(1)) if m else None


# ═══════════════════════ Política de decisão (software) ════════════════════
def decide_state(pkt_count: int, byte_count: int) -> str:
    """
    Política de decisão do Trabalho 4.

    Usa as métricas recebidas via telemetria (pacotes acumulados do
    fluxo) para decidir o estado desejado da regra no switch:

        pkt_count >= BLOCK_PKT_THRESHOLD -> BLOCKED (descarta o fluxo)
        pkt_count >= MARK_PKT_THRESHOLD  -> MARKED  (marca DSCP)
        caso contrário                   -> NONE    (tráfego normal)

    A política é intencionalmente simples (conforme permitido pelo
    enunciado), mas é ela — e não comandos manuais — que decide a
    regra instalada no switch.
    """
    if pkt_count >= BLOCK_PKT_THRESHOLD:
        return STATE_BLOCKED
    if pkt_count >= MARK_PKT_THRESHOLD:
        return STATE_MARKED
    return STATE_NONE


def action_for_state(state: str):
    if state == STATE_MARKED:
        return "mark_flow", str(MARK_DSCP_VALUE)
    if state == STATE_BLOCKED:
        return "drop_flow", ""
    return "no_action", ""


# ═══════════════════════ Estado dos fluxos + reconciliação ═════════════════
class FlowManager:
    def __init__(self, switch: SwitchControl, log=print):
        self.switch = switch
        self.log = log
        self.lock = threading.Lock()
        self.flows = {}  # src_ip -> dict(state, handle, last_seen, pkt_count, byte_count)

    def on_flow_alert(self, src_ip: str, pkt_count: int, byte_count: int, min_ttl: int):
        now = time.time()
        with self.lock:
            f = self.flows.setdefault(src_ip, {
                "state": STATE_NONE, "handle": None, "last_seen": now,
            })
            f["last_seen"]  = now
            f["pkt_count"]  = pkt_count
            f["byte_count"] = byte_count

            desired = decide_state(pkt_count, byte_count)
            current = f["state"]

            self.log(f"[telemetria-fluxo] src={src_ip:<12} pkts={pkt_count:<6} "
                     f"bytes={byte_count:<8} ttl_min={min_ttl:<3} "
                     f"estado_atual={current} estado_desejado={desired}")

            if desired == current:
                return  # nenhuma mudança necessária

            action, params = action_for_state(desired)

            if current == STATE_NONE and desired != STATE_NONE:
                handle = self.switch.install_rule(src_ip, action, params)
                f["handle"] = handle
            elif current != STATE_NONE and desired != STATE_NONE:
                self.switch.update_rule(src_ip, f["handle"], action, params)
            elif desired == STATE_NONE and f["handle"] is not None:
                self.switch.remove_rule(src_ip, f["handle"])
                f["handle"] = None

            f["state"] = desired

    def reconcile_idle_flows(self):
        """Remove regras de fluxos que pararam de enviar telemetria
        (tráfego cessou) — evidencia o requisito de REMOÇÃO automática."""
        now = time.time()
        with self.lock:
            for src_ip, f in self.flows.items():
                if f["state"] != STATE_NONE and (now - f["last_seen"]) > IDLE_TIMEOUT_SEC:
                    self.log(f"[idle] src={src_ip} sem telemetria há "
                             f"{now - f['last_seen']:.1f}s — removendo regra")
                    self.switch.remove_rule(src_ip, f["handle"])
                    f["handle"] = None
                    f["state"]  = STATE_NONE


# ═══════════════════════ Decodificação da telemetria (dataplane) ═══════════
def parse_window_telemetry(raw: bytes):
    """Igual ao collector.py do Trabalho 3 — apenas para acompanhamento."""
    if len(raw) < 26:
        return None
    etype = struct.unpack("!H", raw[12:14])[0]
    if etype != TELEM_ETYPE:
        return None
    pkt, byt, ttl, proto, _ = struct.unpack("!IIBBH", raw[14:26])
    return pkt, byt, ttl, proto


def parse_flow_alert(raw: bytes):
    """Decodifica o novo header flow_alert_t (Trabalho 4)."""
    if len(raw) < 30:
        return None
    etype = struct.unpack("!H", raw[12:14])[0]
    if etype != FLOW_ALERT_ETYPE:
        return None
    src_raw, pkt, byt, ttl, _r1, _r2 = struct.unpack("!4sIIBBH", raw[14:30])
    src_ip = socket.inet_ntoa(src_raw)
    return src_ip, pkt, byt, ttl


# ═══════════════════════════════ Main loop ══════════════════════════════════
def sniff_loop(iface: str, flow_mgr: FlowManager, log=print):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                             socket.htons(ETH_P_ALL))
        sock.bind((iface, 0))
    except PermissionError:
        log("ERRO: permissão negada para abrir socket cru. Execute com sudo.")
        sys.exit(1)
    except OSError as e:
        log(f"ERRO ao abrir socket em {iface}: {e}")
        sys.exit(1)

    log(f"[controller] Escutando telemetria em {iface} "
        f"(janela=0x{TELEM_ETYPE:04X}, alerta_fluxo=0x{FLOW_ALERT_ETYPE:04X})")

    windows_seen = 0
    while True:
        raw, _ = sock.recvfrom(65535)

        alert = parse_flow_alert(raw)
        if alert is not None:
            src_ip, pkt, byt, ttl = alert
            flow_mgr.on_flow_alert(src_ip, pkt, byt, ttl)
            continue

        window = parse_window_telemetry(raw)
        if window is not None:
            pkt, byt, ttl, proto = window
            windows_seen += 1
            ts = datetime.now().strftime("%H:%M:%S")
            proto_name = PROTO_NAMES.get(proto, f"?({proto})")
            log(f"[telemetria-janela #{windows_seen:04d}] [{ts}] "
                f"pkts={pkt} bytes={byt} ttl_min={ttl} proto_dominante={proto_name}")


def housekeeping_loop(flow_mgr: FlowManager, interval: float = 5.0):
    while True:
        time.sleep(interval)
        flow_mgr.reconcile_idle_flows()


def main():
    ap = argparse.ArgumentParser(
        description="Controlador automático (Trabalho 4) — decide e instala "
                     "regras no switch P4 a partir da telemetria recebida."
    )
    ap.add_argument("--iface", default="h3-eth0",
                    help="Interface de h3 onde a telemetria chega (padrão: h3-eth0)")
    ap.add_argument("--thrift-port", type=int, default=9090,
                    help="Porta thrift do simple_switch_CLI (padrão: 9090)")
    ap.add_argument("--skip-setup", action="store_true",
                    help="Não reinstala as regras estáticas iniciais "
                         "(use se elas já foram carregadas por outro script)")
    args = ap.parse_args()

    def log(msg):
        print(msg, flush=True)

    switch = SwitchControl(thrift_port=args.thrift_port, log=log)
    flow_mgr = FlowManager(switch, log=log)

    if not args.skip_setup:
        switch.setup_static_rules()

    threading.Thread(target=housekeeping_loop, args=(flow_mgr,), daemon=True).start()

    try:
        sniff_loop(args.iface, flow_mgr, log=log)
    except KeyboardInterrupt:
        log("\n[controller] Encerrado pelo usuário.")


if __name__ == "__main__":
    main()
