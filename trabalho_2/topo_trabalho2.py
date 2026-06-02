#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import tempfile

from mininet.net  import Mininet
from mininet.topo import Topo
from mininet.log  import setLogLevel, info, error
from mininet.cli  import CLI
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch

# ── Caminhos ──────────────────────────────────────────────────────────────────
THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
BMV2_JSON   = os.path.join(THIS_DIR, "build", "telemetria_trabalho2.json")
THRIFT_PORT = 9090

# ── Regras instaladas via simple_switch_CLI ───────────────────────────────────
# mirroring_add <session_id> <egress_port>  →  clone vai para porta 3 (h3)
RULES = """\
mirroring_add 99 3
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.1.1/32 => 00:00:00:00:01:01 1
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.2.2/32 => 00:00:00:00:02:02 2
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.3.3/32 => 00:00:00:00:03:03 3
"""


# ── P4Switch: node Mininet que roda simple_switch ─────────────────────────────
class P4Switch(Node):
    """
    Node Mininet que executa o BMv2 simple_switch internamente.
    As interfaces são mapeadas para portas P4 na ordem em que os
    links são adicionados.
    """

    def __init__(self, name, json_path, thrift_port=THRIFT_PORT,
                 log_file="/tmp/s1_bmv2.log", **kwargs):
        kwargs.setdefault("inNamespace", False)
        super().__init__(name, **kwargs)
        self.json_path   = json_path
        self.thrift_port = thrift_port
        self.log_file    = log_file
        self._proc       = None
        self._port_map   = {}   # iface_name → porta P4 (1-based)
        self._next_port  = 1

    # Mininet chama start() depois de criar todas as interfaces
    def start(self, _controllers=None):
        # Monta mapeamento iface → porta na ordem que foram adicionadas
        for intf in self.intfList():
            if intf.name == "lo":
                continue
            if intf.name not in self._port_map:
                self._port_map[intf.name] = self._next_port
                self._next_port += 1

        port_args = []
        for iface, port in sorted(self._port_map.items(), key=lambda x: x[1]):
            port_args += ["-i", f"{port}@{iface}"]

        cmd = (
            ["simple_switch"]
            + port_args
            + [
                "--thrift-port", str(self.thrift_port),
                "--log-console",
                "--device-id", "0",
                self.json_path,
            ]
        )

        info(f"*** {self.name}: iniciando BMv2\n")
        info(f"    {' '.join(cmd)}\n")

        log_f    = open(self.log_file, "w")
        self._proc = subprocess.Popen(
            cmd, stdout=log_f, stderr=log_f,
            close_fds=True
        )
        time.sleep(3)   # aguarda o thrift server subir

        if self._proc.poll() is not None:
            error(f"*** ERRO: simple_switch encerrou prematuramente.\n")
            error(f"    Verifique {self.log_file}\n")
            sys.exit(1)

        info(f"*** {self.name}: BMv2 rodando (PID {self._proc.pid})\n")

    def stop(self, deleteIntfs=True):
        if self._proc:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        super().stop(deleteIntfs)

    # Mininet chama isso quando testa conectividade; não usamos OVS
    def attach(self, intf):
        pass

    def detach(self, intf):
        pass

    def dpctl(self, *args):
        pass


# ── Topologia ─────────────────────────────────────────────────────────────────
class TrabalhoTopo(Topo):
    def build(self):
        h1 = self.addHost("h1", ip="10.0.1.1/24", mac="00:00:00:00:01:01")
        h2 = self.addHost("h2", ip="10.0.2.2/24", mac="00:00:00:00:02:02")
        h3 = self.addHost("h3", ip="10.0.3.3/24", mac="00:00:00:00:03:03")
        s1 = self.addSwitch("s1")

        # Ordem dos links define as portas: h1=1, h2=2, h3=3
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


# ── Instalação de regras ───────────────────────────────────────────────────────
def install_rules(thrift_port=THRIFT_PORT):
    info("*** Instalando regras P4 via simple_switch_CLI...\n")
    try:
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=RULES,
            capture_output=True,
            text=True,
            timeout=15,
        )
        for line in result.stdout.splitlines():
            if line.strip():
                info(f"    {line}\n")
        if result.returncode != 0 and result.stderr.strip():
            info(f"[AVISO CLI] {result.stderr.strip()}\n")
        info("*** Regras instaladas com sucesso.\n")
    except FileNotFoundError:
        error("*** ERRO: simple_switch_CLI não encontrado no PATH.\n")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        error("*** ERRO: timeout ao instalar regras.\n")
        sys.exit(1)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    setLogLevel("info")

    # Verifica pré-requisitos
    if not os.path.exists(BMV2_JSON):
        error(f"\nERRO: {BMV2_JSON} não encontrado.\n")
        error("Execute primeiro:\n")
        error("  p4c --target bmv2 --arch v1model \\\n")
        error("      --p4runtime-files build/telemetria_trabalho2.p4.p4info.txt \\\n")
        error("      -o build/ telemetria_trabalho2.p4\n\n")
        sys.exit(1)

    # Cria a topologia com P4Switch no lugar do switch padrão
    topo = TrabalhoTopo()

    # Substituímos o switch OVS pelo P4Switch via parâmetro switch
    # (Mininet instancia o switch a partir do nome 's1' + classe switch)
    # Como precisamos passar json_path, criamos a rede manualmente:
    net = Mininet(topo=None, controller=None, autoSetMacs=False)

    # Hosts
    h1 = net.addHost("h1", ip="10.0.1.1/24", mac="00:00:00:00:01:01")
    h2 = net.addHost("h2", ip="10.0.2.2/24", mac="00:00:00:00:02:02")
    h3 = net.addHost("h3", ip="10.0.3.3/24", mac="00:00:00:00:03:03")

    # Switch P4
    s1 = net.addSwitch("s1", cls=P4Switch,
                        json_path=BMV2_JSON,
                        thrift_port=THRIFT_PORT)

    # Links (ordem define portas: h1=1, h2=2, h3=3)
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    net.start()

    # Rotas default nos hosts (gateway = próprio switch, L2 puro)
    for host in [h1, h2, h3]:
        host.cmd(f"ip route add default dev {host.name}-eth0")

    # Instala as regras P4
    install_rules()

    # Popula ARP manualmente (evita tráfego ARP não-IPv4 no switch P4)
    h1.cmd("arp -s 10.0.2.2 00:00:00:00:02:02")
    h1.cmd("arp -s 10.0.3.3 00:00:00:00:03:03")
    h2.cmd("arp -s 10.0.1.1 00:00:00:00:01:01")
    h2.cmd("arp -s 10.0.3.3 00:00:00:00:03:03")
    h3.cmd("arp -s 10.0.1.1 00:00:00:00:01:01")
    h3.cmd("arp -s 10.0.2.2 00:00:00:00:02:02")

    info("\n")
    info("=" * 62 + "\n")
    info("  Topologia P4 iniciada com sucesso!\n")
    info("  h1 = 10.0.1.1   h2 = 10.0.2.2   h3 = 10.0.3.3 (coletor)\n")
    info("  Log do switch: /tmp/s1_bmv2.log\n")
    info("\n")
    info("  [1] Abra o dashboard em h3:\n")
    info("        mininet> xterm h3\n")
    info("        (no xterm) sudo python3 dashboard.py --iface h3-eth0\n")
    info("\n")
    info("  [2] Gere tráfego:\n")
    info("        mininet> h1 ping -c 30 10.0.2.2\n")
    info("        mininet> h2 iperf -u -s &\n")
    info("        mininet> h1 iperf -u -c 10.0.2.2 -t 20 -b 1M\n")
    info("=" * 62 + "\n\n")

    CLI(net)

    net.stop()


if __name__ == "__main__":
    main()