#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.topo import Topo
from mininet.node import Switch
import os
import sys
import time

class P4SwitchDirect(Switch):
    def __init__(self, name, json_path='build/telemetria_trabalho4.json', **kwargs):
        # Remove parâmetros irrelevantes passados genericamente pelo Mininet
        kwargs.pop('listenPort', None)
        kwargs.pop('dpid', None)
        Switch.__init__(self, name, **kwargs)
        self.json_path = json_path

    def start(self, controllers):
        # Mapeia as interfaces de rede criadas pelo Mininet para as portas do Switch BMv2
        args = ['simple_switch']
        port_idx = 1
        for intf in self.intfList():
            if not intf.IP() and intf.name != 'lo': 
                args.extend(['-i', f'{port_idx}@{intf.name}'])
                port_idx += 1
        
        args.extend(['--thrift-port', '9090'])
        args.append(self.json_path)
        args.append('--log-console')
        
        print(f"=== Iniciando BMv2 Switch {self.name} em Background ===")
        # Usando a flag nativa do Mininet para rodar em segundo plano de forma segura
        self.cmd(' '.join(args) + ' > /dev/null 2>&1 &')
        
        # Pausa crucial de 2 segundos para o processo simple_switch inicializar completamente o socket Thrift
        import time
        time.sleep(2)

        print("=== Ativando Sessao de Espelhamento de Telemetria (ID 333 -> Porta 3) ===")
        os.system('echo "mirroring_add 333 3" | simple_switch_CLI --thrift-port 9090')
class P4Topo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        
        # Conexões explícitas para garantir o alinhamento de portas do switch
        self.addLink(h1, s1) # Porta 1
        self.addLink(h2, s1) # Porta 2
        self.addLink(h3, s1) # Porta 3 (Coletor de Telemetria)

def main():
    json_path = 'build/telemetria_trabalho4.json'
    if not os.path.exists(json_path):
        print(f"Erro: {json_path} nao encontrado. Certifique-se de compilar o P4 primeiro.")
        return

    topo = P4Topo()
    net = Mininet(topo=topo, switch=P4SwitchDirect, controller=None)
    net.start()
    
    print("=== Configurando rotas ARP estaticas ===")
    net.get('h1').cmd('arp -s 10.0.0.2 00:00:00:00:00:02')
    net.get('h1').cmd('arp -s 10.0.0.3 00:00:00:00:00:03')
    net.get('h2').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')
    net.get('h3').cmd('arp -s 10.0.0.1 00:00:00:00:00:01')

    print("=== Populando tabela estatica de roteamento (ipv4_lpm) ===")
    os.system('echo "table_add ipv4_lpm ipv4_forward 10.0.0.1/32 => 00:00:00:00:00:01 1" | simple_switch_CLI --thrift-port 9090')
    os.system('echo "table_add ipv4_lpm ipv4_forward 10.0.0.2/32 => 00:00:00:00:00:02 2" | simple_switch_CLI --thrift-port 9090')
    os.system('echo "table_add ipv4_lpm ipv4_forward 10.0.0.3/32 => 00:00:00:00:00:03 3" | simple_switch_CLI --thrift-port 9090')

    print("\n=== REDE MININET ATIVA ===")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()