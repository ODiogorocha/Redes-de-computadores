import os
import json
import time
from collections import defaultdict
from scapy.all import sniff, IP, UDP, TCP

JSON_PATH = "telemetria_trabalho4.json"
LIMIAR_PACOTES_POR_SEGUNDO = 30  #a cima disso é ataque 

estatisticas = {"total_packets": 0, "pps": 0, "bps": 0}
fluxos_recentes = []
regras_ativas = []
politica_ativa = "Monitoramento Ativo (Forward)"
status_gerador = {"status": "Inativo", "tipo": "Nenhum"}

contagem_ips = defaultdict(int)
ips_bloqueados = set()
ultimo_reset = time.time()
pacotes_segundo = 0
bytes_segundo = 0

def salvar_dashboard():
    estado = {
        "switch_status": "Conectado",
        "traffic_stats": estatisticas,
        "recent_flows": fluxos_recentes[-5:], 
        "controller_policies": {"politica_ativa": politica_ativa},
        "active_rules": regras_ativas,
        "traffic_generator": status_gerador
    }
    with open(JSON_PATH + ".tmp", "w") as f:
        json.dump(estado, f, indent=4)
    os.replace(JSON_PATH + ".tmp", JSON_PATH)

def bloquear_ip(ip_origem):
    global politica_ativa
    if ip_origem not in ips_bloqueados:
        print(f"  [Controlador] Limiar excedido para {ip_origem}! Injetando regra de DROP no s1...")
        
        cmd = f'echo "table_add bloqueio_ip drop {ip_origem} =>" | simple_switch_CLI'
        os.system(cmd)
        
        ips_bloqueados.add(ip_origem)
        politica_ativa = f"Mitigação Ativa: Bloqueando {ip_origem}"
        regras_ativas.append({"Tabela": "bloqueio_ip", "Match": ip_origem, "Ação": "drop"})
        salvar_dashboard()

def processar_telemetria(pacote):
    global ultimo_reset, pacotes_segundo, bytes_segundo, politica_ativa, status_gerador

    if IP in pacote and pacote[IP].dst != "10.0.0.3":
        ip_src = pacote[IP].src
        ip_dst = pacote[IP].dst
        tamanho = len(pacote)
        
        protocolo = "ICMP" if pacote[IP].proto == 1 else "UDP" if UDP in pacote else "TCP" if TCP in pacote else "OUTRO"
        
        estatisticas["total_packets"] += 1
        pacotes_segundo += 1
        bytes_segundo += tamanho
        
        if ip_src not in ips_bloqueados:
            contagem_ips[ip_src] += 1
            fluxos_recentes.append({"src_ip": ip_src, "dst_ip": ip_dst, "protocolo": protocolo, "bytes": tamanho, "decisao": "FORWARD"})

        agora = time.time()
        if agora - ultimo_reset >= 1.0:
            estatisticas["pps"] = pacotes_segundo
            estatisticas["bps"] = bytes_segundo * 8
            
            status_gerador = {"status": "Ativo", "tipo": "Carga Intensa (Ataque)" if pacotes_segundo > LIMIAR_PACOTES_POR_SEGUNDO else "Tráfego Normal"}
            if pacotes_segundo == 0:
                status_gerador = {"status": "Inativo", "tipo": "Nenhum"}

            for ip, pacotes in contagem_ips.items():
                if pacotes > LIMIAR_PACOTES_POR_SEGUNDO:
                    bloquear_ip(ip)

            pacotes_segundo = 0
            bytes_segundo = 0
            contagem_ips.clear()
            ultimo_reset = agora
            salvar_dashboard()

print(" Controlador Inteligente iniciado! Escutando telemetria na interface h3-eth0...")
salvar_dashboard()
sniff(iface="h3-eth0", prn=processar_telemetria, store=False)