#!/usr/bin/env python3
import time
import random
import socket
import json
import os

TARGET_IP = "10.0.0.2"
SHARED_FILE = "shared_metrics.json"

def enviar_pacotes(pps, duracao, perfil):
    print(f"[{time.strftime('%H:%M:%S')}] Modo: {perfil} | Enviando a {pps} pps...")
    
    dados = {
        "status_gerador": " Executando",
        "perfil_atual": perfil,
        "pps": pps,
        "kbps": round(pps * 4.33, 2), 
        "timestamp": time.time()
    }
    with open(SHARED_FILE, 'w') as f:
        json.dump(dados, f)

    intervalo = 1.0 / pps if pps > 0 else 1.0
    inicio = time.time()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"X" * 500 

    while time.time() - inicio < duracao:
        if pps > 0:
            try:
                sock.sendto(payload, (TARGET_IP, 12345))
            except:
                pass
            time.sleep(intervalo)
        else:
            time.sleep(1)

def main():
    print(" Gerador Automático de Tráfego Iniciado em Loop Infinito...")
    
    try:
        while True:
            duracao_normal = random.randint(10, 15)
            pps_normal = random.randint(5, 12)
            enviar_pacotes(pps_normal, duracao_normal, "Normal (Apenas Pings)")

            duracao_carga = random.randint(5, 8)
            pps_carga = random.randint(35, 50)
            enviar_pacotes(pps_carga, duracao_carga, "Carga Oscilante (Pico)")

            duracao_ataque = random.randint(12, 18)
            pps_ataque = random.randint(90, 125)
            enviar_pacotes(pps_ataque, duracao_ataque, " Carga Intensa (Ataque DoS)")

    except KeyboardInterrupt:
        print("\n Gerador desligado pelo usuário.")
        if os.path.exists(SHARED_FILE):
            os.remove(SHARED_FILE)

if __name__ == "__main__":
    main()