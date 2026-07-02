#!/usr/bin/env bash
# run.sh — Trabalho 4 (UFSM)
# Comandos de compilação e execução usados na demonstração.
# Ajuste os caminhos (mininet, topo, etc.) conforme o ambiente do grupo,
# mantendo a mesma organização já usada no Trabalho 3.

set -e

echo "== 1) Compilando o programa P4 =="
mkdir -p build
p4c-bm2-ss --p4v 16 \
  --p4runtime-files build/telemetria_trabalho4.p4info.txt \
  -o build/telemetria_trabalho4.json \
  telemetria_trabalho4.p4

echo "== 2) Subindo a topologia (Mininet + BMv2) =="
echo "   (reaproveitar o mesmo script/comando de topologia usado no Trabalho 3,"
echo "    apontando o switch s1 para build/telemetria_trabalho4.json,"
echo "    thrift_port=9090, portas 1/2/3 -> h1/h2/h3, conforme topo_trabalho4.json)"
echo "   Ex.: sudo python3 topo_trabalho4.py"

echo "== 3) Dentro da CLI do Mininet, iniciar o controlador em h3 =="
echo "   mininet> h3 sudo python3 controller.py --iface h3-eth0 --thrift-port 9090 &"

echo "== 4) (Opcional) abrir o dashboard de acompanhamento em h3 =="
echo "   -- opção A: Tkinter (precisa de X forwarding/display local)"
echo "   mininet> h3 sudo python3 dashboard.py --iface h3-eth0 &"
echo "   -- opção B: Streamlit (web, recomendado ao acessar via SSH)"
echo "   mininet> h3 sudo \$(which streamlit) run streamlit_dashboard.py \\"
echo "            --server.address 0.0.0.0 --server.port 8501 &"
echo "   No SEU computador: ssh -L 8501:localhost:8501 usuario@servidor"
echo "   e abra http://localhost:8501 no navegador local."

echo "== 5) Gerar tráfego normal a partir de h1 =="
echo "   mininet> h1 python3 traffic_gen.py --dst 10.0.2.2 --mode normal"

echo "== 6) Gerar tráfego em rajada a partir de h1 (dispara a decisão) =="
echo "   mininet> h1 python3 traffic_gen.py --dst 10.0.2.2 --mode burst"

echo "== 7) Verificar a regra instalada automaticamente =="
echo "   simple_switch_CLI --thrift-port 9090 <<< 'table_dump MyIngress.traffic_action'"
