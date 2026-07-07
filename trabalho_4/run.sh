#!/bin/bash

echo "=== LIMPANDO AMBIENTE MININET ==="
sudo mn -c

echo "=== COMPILANDO PROGRAMA P4 ==="
mkdir -p build
p4c-bm2-ss --p4v 16 telemetria_trabalho4.p4 -o build/telemetria_trabalho4.json

echo "=== INICIANDO TOPOLOGIA ==="
sudo python3 topologia.py