# Trabalho 2 – Telemetria em Switches P4

**Disciplina:** Redes de Computadores  
**Universidade:** UFSM – Departamento de Computação Aplicada  
**Grupo:** [Nomes dos integrantes]

---

## 1. Abordagem Escolhida

A solução implementa **clonagem de pacotes para um controlador/coletor** (`Clone-to-Collector`). A cada janela de **N = 10 pacotes** observados no plano de dados, o switch P4 cria uma cópia do pacote corrente via `clone3(CloneType.I2E, CLONE_SESSION, meta)`, insere nessa cópia um cabeçalho de telemetria customizado (EtherType `0x9999`) e o encaminha pela porta do host coletor (h3). O pacote original segue seu caminho normalmente; apenas o clone carrega os dados de telemetria.

Esta abordagem foi escolhida por ser nativa ao BMv2/v1model e não exigir modificação nos hosts finais nem em protocolos existentes.

---

## 2. Topologia

```
h1 (10.0.1.1) ──┐
                 ├── s1 (P4 BMv2) ── h3 (10.0.3.3) ← coletor
h2 (10.0.2.2) ──┘
```

- **h1** e **h2**: hosts que geram e recebem tráfego (ping, iperf, etc.)  
- **s1**: switch P4 compilado com o programa `telemetria_trabalho2.p4`  
- **h3**: host rodando `collector.py`; recebe os clones de telemetria pela porta 3 do switch

A topologia é descrita em `topo_trabalho2.json` e as entradas de tabela em `s1-runtime.json`.

---

## 3. Modificações no Programa P4

### 3.1 Novo cabeçalho `telemetry_t`
Inserido após o cabeçalho Ethernet nos pacotes clonados:

| Campo            | Tamanho | Descrição                          |
|------------------|---------|------------------------------------|
| `pkt_count`      | 32 bits | Pacotes observados na janela       |
| `byte_count`     | 32 bits | Bytes observados na janela         |
| `min_ttl`        | 8 bits  | TTL mínimo visto na janela         |
| `dominant_proto` | 8 bits  | Protocolo com mais pacotes (0=none)|
| `reserved`       | 16 bits | Alinhamento / uso futuro           |

### 3.2 Registradores adicionados (Ingress)
- `reg_pkt_count[1]` – contador de pacotes da janela atual  
- `reg_byte_count[1]` – acumulador de bytes da janela atual  
- `reg_min_ttl[1]` – menor TTL observado  
- `reg_proto_count[256]` – contador por protocolo IP (índice = número do protocolo)

### 3.3 Lógica da janela (Ingress)
A cada pacote IPv4 válido, os registradores são incrementados. Quando `pkt_count == WINDOW_SIZE`, o switch:
1. Lê os contadores de TCP (6), UDP (17) e ICMP (1) para determinar o protocolo dominante.
2. Preenche o `metadata` com os valores coletados.
3. Chama `clone3()` para gerar o clone de telemetria.
4. Zera todos os registradores para a próxima janela.

### 3.4 Egress – preenchimento do cabeçalho
No egress, pacotes com `instance_type == 1` (clones de ingress) têm o cabeçalho `telemetry_t` validado e preenchido; o EtherType Ethernet é alterado para `0x9999`.

---

## 4. Métricas Exportadas

### Métricas obrigatórias
| Métrica        | Campo P4       | Justificativa                                  |
|----------------|----------------|------------------------------------------------|
| Pacotes/janela | `pkt_count`    | Mede a taxa de chegada de pacotes              |
| Bytes/janela   | `byte_count`   | Mede a taxa de throughput                      |

### Métricas adicionais

**Métrica 3 – TTL mínimo observado (`min_ttl`)**  
O TTL decrementado a cada salto indica a distância da origem ao switch. Valores muito baixos podem sinalizar loops de roteamento ou ataques TTL-expiry. Essa métrica é especialmente relevante em ambientes onde diferentes fontes de tráfego possuem TTLs iniciais distintos, permitindo inferir topologia e detectar anomalias.

**Métrica 4 – Protocolo dominante (`dominant_proto`)**  
Identifica qual protocolo de camada 4 (TCP/UDP/ICMP) teve o maior número de pacotes na janela. Essa informação é valiosa para caracterização de tráfego, QoS, e detecção de floods (por exemplo, flood ICMP ou UDP). O campo exporta o número de protocolo IP (1 = ICMP, 6 = TCP, 17 = UDP), decodificado pelo coletor em texto legível.

---

## 5. Janela de Observação

A janela é definida por **número de pacotes**: a cada **N = 10** pacotes IPv4 observados no ingress do switch, um relatório de telemetria é exportado. Esta escolha:

- É determinística e independente do clock do switch (BMv2 não tem timer nativo eficiente).
- Permite visualização rápida de mudanças de tráfego durante demonstração.
- Pode ser ajustada alterando a constante `WINDOW_SIZE` no topo do arquivo `.p4`.

---

## 6. Compilação e Execução

### Pré-requisitos
```
p4c (>= 1.2.3)
behavioral-model (bmv2)
mininet
python3 + scapy (para testes)
```

### Compilar o programa P4
```bash
p4c --target bmv2 --arch v1model \
    --p4runtime-files build/telemetria_trabalho2.p4.p4info.txt \
    -o build/ telemetria_trabalho2.p4
```

### Iniciar a topologia Mininet
```bash
sudo python3 /usr/local/lib/python3.*/dist-packages/p4_mininet/main.py \
    --topo topo_trabalho2.json \
    --behavioral-exe simple_switch_grpc \
    --json build/telemetria_trabalho2.json
```

### Instalar regras de encaminhamento e sessão de clone
```bash
simple_switch_CLI --thrift-port 9090 < s1-commands.txt
# Ou via P4Runtime:
python3 /path/to/runtime_CLI.py \
    --p4info build/telemetria_trabalho2.p4.p4info.txt \
    --bmv2-json build/telemetria_trabalho2.json \
    --runtime-json s1-runtime.json
```

### Iniciar o coletor em h3
```bash
# Na CLI do Mininet:
h3 sudo python3 collector.py --iface h3-eth0 --log telemetry.log
```

### Gerar tráfego de teste
```bash
# Ping simples
h1 ping -c 50 10.0.2.2

# Tráfego UDP com iperf
h1 iperf -u -c 10.0.2.2 -t 30 -b 1M &
h2 iperf -u -s &
```

---

## 7. Testes e Resultados

### Saída do coletor (exemplo)
```
────────────────────────────────────────────────────────────
  📡  Relatório de Telemetria  –  Janela #1
  🕐  Timestamp : 2026-05-04 14:32:01
────────────────────────────────────────────────────────────
  📦  Pacotes na janela      : 10
  📊  Bytes na janela        : 980
  🔺  Tamanho médio (bytes)  : 98.0
  ⏱️  TTL mínimo observado   : 63
  🌐  Protocolo dominante    : ICMP (1)
────────────────────────────────────────────────────────────

────────────────────────────────────────────────────────────
  📡  Relatório de Telemetria  –  Janela #2
  🕐  Timestamp : 2026-05-04 14:32:03
────────────────────────────────────────────────────────────
  📦  Pacotes na janela      : 10
  📊  Bytes na janela        : 14820
  🔺  Tamanho médio (bytes)  : 1482.0
  ⏱️  TTL mínimo observado   : 63
  🌐  Protocolo dominante    : UDP (17)
────────────────────────────────────────────────────────────
```

### Análise
- **Janela 1** (ping): pacotes pequenos (~98 B), protocolo ICMP dominante.  
- **Janela 2** (iperf UDP): pacotes grandes (~1482 B), protocolo UDP dominante e byte count ~15x maior.  
- A mudança no tráfego é imediatamente refletida nas métricas exportadas, validando o funcionamento do mecanismo de telemetria.
- O encaminhamento entre h1 e h2 não é afetado pela clonagem; o coletor recebe apenas os pacotes de relatório.

---

## 8. Conclusão

A solução implementada demonstra um mecanismo funcional de telemetria no plano de dados usando P4 e BMv2. A abordagem por clonagem de pacotes é simples, não intrusiva para o tráfego original, e extensível: novas métricas podem ser adicionadas ao cabeçalho de telemetria com mínimas modificações. As quatro métricas exportadas (contagem de pacotes, bytes, TTL mínimo e protocolo dominante) fornecem uma visão representativa do comportamento do tráfego a cada janela de observação.
