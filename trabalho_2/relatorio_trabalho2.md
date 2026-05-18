# Relatório – Trabalho 2: Telemetria em Switches P4

**Disciplina:** Redes de Computadores Avançadas  
**Universidade:** UFSM – Departamento de Computação Aplicada  

---

## 1. Abordagem Escolhida

A solução implementa **clonagem de pacotes para um controlador/coletor** (*Clone-to-Collector*). A cada janela de **N = 10 pacotes IPv4** processados no ingress do switch, o plano de dados:

1. Coleta as métricas nos registradores;
2. Preenche campos de metadata anotados com `@field_list`;
3. Chama `clone_preserving_field_list(CloneType.I2E, 99, 1)` para gerar uma cópia do pacote direcionada ao host h3;
4. No egress, o clone recebe um cabeçalho de telemetria customizado (EtherType `0x9999`) e é enviado a h3;
5. O pacote original segue normalmente para seu destino.

Essa abordagem foi escolhida por ser nativa ao modelo v1model do BMv2, não requerer modificações nos hosts finais e produzir os dados de telemetria inteiramente no plano de dados P4.

---

## 2. Topologia

```
h1 (10.0.1.1/24) ── porta 1 ──┐
                               s1 (BMv2 simple_switch) ── porta 3 ── h3 (10.0.3.3/24)
h2 (10.0.2.2/24) ── porta 2 ──┘
                                             ↑ coletor/dashboard
```

| Nó | Endereço IP  | MAC               | Função               |
|----|--------------|-------------------|----------------------|
| h1 | 10.0.1.1/24 | 00:00:00:00:01:01 | Gerador de tráfego   |
| h2 | 10.0.2.2/24 | 00:00:00:00:02:02 | Receptor de tráfego  |
| s1 | —           | —                 | Switch P4 (BMv2)     |
| h3 | 10.0.3.3/24 | 00:00:00:00:03:03 | Coletor de telemetria|

A topologia é instanciada por `topo_trabalho2.py`, que cria os nós no Mininet, inicia o `simple_switch` com o JSON compilado e instala automaticamente as regras via `simple_switch_CLI`.

---

## 3. Modificações no Programa P4

### 3.1 Cabeçalho de telemetria (`telemetry_t`)

Inserido após o cabeçalho Ethernet nos pacotes clonados:

| Campo            | Bits | Descrição                             |
|------------------|------|---------------------------------------|
| `pkt_count`      |  32  | Pacotes observados na janela          |
| `byte_count`     |  32  | Bytes observados na janela            |
| `min_ttl`        |   8  | TTL mínimo visto na janela            |
| `dominant_proto` |   8  | Protocolo com mais pacotes (1/6/17)   |
| `reserved`       |  16  | Alinhamento / uso futuro              |

### 3.2 Metadata com `@field_list`

Os campos de telemetria no metadata são anotados com `@field_list(1)`, garantindo que sejam preservados pelo mecanismo de clonagem do v1model:

```p4
struct metadata_t {
    @field_list(FL_TELEM)  bit<32> telem_pkt_count;
    @field_list(FL_TELEM)  bit<32> telem_byte_count;
    @field_list(FL_TELEM)  bit<8>  telem_min_ttl;
    @field_list(FL_TELEM)  bit<8>  telem_dominant_proto;
}
```

### 3.3 Registradores (Ingress)

| Registrador       | Tamanho   | Uso                                      |
|-------------------|-----------|------------------------------------------|
| `reg_pkt_count`   | 1 × 32b   | Contador de pacotes da janela atual      |
| `reg_byte_count`  | 1 × 32b   | Acumulador de bytes da janela atual      |
| `reg_min_ttl`     | 1 × 8b    | Menor TTL observado                      |
| `reg_proto_count` | 256 × 32b | Contador por número de protocolo IP      |

### 3.4 Lógica da janela

A cada pacote IPv4 válido, os registradores são atualizados. Quando `pkt_count == WINDOW_SIZE (10)`:

1. Os contadores de TCP (6), UDP (17) e ICMP (1) são lidos para determinar o protocolo dominante;
2. O metadata é preenchido com os valores coletados;
3. `clone_preserving_field_list` é chamado gerando o clone para a sessão 99;
4. Todos os registradores são zerados para a próxima janela.

### 3.5 Egress – construção do pacote de telemetria

```p4
if (std_meta.instance_type == 1) {   // clone de ingress
    hdr.telemetry.setValid();
    hdr.telemetry.pkt_count      = meta.telem_pkt_count;
    hdr.telemetry.byte_count     = meta.telem_byte_count;
    hdr.telemetry.min_ttl        = meta.telem_min_ttl;
    hdr.telemetry.dominant_proto = meta.telem_dominant_proto;
    hdr.ethernet.etherType       = 0x9999;
}
```

---

## 4. Métricas Exportadas

### Métricas obrigatórias

| Métrica        | Campo P4      | Descrição                        |
|----------------|---------------|----------------------------------|
| Pacotes/janela | `pkt_count`   | Número de pacotes na janela      |
| Bytes/janela   | `byte_count`  | Volume de dados na janela        |

### Métricas adicionais

**Métrica 3 – TTL mínimo (`min_ttl`)**  
O TTL é decrementado a cada salto de roteamento. Valores muito baixos indicam que os pacotes percorreram muitos hops antes de chegar ao switch — útil para detectar loops de roteamento, ataques de TTL-expiry e caracterizar a topologia entre a origem e o ponto de medição. O switch registra o menor TTL visto em toda a janela, capturando o caso mais crítico.

**Métrica 4 – Protocolo dominante (`dominant_proto`)**  
Identifica qual protocolo de camada 4 (TCP/UDP/ICMP) teve o maior número de pacotes na janela. Exporta o número de protocolo IP (1 = ICMP, 6 = TCP, 17 = UDP), decodificado pelo coletor. Essa métrica é valiosa para: caracterização de tráfego, priorização/QoS, e detecção de anomalias como floods ICMP ou UDP. Mudanças de tráfego (ex.: de ping para iperf) são imediatamente refletidas nessa métrica.

---

## 5. Janela de Observação

A janela é definida por **número de pacotes**: a cada **N = 10** pacotes IPv4 observados no ingress, um relatório é exportado. Justificativas:

- É determinística e independente de clock (BMv2 não oferece timer de alta resolução nativo);
- Permite observar rapidamente a variação do tráfego em demonstrações;
- O valor N pode ser ajustado alterando a constante `WINDOW_SIZE` no `.p4`.

---

## 6. Comandos para Compilar e Executar

### Compilar

```bash
mkdir -p build
p4c --target bmv2 --arch v1model \
    --p4runtime-files build/telemetria_trabalho2.p4.p4info.txt \
    -o build/ telemetria_trabalho2.p4
```

### Iniciar a topologia

```bash
sudo python3 topo_trabalho2.py
```

### Iniciar o dashboard em h3 (na CLI do Mininet)

```
mininet> xterm h3
# no xterm de h3:
sudo python3 dashboard.py --iface h3-eth0
```

Ou usando o coletor texto:

```
mininet> h3 sudo python3 collector.py --iface h3-eth0 &
```

### Gerar tráfego

```
mininet> h1 ping -c 50 10.0.2.2
mininet> h2 iperf -u -s &
mininet> h1 iperf -u -c 10.0.2.2 -t 30 -b 1M
mininet> h2 iperf -s &
mininet> h1 iperf -c 10.0.2.2 -t 30
```

---

## 7. Logs e Resultados

### Saída do coletor (modo texto)

```
──────────────────────────────────────────────────────
  Janela #0001   [2026-05-04 14:32:01]
──────────────────────────────────────────────────────
  Pacotes na janela      : 10
  Bytes na janela        : 980
  Tamanho medio (bytes)  : 98.0
  TTL minimo observado   : 63
  Protocolo dominante    : ICMP (1)
──────────────────────────────────────────────────────

──────────────────────────────────────────────────────
  Janela #0002   [2026-05-04 14:32:05]
──────────────────────────────────────────────────────
  Pacotes na janela      : 10
  Bytes na janela        : 14820
  Tamanho medio (bytes)  : 1482.0
  TTL minimo observado   : 63
  Protocolo dominante    : UDP (17)
──────────────────────────────────────────────────────
```

### Verificação do clone com tcpdump

```bash
h3 tcpdump -i h3-eth0 -n -e ether proto 0x9999
# Deve exibir 1 pacote a cada 10 pkts h1→h2
```

---

## 8. Análise dos Resultados

- **Janela 1 (ping ICMP):** pacotes pequenos (~98 B), protocolo dominante ICMP, TTL = 63 (1 hop).
- **Janela 2 (iperf UDP):** pacotes grandes (~1482 B), protocolo dominante UDP, throughput ~15× maior.
- A mudança do tráfego é imediatamente refletida nas métricas exportadas, validando o mecanismo.
- O encaminhamento entre h1 e h2 não é afetado; h3 recebe apenas os clones de telemetria.
- O dashboard Tkinter atualiza em tempo real, mostrando sparklines do histórico e o protocolo dominante com cores distintas para cada protocolo.

---

## 9. Conclusão

A solução demonstra um mecanismo funcional de telemetria no plano de dados usando P4 e BMv2. A abordagem por clonagem é simples, não intrusiva e produz dados exclusivamente no plano de dados P4 — sem depender de `tcpdump` ou estatísticas do Mininet. As quatro métricas exportadas fornecem uma visão representativa do comportamento do tráfego e refletem mudanças em tempo real.