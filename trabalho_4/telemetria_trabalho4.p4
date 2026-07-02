
#include <core.p4>
#include <v1model.p4>

/* =============================================================
   TRABALHO 4 — evolução do TRABALHO 3
   -------------------------------------------------------------
   O que foi REAPROVEITADO do Trabalho 3 (sem alteração de lógica):
     - telemetry_t / janela global (pkt_count, byte_count, min_ttl,
       dominant_proto) e o mecanismo de clonagem para h3.
     - tabela ipv4_lpm de encaminhamento estático.

   O que foi ADICIONADO para o Trabalho 4:
     - Contagem de pacotes/bytes/TTL POR FLUXO (por IP de origem),
       reportada periodicamente ao controlador (flow_alert_t).
     - Tabela `traffic_action`, populada em tempo de execução pelo
       CONTROLADOR (não estaticamente!) com a decisão a aplicar
       sobre um IP de origem específico: marcar (DSCP), redirecionar
       ou descartar.
   ============================================================= */

/* ---- Constantes ------------------------------------------- */
#define WINDOW_SIZE       10      /* janela global (Trabalho 3)      */
#define CLONE_SESSION     99      /* sessão de clone -> porta de h3  */
#define FLOW_ALERT_MASK   7       /* reporta fluxo a cada 8 pacotes  */
                                   /* (8 = 2^3, permite usar AND      */
                                   /*  em vez de módulo em P4)        */

/* field_list ids usados em clone_preserving_field_list        */
#define FL_TELEM      1   /* telemetria de janela (Trabalho 3)  */
#define FL_ALERT      2   /* alerta de fluxo (Trabalho 4 - novo)*/

/* razões de clone, carregadas via metadado preservado          */
#define REASON_WINDOW 1
#define REASON_FLOW   2

/* ---- Headers --------------------------------------------- */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

/* Cabeçalho de telemetria de JANELA GLOBAL (igual ao Trabalho 3) */
header telemetry_t {
    bit<32> pkt_count;       /* pacotes na janela              */
    bit<32> byte_count;      /* bytes na janela                */
    bit<8>  min_ttl;         /* TTL mínimo observado           */
    bit<8>  dominant_proto;  /* protocolo mais frequente       */
    bit<16> reserved;        /* alinhamento                    */
}

/* Cabeçalho de ALERTA DE FLUXO (NOVO no Trabalho 4)
   Enviado periodicamente ao controlador com as métricas de UM
   fluxo (identificado pelo IP de origem) para que o controlador
   decida se deve instalar/atualizar/remover uma regra.          */
header flow_alert_t {
    bit<32> srcAddr;         /* fluxo identificado pelo IP origem */
    bit<32> pkt_count;       /* pacotes acumulados do fluxo       */
    bit<32> byte_count;      /* bytes acumulados do fluxo         */
    bit<8>  min_ttl;         /* TTL mínimo do fluxo                */
    bit<8>  reserved;
    bit<16> reserved2;
}

/* ---- Metadata -------------------------------------------- */
struct metadata_t {
    /* campos preservados pelo clone de janela (FL_TELEM) */
    @field_list(FL_TELEM)
    bit<32> telem_pkt_count;
    @field_list(FL_TELEM)
    bit<32> telem_byte_count;
    @field_list(FL_TELEM)
    bit<8>  telem_min_ttl;
    @field_list(FL_TELEM)
    bit<8>  telem_dominant_proto;

    /* campos preservados pelo clone de fluxo (FL_ALERT) */
    @field_list(FL_ALERT)
    bit<32> flow_srcAddr;
    @field_list(FL_ALERT)
    bit<32> flow_pkt_count;
    @field_list(FL_ALERT)
    bit<32> flow_byte_count;
    @field_list(FL_ALERT)
    bit<8>  flow_min_ttl;

    /* indica, na cópia clonada, qual telemetria deve ser emitida
       (precisa estar presente nos DOIS field lists, pois o clone
       pode ocorrer por qualquer um dos dois motivos)               */
    @field_list(FL_TELEM, FL_ALERT)
    bit<8>  clone_reason;
}

struct headers_t {
    ethernet_t   ethernet;
    telemetry_t  telemetry;
    flow_alert_t flow_alert;
    ipv4_t       ipv4;
}

/* ---- Parser ---------------------------------------------- */
parser MyParser(packet_in        pkt,
                out headers_t    hdr,
                inout metadata_t meta,
                inout standard_metadata_t std_meta) {

    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800  : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

/* ---- Checksum Verify ------------------------------------- */
control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/* ---- Ingress --------------------------------------------- */
control MyIngress(inout headers_t    hdr,
                  inout metadata_t   meta,
                  inout standard_metadata_t std_meta) {

    /* ===== Registradores da janela GLOBAL (Trabalho 3) ===== */
    register<bit<32>>(1)   reg_pkt_count;
    register<bit<32>>(1)   reg_byte_count;
    register<bit<8>>(1)    reg_min_ttl;
    register<bit<32>>(256) reg_proto_count;  /* índice = número do protocolo */

    /* ===== Registradores POR FLUXO (Trabalho 4 - NOVO) =====
       Indexados pelo último octeto do IP de origem. Como a
       topologia usa poucos hosts (h1, h2, h3...), isso identifica
       cada fluxo de forma direta e simples de explicar. */
    register<bit<32>>(256) reg_flow_pkt;
    register<bit<32>>(256) reg_flow_byte;
    register<bit<8>>(256)  reg_flow_ttl;

    /* ---- Actions de encaminhamento (Trabalho 3, reaproveitado) ---- */
    action drop() {
        mark_to_drop(std_meta);
    }

    action ipv4_forward(bit<48> dstMac, bit<9> port) {
        std_meta.egress_spec  = port;
        hdr.ethernet.srcAddr  = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr  = dstMac;
        hdr.ipv4.ttl          = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key            = { hdr.ipv4.dstAddr : lpm; }
        actions        = { ipv4_forward; drop; }
        default_action = drop();
        size           = 1024;
    }

    /* ================================================================
       Tabela de DECISÃO/AÇÃO (Trabalho 4 - NOVO)
       -----------------------------------------------------------------
       Esta tabela começa VAZIA. Ela só é preenchida em tempo de
       execução pelo CONTROLADOR, a partir da política implementada
       em software (controller.py), com base nas métricas recebidas
       via flow_alert_t. Não existem regras estáticas aqui.
       ================================================================ */
    action no_action() { }

    action mark_flow(bit<8> dscp) {
        /* Marca o tráfego (ex.: sinaliza fluxo sob monitoramento/
           QoS reduzido) alterando o campo DiffServ do IPv4.        */
        hdr.ipv4.diffserv = dscp;
    }

    action drop_flow() {
        /* Descarta o fluxo identificado como acima do limiar.      */
        mark_to_drop(std_meta);
    }

    action redirect_flow(bit<9> port) {
        /* Redireciona o fluxo para outra porta/caminho.            */
        std_meta.egress_spec = port;
    }

    table traffic_action {
        key            = { hdr.ipv4.srcAddr : exact; }
        actions        = { no_action; mark_flow; drop_flow; redirect_flow; }
        default_action = no_action();
        size           = 256;
    }

    /* ---- Apply ---- */
    apply {
        if (!hdr.ipv4.isValid()) {
            drop();
            return;
        }

        /* 1) Encaminhamento (Trabalho 3) */
        ipv4_lpm.apply();

        bool ja_clonado = false;

        /* ===== 2) Telemetria de JANELA GLOBAL (Trabalho 3, intacta) ===== */
        bit<32> cnt;
        bit<32> bytes;
        bit<8>  cur_min_ttl;
        bit<32> proto_cnt;
        bit<32> tcp_cnt;
        bit<32> udp_cnt;
        bit<32> icmp_cnt;

        reg_pkt_count.read (cnt,         0);
        reg_byte_count.read(bytes,        0);
        reg_min_ttl.read   (cur_min_ttl,  0);

        cnt   = cnt + 1;
        bytes = bytes + (bit<32>)std_meta.packet_length;

        if (cnt == 1 || hdr.ipv4.ttl < cur_min_ttl) {
            cur_min_ttl = hdr.ipv4.ttl;
        }

        reg_proto_count.read (proto_cnt, (bit<32>)hdr.ipv4.protocol);
        proto_cnt = proto_cnt + 1;
        reg_proto_count.write((bit<32>)hdr.ipv4.protocol, proto_cnt);

        reg_pkt_count.write (0, cnt);
        reg_byte_count.write(0, bytes);
        reg_min_ttl.write   (0, cur_min_ttl);

        if (cnt == WINDOW_SIZE) {
            reg_proto_count.read(tcp_cnt,  6);
            reg_proto_count.read(udp_cnt,  17);
            reg_proto_count.read(icmp_cnt, 1);

            bit<8> dom;
            if (tcp_cnt >= udp_cnt && tcp_cnt >= icmp_cnt) {
                dom = 6;
            } else if (udp_cnt >= tcp_cnt && udp_cnt >= icmp_cnt) {
                dom = 17;
            } else {
                dom = 1;
            }

            meta.telem_pkt_count      = cnt;
            meta.telem_byte_count     = bytes;
            meta.telem_min_ttl        = cur_min_ttl;
            meta.telem_dominant_proto = dom;
            meta.clone_reason         = REASON_WINDOW;

            clone_preserving_field_list(CloneType.I2E,
                                        (bit<32>)CLONE_SESSION,
                                        FL_TELEM);
            ja_clonado = true;

            reg_pkt_count.write (0, 0);
            reg_byte_count.write(0, 0);
            reg_min_ttl.write   (0, 0);
            reg_proto_count.write(6,  0);
            reg_proto_count.write(17, 0);
            reg_proto_count.write(1,  0);
        }

        /* ===== 3) Telemetria POR FLUXO (Trabalho 4 - NOVO) =====
           Base para a DECISÃO do controlador. Reaproveita as mesmas
           métricas do Trabalho 3 (pacotes e bytes) + TTL mínimo,
           agora agregadas por IP de origem em vez de globalmente.   */
        bit<32> fidx = (bit<32>)hdr.ipv4.srcAddr[7:0];
        bit<32> fpkt;
        bit<32> fbytes;
        bit<8>  fttl;

        reg_flow_pkt.read (fpkt,   fidx);
        reg_flow_byte.read(fbytes, fidx);
        reg_flow_ttl.read (fttl,   fidx);

        fpkt   = fpkt + 1;
        fbytes = fbytes + (bit<32>)std_meta.packet_length;
        if (fpkt == 1 || hdr.ipv4.ttl < fttl) {
            fttl = hdr.ipv4.ttl;
        }

        reg_flow_pkt.write (fidx, fpkt);
        reg_flow_byte.write(fidx, fbytes);
        reg_flow_ttl.write (fidx, fttl);

        /* Reporta ao controlador a cada 8 pacotes do MESMO fluxo.
           Evita clonar duas vezes o mesmo pacote (P4/BMv2 não
           garante suporte a clone duplo em um único pacote).       */
        if (!ja_clonado && (fpkt & FLOW_ALERT_MASK) == 0) {
            meta.flow_srcAddr   = hdr.ipv4.srcAddr;
            meta.flow_pkt_count = fpkt;
            meta.flow_byte_count= fbytes;
            meta.flow_min_ttl   = fttl;
            meta.clone_reason   = REASON_FLOW;

            clone_preserving_field_list(CloneType.I2E,
                                        (bit<32>)CLONE_SESSION,
                                        FL_ALERT);
        }

        /* ===== 4) Aplicação da DECISÃO instalada pelo controlador =====
           Esta é a regra que materializa o ciclo de controle:
           telemetria -> decisão (no controlador) -> regra no switch
           -> mudança no tráfego. A tabela é populada via P4Runtime
           pelo controller.py, nunca estaticamente.                  */
        traffic_action.apply();
    }
}

/* ---- Egress ---------------------------------------------- */
control MyEgress(inout headers_t    hdr,
                 inout metadata_t   meta,
                 inout standard_metadata_t std_meta) {
    apply {
        /* instance_type == 1  →  PKT_INSTANCE_TYPE_INGRESS_CLONE */
        if (std_meta.instance_type == 1) {

            if (meta.clone_reason == REASON_WINDOW) {
                /* Telemetria de janela global (Trabalho 3) */
                hdr.telemetry.setValid();
                hdr.telemetry.pkt_count      = meta.telem_pkt_count;
                hdr.telemetry.byte_count     = meta.telem_byte_count;
                hdr.telemetry.min_ttl        = meta.telem_min_ttl;
                hdr.telemetry.dominant_proto = meta.telem_dominant_proto;
                hdr.telemetry.reserved       = 0;
                hdr.ethernet.etherType       = 0x9999;

            } else if (meta.clone_reason == REASON_FLOW) {
                /* Alerta de fluxo (Trabalho 4 - NOVO) */
                hdr.flow_alert.setValid();
                hdr.flow_alert.srcAddr    = meta.flow_srcAddr;
                hdr.flow_alert.pkt_count  = meta.flow_pkt_count;
                hdr.flow_alert.byte_count = meta.flow_byte_count;
                hdr.flow_alert.min_ttl    = meta.flow_min_ttl;
                hdr.flow_alert.reserved   = 0;
                hdr.flow_alert.reserved2  = 0;
                hdr.ethernet.etherType    = 0x9998;
            }
        }
    }
}

/* ---- Checksum Compute ------------------------------------ */
control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/* ---- Deparser -------------------------------------------- */
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.telemetry);    /* emitido só se setValid() (janela)  */
        pkt.emit(hdr.flow_alert);   /* emitido só se setValid() (fluxo)   */
        pkt.emit(hdr.ipv4);
    }
}

/* ---- Instância do switch --------------------------------- */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
