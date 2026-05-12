/* ============================================================
 * telemetria_trabalho2.p4
 * Telemetria via clonagem de pacotes (abordagem: Clone-to-Collector)
 * Coleta: pacotes/janela, bytes/janela, TTL mínimo, protocolo mais frequente
 * Janela: a cada N=10 pacotes observados
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

/* ---- Constantes ------------------------------------------- */
#define WINDOW_SIZE    10
#define CLONE_SESSION  99

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

/* Cabeçalho de telemetria inserido nos pacotes clonados */
header telemetry_t {
    bit<32> pkt_count;      /* pacotes na janela          */
    bit<32> byte_count;     /* bytes na janela             */
    bit<8>  min_ttl;        /* TTL mínimo observado        */
    bit<8>  dominant_proto; /* protocolo mais frequente    */
    bit<16> reserved;
}

struct headers {
    ethernet_t  ethernet;
    telemetry_t telemetry;
    ipv4_t      ipv4;
}

struct metadata {
    bit<1>  is_clone;
    bit<32> pkt_count;
    bit<32> byte_count;
    bit<8>  min_ttl;
    bit<8>  dominant_proto;
}

/* ---- Parser ---------------------------------------------- */
parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t std_meta) {

    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
}

/* ---- Checksum Verification -------------------------------- */
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/* ---- Ingress --------------------------------------------- */
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t std_meta) {

    /* Registradores da janela de observação */
    register<bit<32>>(1) reg_pkt_count;
    register<bit<32>>(1) reg_byte_count;
    register<bit<8>> (1) reg_min_ttl;

    /* Contadores por protocolo (índice = número do protocolo)  */
    /* Usamos os 3 principais: TCP=6, UDP=17, ICMP=1            */
    register<bit<32>>(256) reg_proto_count;

    /* Tabela de encaminhamento L3 */
    action drop() {
        mark_to_drop(std_meta);
    }

    action ipv4_forward(bit<48> dstMac, bit<9> port) {
        std_meta.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv4.ttl         = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key   = { hdr.ipv4.dstAddr : lpm; }
        actions       = { ipv4_forward; drop; }
        default_action = drop();
        size           = 1024;
    }

    apply {
        /* Só processa IPv4 */
        if (!hdr.ipv4.isValid()) {
            drop();
            return;
        }

        /* --- Encaminhamento --- */
        ipv4_lpm.apply();

        /* --- Telemetria --- */
        bit<32> cnt;
        bit<32> bytes;
        bit<8>  min_ttl;
        bit<32> proto_cnt;
        bit<32> tcp_cnt;
        bit<32> udp_cnt;
        bit<32> icmp_cnt;

        reg_pkt_count.read(cnt,   0);
        reg_byte_count.read(bytes, 0);
        reg_min_ttl.read(min_ttl,  0);

        cnt   = cnt + 1;
        bytes = bytes + (bit<32>)std_meta.packet_length;

        /* Atualiza TTL mínimo */
        if (cnt == 1 || hdr.ipv4.ttl < min_ttl) {
            min_ttl = hdr.ipv4.ttl;
        }

        /* Atualiza contador do protocolo */
        reg_proto_count.read(proto_cnt, (bit<32>)hdr.ipv4.protocol);
        proto_cnt = proto_cnt + 1;
        reg_proto_count.write((bit<32>)hdr.ipv4.protocol, proto_cnt);

        reg_pkt_count.write(0, cnt);
        reg_byte_count.write(0, bytes);
        reg_min_ttl.write(0, min_ttl);

        /* --- Fim da janela? --- */
        if (cnt == WINDOW_SIZE) {
            /* Determina protocolo dominante */
            reg_proto_count.read(tcp_cnt,  6);
            reg_proto_count.read(udp_cnt,  17);
            reg_proto_count.read(icmp_cnt, 1);

            bit<8> dom = 0;
            if (tcp_cnt >= udp_cnt && tcp_cnt >= icmp_cnt) {
                dom = 6;
            } else if (udp_cnt >= tcp_cnt && udp_cnt >= icmp_cnt) {
                dom = 17;
            } else {
                dom = 1;
            }

            /* Salva valores no metadata para egress usar */
            meta.pkt_count     = cnt;
            meta.byte_count    = bytes;
            meta.min_ttl       = min_ttl;
            meta.dominant_proto = dom;
            meta.is_clone      = 1;

            /* Clona o pacote para a sessão do coletor */
            clone3(CloneType.I2E, (bit<32>)CLONE_SESSION, meta);

            /* Zera registradores */
            reg_pkt_count.write(0, 0);
            reg_byte_count.write(0, 0);
            reg_min_ttl.write(0, 0);
            reg_proto_count.write(6,  0);
            reg_proto_count.write(17, 0);
            reg_proto_count.write(1,  0);
        }
    }
}

/* ---- Egress --------------------------------------------- */
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {
    apply {
        /* Só modifica pacotes clonados (clone bit setado pelo BMv2) */
        if (std_meta.instance_type == 1) { /* PKT_INSTANCE_TYPE_INGRESS_CLONE */
            /* Insere cabeçalho de telemetria após o Ethernet */
            hdr.telemetry.setValid();
            hdr.telemetry.pkt_count      = meta.pkt_count;
            hdr.telemetry.byte_count     = meta.byte_count;
            hdr.telemetry.min_ttl        = meta.min_ttl;
            hdr.telemetry.dominant_proto = meta.dominant_proto;
            hdr.telemetry.reserved       = 0;

            /* Marca EtherType especial para o coletor identificar */
            hdr.ethernet.etherType = 0x9999;
        }
    }
}

/* ---- Checksum Computation -------------------------------- */
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification,
              hdr.ipv4.flags, hdr.ipv4.fragOffset,
              hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

/* ---- Deparser -------------------------------------------- */
control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.telemetry); /* só emitido se setValid() foi chamado */
        pkt.emit(hdr.ipv4);
    }
}

/* ---- Switch ---------------------------------------------- */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
