/* ============================================================
 * telemetria_trabalho2.p4
 * Telemetria via clonagem de pacotes (Clone-to-Collector)
 * Métricas: pacotes/janela, bytes/janela, TTL mínimo, protocolo dominante
 * Janela : a cada WINDOW_SIZE=10 pacotes IPv4 observados
 *
 * API moderna: clone_preserving_field_list  (p4c >= 1.2.4)
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

/* ---- Constantes ------------------------------------------- */
#define WINDOW_SIZE   10
#define CLONE_SESSION 99

/* field_list id usado em clone_preserving_field_list          */
#define FL_TELEM      1

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

/* Cabeçalho de telemetria emitido apenas nos clones           */
header telemetry_t {
    bit<32> pkt_count;       /* pacotes na janela              */
    bit<32> byte_count;      /* bytes na janela                */
    bit<8>  min_ttl;         /* TTL mínimo observado           */
    bit<8>  dominant_proto;  /* protocolo mais frequente       */
    bit<16> reserved;        /* alinhamento                    */
}

/* ---- Metadata -------------------------------------------- */
struct metadata_t {
    /* campos preservados pelo clone */
    @field_list(FL_TELEM)
    bit<32> telem_pkt_count;
    @field_list(FL_TELEM)
    bit<32> telem_byte_count;
    @field_list(FL_TELEM)
    bit<8>  telem_min_ttl;
    @field_list(FL_TELEM)
    bit<8>  telem_dominant_proto;
}

struct headers_t {
    ethernet_t  ethernet;
    telemetry_t telemetry;
    ipv4_t      ipv4;
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

    /* Registradores da janela */
    register<bit<32>>(1)   reg_pkt_count;
    register<bit<32>>(1)   reg_byte_count;
    register<bit<8>>(1)    reg_min_ttl;
    register<bit<32>>(256) reg_proto_count;  /* índice = número de protocolo */

    /* ---- Actions ---- */
    action drop() {
        mark_to_drop(std_meta);
    }

    action ipv4_forward(bit<48> dstMac, bit<9> port) {
        std_meta.egress_spec  = port;
        hdr.ethernet.srcAddr  = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr  = dstMac;
        hdr.ipv4.ttl          = hdr.ipv4.ttl - 1;
    }

    /* ---- Tabela L3 ---- */
    table ipv4_lpm {
        key            = { hdr.ipv4.dstAddr : lpm; }
        actions        = { ipv4_forward; drop; }
        default_action = drop();
        size           = 1024;
    }

    /* ---- Apply ---- */
    apply {
        if (!hdr.ipv4.isValid()) {
            drop();
            return;
        }

        /* Encaminhamento */
        ipv4_lpm.apply();

        /* ── Telemetria ── */
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

        /* TTL mínimo */
        if (cnt == 1 || hdr.ipv4.ttl < cur_min_ttl) {
            cur_min_ttl = hdr.ipv4.ttl;
        }

        /* Contador por protocolo */
        reg_proto_count.read (proto_cnt, (bit<32>)hdr.ipv4.protocol);
        proto_cnt = proto_cnt + 1;
        reg_proto_count.write((bit<32>)hdr.ipv4.protocol, proto_cnt);

        reg_pkt_count.write (0, cnt);
        reg_byte_count.write(0, bytes);
        reg_min_ttl.write   (0, cur_min_ttl);

        /* ── Fim da janela? ── */
        if (cnt == WINDOW_SIZE) {

            /* Protocolo dominante entre TCP(6), UDP(17), ICMP(1) */
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

            /* Preenche metadata que será preservado no clone */
            meta.telem_pkt_count      = cnt;
            meta.telem_byte_count     = bytes;
            meta.telem_min_ttl        = cur_min_ttl;
            meta.telem_dominant_proto = dom;

            /* Clona para a sessão 99 (porta de h3), preservando FL_TELEM */
            clone_preserving_field_list(CloneType.I2E,
                                        (bit<32>)CLONE_SESSION,
                                        FL_TELEM);

            /* Zera registradores para a próxima janela */
            reg_pkt_count.write (0, 0);
            reg_byte_count.write(0, 0);
            reg_min_ttl.write   (0, 0);
            reg_proto_count.write(6,  0);
            reg_proto_count.write(17, 0);
            reg_proto_count.write(1,  0);
        }
    }
}

/* ---- Egress ---------------------------------------------- */
control MyEgress(inout headers_t    hdr,
                 inout metadata_t   meta,
                 inout standard_metadata_t std_meta) {
    apply {
        /* instance_type == 1  →  PKT_INSTANCE_TYPE_INGRESS_CLONE */
        if (std_meta.instance_type == 1) {

            /* Insere cabeçalho de telemetria após Ethernet */
            hdr.telemetry.setValid();
            hdr.telemetry.pkt_count      = meta.telem_pkt_count;
            hdr.telemetry.byte_count     = meta.telem_byte_count;
            hdr.telemetry.min_ttl        = meta.telem_min_ttl;
            hdr.telemetry.dominant_proto = meta.telem_dominant_proto;
            hdr.telemetry.reserved       = 0;

            /* EtherType especial para o coletor identificar */
            hdr.ethernet.etherType = 0x9999;
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
        pkt.emit(hdr.telemetry);  /* emitido só se setValid() foi chamado */
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