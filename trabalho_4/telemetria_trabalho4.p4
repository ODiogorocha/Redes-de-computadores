#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<9>  egressSpec_t;

struct metadata { }
header ethernet_t { bit<48> dstAddr; bit<48> srcAddr; bit<16> etherType; }
header ipv4_t { bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen; bit<16> identification; bit<3> flags; bit<13> fragOffset; bit<8> ttl; bit<8> protocol; bit<16> hdrChecksum; bit<32> srcAddr; bit<32> dstAddr; }
struct headers { ethernet_t ethernet; ipv4_t ipv4; }

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { 0x0800: parse_ipv4; default: accept; }
    }
    state parse_ipv4 { packet.extract(hdr.ipv4); transition accept; }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action drop() { mark_to_drop(standard_metadata); }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table bloqueio_ip {
        key = { hdr.ipv4.srcAddr: exact; }
        actions = { drop; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (bloqueio_ip.apply().hit) {
            } else {
                ipv4_lpm.apply();
                
                if (standard_metadata.egress_spec != 3) {
                    clone_preserving_field_list(CloneType.I2E, 333, 8w0);
                }
            }
        }
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { apply { } }
control MyDeparser(packet_out packet, in headers hdr) { apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); } }

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(), MyComputeChecksum(), MyDeparser()) main;