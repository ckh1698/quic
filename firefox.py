# importing the pyshark module
import socket
from struct import pack
import pyshark
import json
import glob
import os
import hashlib

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def writeByteStringToFile(out, data):
    out.write(json.dumps(data))
    out.write("\n")

field_dict = {
    "JA3_fields" : ["tls.handshake.ja3_full", "tls.handshake.ja3"],
    "transport_parameters" : ["tls.quic.parameter.initial_max_stream_data_bidi_remote", "tls.quic.parameter.initial_max_stream_data_uni", "tls.quic.parameter.active_connection_id_limit", "tls.quic.parameter.initial_max_streams_uni", "tls.quic.parameter.max_idle_timeout" , "tls.quic.parameter.initial_max_streams_bidi", "tls.quic.parameter.initial_max_data" , "tls.quic.parameter.max_datagram_frame_size", "tls.quic.parameter.max_ack_delay", "tls.quic.parameter.initial_max_stream_data_bidi_local"],
    "quic_data" : ["quic.header_form", "quic.fixed_bit", "quic.packet_number_length", "quic.version", "quic.frame_type", "quic.crypto.offset"],
    "ext_field_1": ["tls.handshake.extension.type", "tls.handshake.extensions_reneg_info_len", "tls.handshake.extensions_supported_groups", "tls.handshake.extensions_supported_group"],
    "ext_field_2": ["tls.handshake.extensions_alpn_list", "tls.handshake.extensions_alpn_str", "tls.handshake.extensions_status_request_type", "tls.handshake.extensions_status_request_exts_len", "tls.handshake.sig_hash_algs", "tls.handshake.sig_hash_alg", "tls.handshake.sig_hash_hash", "tls.handshake.sig_hash_sig", "tls.handshake.extensions_key_share_group", "tls.handshake.extensions.supported_versions_len", "tls.handshake.extensions.supported_version", "tls.extension.psk_ke_mode", "tls.record_size_limit"],
    "remaining_field": ["tls.handshake.type", "tls.handshake.version", "tls.handshake.cipher_suites_length", "tls.handshake.ciphersuites", "tls.handshake.ciphersuite", "tls.handshake.comp_methods_length", "tls.handshake.comp_methods", "tls.handshake.comp_method"],
}

fields = field_dict["transport_parameters"]

def capture_pcap(input_file):
    res = ""
    # print("Input file = ", input_file)
    capture = pyshark.FileCapture(input_file)
    i = 0
    filename = "firefox.json"
    out = open(filename, 'w')
    # CAPTURING THE TRANSPORT PARAMETERS PRESENT IN THE FIRST QUIC PACKET
    for packet in capture:
        # filtering out semrush packets (34.120.45.191) and those are quic
        # ip for digitallife (machines) - 35.227.210.81
        # if(packet.__contains__("quic") and (packet.ip.src == '35.227.210.81' or packet.ip.dst == '35.227.210.81')):
        if(packet.__contains__("quic") and (packet.ip.src == '34.120.45.191' or packet.ip.dst == '34.120.45.191')):
            writeByteStringToFile(out, packet.quic.__dict__["_all_fields"])
            if i == 0:
                for field in fields:
                    if field != "tls.handshake.ciphersuite":
                        # print(i, "###############", packet.quic.__dict__["_all_fields"][field])
                        if(field in packet.quic.__dict__["_all_fields"]):
                            res = res + "-" + packet.quic.__dict__["_all_fields"][field]
                        else:
                            res = res + "-0"
                    else:
                        cipherSuites = packet.quic.get_field('tls_handshake_ciphersuite').all_fields
                        # print(cipherSuites)
                        for cipher in cipherSuites:
                            res = res + "-" + str(cipher)
                res = res[1:]
                i += 1
            else:
                break
    # print("res = ", res)
    hash = hashlib.md5(res.encode('utf-8')).hexdigest()
    print(hash)
    capture.close()


path = "/Users/ckharbanda/Desktop/227/project/github/pcap-files/ff_version/"
# print(path)
# path = "/Users/ckharbanda/Desktop/227/project/github/pcap-files/machines/"
for files in glob.glob(os.path.join(path, '*.pcap')):
    # print(files)
    capture_pcap(files)