# importing the pyshark module
import socket
from struct import pack
import pyshark
import json

# capture on the first wifi interface
iface_name = 'en0'
# targeting all HTTPS traffic on port 443
filter_string = 'port 443'

# building our live capture instance
capture = pyshark.FileCapture(input_file="/Users/ckharbanda/Desktop/227/project/pcap-files/firefox/gumtree-1.pcap")

# for capturing the traffic
# timeout of 5 seconds and a limit of 10 packets total
# capture.sniff(timeout=5, packet_count=10)
def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def writeByteStringToFile(out, data):
    out.write(json.dumps(data))
    out.write("\n")

def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.
    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time
    return f'Packet Timestamp: {packet_time}' \
           f'\nProtocol type: {protocol}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}\n'

filename = "example-del.json"
out = open(filename, 'w')
i = 1
j = 1
l = 0
max_l = 0
max_l_fields = ""
min_l_fields = ""
min_l = 10000
max_pos = 0
min_pos = 0
for packet in capture:
    if(packet.__contains__("quic")):
        if i == 0 or i == 1:
            writeByteStringToFile(out, packet.quic.__dict__["_all_fields"])
            # print(i, "###############", packet.quic.__dict__["_all_fields"])
            # print("1: ", packet.transport_layer)
            # print("2: ", packet.ip)                      
            # print("3: ",packet[packet.transport_layer].dstport)
            print("Packet details :\n", get_packet_details(packet))
            print("All_fields : \n", packet.quic.__dict__["_all_fields"].keys())

        l = len(packet.quic.__dict__["_all_fields"])
        if max_l < l:
            max_l = l
            max_l_fields = packet.quic.__dict__["_all_fields"]
            max_pos = i
        if min_l > l:
            min_l = l
            min_l_fields = packet.quic.__dict__["_all_fields"]
            min_pos = i
        i+=1
    j+=1

# print("i = ", i, " j = ", j, " l = ", l)
# print("max_l = ", max_l, " min_l = ", min_l)
# print("max_pos = ", max_pos, " min_pos = ", min_pos)
# print("max_l_fields = ", max_l_fields.keys(), " min_l_fields = ", min_l_fields.keys())




