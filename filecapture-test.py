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
capture = pyshark.FileCapture(input_file="/Users/ckharbanda/Desktop/227/project/pcap-files/firefox/cbonat1.pcap")

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

filename = "example-del.pcap"
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
        writeByteStringToFile(out, packet.quic.__dict__["_all_fields"])
        if i == 0 or i == 1:
            print(i, "###############", packet.quic.__dict__["_all_fields"])
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




