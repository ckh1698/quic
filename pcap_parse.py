# importing the pyshark module
import socket
from struct import pack
import pyshark
import json

def proto_name_by_num(proto_num):
    for name,num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"

def writeByteStringToFile(out, data):
    out.write(json.dumps(data))
    out.write("\n")


def capture_pcap(input_file):
    res = ""
    # print("Input file = ", input_file)
    capture = pyshark.FileCapture(input_file)
    i = 0
    filename = "file.json"
    out = open(filename, 'w')
    # CAPTURING THE TRANSPORT PARAMETERS PRESENT IN THE FIRST QUIC PACKET
    for packet in capture:
        print(packet.ip.src)
        print(packet.ip.dst)
        if(packet.__contains__("quic") and (packet.ip.src == '34.120.45.191' or packet.ip.dst == '34.120.45.191')):
            writeByteStringToFile(out, packet.quic.__dict__["_all_fields"])
            if i == 0:
                res = res + "-" + packet.quic.__dict__["_all_fields"]
                res = res[1:]
                i += 1
            else:
                break
    print("res = ", res)
    capture.close()

path = "/Users/ckharbanda/Desktop/227/project/pcap-files/ff_version/92.0_semrush-1.pcap"
capture_pcap(path)