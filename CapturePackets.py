from scapy.all import *

load_module("p0f")

packets = sniff(prn=lambda x: x.summary(), count=20)

for packet in packets:
    print(packet.show(), "\n\n")

wrpcap("pcap/sample.pcap", packets)
