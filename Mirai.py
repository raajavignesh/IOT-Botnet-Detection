from scapy.all import *

packets = rdpcap("pcap/MiraiTraffic.pcap")


flag = False
destports = set()
srcports = set()
srcip = set()
destip = set()

ip = set()

for packet in packets:
    print(packet.show())
    if(packet.haslayer(IP)):
        srcip.add("IPv4 -- "+packet[IP].src)
        destip.add("IPv4 -- "+packet[IP].dst)

        if(packet.haslayer(TCP)):
            x = "TCP -- " + packet[IP].src + " : " + str(packet[TCP].sport) + \
                "  -->  " + packet[IP].dst + " : " + str(packet[TCP].dport)
            ip.add(x)
            srcports.add("TCP -- " + str(packet[TCP].sport))
            destports.add("TCP -- " + str(packet[TCP].dport))
    if(packet.haslayer(IPv6)):
        srcip.add("IPv6 -- "+packet[IPv6].src)
        destip.add("IPv6 -- "+packet[IPv6].dst)
        if(packet.haslayer(UDP)):
            x = "UDP -- "+packet[IPv6].src + " : " + str(packet[UDP].sport) + \
                "  -->  " + packet[IPv6].dst + " : " + str(packet[UDP].dport)
            ip.add(x)
            srcports.add("UDP -- " + str(packet[UDP].sport))
            destports.add("UDP -- " + str(packet[UDP].dport))

    # if(packet.haslayer(Raw)):
    #     print(hexdump(packet))

print("\n\nSource IP Address")
print("------------------")
print('\n'.join(map(str, srcip)))
print()
print("Destination IP Address")
print("-----------------------")
print('\n'.join(map(str, destip)))
print("\n")


print("Source Ports")
print("-------------")
print('\n'.join(map(str, srcports)))
print()
print("Destination Ports")
print("------------------")
print('\n'.join(map(str, destports)))
print()

print("Packet Requests and Responses")
print("------------------------------")
print(packets, "\n")
print('\n'.join(map(str, ip)))

for src in srcports:
    if(int(src[7:]) == 23 or int(src[7:]) == 2323):
        flag = True
        break
    else:
        flag = False
if(flag):
    print("\n\nMirai Botnet trying to connect to Telnet")
else:
    print("\n\nNo Botnet detected")
