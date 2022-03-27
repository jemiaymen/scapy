from api import handle_pkt, sniff 


print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'eth0'


print('\n')
print("sniffing on %s" % iface)


sniff(filter="tcp and port 1117" , prn = lambda x: handle_pkt(x))


