from api import handle_pkt, sniff 


print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'wlp0s20f3'


print('\n')
print("sniffing on %s" % iface)


sniff(count=1,filter="tcp and port 1234" , prn = lambda x: handle_pkt(x))

