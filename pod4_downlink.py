from api import handle_pkt,sniff , sleep ,change_ip , sendp


print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'eth0'


print('\n')
print("sniffing on %s" % iface)


pkts = sniff(count=1,filter="tcp and port  1112" , prn = lambda x: handle_pkt(x))


print('\n')
print('----------- sleep for 5 sec ------------')
print('\n')

sleep(5)

pkt = pkts[0]

pkt1 = change_ip(pkt, pkt[IP].src  ,'10.244.1.26')

pkt1[TCP].dport = 1113

pkt1.show()

sendp(pkt,iface=iface,verbose=True)

while (True):
    sleep(5)