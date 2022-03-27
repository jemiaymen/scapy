from api import handle_pkt,sniff , sleep ,change_ip , sendp ,decapsulate


print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'eth0'


print('\n')
print("sniffing on %s" % iface)


pkts = sniff(count=1,filter="tcp and port 1116" , prn = lambda x: handle_pkt(x))


print('\n')
print('----------- sleep for 5 sec ------------')
print('\n')

sleep(5)

pkt = pkts[0]

pkt1 = change_ip(pkt, pkt[IP].src  ,'15.145.21.15')

pkt1.show()

print('\n')
print('----------- decapsulate ------------')
print('\n')

pkt2 = decapsulate(pkt1)

pkt2.show()


print('\n')
print('----------- change ip to pod9 ------------')
print('\n')

pkt2 = change_ip(pkt2,dst='10.244.1.30')

pkt2[TCP].dport = 1117

pkt2.show()

sendp(pkt,iface=iface,verbose=True)


while (True):
    sleep(5)