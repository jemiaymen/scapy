from api import encapsulate,decapsulate, handle_pkt,sys, sniff,sendp , send


print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'wlp0s20f3'


print('\n')
print("sniffing on %s" % iface)


pkts = sniff(count=1,filter="tcp and port 1234" , prn = lambda x: handle_pkt(x))


print('\n')
print('----------- encapsulate pkt ------------')
print('\n')

pkt = pkts[0]


pkt = encapsulate(pkt,iface=iface,dst='127.0.0.2')


pkt.show()


pkt1 = decapsulate(pkt)

pkt1.show()


# send to pod 3 or pod 4

# send(iface=iface,dst='10.10.10.12',msg ="next message",dport=1333,show_pkt=True)

sendp(pkt,iface=iface,verbose=True)


