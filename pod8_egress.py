from api import handle_pkt,sys, sniff , sleep ,send,decapsulate


print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'wlp0s20f3'


print('\n')
print("sniffing on %s" % iface)


pkts = sniff(count=1,filter="tcp and port 1234" , prn = lambda x: handle_pkt(x))


print('\n')
print('----------- sleep for 5 sec ------------')
print('\n')

sleep(5)

pkt = pkts[0]

pkt = decapsulate(pkt)

# send to pod 9 qos
send(iface=iface,dst='10.10.10.10',msg ="next message",dport=1234,show_pkt=True)