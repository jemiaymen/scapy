from api import encapsulate, handle_pkt, sniff,sleep,TCP,get_pkt




print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'eth0'


print('\n')
print("sniffing on %s" % iface)

pkt = get_pkt(dport=1234 , dst = '172.17.0.3')


print('\n')
print('----------- encapsulate pkt ------------')
print('\n')


encapsulate(pkt,iface=iface,dst='172.17.0.4')

while(True):
    sleep(15)


