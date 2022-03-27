from api import handle_pkt,sniff , sleep , get_pkt ,decapsulate


print('\n')
print('----------- receive pkt with scapy ------------')
print('\n')
iface = 'eth0'


print('\n')
print("sniffing on %s" % iface)


pkt = get_pkt(dst='172.17.0.4')


print('\n')
print('----------- sleep for 5 sec ------------')
print('\n')

sleep(5)




decapsulate(pkt,iface,'172.17.0.5')

while (True):
    sleep(5)