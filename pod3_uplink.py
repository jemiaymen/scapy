from api import handle_pkt,sniff , sleep ,change_ip , sendp




while (True):
    print('\n')
    print('----------- receive pkt with scapy ------------')
    print('\n')
    iface = 'eth0'


    print('\n')
    print("sniffing on %s" % iface)


    pkts = sniff(count=1,filter="tcp and port 1112" , prn = lambda x: handle_pkt(x))


    print('\n')
    print('----------- sleep for 5 sec ------------')
    print('\n')

    sleep(5)

    pkt = pkts[0]

    pkt1 = change_ip(pkt,'10.244.1.26')
    pkt.getlayer(2).dport = 1113
    pkt1.show()

    sendp(pkt,iface=iface,verbose=True)
    sleep(15)



