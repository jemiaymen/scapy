from api import encapsulate, handle_pkt, sniff,sendp ,sleep




while (True):
    print('\n')
    print('----------- receive pkt with scapy ------------')
    print('\n')
    iface = 'eth0'


    print('\n')
    print("sniffing on %s" % iface)


    pkts = sniff(count=1,filter="tcp and port 1111" , prn = lambda x: handle_pkt(x))


    print('\n')
    print('----------- encapsulate pkt ------------')
    print('\n')

    pkt = pkts[0]

    pkt = encapsulate(pkt,iface=iface,dst='10.244.1.25')

    pkt.getlayer(2).dport = 1112

    pkt.show()

    sendp(pkt,iface=iface,verbose=True)
    sleep(15)


