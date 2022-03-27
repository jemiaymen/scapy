import random
import socket
from time import sleep
import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

def handle_pkt(pkt,debug=True):

    if TCP in pkt :

        if(debug):
            print("I got a Package in port ")
            pkt.show()

            sys.stdout.flush()
        else:

            pkt.show()
            sys.stdout.flush()

def send(iface='eth0',dst='127.0.0.1',msg='Hello World',dport=1234 ,show_pkt=False):
    
    if(iface not in get_if_list()):
        print(' [{0}] inteface not found .'.format(iface))
        print('list of interfaces :',get_if_list())
        return 

    sport = random.randint(49152,65535)
    to = socket.gethostbyname(dst)

    pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff') /IP(dst=to) / TCP(dport=dport , sport=sport ) / msg

    if(show_pkt):
        pkt.show2()
    
    print('Sending [ {0} ] to {1}'.format(msg,dst))

    sendp(pkt,iface=iface,verbose=show_pkt)

def encapsulate(pkt,iface='eth0',dst = '127.0.0.1',dport=1234):
    
    if(iface not in get_if_list()):
        print(' [{0}] inteface not found .'.format(iface))
        print('list of interfaces :',get_if_list())
        return 

    sport = random.randint(49152,65535)
    to = socket.gethostbyname(dst)

    pkt_with_header = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff') /IP(dst=to) / TCP(dport=dport , sport=sport )  / pkt


    print('\n')
    print('**************** encap *************')
    print('\n')

    print('\n')
    print('----------- old packet ------------')
    print('\n')

    pkt.show()


    print('\n')
    print('----------- new packet (encapsulate) ------------')
    print('\n')

    pkt_with_header.show()


    print('Sending packet to next pod')

    sendp(pkt_with_header,iface=iface,verbose=True)

def change_ip(pkt,dst):

    d = socket.gethostbyname(dst)
    pkt.getlayer(1).dst = d
    del pkt.getlayer(1).chksum
    return pkt

def decapsulate(pkt,iface='eth0',dst='127.0.0.1'):

    print('\n')
    print('**************** decap *************')
    print('\n')


    print('\n')
    print('----------- old packet ------------')
    print('\n')

    pkt.show()


    print('\n')
    print('----------- new packet (decapsulate) ------------')
    print('\n')

    
    old_pkt = pkt.getlayer(3)

    print('\n')
    print('----------- new packet with raw layer ------------')
    print('\n')

    old_pkt.show()

    old_pkt2 = Ether(old_pkt[Raw].load)  

    print('\n')
    print('----------- new packet ------------')
    print('\n')

    old_pkt2.show()


    print('\n')
    print('----------- change ip for pkt ------------')
    print('\n')


    pkt2 = change_ip(old_pkt2,dst)

    pkt2.show()
    
    print('Sending packet to receiver')

    sendp(pkt,iface=iface,verbose=True)

def get_pkt(dport=1234,dst='127.0.0.1'):
    while(True):
        pkts = sniff(count=1,filter="tcp and port {0}".format(dport) )
        if TCP in pkts[0] and pkts[0][TCP].dport == 1234 and str(pkts[0][IP].dst) == dst :
            break
    return pkts[0]