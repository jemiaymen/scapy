import random
import socket
from time import sleep
import sys,os

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

def handle_pkt(pkt,dst='127.0.0.1'):
    if TCP in pkt and pkt[TCP].dport == 1234 and str(pkt[IP].dst) == dst :
        pkt.show2()
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

def change_ip(pkt,dst,dport=1234):

    sport = random.randint(49152,65535)
    d = socket.gethostbyname(dst)
    pkt.getlayer(1).dst = d
    pkt.getlayer(2).dport = dport
    pkt.getlayer(2).sport = sport

    return pkt

def decapsulate(pkt,iface='eth0',dst='127.0.0.1'):

    print('\n')
    print('----------- old packet ------------')
    print('\n')

    pkt.show()


    print('\n')
    print('----------- new packet (decapsulate) ------------')
    print('\n')

    
    old_pkt = pkt.getlayer(3)

    n_pkt = Ether(old_pkt[Raw].load)  

    n_pkt.show()

    data = n_pkt[Raw].load

    send(iface=iface,dst=dst,msg = data , show_pkt=True )

    # sport = random.randint(49152,65535)
    # d = socket.gethostbyname(dst)
    # n_pkt['IP'].dst = d
    # n_pkt['TCP'].dport = 1234
    # n_pkt['TCP'].sport = sport

    # del n_pkt['IP'].len
    # del n_pkt['IP'].chksum
    # del n_pkt['TCP'].chksum
    # del n_pkt['IP'].len

    # pkt2 = Ether(n_pkt.build())

    # pkt2.show()



    # n_pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff') /IP(dst=d) / TCP(dport=1234 , sport=sport ) / pkt2[Raw].load
    
    # n_pkt.show()

    # print('Sending packet to receiver')

    # sendp(n_pkt,iface=iface,verbose=True)

    # sr(n_pkt,iface=iface)

def get_pkt(dport=1234,dst='127.0.0.1'):
    while(True):
        pkts = sniff(count=1,filter="tcp and port {0}".format(dport) )
        if TCP in pkts[0] and pkts[0][TCP].dport == 1234 and str(pkts[0][IP].dst) == dst :
            break
    return pkts[0]

def get_current_pod_ip():
    return socket.gethostbyname(socket.gethostname())

def get_next_pod_ip():
    old_ip = get_current_pod_ip()
    numbers = old_ip.split('.')
    last = int(numbers[3])
    last += 1
    return '{0}.{1}.{2}.{3}'.format(numbers[0],numbers[1],numbers[2],last)