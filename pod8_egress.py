import random
import socket
import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

iface = 'eth0'
dport = 60000 


#pods ip
current_pod_ip = '10.244.246.136'
receiver_ip = '10.244.246.137'

def get_pkt():
    while (True):
        pkts = sniff(count=1,filter="tcp and port {0}".format(dport) )
        if TCP in pkts[0] and pkts[0][TCP].dport == dport and str(pkts[0][IP].dst) == current_pod_ip :
            return pkts[0]

def decap(pkt):
    old = pkt[Raw].load

    n_pkt = Ether(old)  

    n_pkt.show()
    sys.stdout.flush()

    return n_pkt


    
if __name__ == "__main__":
    while (True):

        pkt = get_pkt()
        
        print('\n')
        print('----------- origine packet ------------')
        print('\n')

        pkt.show()
        sys.stdout.flush()


        print('\n')
        print('----------- new packet (decapsulate) {0} times ------------'.format(5))
        print('\n')
        pkts = []
        p = pkt
        for _ in range(5):
            p = decap(p)
            pkts.append(p)
        

        data = p[Raw].load
        dst = receiver_ip


        sport = random.randint(49152,65535)
        to = socket.gethostbyname(dst)

        pkt2 = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to) / TCP(dport=dport , sport=sport ) / data


        pkt2.show()
        sys.stdout.flush()

        sendp(pkt2,iface=iface,verbose=True)
    
