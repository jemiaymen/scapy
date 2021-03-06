import random
import socket
import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

iface = 'eth0'
dport = 60000 


#pods ip
current_pod_ip = '10.244.246.139'
reciever_ip = '10.244.246.130'


def get_pkt():
    while (True):
        pkts = sniff(count=1,filter="tcp and port {0}".format(dport) )
        if TCP in pkts[0] and pkts[0][TCP].dport == dport and str(pkts[0][IP].dst) == current_pod_ip :
            return pkts[0]






if __name__ == "__main__":
    while(True):
        pkt = get_pkt()
    
        pkt[IP].dst= reciever_ip
        pkt[IP].src= current_pod_ip
        pkt[Ether].src=get_if_hwaddr('eth0')
        pkt[Ether].dst='ee:ee:ee:ee:ee:ee'

          

        #pkt[TCP].sport=random.randint(49152,65535)
        
        sendp(pkt,iface=iface,verbose=True)
        pkt.show()
        sys.stdout.flush()

        
