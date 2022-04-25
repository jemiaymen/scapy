import random
import socket
import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

iface = 'eth0'
dport = 60000 


#pods ip
current_pod_ip = '10.244.246.132'
qos_ip = '10.244.246.133'


def get_pkt():
    while (True):
        pkts = sniff(count=1,filter="tcp and port {0}".format(dport) )
        if TCP in pkts[0] and pkts[0][TCP].dport == dport and str(pkts[0][IP].dst) == current_pod_ip :
            return pkts[0]

if __name__ == "__main__":
    while(True):
        
        pkt = get_pkt()
        dst = qos_ip

        sport = random.randint(49152,65535)
        to = socket.gethostbyname(dst)

        pkt2 = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to) / TCP(dport=dport , sport=sport ) / pkt


        pkt2.show2()
        sys.stdout.flush()

        sendp(pkt,iface=iface,verbose=True)
