import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

iface = 'eth0'
dport = 60000 


#pods ip
current_pod_ip = '10.244.246.137'

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 60000 and str(pkt[IP].dst) == current_pod_ip :
        pkt.show()
        sys.stdout.flush()
        

if __name__ == "__main__":
    sniff(filter="tcp and port 60000" ,iface = iface, prn = lambda x: handle_pkt(x))

