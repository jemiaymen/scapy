import sys,os,time

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

"""iface = 'eth0'
dport = 60000 


def save_packet_one(p):
    wrpcap('receiver.pcap', p, append=True)

#pods ip
current_pod_ip = '10.244.246.137'

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 60000 and str(pkt[IP].dst) == current_pod_ip :
        pkt.show()
        sys.stdout.flush()
        save_packet_one(pkt)
"""
if __name__ == "__main__":
    os.system('tcpdump -i eth0 -w receiver.pcap -c 10 dst 10.244.246.137')
    while 1:
        time.sleep(1)
    #sniff(filter="tcp and port 60000" ,iface = iface, prn = lambda x: handle_pkt(x))
