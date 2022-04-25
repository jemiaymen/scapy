import random
import socket
import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

iface = 'eth0'
dport = 60000 


#pods ip
current_pod_ip = '10.244.246.130'
uplink_ip = '10.244.246.131'
downlink_ip = '10.244.246.132'


def get_pkt():
    while (True):
        pkts = sniff(count=1,filter="tcp and port {0}".format(dport) )
        if TCP in pkts[0] and pkts[0][TCP].dport == dport and str(pkts[0][IP].dst) == current_pod_ip :
            return pkts[0]

if __name__ == "__main__":
    while(True):
        
        
        pkt = get_pkt()
        
        msg = str(pkt[Raw].load).lower()
        
        dst = uplink_ip

        if('down' in msg):
            dst = downlink_ip
            

        sport = random.randint(49152,65535)
        to = socket.gethostbyname(dst)

        pkt_with_header = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to) / TCP(dport=dport , sport=sport )  / pkt


        print('\n')
        print('**************** encap *************')
        print('\n')

        print('\n')
        print('----------- old packet ------------')
        print('\n')

        pkt.show()
        sys.stdout.flush()


        print('\n')
        print('----------- new packet (encapsulate) ------------')
        print('\n')

        pkt_with_header.show()
        sys.stdout.flush()


        print('Sending packet to next pod')

        sendp(pkt_with_header,iface=iface,verbose=True)



