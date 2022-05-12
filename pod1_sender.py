import random
import socket
from time import sleep
import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *

"""iface = 'eth0'
dport = 60000 
i = 1


dst_ip = '10.244.246.130'

port=60000

src_ip='10.244.246.129'
"""


"""def save_packet_one(p):
    wrpcap('sender.pcap', p, append=True)


def save_packet_two(p):
    wrpcap('final_captures.pcap', p, append=True)


def sniff_packets(sip,dip,sp,dp):
    while True:
        if sys.argv[1].lower()=="o":
            save_packet_one(sniff(filter="tcp", count=1))
        else:
            save_packet_two(sniff(filter="tcp", count=1))
"""
#sniff_packets(src_ip,dst_ip,port,port)

def create_packet(sip,dip,msg):
	return Ether(src='ee:ee:ee:ee:ee:ee',dst='ee:ee:ee:ee:ee:ee') /IP(src=sip,dst=dip) / TCP(dport=60000 , sport=random.randint(49152,65535) ) / str(msg)

def save_pkt_sender(p):
    wrpcap('sender.pcap', p, append=True)


def record():
    print('Creating packets...')
    p=create_packet('10.244.246.129','10.244.246.130',0)
    for x in range(10):
        #p=create_packet('10.244.246.130','10.244.246.129',60000,60000,x)
        #save_pkt(p)
        p.time=round(p.time,3)
        t=p.time
        p[TCP].payload=Raw(str(x))
        p.time=round(p.time+0.001,3)
        p[TCP].sport=random.randint(49152,65535)
        save_pkt_sender(p)
        #print(p.time-t,bytes(p[TCP].payload))
    print('Replaying...')
    os.system('tcpreplay -i eth0 sender.pcap')


#pod2 ip (ingress)
dst = '10.244.246.130'

if __name__ == "__main__":

    # test if is a valid interface
    sleep(20)
    record()
    while 1:
        sleep(1)
    """
    if (iface not in get_if_list()):
        print(' [{0}] inteface not found .'.format(iface))
        print('list of interfaces :',get_if_list())
    else:
        
        while (True):

            sport = 60000#random.randint(49152,65535)
            to = socket.gethostbyname(dst)

            if( i % 2 == 0):
                msg = 'Hello word ({0}) uplink'.format(i)
            else:
                msg = 'Hello word ({0}) downlink'.format(i)
            
            pkt = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to) / TCP(dport=dport , sport=sport ) / msg


            pkt.show2()
            sys.stdout.flush()

            sendp(pkt,iface=iface,verbose=True)
            save_packet_one(pkt)
            i += 1
            sleep(4)
"""