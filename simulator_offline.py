from scapy.all import *

import time,os



def delete_file(w):
    if os.path.exists(w):
        os.remove(w)

def get_data_from_pkt(p):
	return bytes(p[TCP].payload)


def get_timestamp_from_pkt(p):
	return p.time


def create_packet(sip,dip,sp,dp,msg):
	return Ether(src='ee:ee:ee:ee:ee:ee',dst='ee:ee:ee:ee:ee:ee') /IP(src=sip,dst=dip) / TCP(dport=dp , sport=sp ) / str(msg)


def save_pkt(p):
    wrpcap('data_offline.pcap', p, append=True)


def save_pkt_sender(p):
    wrpcap('sender_offine.pcap', p, append=True)
	

def save_pkt_receiver(p):
    wrpcap('receiver_offline.pcap', p, append=True)


def read_pcap(file):
	return rdpcap(file)


def find_packet_in_pcap(pkt,pkt_load):
    for x in pkt_load:
        if get_data_from_pkt(pkt)==get_data_from_pkt(x):
                return get_timestamp_from_pkt(x)-get_timestamp_from_pkt(pkt)
    return -1


"""def record():
    for x in range(10):
        p=create_packet('10.244.246.130','10.244.246.129',60000,60000,x)
        save_pkt_sender(p)
        save_pkt(p)
        t=time.time()
        time.sleep(0.001)
        p.time+=time.time()-t
        #p=create_packet('10.244.246.130','10.244.246.129',60000,60000,x)
        save_pkt_receiver(p)
        save_pkt(p)
"""
def record():
    print('Creating packets...')
    p=create_packet('10.244.246.130','10.244.246.129',60000,60000,0)
    for x in range(10):
        #p=create_packet('10.244.246.130','10.244.246.129',60000,60000,x)
        #save_pkt(p)
        p.time=round(p.time,3)
        t=p.time
        p[TCP].payload=Raw(str(x))
        p.time=round(p.time+0.001,3)
        save_pkt_sender(p)
        #print(p.time-t,bytes(p[TCP].payload))
    print('Replaying...')
    os.system('sudo tcpreplay -i docker0 sender.pcap')

def analyze():
    data_sender=read_pcap('sender_offline.pcap')
    data_receiver=read_pcap('receiver_offline.pcap')
    for x in data_sender:
        print('Latency: {}'.format(find_packet_in_pcap(x,data_receiver)))

"""delete_file('sender_offline.pcap')

delete_file('receiver_offline.pcap')

delete_file('data_offline.pcap')
"""
record()

#analyze()
