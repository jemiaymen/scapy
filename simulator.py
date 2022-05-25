
from sre_constants import SUCCESS
from scapy.all import *

import time,os



def get_data_from_pkt(p):
    try:
        #print(bytes(p[TCP].payload))
        return bytes(p[TCP].payload)
    except:
        return b''


def get_timestamp_from_pkt(p):
	return p.time



def read_pcap(file):
	return rdpcap(file)


def find_packet_in_pcap(pkt,pkt_load):
    for x in pkt_load:
        if get_data_from_pkt(pkt)==get_data_from_pkt(x):
                return get_timestamp_from_pkt(x)-get_timestamp_from_pkt(pkt)
    return -1



def analyze():
    data_sender=read_pcap('src.pcap')
    data_receiver=read_pcap('target.pcap')
    success=0
    for x in data_sender:
        latency=find_packet_in_pcap(x,data_receiver)
        if latency!=-1:
            success+=1
        print('Latency: {}'.format(latency))
    print('\nNetwork throughput: {} %'.format(round(100 * float(success)/float(len(data_sender))),3))


analyze()