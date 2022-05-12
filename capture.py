from scapy.all import *

import sys


dst_ip = '10.244.246.130'

port=60000

src_ip='10.244.246.129'



def save_packet_one(p):
    wrpcap('original_captures.pcap', p, append=True)
  

def save_packet_two(p):
    wrpcap('final_captures.pcap', p, append=True)


def sniff_packets():
    while True:
         save_packet_one(sniff(filter="tcp", count=1))
       
sniff_packets()
