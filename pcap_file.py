from scapy.all import *
import socket

iface = 'eth0'
dport = 60000 
ips = { 'sender' :'10.244.246.129',
        'ingress' : '10.244.246.130',
        'uplink' : '10.244.246.131',
        'downlink':'10.244.246.132',
        'qos':'10.244.246.133',
        'usage_accounting':'10.244.246.134',
        'lawfull':'10.244.246.135',
        'egress':'10.244.246.136',
        'receiver':'10.244.246.137',
        'capture':'10.244.246.139' }

sport = 60001



pkts = []

to = socket.gethostbyname(ips['capture'])

for x in range(1,101):

    msg = 'Hello word ({0})'.format(x)
    pkt = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to) / TCP(dport=dport , sport=sport ) / msg
    pkts.append(pkt)

wrpcap("src.pcap",pkts)

while True:
    pass