import subprocess
from scapy.all import *

import random
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
        'receiver':'10.244.246.137' }

sport = random.randint(49152,65535)

to = socket.gethostbyname(ips['ingress'])

pkts = []
for x in range(10):
    pkt = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to) / TCP(dport=dport , sport=sport ) / "Test PKT {0}".format(x) 
    pkts.append(pkt)


wrpcap("/app/src.pcap",pkts)

tcpreplay_cli = "tcpreplay -i {0} --topspeed /app/src.pcap".format(iface)



tcpreplay = subprocess.Popen(tcpreplay_cli,shell=True)
# tcpreplay.wait()

# sleep(0.3)

# tcpdump_cli = "tcpdump -tt -i {0} src host {1} > dst.pcap".format(iface,ips['sender'])
# tcpdump = subprocess.Popen(tcpdump_cli , shell=True)
# tcpdump.wait()

def handle_pkt(pkt):
    pkt.show2()
    sys.stdout.flush()

final_pkts = sniff(count=10,filter="tcp and port {0}".format(dport) , prn= lambda x: handle_pkt(x) )

wrpcap("/app/dst.pcap",final_pkts)

latency = subprocess.Popen('/app/pcap_latency --latency-histo /app/src.pcap /app/dst.pcap',shell=True)
latency.wait()