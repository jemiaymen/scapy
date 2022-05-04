import subprocess
from time import sleep
from scapy.all import *

import random
import socket

iface = 'wlp0s20f3'
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
to1 = socket.gethostbyname(ips['ingress'])
to2 = socket.gethostbyname(ips['uplink'])

pkt = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to1) / TCP(dport=dport , sport=sport ) / "Test PKT"
pkt2 = Ether(src=get_if_hwaddr(iface),dst='ee:ee:ee:ee:ee:ee') /IP(dst=to2) / TCP(dport=dport , sport=sport ) / "Test PKT Uplink"

wrpcap("src.pcap",[pkt,pkt2])

tcpreplay_cli = "tcpreplay -i {0} --topspeed src.pcap".format(iface)

tcpdump_cli = "tcpdump -tt -i {0} src host {1} > dst.pcap".format(iface,ips['sender'])

tcpreplay = subprocess.Popen(tcpreplay_cli,shell=True)
# tcpreplay.wait()

# sleep(0.3)

# tcpdump = subprocess.Popen(tcpdump_cli , shell=True)
# tcpdump.wait()

def handle_pkt(pkt):
    pkt.show2()
    sys.stdout.flush()

final_pkts = sniff(count=2,filter="tcp and port {0}".format(dport) , prn= lambda x: handle_pkt(x) )

wrpcap("dst.pcap",final_pkts)