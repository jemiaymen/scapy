from api import *


iface = 'eth0'

while(True):
    
    pkt = get_pkt(dport=60000 , dst = get_current_pod_ip())
    dst = get_next_pod_ip()

    send(iface=iface,dst = dst , payload = pkt,show_pkt=True)

    #sleep(1)
