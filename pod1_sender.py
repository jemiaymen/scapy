
from api import send,sleep,get_next_pod_ip

i = 1
while (True):
    
    if( i % 3 == 0):
        msg = 'Hello word ({0}) uplink'.format(i)
    else:
        msg = 'Hello word ({0}) downlink'.format(i)
    send(iface='eth0',payload= msg ,show_pkt=True , dst=get_next_pod_ip())
    i += 1
    sleep(10)