
from api import send,sleep,get_next_pod_ip

i = 1
while (True):
    sleep(10)
    send(iface='eth0',msg='Hello word ( {0} )'.format(i),show_pkt=True , dst=get_next_pod_ip())
    i += 1