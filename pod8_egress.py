from api import *

iface = 'eth0'

while (True):

    pkt = get_pkt(dst=get_current_pod_ip())
    decapsulate(pkt,iface,get_next_pod_ip())
    
  #  sleep(1)
