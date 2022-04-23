from api import *



iface = 'eth0'


while(True):
    
    
    pkt = get_pkt(dport=60000 , dst = get_current_pod_ip())
    
    msg = str(pkt[Raw].load).lower()
    
    dst = dst = get_next_pod_ip()

    if('down' in msg):
        dst = get_next_pod_ip(pod_ip = get_next_pod_ip())
        

    encapsulate(pkt,iface=iface,dst=dst)
    #sleep(1)


