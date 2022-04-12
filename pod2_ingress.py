from api import encapsulate, sleep,get_pkt,get_current_pod_ip,get_next_pod_ip






while(True):
    sleep(10)
    iface = 'eth0'

    pkt = get_pkt(dport=1234 , dst = get_current_pod_ip())

    encapsulate(pkt,iface=iface,dst=get_next_pod_ip())


