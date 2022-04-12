from api import sleep , get_pkt ,decapsulate ,get_current_pod_ip,get_next_pod_ip



while (True):
    sleep(10)

    iface = 'eth0'


    pkt = get_pkt(dst=get_current_pod_ip())


    decapsulate(pkt,iface,get_next_pod_ip())
