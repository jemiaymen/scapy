from api import sniff,handle_pkt,get_current_pod_ip


iface = 'eth0'
pod_ip = get_current_pod_ip()

print(pod_ip)

sniff(filter="tcp and port 1234" ,iface = iface, prn = lambda x: handle_pkt(x,pod_ip))

