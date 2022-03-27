from api import send,sleep



while (True):
    sleep(15)
    send(iface='eth0',msg='uplink Handling case',show_pkt=True , dst='10.244.1.23')