from api import send,sleep



while (True):
    sleep(5)
    send(iface='wlp0s20f3',msg='up senario',show_pkt=True)