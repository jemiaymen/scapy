from api import send,sleep


sleep(5)
send(iface='eth0',msg='Hello word',show_pkt=True , dst='172.17.0.3')

while (True):
    sleep(15)
    