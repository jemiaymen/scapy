import random
import socket
from time import sleep
import sys

from scapy.all import *
from scapy.layers.l2 import *
from scapy.layers.inet import *


class OuterEther(Packet):
    name = "OuterEther"
    fields_desc = [
        StrField("name","Ether"),
        ShortField("number",1)
    ]
    
    def do_dissect_payload(self, s):
        cls = self.guess_payload_class(s)
        p = cls(s, _internal=1, _underlayer=self)
        self.add_payload(p)

class OuterIP(Packet):
    
    name = "OuterIP"
    fields_desc = [
        StrField("name","IP"),
        ShortField("number",2)
    ]

    def do_dissect_payload(self, s):
        cls = self.guess_payload_class(s)
        p = cls(s, _internal=1, _underlayer=self)
        self.add_payload(p)

def handle_pkt(pkt,port=1234,debug=False):

    if TCP in pkt and pkt[TCP].dport == port:

        if(debug):

            print("I got a Package in port {0}".format(port))
            pkt.show2()

            sys.stdout.flush()
        else:

            pkt.show2()
            sys.stdout.flush()

def send(iface='eth0',dst='127.0.0.1',msg='Hello World',dport=1234 ,show_pkt=False):
    
    if(iface not in get_if_list()):
        print(' [{0}] inteface not found .'.format(iface))
        print('list of interfaces :',get_if_list())
        return 

    sport = random.randint(49152,65535)
    to = socket.gethostbyname(dst)

    pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff') /IP(dst=to) / TCP(dport=dport , sport=sport ) / msg

    if(show_pkt):
        pkt.show2()
    
    print('Sending [ {0} ] to {1}'.format(msg,dst))

    sendp(pkt,iface=iface,verbose=show_pkt)

def encapsulate(pkt,iface='eth0',src = '127.0.0.1',dst='127.0.0.2'):
    
    pkt = change_ip(pkt,src,dst)

    e = OuterEther(name="encap ether")
    i = OuterIP(name="encap ip")

    return  pkt / OuterEther() / OuterIP() 

def change_ip(pkt,src,dst):
    pkt[IP].src = src
    pkt[IP].dst = dst
    del pkt[IP].chksum
    return pkt

def decapsulate(pkt):
    pkt.getlayer(3).remove_payload()
    return pkt


