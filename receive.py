#!/usr/bin/env python3
import os
import sys
from time import sleep

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swids",
                                  adjust=lambda pkt,l:l+4),
                    ShortField("count", 0),
                    FieldListField("swids",
                                   [],
                                   IntField("", 0),
                                   length_from=lambda pkt:pkt.count*4) ]


def handle_pkt(pkt,port=1234,debug=False):

    if TCP in pkt and pkt[TCP].dport == port:

        if(debug):

            print("I got a Package in port {0}".format(port))
            pkt.show2()

            sys.stdout.flush()
        else:

            pkt.show2()
            sys.stdout.flush()


def main():
    print('\n')
    print('----------- receive pkt with scapy ------------')
    print('\n')

    

    iface = 'eth0'

    # while(iface not in get_if_list()):
    #     print('\n')
    #     iface = input('Enter interface : ')
    #     print('\n')
    #     if(iface not in get_if_list()):
    #         print('[{0}] inteface not found .'.format(iface))
    #         print('list of interfaces :',get_if_list())
        

    print('\n')
    print("sniffing on %s" % iface)

    sys.stdout.flush()

    sniff(iface = iface, prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()