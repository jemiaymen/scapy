#!/bin/sh
tcpdump -i eth0 -w /app/target.pcap -c 1 dst 10.244.246.130
