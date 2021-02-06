#!/usr/bin/env python3


import netfilterqueue
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        print(scapy_packet.show())
    
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bid(0, process_packet)
queue.run()