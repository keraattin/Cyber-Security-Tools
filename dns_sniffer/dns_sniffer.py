#!/usr/bin/env python3


# Imports
##############################################################################
from scapy.all import *
import sys
##############################################################################


# Global Values
##############################################################################
INTERFACE = "eth0"
A_RECORD  = 1
##############################################################################



##############################################################################
# DNS Question Records
def sniff_dns_qr(packet):
    if IP in packet:
        ip_src = packet[IP].src
        if packet.haslayer(DNSQR):
            if packet.getlayer(DNSQR).qtype == A_RECORD:
                qname = packet.getlayer(DNSQR).qname.decode("utf-8")
                print("["+ ip_src +"] \t-> [" + qname + "]")


# DNS Resource Records
def sniff_dns_rr(packet):
    if IP in packet:
        ip_src = packet[IP].src
        if packet.haslayer(DNSRR):
            if packet.getlayer(DNSRR).type == A_RECORD:
                rrname = packet.getlayer(DNSRR).rrname.decode("utf-8")
                rdata  = packet.getlayer(DNSRR).rdata
                print("["+ ip_src +"] \t-> [" + rrname + "(" + rdata + ")]")
##############################################################################



##############################################################################
sniff(iface = INTERFACE, filter="port 53", prn = sniff_dns_rr, store = 1)
##############################################################################