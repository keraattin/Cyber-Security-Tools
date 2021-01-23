#!/usr/bin/env python3

# Imports
##############################################################################
import scapy.all as scapy
from scapy.layers import http
##############################################################################


# Global Values
##############################################################################
INTERFACE = "eth0"
##############################################################################



def process_packet(packet):
    print(packet.layers())


def sniff(interface):
    scapy.sniff(iface = interface,
                store = False,
                prn   = process_packet)

sniff(INTERFACE)