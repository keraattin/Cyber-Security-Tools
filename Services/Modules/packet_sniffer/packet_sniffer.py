#!/usr/bin/env python3

# Imports
##############################################################################
import scapy.all as scapy
from scapy.layers import http
##############################################################################


# Global Values
##############################################################################
INTERFACE = "eth0"
CACHE     = []
CAP_FILE  = "temp.cap"
##############################################################################


# Functions
##############################################################################
def process_packet(packet):
    summary = packet.summary()
    CACHE.append(summary)
    scapy.wrpcap(CAP_FILE, packet, append=True)


def sniff(interface):
    scapy.sniff(iface = interface,
                store = False,
                prn   = process_packet)
##############################################################################


# Main
##############################################################################
if __name__ == '__main__':
    try:
        sniff(INTERFACE)
    except KeyboardInterrupt:
        print("[+] Done!")
        print("[-] Quiting...")
    for packet in CACHE:
        print(packet)
    print("[+] Done!")
    print("[-] Quiting...")
##############################################################################