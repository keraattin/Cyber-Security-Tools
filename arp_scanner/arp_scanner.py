#!/usr/bin/env python


import scapy.all as scapy


# Gloabal Variables
##############################################################################
BRDCST_MAC = "ff:ff:ff:ff:ff:ff"                  # Broadcast MAC Address
ANSWRD_LST_INDEX = 0                              # Answered Packages Index
ARP_FRAME_INDEX = 1                               # Arp Frame Index
TARGET = "10.0.2.1/24"                            # Target IP Address
##############################################################################


def scan(ip,timeout=1):
    arp_request = scapy.ARP()                     # ARP Package Generated
    arp_request.pdst = ip                         # Set Target IP Address

    broadcast_ether = scapy.Ether()               # Ethernet Frame Generated 
    broadcast_ether.dst = BRDCST_MAC              # Set Destination MAC

    # Arp and Broadcast Ether Package Combined
    broadcast_arp_request = broadcast_ether/arp_request

    # Sending Packages
    answered_list = scapy.srp(broadcast_arp_request,
        timeout=timeout, verbose = False)[ANSWRD_LST_INDEX]
    
    clients_list = []                             #List For Clients

    for client in answered_list:
        client_dict = {"ip_addr":client[ARP_FRAME_INDEX].psrc,
                       "mac_addr":client[ARP_FRAME_INDEX].hwsrc}
        clients_list.append(client_dict)
    
    return clients_list


def main():
    clients = scan(TARGET)
    print("IP ADDRESS\tMAC ADDRESS")
    for client in clients:
        print(client["ip_addr"]+"\t"+client["mac_addr"])


if __name__ == "__main__":
    main()