#!/usr/bin/env python3


# Imports
##############################################################################
from flask import Flask, request, abort, jsonify, render_template
from flask_restful import Resource, Api, abort
from werkzeug.exceptions import BadRequest
import scapy.all as scapy
import requests

from .schema import ArpScannerGetSchema
##############################################################################


# Gloabal Variables
##############################################################################
BRDCST_MAC          = "ff:ff:ff:ff:ff:ff"        # Broadcast MAC Address
ANSWRD_LST_INDEX    = 0                          # Answered Packages Index
ARP_FRAME_INDEX     = 1                          # Arp Frame Index
TIMEOUT             = 1                          # Timeout
OK_STATUS_CODE      = 200                        # OK Status Code
##############################################################################


# Arp Scan Function
# This Method Takes Target as Argument
# And It Returns List of Clients
##############################################################################
def arp_scan(target):
    arp_request = scapy.ARP()                     # ARP Package Generated
    arp_request.pdst = target                     # Set Target IP Address

    broadcast_ether = scapy.Ether()               # Ethernet Frame Generated 
    broadcast_ether.dst = BRDCST_MAC              # Set Destination MAC

    # Arp and Broadcast Ether Package Combined
    broadcast_arp_request = broadcast_ether/arp_request

    # Sending Packages
    answered_list = scapy.srp(broadcast_arp_request,
        timeout=TIMEOUT, verbose = False)[ANSWRD_LST_INDEX]
        
    clients_list = []                             # List of Clients

    for client in answered_list:
        ip_addr = client[ARP_FRAME_INDEX].psrc    # Ip Address
        mac_addr = client[ARP_FRAME_INDEX].hwsrc  # MAC Address

        client_dict = {"ip_addr":ip_addr,
                       "mac_addr":mac_addr}
        
        clients_list.append(client_dict)
        
    return clients_list
##############################################################################


# Api Methods
##############################################################################
class ArpScan(Resource):
    def get(self):
        arp_scan_get_schema = ArpScannerGetSchema()   # Schema Object

        data = request.get_json()                     # Getting Data

        # Validating Request Parameters
        errors = arp_scan_get_schema.validate(data)
        if errors:
            raise BadRequest(errors)

        target = data['target']

        clients_list = arp_scan(target)               # Arp Scan Function
        return clients_list
##############################################################################


