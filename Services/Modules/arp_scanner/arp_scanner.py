#!/usr/bin/env python3


# Imports
##############################################################################
from flask import Flask, request, abort, jsonify, render_template
from flask_restful import Resource, Api, abort
from werkzeug.exceptions import BadRequest
import scapy.all as scapy
import requests

from args import arp_scanner_get_args
from validators import validate_ip_addr
from schema import ArpScannerGetSchema
##############################################################################


# Gloabal Variables
##############################################################################
BRDCST_MAC          = "ff:ff:ff:ff:ff:ff"        # Broadcast MAC Address
ANSWRD_LST_INDEX    = 0                          # Answered Packages Index
ARP_FRAME_INDEX     = 1                          # Arp Frame Index
TIMEOUT             = 1                          # Timeout
PARAMS_COUNT        = 1                          # Number of Parameters
OK_STATUS_CODE      = 200                        # OK Status Code
MAC_PARAMS_COUNT    = 1                          # Number of Parameters


TARGET_NOT_VALID_MSG = ("Target not sent correctly..."
                        "See the documentation for more information")
PARAMS_NOT_SEND_MSG = ("Parameters not sent correctly..."
                       "See the documentation for more information")
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
        args = request.args                           # Arguments
        # Arguments Validation
        if not args or len(args)>PARAMS_COUNT:
            raise BadRequest(PARAMS_NOT_SEND_MSG)

        target = str(args['target'])                  # Targets
        # Target Validation
        if not validate_ip_addr(target):
            raise BadRequest(TARGET_NOT_VALID_MSG)

        clients_list = arp_scan(target)               # Arp Scan Function
        return clients_list
##############################################################################


