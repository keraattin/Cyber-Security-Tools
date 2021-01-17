#!/usr/bin/env python3


from flask import Flask, request, abort, jsonify, render_template
from flask_restful import Resource, Api, abort
from werkzeug.exceptions import BadRequest
import scapy.all as scapy
import re
import requests


# Gloabal Variables
##############################################################################
BRDCST_MAC = "ff:ff:ff:ff:ff:ff"                  # Broadcast MAC Address
ANSWRD_LST_INDEX = 0                              # Answered Packages Index
ARP_FRAME_INDEX = 1                               # Arp Frame Index
TIMEOUT = 1                                       # Timeout
PARAMS_COUNT = 1                                  # Number of Parameters
DEBUG = True                                      # Debug Mode
PORT = 5000                                       # Port Number
OK_STATUS_CODE = 200                              # OK Status Code
MAC_VEND_URL = "http://api.macvendors.com/"       # Mac Vendor Api URL
MAC_PARAMS_COUNT = 1                              # Number of Parameters

app = Flask(__name__)
api = Api(app)


IP_SUBNET_PATTERN = ("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\/([1-9]|[1][0-9]|[2][0-9]|[3][0-2])$")

IP_PATTERN = ("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
                    "\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

MAC_PATTRN = ("^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


TARGET_NOT_VALID_MSG = ("Target not sent correctly..."
                        "See the documentation for more information")
PARAMS_NOT_SEND_MSG = ("Parameters not sent correctly..."
                     "See the documentation for more information")
##############################################################################


# Validate Target IP Address
##############################################################################
def validate_ip_addr(ip_addr):
    ip_matches = re.search(IP_PATTERN,ip_addr)
    ip_subnet_matches = re.search(IP_SUBNET_PATTERN,ip_addr)
    if ip_matches or ip_subnet_matches:
        return True
    else:
        return False
##############################################################################


# Validate Target Mac Address
##############################################################################
def validate_mac_addr(mac_addr):
    matches = re.search(MAC_PATTRN,mac_addr)
    if matches:
        return True
    else:
        return False
##############################################################################


# Get Vendor Function
# This Method Takes Mac Address as Argument
# Returns Vendor of Mac Address
##############################################################################
def get_vendor(mac_addr):
    url =  MAC_VEND_URL + str(mac_addr)

    payload={}                                        # Payloads
    headers = {}                                      # Headers

    response = requests.request("GET", url, 
            headers=headers, data=payload, timeout=TIMEOUT)

    status_code = response.status_code                # Status Code of Request

    if status_code == OK_STATUS_CODE:
        vendor = response.text
        return str(vendor)
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
        vendor = get_vendor(mac_addr)             # Vendor

        client_dict = {"ip_addr":ip_addr,
                       "mac_addr":mac_addr,
                       "vendor":vendor}
        
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


class Vendor(Resource):
    def get(self):
        args = request.args                           # Arguments
        # Arguments Validation
        if not args or len(args)>MAC_PARAMS_COUNT:
            raise BadRequest(PARAMS_NOT_SEND_MSG)

        mac_addr = str(args['mac_addr'])               # MAC Address
        # Target Validation
        if not validate_mac_addr(mac_addr):
            raise BadRequest(TARGET_NOT_VALID_MSG)

        mac_addr = str(args['mac_addr'])              # Mac Address

        vendor = get_vendor(mac_addr)
        return vendor
##############################################################################


# Pages
##############################################################################
## Homepage
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html', port=PORT)


## Error Page
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404
##############################################################################


# Endpoints
##############################################################################
api.add_resource(ArpScan, '/arp_scan')
api.add_resource(Vendor, '/vendor')
##############################################################################


if __name__ == '__main__':
    app.run(debug=DEBUG,port=PORT)