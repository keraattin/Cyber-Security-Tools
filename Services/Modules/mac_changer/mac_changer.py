#!/usr/bin/env python3


# Imports
##############################################################################
from flask import Flask, request, abort, jsonify, render_template
from flask_restful import Resource, Api, abort, reqparse
from werkzeug.exceptions import BadRequest
import subprocess

from .args import mac_changer_post_args
from .validators import validate_mac_addr
##############################################################################


# Global Values
##############################################################################
NOT_VALID_MAC_ADDR_MSG = "Not a Valid MAC Address"
##############################################################################


# Functions
##############################################################################
def change_mac_addr(iface,mac_addr):
    # Down Interface
    subprocess.call(['ifconfig','{}'.format(iface),'down'])

    # Change Hw Adress
    subprocess.call(['ifconfig',
                    '{}'.format(iface),
                    'hw',
                    'ether',
                    '{}'.format(mac_addr)])
    
    # Up Interface
    subprocess.call(['ifconfig','{}'.format(iface),'up'])
##############################################################################


# Api Methods
##############################################################################
class MacChanger(Resource):
    def post(self):
        args = mac_changer_post_args.parse_args()   # Arguments
        
        iface    = args['iface']
        mac_addr = args['mac_addr']

        # If MAC Address not Valid
        if not validate_mac_addr(mac_addr):
            raise BadRequest(NOT_VALID_MAC_ADDR_MSG)

        change_mac_addr(iface,mac_addr)

        return {"message":
                "Your MAC Address Changed to {}".format(mac_addr)},201
##############################################################################


# Endpoints
##############################################################################

##############################################################################


# Main
##############################################################################
if __name__ == '__main__':
    app.run(debug=DEBUG,port=PORT)
##############################################################################