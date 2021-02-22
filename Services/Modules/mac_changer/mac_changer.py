#!/usr/bin/env python3


# Imports
##############################################################################
from flask import Flask, request, abort, jsonify, render_template
from flask_restful import Resource, Api, abort, reqparse
from werkzeug.exceptions import BadRequest
import subprocess

from .schema import MacChangerPostSchema
from .validators import validate_mac_addr
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
        mac_changer_post_schema = MacChangerPostSchema()   # Schema Object

        data = request.get_json()                          # Getting Data

        # Validating Request Parameters
        errors = mac_changer_post_schema.validate(data)
        if errors:
            raise BadRequest(errors)
        
        iface    = data['iface']
        mac_addr = data['mac_addr']

        change_mac_addr(iface,mac_addr)

        return {"message":
                "Your MAC Address Changed to {}".format(mac_addr)},201
##############################################################################