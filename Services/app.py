#!/usr/bin/env python3


##############################################################################
from flask import Flask, request, abort, jsonify, render_template
from flask_restful import Resource, Api, abort
from werkzeug.exceptions import BadRequest

# Modules
from Modules.arp_scanner.arp_scanner import ArpScan
from Modules.arp_spoofer.arp_spoofer import ArpSpoof
from Modules.mac_changer.mac_changer import MacChanger
##############################################################################


# Gloabal Variables
##############################################################################
DEBUG = True                                      # Debug Mode
PORT = 5001                                       # Port Number

app = Flask(__name__)
api = Api(app)
##############################################################################


# Endpoints
##############################################################################
api.add_resource(ArpScan, '/api/arp_scan')

api.add_resource(ArpSpoof, '/api/arp_spoof')

api.add_resource(MacChanger, '/api/mac_changer')
##############################################################################


# Main
##############################################################################
if __name__ == '__main__':
    app.run(debug=DEBUG, port=PORT)
##############################################################################