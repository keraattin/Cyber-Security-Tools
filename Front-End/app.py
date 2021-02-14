#!/usr/bin/env python3


# Imports
##############################################################################
from flask import Flask, request, abort, jsonify, render_template
import requests
##############################################################################


# Global Values
##############################################################################
DEBUG = True                                      # Debug Mode
PORT = 5000                                       # Port Number

API_URL = "http://localhost:5000"                 # API Services Url
ARP_SCN_URL = API_URL + "/api/arp_scan"           # Arp Scan API Url
ARP_SPF_URL = API_URL + "/api/arp_spoof"          # Arp Spoof API Url

app = Flask(__name__)
##############################################################################


# Pages
##############################################################################
## Homepage
@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')


## Arp Scanner
@app.route('/arp_scanner/', methods=['GET'])
def arp_scanner():
    return render_template('arp_scanner.html', api_url=ARP_SCN_URL)


## Arp Spoofer
@app.route('/arp_spoofer/', methods=['GET'])
def arp_spoofer():
    return render_template('arp_spoofer.html', api_url=ARP_SPF_URL)


## Error Page
@app.errorhandler(404)
def page_not_found(e):
    # note that we set the 404 status explicitly
    return render_template('404.html'), 404
##############################################################################


# Main
##############################################################################
if __name__ == '__main__':
    app.run(debug=DEBUG, port=PORT)
##############################################################################