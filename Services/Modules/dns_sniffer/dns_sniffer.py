#!/usr/bin/env python3


# Imports
##############################################################################
from scapy.all import *
import sys
from flask_restful import Resource, Api, abort
from werkzeug.exceptions import BadRequest
from flask import Flask, request, abort, jsonify

from .schema import DnsSnifferGetSchema
##############################################################################


# Global Values
##############################################################################
INTERFACE = "eth0"
A_RECORD  = 1
FILTER    = "port 53"
CACHE     = []
##############################################################################


#Functions
##############################################################################
# DNS Question Records
def sniff_dns_qr(packet):
    if IP in packet:
        ip_src = packet[IP].src
        if packet.haslayer(DNSQR):
            if packet.getlayer(DNSQR).qtype == A_RECORD:
                qname = packet.getlayer(DNSQR).qname.decode("utf-8")
                qr = { "ip_src" : ip_src,
                       "qname"  : qname }
                CACHE.append(qr)


# DNS Resource Records
def sniff_dns_rr(packet):
    if IP in packet:
        ip_src = packet[IP].src
        if packet.haslayer(DNSRR):
            if packet.getlayer(DNSRR).type == A_RECORD:
                rrname = packet.getlayer(DNSRR).rrname.decode("utf-8")
                rdata  = packet.getlayer(DNSRR).rdata
                rr     = { "ip_src" : ip_src,
                           "rrname" : rrname }
                CACHE.append(rr)
##############################################################################


# Api Class
##############################################################################
class DnsSniffer(Resource):
    def get(self):
        dns_sniffer_get_schema = DnsSnifferGetSchema()        # Schema Object

        data = request.get_json()                             # Getting Data

        # Validating Request Parameters
        errors = dns_sniffer_get_schema.validate(data)
        if errors:
            raise BadRequest(errors)

        iface  = data['iface']

        return CACHE
##############################################################################


##############################################################################
sniff(iface = INTERFACE, filter=FILTER, prn = sniff_dns_rr, store = 1)
##############################################################################