#!/usr/bin/env python3


# Imports
##############################################################################
from flask_restful import reqparse
##############################################################################


# Args
##############################################################################
arp_scan_get_args = reqparse.RequestParser()
arp_scan_get_args.add_argument("target",  type=str, 
        help="Target Ip Adress",  required=True)
##############################################################################